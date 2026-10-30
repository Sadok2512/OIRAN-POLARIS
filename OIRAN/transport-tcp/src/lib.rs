//! Bounded, provenance-preserving TCP stream reconstruction for offline captures.

use capture_pcap::{CapturePacket, TransportProtocol, TransportView};
use event_schema::{ExactTimestamp, PacketReference};
use std::collections::{BTreeMap, HashMap};

pub const VERSION: &str = "0.1.0";
const MAX_CONNECTIONS: usize = 4096;
const MAX_DIRECTION_BYTES: usize = 16 * 1024 * 1024;
const MAX_PENDING_SEGMENTS: usize = 4096;
const IDLE_TIMEOUT_NS: i128 = 300_000_000_000;

#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct TcpEndpoint {
    pub address: String,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct TcpConnectionKey {
    pub low: TcpEndpoint,
    pub high: TcpEndpoint,
}

impl TcpConnectionKey {
    pub fn new(source: TcpEndpoint, destination: TcpEndpoint) -> (Self, bool) {
        if source <= destination {
            (
                Self {
                    low: source,
                    high: destination,
                },
                true,
            )
        } else {
            (
                Self {
                    low: destination,
                    high: source,
                },
                false,
            )
        }
    }
    pub fn id(&self) -> String {
        format!(
            "{}:{}-{}:{}",
            self.low.address, self.low.port, self.high.address, self.high.port
        )
    }
}

#[derive(Clone, Debug)]
pub struct ProvenanceSpan {
    pub start: usize,
    pub end: usize,
    pub timestamp: ExactTimestamp,
    pub packet: PacketReference,
}

#[derive(Clone, Debug)]
pub struct ReassembledDirection {
    pub source: TcpEndpoint,
    pub destination: TcpEndpoint,
    pub bytes: Vec<u8>,
    pub spans: Vec<ProvenanceSpan>,
    pub incomplete: bool,
    pub retransmissions: usize,
    pub duplicate_segments: usize,
}

#[derive(Clone, Debug)]
pub struct ReassembledConnection {
    pub key: TcpConnectionKey,
    pub directions: [ReassembledDirection; 2],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpErrorKind {
    Malformed,
    LimitExceeded,
    StreamGap,
    Evicted,
}

#[derive(Clone, Debug)]
pub struct TcpError {
    pub kind: TcpErrorKind,
    pub packet_number: u64,
    pub message: String,
}

#[derive(Clone)]
struct Segment {
    seq: u32,
    payload: Vec<u8>,
    timestamp: ExactTimestamp,
    packet: PacketReference,
}

#[derive(Default)]
struct HalfStream {
    next_seq: Option<u32>,
    pending: BTreeMap<u32, Segment>,
    bytes: Vec<u8>,
    spans: Vec<ProvenanceSpan>,
    incomplete: bool,
    retransmissions: usize,
    duplicate_segments: usize,
}

#[derive(Default)]
struct ConnectionState {
    halves: [HalfStream; 2],
    last_seen_ns: i128,
}

#[derive(Default)]
pub struct TcpReassembler {
    connections: HashMap<TcpConnectionKey, ConnectionState>,
    evicted: Vec<(TcpConnectionKey, ConnectionState)>,
    errors: Vec<TcpError>,
}

impl TcpReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn consume(&mut self, packet: &CapturePacket, view: &TransportView) {
        if view.protocol != TransportProtocol::Tcp {
            return;
        }
        let now = packet.metadata.timestamp.unix_nanoseconds().unwrap_or(0);
        let expired = self
            .connections
            .iter()
            .filter(|(_, state)| now.saturating_sub(state.last_seen_ns) > IDLE_TIMEOUT_NS)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in expired {
            if let Some(state) = self.connections.remove(&key) {
                self.evicted.push((key.clone(), state));
            }
            self.errors.push(TcpError {
                kind: TcpErrorKind::Evicted,
                packet_number: packet.metadata.packet_number,
                message: format!("idle TCP connection finalized: {}", key.id()),
            });
        }
        if self.connections.len() >= MAX_CONNECTIONS {
            self.errors.push(TcpError {
                kind: TcpErrorKind::LimitExceeded,
                packet_number: packet.metadata.packet_number,
                message: "TCP connection limit exceeded".into(),
            });
            return;
        }
        let start = view.payload_offset;
        if view.payload_length < 20 || start + view.payload_length > packet.data.len() {
            return;
        }
        let tcp = &packet.data[start..start + view.payload_length];
        let header_len = usize::from(tcp[12] >> 4) * 4;
        if header_len < 20 || header_len > tcp.len() {
            self.errors.push(TcpError {
                kind: TcpErrorKind::Malformed,
                packet_number: packet.metadata.packet_number,
                message: "invalid TCP data offset".into(),
            });
            return;
        }
        let payload = &tcp[header_len..];
        if payload.is_empty() {
            return;
        }
        let source = TcpEndpoint {
            address: view.source_ip.clone(),
            port: view.source_port.unwrap_or(0),
        };
        let destination = TcpEndpoint {
            address: view.destination_ip.clone(),
            port: view.destination_port.unwrap_or(0),
        };
        let (key, low_to_high) = TcpConnectionKey::new(source, destination);
        let state = self.connections.entry(key).or_default();
        state.last_seen_ns = now;
        let half = &mut state.halves[if low_to_high { 0 } else { 1 }];
        let mut seq = u32::from_be_bytes(tcp[4..8].try_into().expect("four bytes"));
        if tcp[13] & 0x02 != 0 {
            seq = seq.wrapping_add(1);
        }
        let segment = Segment {
            seq,
            payload: payload.to_vec(),
            timestamp: packet.metadata.timestamp.clone(),
            packet: packet_reference(packet),
        };
        insert_segment(half, segment, &mut self.errors);
    }

    /// Return connections finalized by the idle timeout and release their
    /// reassembly buffers immediately. Long-running captures must call this
    /// while packets are being visited; retaining evicted connections until
    /// EOF makes resident memory proportional to the complete capture.
    pub fn take_finalized(&mut self) -> Vec<ReassembledConnection> {
        let mut states = std::mem::take(&mut self.evicted);
        states.sort_by(|a, b| a.0.cmp(&b.0));
        finalize_states(states, &mut self.errors)
    }

    pub fn finish(mut self) -> (Vec<ReassembledConnection>, Vec<TcpError>) {
        let mut states: Vec<_> = self.connections.drain().collect();
        states.append(&mut self.evicted);
        states.sort_by(|a, b| a.0.cmp(&b.0));
        let output = finalize_states(states, &mut self.errors);
        (output, self.errors)
    }
}

fn finalize_states(
    states: Vec<(TcpConnectionKey, ConnectionState)>,
    errors: &mut Vec<TcpError>,
) -> Vec<ReassembledConnection> {
    let mut output = Vec::with_capacity(states.len());
    for (key, mut state) in states {
        for half in &mut state.halves {
            flush_pending(half, errors);
        }
        let [a, b] = state.halves;
        output.push(ReassembledConnection {
            directions: [
                direction(key.low.clone(), key.high.clone(), a),
                direction(key.high.clone(), key.low.clone(), b),
            ],
            key,
        });
    }
    output
}

fn direction(
    source: TcpEndpoint,
    destination: TcpEndpoint,
    half: HalfStream,
) -> ReassembledDirection {
    ReassembledDirection {
        source,
        destination,
        bytes: half.bytes,
        spans: half.spans,
        incomplete: half.incomplete,
        retransmissions: half.retransmissions,
        duplicate_segments: half.duplicate_segments,
    }
}

fn insert_segment(half: &mut HalfStream, mut segment: Segment, errors: &mut Vec<TcpError>) {
    if half.next_seq.is_none() {
        half.next_seq = Some(segment.seq);
    }
    let expected = half.next_seq.unwrap();
    if seq_before(segment.seq, expected) {
        let overlap = expected.wrapping_sub(segment.seq) as usize;
        half.retransmissions += 1;
        if overlap >= segment.payload.len() {
            half.duplicate_segments += 1;
            return;
        }
        segment.payload.drain(..overlap);
        segment.seq = expected;
    }
    if half.pending.len() >= MAX_PENDING_SEGMENTS
        || half.bytes.len() + segment.payload.len() > MAX_DIRECTION_BYTES
    {
        errors.push(TcpError {
            kind: TcpErrorKind::LimitExceeded,
            packet_number: segment.packet.packet_number,
            message: "TCP direction buffer limit exceeded".into(),
        });
        half.incomplete = true;
        return;
    }
    match half.pending.get(&segment.seq) {
        Some(existing) if existing.payload.len() >= segment.payload.len() => {
            half.duplicate_segments += 1;
            return;
        }
        _ => {
            half.pending.insert(segment.seq, segment);
        }
    }
    drain_contiguous(half);
}

fn drain_contiguous(half: &mut HalfStream) {
    loop {
        let expected = match half.next_seq {
            Some(value) => value,
            None => return,
        };
        let Some(segment) = half.pending.remove(&expected) else {
            return;
        };
        append(half, segment);
    }
}

fn flush_pending(half: &mut HalfStream, errors: &mut Vec<TcpError>) {
    while let Some((&seq, _)) = half.pending.iter().next() {
        if Some(seq) != half.next_seq {
            half.incomplete = true;
            let packet = half
                .pending
                .get(&seq)
                .map(|s| s.packet.packet_number)
                .unwrap_or(0);
            errors.push(TcpError {
                kind: TcpErrorKind::StreamGap,
                packet_number: packet,
                message: "TCP stream gap preserved as incomplete".into(),
            });
            half.next_seq = Some(seq);
        }
        drain_contiguous(half);
    }
}

fn append(half: &mut HalfStream, segment: Segment) {
    let start = half.bytes.len();
    half.bytes.extend_from_slice(&segment.payload);
    let end = half.bytes.len();
    half.spans.push(ProvenanceSpan {
        start,
        end,
        timestamp: segment.timestamp,
        packet: segment.packet,
    });
    half.next_seq = Some(segment.seq.wrapping_add(segment.payload.len() as u32));
}

fn seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn packet_reference(packet: &CapturePacket) -> PacketReference {
    let sll2 = packet.metadata.sll2.as_ref();
    PacketReference {
        source_file: packet.metadata.source_file.clone(),
        source_sha256: packet
            .metadata
            .capture_id
            .strip_prefix("sha256:")
            .map(str::to_owned),
        packet_number: packet.metadata.packet_number,
        byte_offset: packet.metadata.byte_offset,
        interface_id: packet.metadata.interface_id,
        link_type: Some(packet.metadata.link_type),
        sll2_protocol_type: sll2.map(|x| x.protocol_type),
        sll2_reserved: sll2.map(|x| x.reserved),
        sll2_interface_index: sll2.map(|x| x.interface_index),
        sll2_arphrd_type: sll2.map(|x| x.arphrd_type),
        sll2_packet_type: sll2.map(|x| x.packet_type),
        sll2_address_length: sll2.map(|x| x.address_length),
        sll2_address: sll2.map(|x| {
            x.address[..usize::from(x.address_length)]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        }),
        captured_length: packet.metadata.captured_length,
        original_length: packet.metadata.original_length,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn half() -> HalfStream {
        HalfStream::default()
    }
    fn segment(seq: u32, payload: &[u8], packet: u64) -> Segment {
        Segment {
            seq,
            payload: payload.to_vec(),
            timestamp: ExactTimestamp {
                seconds: 1,
                nanoseconds: packet as u32,
                raw_ticks: packet,
                resolution_base: 10,
                resolution_exponent: 9,
            },
            packet: PacketReference {
                source_file: "fixture".into(),
                source_sha256: None,
                packet_number: packet,
                byte_offset: 0,
                interface_id: 0,
                link_type: Some(1),
                sll2_protocol_type: None,
                sll2_reserved: None,
                sll2_interface_index: None,
                sll2_arphrd_type: None,
                sll2_packet_type: None,
                sll2_address_length: None,
                sll2_address: None,
                captured_length: payload.len() as u32,
                original_length: payload.len() as u32,
            },
        }
    }

    #[test]
    fn reorders_and_deduplicates_segments() {
        let mut h = half();
        let mut errors = vec![];
        insert_segment(&mut h, segment(10, b"abc", 1), &mut errors);
        insert_segment(&mut h, segment(16, b"ghi", 3), &mut errors);
        insert_segment(&mut h, segment(13, b"def", 2), &mut errors);
        insert_segment(&mut h, segment(13, b"def", 4), &mut errors);
        assert_eq!(h.bytes, b"abcdefghi");
        assert_eq!(h.duplicate_segments, 1);
        assert!(errors.is_empty());
    }

    #[test]
    fn records_gap_without_panicking() {
        let mut h = half();
        let mut errors = vec![];
        insert_segment(&mut h, segment(10, b"abc", 1), &mut errors);
        insert_segment(&mut h, segment(20, b"z", 2), &mut errors);
        flush_pending(&mut h, &mut errors);
        assert!(h.incomplete);
        assert_eq!(h.bytes, b"abcz");
        assert_eq!(errors[0].kind, TcpErrorKind::StreamGap);
    }
}
