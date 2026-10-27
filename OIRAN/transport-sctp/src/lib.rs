//! SCTP DATA message parsing and conservative reassembly.

use capture_pcap::{CapturePacket, TransportProtocol, TransportView};
use event_schema::{stable_hash, ExactTimestamp, PacketReference};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SctpErrorKind {
    Malformed,
    Duplicate,
    Incomplete,
    UnsupportedIData,
    AssociationRestart,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SctpError {
    pub kind: SctpErrorKind,
    pub packet_number: u64,
    pub message: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SctpMessage {
    pub association_id: String,
    pub association_generation: u64,
    pub source_ip: String,
    pub destination_ip: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub verification_tag: u32,
    pub stream_id: u16,
    pub stream_sequence: u16,
    pub ppid: u32,
    pub first_tsn: u32,
    pub last_tsn: u32,
    pub unordered: bool,
    pub payload: Vec<u8>,
    pub packet_references: Vec<PacketReference>,
    pub timestamp: ExactTimestamp,
}
#[derive(Clone, Debug)]
struct Fragment {
    source_ip: String,
    destination_ip: String,
    source_port: u16,
    destination_port: u16,
    vtag: u32,
    stream_id: u16,
    ssn: u16,
    ppid: u32,
    first_tsn: u32,
    last_tsn: u32,
    unordered: bool,
    payload: Vec<u8>,
    refs: Vec<PacketReference>,
    timestamp: ExactTimestamp,
    association_id: String,
    generation: u64,
}
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FragKey {
    association: String,
    generation: u64,
    direction: String,
    stream: u16,
    ssn: u16,
    ppid: u32,
}

#[derive(Default)]
pub struct SctpReassembler {
    generations: HashMap<String, u64>,
    fragments: HashMap<FragKey, Fragment>,
    seen: HashSet<(String, u64, String, u32)>,
    errors: Vec<SctpError>,
}
impl SctpReassembler {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn consume(&mut self, packet: &CapturePacket, view: &TransportView) -> Vec<SctpMessage> {
        if view.protocol != TransportProtocol::Sctp {
            return Vec::new();
        }
        let data = &packet.data[view.payload_offset..view.payload_offset + view.payload_length];
        if data.len() < 12 {
            self.error(
                SctpErrorKind::Malformed,
                packet,
                "SCTP common header truncated",
            );
            return Vec::new();
        }
        let source_port = be16(&data[0..2]);
        let destination_port = be16(&data[2..4]);
        let vtag = be32(&data[4..8]);
        let association = association_key(
            &view.source_ip,
            source_port,
            &view.destination_ip,
            destination_port,
        );
        let direction = format!(
            "{}:{}>{}:{}",
            view.source_ip, source_port, view.destination_ip, destination_port
        );
        let mut generation = *self.generations.entry(association.clone()).or_insert(0);
        let mut out = Vec::new();
        let mut offset = 12;
        while offset < data.len() {
            if data.len() - offset < 4 {
                self.error(
                    SctpErrorKind::Malformed,
                    packet,
                    "SCTP chunk header truncated",
                );
                break;
            }
            let kind = data[offset];
            let flags = data[offset + 1];
            let length = be16(&data[offset + 2..offset + 4]) as usize;
            if length < 4 || offset + length > data.len() {
                self.error(
                    SctpErrorKind::Malformed,
                    packet,
                    "invalid SCTP chunk length",
                );
                break;
            }
            let chunk = &data[offset..offset + length];
            match kind {
                0 => {
                    if chunk.len() < 16 {
                        self.error(SctpErrorKind::Malformed, packet, "DATA chunk truncated");
                    } else {
                        let tsn = be32(&chunk[4..8]);
                        let stream = be16(&chunk[8..10]);
                        let ssn = be16(&chunk[10..12]);
                        let ppid = be32(&chunk[12..16]);
                        let seen_key = (association.clone(), generation, direction.clone(), tsn);
                        if !self.seen.insert(seen_key) {
                            self.error(
                                SctpErrorKind::Duplicate,
                                packet,
                                format!("duplicate/retransmitted DATA TSN {tsn}"),
                            );
                        } else {
                            let begin = flags & 0x02 != 0;
                            let end = flags & 0x01 != 0;
                            let unordered = flags & 0x04 != 0;
                            let key = FragKey {
                                association: association.clone(),
                                generation,
                                direction: direction.clone(),
                                stream,
                                ssn,
                                ppid,
                            };
                            if begin && end {
                                out.push(SctpMessage {
                                    association_id: association.clone(),
                                    association_generation: generation,
                                    source_ip: view.source_ip.clone(),
                                    destination_ip: view.destination_ip.clone(),
                                    source_port,
                                    destination_port,
                                    verification_tag: vtag,
                                    stream_id: stream,
                                    stream_sequence: ssn,
                                    ppid,
                                    first_tsn: tsn,
                                    last_tsn: tsn,
                                    unordered,
                                    payload: chunk[16..].to_vec(),
                                    packet_references: vec![packet_ref(packet)],
                                    timestamp: packet.metadata.timestamp.clone(),
                                });
                            } else if begin {
                                if self.fragments.remove(&key).is_some() {
                                    self.error(
                                        SctpErrorKind::Incomplete,
                                        packet,
                                        "new beginning replaced incomplete SCTP message",
                                    );
                                }
                                self.fragments.insert(
                                    key,
                                    Fragment {
                                        source_ip: view.source_ip.clone(),
                                        destination_ip: view.destination_ip.clone(),
                                        source_port,
                                        destination_port,
                                        vtag,
                                        stream_id: stream,
                                        ssn,
                                        ppid,
                                        first_tsn: tsn,
                                        last_tsn: tsn,
                                        unordered,
                                        payload: chunk[16..].to_vec(),
                                        refs: vec![packet_ref(packet)],
                                        timestamp: packet.metadata.timestamp.clone(),
                                        association_id: association.clone(),
                                        generation,
                                    },
                                );
                            } else if let Some(fragment) = self.fragments.get_mut(&key) {
                                if tsn != fragment.last_tsn.wrapping_add(1) {
                                    self.fragments.remove(&key);
                                    self.error(
                                        SctpErrorKind::Incomplete,
                                        packet,
                                        "fragment TSN gap; message discarded",
                                    );
                                } else {
                                    fragment.last_tsn = tsn;
                                    fragment.payload.extend_from_slice(&chunk[16..]);
                                    fragment.refs.push(packet_ref(packet));
                                    if end {
                                        let f =
                                            self.fragments.remove(&key).expect("fragment exists");
                                        out.push(f.complete());
                                    }
                                }
                            } else {
                                self.error(
                                    SctpErrorKind::Incomplete,
                                    packet,
                                    "non-beginning DATA fragment has no assembly",
                                );
                            }
                        }
                    }
                }
                1 => {
                    generation = self
                        .generations
                        .entry(association.clone())
                        .and_modify(|g| *g += 1)
                        .or_insert(1)
                        .to_owned();
                    let affected: Vec<_> = self
                        .fragments
                        .keys()
                        .filter(|k| k.association == association)
                        .cloned()
                        .collect();
                    for key in affected {
                        self.fragments.remove(&key);
                        self.error(
                            SctpErrorKind::AssociationRestart,
                            packet,
                            "INIT reset incomplete association state",
                        );
                    }
                }
                64 => self.error(
                    SctpErrorKind::UnsupportedIData,
                    packet,
                    "SCTP I-DATA/interleaving is unsupported",
                ),
                _ => {}
            }
            offset += align4(length);
            if offset > data.len() {
                self.error(
                    SctpErrorKind::Malformed,
                    packet,
                    "SCTP chunk padding exceeds packet",
                );
                break;
            }
        }
        out
    }
    pub fn finish(mut self) -> (Vec<SctpError>, usize) {
        let incomplete = self.fragments.len();
        for f in self.fragments.values() {
            self.errors.push(SctpError {
                kind: SctpErrorKind::Incomplete,
                packet_number: f.refs.last().map(|p| p.packet_number).unwrap_or(0),
                message: format!(
                    "incomplete SCTP message stream={} ssn={} TSN {}..{}",
                    f.stream_id, f.ssn, f.first_tsn, f.last_tsn
                ),
            });
        }
        (self.errors, incomplete)
    }
    pub fn errors(&self) -> &[SctpError] {
        &self.errors
    }
    fn error(&mut self, kind: SctpErrorKind, packet: &CapturePacket, message: impl Into<String>) {
        self.errors.push(SctpError {
            kind,
            packet_number: packet.metadata.packet_number,
            message: message.into(),
        });
    }
}
impl Fragment {
    fn complete(self) -> SctpMessage {
        SctpMessage {
            association_id: self.association_id,
            association_generation: self.generation,
            source_ip: self.source_ip,
            destination_ip: self.destination_ip,
            source_port: self.source_port,
            destination_port: self.destination_port,
            verification_tag: self.vtag,
            stream_id: self.stream_id,
            stream_sequence: self.ssn,
            ppid: self.ppid,
            first_tsn: self.first_tsn,
            last_tsn: self.last_tsn,
            unordered: self.unordered,
            payload: self.payload,
            packet_references: self.refs,
            timestamp: self.timestamp,
        }
    }
}
fn association_key(a: &str, ap: u16, b: &str, bp: u16) -> String {
    let left = format!("{a}:{ap}");
    let right = format!("{b}:{bp}");
    let canonical = if left <= right {
        format!("{left}|{right}")
    } else {
        format!("{right}|{left}")
    };
    format!("sctp-{:016x}", stable_hash(canonical.as_bytes()))
}
fn packet_ref(p: &CapturePacket) -> PacketReference {
    let sll2 = p.metadata.sll2.as_ref();
    PacketReference {
        source_file: p.metadata.source_file.clone(),
        source_sha256: p
            .metadata
            .capture_id
            .strip_prefix("sha256:")
            .map(str::to_owned),
        packet_number: p.metadata.packet_number,
        byte_offset: p.metadata.byte_offset,
        interface_id: p.metadata.interface_id,
        link_type: Some(p.metadata.link_type),
        sll2_protocol_type: sll2.map(|header| header.protocol_type),
        sll2_reserved: sll2.map(|header| header.reserved),
        sll2_interface_index: sll2.map(|header| header.interface_index),
        sll2_arphrd_type: sll2.map(|header| header.arphrd_type),
        sll2_packet_type: sll2.map(|header| header.packet_type),
        sll2_address_length: sll2.map(|header| header.address_length),
        sll2_address: sll2.map(|header| {
            header.address[..usize::from(header.address_length)]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        }),
        captured_length: p.metadata.captured_length,
        original_length: p.metadata.original_length,
    }
}
fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
fn align4(v: usize) -> usize {
    (v + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;
    use capture_pcap::{PacketMetadata, TransportView};
    fn packet(number: u64, chunks: &[u8]) -> (CapturePacket, TransportView) {
        let mut data = vec![0x96, 0x0c, 0x82, 0xd4, 0, 0, 0, 7, 0, 0, 0, 0];
        data.extend_from_slice(chunks);
        let len = data.len();
        (
            CapturePacket {
                metadata: PacketMetadata {
                    capture_id: "c".into(),
                    source_file: "x".into(),
                    packet_number: number,
                    byte_offset: number * 100,
                    timestamp: ExactTimestamp {
                        seconds: number as i64,
                        nanoseconds: 0,
                        raw_ticks: number,
                        resolution_base: 10,
                        resolution_exponent: 9,
                    },
                    captured_length: len as u32,
                    original_length: len as u32,
                    interface_id: 0,
                    link_type: 1,
                    sll2: None,
                    truncated: false,
                },
                data,
            },
            TransportView {
                source_ip: "10.0.0.1".into(),
                destination_ip: "10.0.0.2".into(),
                protocol: TransportProtocol::Sctp,
                source_port: Some(38412),
                destination_port: Some(33492),
                payload_offset: 0,
                payload_length: len,
            },
        )
    }
    fn data(flags: u8, tsn: u32, stream: u16, ssn: u16, ppid: u32, payload: &[u8]) -> Vec<u8> {
        let len = 16 + payload.len();
        let mut v = vec![0, flags];
        v.extend_from_slice(&(len as u16).to_be_bytes());
        v.extend_from_slice(&tsn.to_be_bytes());
        v.extend_from_slice(&stream.to_be_bytes());
        v.extend_from_slice(&ssn.to_be_bytes());
        v.extend_from_slice(&ppid.to_be_bytes());
        v.extend_from_slice(payload);
        v.resize(align4(len), 0);
        v
    }
    #[test]
    fn single_and_multiple_chunks() {
        let mut chunks = data(3, 1, 4, 0, 60, b"one");
        chunks.extend_from_slice(&data(3, 2, 5, 0, 60, b"two"));
        let (p, v) = packet(1, &chunks);
        let mut r = SctpReassembler::new();
        let m = r.consume(&p, &v);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].payload, b"one");
        assert_eq!(m[1].stream_id, 5);
    }
    #[test]
    fn fragments_and_retransmission() {
        let (p1, v1) = packet(1, &data(2, 10, 4, 1, 60, b"ab"));
        let (p2, v2) = packet(2, &data(1, 11, 4, 1, 60, b"cd"));
        let mut r = SctpReassembler::new();
        assert!(r.consume(&p1, &v1).is_empty());
        let m = r.consume(&p2, &v2);
        assert_eq!(m[0].payload, b"abcd");
        assert!(r.consume(&p2, &v2).is_empty());
        assert!(r
            .errors()
            .iter()
            .any(|e| e.kind == SctpErrorKind::Duplicate));
    }
    #[test]
    fn missing_fragment_is_never_emitted() {
        let (p, v) = packet(1, &data(1, 9, 2, 3, 60, b"tail"));
        let mut r = SctpReassembler::new();
        assert!(r.consume(&p, &v).is_empty());
        let (errors, incomplete) = r.finish();
        assert_eq!(incomplete, 0);
        assert!(errors.iter().any(|e| e.kind == SctpErrorKind::Incomplete));
        let (p, v) = packet(2, &data(2, 20, 3, 4, 60, b"start"));
        let mut r = SctpReassembler::new();
        assert!(r.consume(&p, &v).is_empty());
        let (_, incomplete) = r.finish();
        assert_eq!(incomplete, 1);
    }
    #[test]
    fn idata_is_explicitly_unsupported() {
        let chunk = vec![64, 0, 0, 4];
        let (p, v) = packet(1, &chunk);
        let mut r = SctpReassembler::new();
        r.consume(&p, &v);
        assert_eq!(r.errors()[0].kind, SctpErrorKind::UnsupportedIData);
    }
}
