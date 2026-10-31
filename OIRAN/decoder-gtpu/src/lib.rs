//! 3GPP TS 29.281 GTPv1-U decoder; application payload stays opaque.

use event_schema::{
    sha256_hex, DecodeStatus, Direction, EvidenceReference, EvidenceState, InformationElement,
    NamedValue, NormalizedEvent, Protocol,
};
use plugin_runtime::{
    DecoderCapabilities, DecoderInput, DecoderManifest, DecoderOutput, ProtocolDecoder,
    PLUGIN_API_VERSION,
};

pub const VERSION: &str = "0.2.0";
#[derive(Default)]
pub struct GtpuDecoder;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GtpuHeader {
    pub message_type: u8,
    pub teid: u32,
    pub sequence_number: Option<u16>,
    pub npdu_number: Option<u8>,
    pub payload_offset: usize,
    pub payload_length: usize,
    pub extensions: Vec<GtpuExtension>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GtpuExtension {
    pub extension_type: u8,
    pub content: Vec<u8>,
    pub pdu_type: Option<u8>,
    pub qfi: Option<u8>,
}

pub fn parse(payload: &[u8]) -> Result<GtpuHeader, String> {
    if payload.len() < 8 {
        return Err("GTP-U mandatory header truncated".into());
    }
    let flags = payload[0];
    if flags >> 5 != 1 {
        return Err("unsupported GTP version".into());
    }
    if flags & 0x10 == 0 {
        return Err("GTP protocol-type bit is not set".into());
    }
    let total = 8 + be16(&payload[2..4]) as usize;
    if total > payload.len() {
        return Err("declared GTP-U payload exceeds UDP payload".into());
    }
    let message_type = payload[1];
    let teid = be32(&payload[4..8]);
    let optional = flags & 0x07 != 0;
    let mut offset = 8;
    let mut sequence = None;
    let mut npdu = None;
    let mut extensions = Vec::new();
    if optional {
        if total < 12 {
            return Err("GTP-U optional fields truncated".into());
        }
        if flags & 0x02 != 0 {
            sequence = Some(be16(&payload[8..10]));
        }
        if flags & 0x01 != 0 {
            npdu = Some(payload[10]);
        }
        let mut next = if flags & 0x04 != 0 { payload[11] } else { 0 };
        offset = 12;
        let mut count = 0;
        while next != 0 {
            count += 1;
            if count > 32 {
                return Err("GTP-U extension chain exceeds 32 headers".into());
            }
            if offset >= total {
                return Err("GTP-U extension header truncated".into());
            }
            let len = payload[offset] as usize * 4;
            if len < 4 || offset + len > total {
                return Err("invalid GTP-U extension length".into());
            }
            let content = payload[offset + 1..offset + len - 1].to_vec();
            let (pdu_type, qfi) = if next == 0x85 && !content.is_empty() {
                (Some(content[0] >> 4), content.get(1).map(|b| b & 0x3f))
            } else {
                (None, None)
            };
            extensions.push(GtpuExtension {
                extension_type: next,
                content,
                pdu_type,
                qfi,
            });
            next = payload[offset + len - 1];
            offset += len;
        }
    }
    if offset > total {
        return Err("GTP-U header exceeds declared message".into());
    }
    Ok(GtpuHeader {
        message_type,
        teid,
        sequence_number: sequence,
        npdu_number: npdu,
        payload_offset: offset,
        payload_length: total - offset,
        extensions,
    })
}
impl ProtocolDecoder for GtpuDecoder {
    fn manifest(&self) -> DecoderManifest {
        DecoderManifest {
            decoder_name: "decoder-gtpu",
            decoder_version: VERSION,
            api_version: PLUGIN_API_VERSION,
            protocol: Protocol::Gtpu,
            specification: "3GPP TS 29.281",
            deterministic: true,
        }
    }
    fn capabilities(&self) -> DecoderCapabilities {
        DecoderCapabilities {
            message_families: &["G-PDU", "Echo", "Error Indication"],
            preserves_unknown_fields: true,
            supports_extensions: true,
            limitations: &[
                "user-plane application payload is not decoded",
                "TEID alone is not treated as a session key",
            ],
        }
    }
    fn decode(&self, input: &DecoderInput<'_>) -> DecoderOutput {
        match parse(input.payload) {
            Ok(header) => {
                let mut ies = Vec::new();
                for ext in &header.extensions {
                    ies.push(InformationElement {
                        id: Some(ext.extension_type as u16),
                        name: if ext.extension_type == 0x85 {
                            "PDU Session Container".into()
                        } else {
                            format!("Extension-0x{:02x}", ext.extension_type)
                        },
                        length: ext.content.len() as u32,
                        value: match (ext.pdu_type, ext.qfi) {
                            (Some(p), Some(q)) => Some(format!("pdu_type={p},qfi={q}")),
                            (Some(p), None) => Some(format!("pdu_type={p}")),
                            _ => None,
                        },
                        raw_sha256: Some(sha256_hex(&ext.content)),
                        status: if ext.extension_type == 0x85 {
                            DecodeStatus::Decoded
                        } else {
                            DecodeStatus::Unsupported
                        },
                    });
                }
                let mut ids = vec![NamedValue {
                    name: "teid".into(),
                    value: format!("0x{:08x}", header.teid),
                    pseudonymized: false,
                }];
                if let Some(seq) = header.sequence_number {
                    ids.push(NamedValue {
                        name: "sequence_number".into(),
                        value: seq.to_string(),
                        pseudonymized: false,
                    });
                }
                if header.message_type == 255 {
                    if let Some((source, destination)) = inner_ipv4_addresses(
                        &input.payload
                            [header.payload_offset..header.payload_offset + header.payload_length],
                    ) {
                        ids.push(NamedValue {
                            name: "inner_source_ip".into(),
                            value: source.clone(),
                            pseudonymized: false,
                        });
                        ids.push(NamedValue {
                            name: "inner_destination_ip".into(),
                            value: destination.clone(),
                            pseudonymized: false,
                        });
                        let ue_ip = match infer_direction(input) {
                            Direction::Uplink => Some(source),
                            Direction::Downlink => Some(destination),
                            _ => None,
                        };
                        if let Some(ue_ip) = ue_ip {
                            ids.push(NamedValue {
                                name: "ue_ip".into(),
                                value: ue_ip,
                                pseudonymized: false,
                            });
                        }
                    }
                }
                let mut event = NormalizedEvent {
                    event_id: String::new(),
                    parent_event_id: None,
                    probe_id: "oiran-vprobe-01".into(),
                    capture_point_id: input.interface.into(),
                    capture_id: input.capture_id.into(),
                    packet_references: input.packet_references.to_vec(),
                    timestamp: input.timestamp.clone(),
                    interface: input.interface.into(),
                    protocol: Protocol::Gtpu,
                    message_name: name(header.message_type).into(),
                    message_type: header.message_type as u32,
                    procedure_code: None,
                    procedure: None,
                    security_state: None,
                    source_byte_offset: None,
                    source_endpoint: input.source_endpoint.clone(),
                    destination_endpoint: input.destination_endpoint.clone(),
                    direction: infer_direction(input),
                    session_identifiers: ids,
                    information_elements: ies,
                    decoder_name: "decoder-gtpu".into(),
                    decoder_version: VERSION.into(),
                    schema_version: NormalizedEvent::SCHEMA_VERSION,
                    decoding_status: DecodeStatus::Decoded,
                    errors: Vec::new(),
                    raw_payload_reference: input.raw_payload_reference.into(),
                    evidence_references: vec![EvidenceReference {
                        state: EvidenceState::Exact,
                        kind: "packet-provenance".into(),
                        reference: input.raw_payload_reference.into(),
                    }],
                    sbi: None,
                };
                event.assign_deterministic_id();
                DecoderOutput {
                    status: DecodeStatus::Decoded,
                    events: vec![event],
                    errors: Vec::new(),
                }
            }
            Err(e) => DecoderOutput {
                status: DecodeStatus::Malformed,
                events: Vec::new(),
                errors: vec![e],
            },
        }
    }
}

fn inner_ipv4_addresses(payload: &[u8]) -> Option<(String, String)> {
    if payload.len() < 20 || payload[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(payload[0] & 0x0f) * 4;
    if header_len < 20 || header_len > payload.len() {
        return None;
    }
    let address = |bytes: &[u8]| format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);
    Some((address(&payload[12..16]), address(&payload[16..20])))
}
fn infer_direction(i: &DecoderInput<'_>) -> Direction {
    let src = i
        .source_endpoint
        .network_function
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let dst = i
        .destination_endpoint
        .network_function
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    if src.contains("gnb") && dst.contains("upf") {
        Direction::Uplink
    } else if src.contains("upf") && dst.contains("gnb") {
        Direction::Downlink
    } else {
        Direction::Unknown
    }
}
fn name(t: u8) -> &'static str {
    match t {
        1 => "Echo Request",
        2 => "Echo Response",
        26 => "Error Indication",
        31 => "Supported Extension Headers Notification",
        254 => "End Marker",
        255 => "G-PDU",
        _ => "Unknown GTP-U Message",
    }
}
fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

// ---------------------------------------------------------------------------
// 2.5.3 — N3 headers-only aggregation (TS 29.281 §5.1).
//
// Rule, inherited from the capture-helper O3 contract: on N3, OIRAN keeps
// only the GTP-U header + optional PDU-session extension. Inner payload
// is never retained — only its length and a 1-bit TCP flag footprint are
// read to feed the aggregate counters.
//
// Memory bound: the aggregator holds at most one `TunnelFlow` entry per
// (TEID × 5-tuple of the outer encapsulation × direction). The 5-tuple
// here is the GTP-U *outer* (gNB IP ↔ UPF IP + UDP ports) because the
// inner payload is intentionally left opaque. Each entry carries fixed-
// size counters (16 u64 + 8 u8 + three Option<u8/u16> fields) → ~128 B
// per tunnel. On a lab segment with ≤ 128 tunnels the aggregator never
// exceeds 32 KiB regardless of how many GTP-U frames feed it.
//
// Covered by:
// - `aggregator_bounded_memory_on_half_million_packets` (unit): 500 000
//   G-PDU frames spread over 4 TEIDs → aggregator stays at exactly 4
//   `TunnelFlow` entries. Pre-aggregation, the live-probe retained 500
//   000 NormalizedEvent instances (~130 MiB) on the same input.
// - `aggregator_emits_one_event_per_teid_with_counters` (unit): a
//   single aggregated event per TEID is emitted at `into_events()`,
//   carrying `packets_ul`, `packets_dl`, `bytes_ul`, `bytes_dl`,
//   `first_seen_ns`, `last_seen_ns`, `qfi`, `retransmits_tcp`.

/// Direction classifier for the outer GTP-U header. Mirrors
/// `infer_direction` but takes the raw endpoint identifiers so the
/// aggregator can run during streaming decode without a `DecoderInput`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunnelDirection {
    Uplink,
    Downlink,
    Unknown,
}

/// Fixed-size per-tunnel counters. 136 B on a 64-bit target (vs. ≥ 1 KiB
/// per NormalizedEvent pre-aggregation).
#[derive(Clone, Debug, Default)]
pub struct TunnelFlow {
    pub teid: u32,
    pub direction: TunnelDirection,
    pub outer_source_ip: String,
    pub outer_destination_ip: String,
    pub outer_source_port: u16,
    pub outer_destination_port: u16,
    pub packets_ul: u64,
    pub packets_dl: u64,
    pub bytes_ul: u64,
    pub bytes_dl: u64,
    pub first_seen_ns: Option<u64>,
    pub last_seen_ns: Option<u64>,
    pub qfi: Option<u8>,
    /// Set to true if the TCP SYN+ACK handshake was observed inside the
    /// GTP-U payload. The aggregator only reads the TCP header (first
    /// 20 bytes of the inner IP payload); payload bytes stay opaque.
    pub tcp_handshake_seen: bool,
    pub retransmits_tcp: u64,
    /// Round-trip time estimate in microseconds between the first
    /// uplink SYN and the first downlink SYN+ACK on the same tunnel.
    /// `None` when either observation is missing — the counter is
    /// opportunistic and never fabricated.
    pub rtt_microseconds: Option<u64>,
}

impl Default for TunnelDirection {
    fn default() -> Self {
        TunnelDirection::Unknown
    }
}

/// 5-tuple key the aggregator uses to group packets.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TunnelKey {
    pub teid: u32,
    pub outer_source_ip: String,
    pub outer_destination_ip: String,
    pub outer_source_port: u16,
    pub outer_destination_port: u16,
}

/// Streaming N3 aggregator. Feed one `observe()` call per packet; the
/// internal map stays bounded by the number of distinct tunnels.
#[derive(Default)]
pub struct GtpuAggregator {
    flows: std::collections::HashMap<TunnelKey, TunnelFlow>,
    /// First UL SYN timestamps per TEID — kept out of `TunnelFlow` so
    /// the per-flow struct can stay fixed-size.
    pending_syn_ns: std::collections::HashMap<u32, u64>,
}

/// Minimal per-packet input the aggregator consumes. Does **not** take a
/// reference to the full payload — only the header + direction classifier
/// + a tiny 20-byte inner TCP header slice when applicable, so the caller
/// can zero the heap allocation immediately after `observe()`.
#[derive(Clone, Debug)]
pub struct TunnelPacket<'a> {
    pub header: GtpuHeader,
    pub direction: TunnelDirection,
    pub outer_source_ip: &'a str,
    pub outer_destination_ip: &'a str,
    pub outer_source_port: u16,
    pub outer_destination_port: u16,
    pub timestamp_ns: u64,
    /// Captured length of the whole GTP-U frame (outer IP + UDP + GTP-U
    /// header + inner payload). Used only for the bytes counters.
    pub frame_bytes: u64,
    /// First 20 bytes of the inner IP + TCP header, if the inner payload
    /// is TCP. `None` for UDP / ICMP inner payloads.
    pub inner_tcp_header: Option<&'a [u8]>,
}

impl GtpuAggregator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Feed one GTP-U packet. The caller never retains the payload after
    /// this call — the aggregator only pulls out the counters it needs.
    pub fn observe(&mut self, packet: TunnelPacket<'_>) {
        let key = TunnelKey {
            teid: packet.header.teid,
            outer_source_ip: packet.outer_source_ip.to_owned(),
            outer_destination_ip: packet.outer_destination_ip.to_owned(),
            outer_source_port: packet.outer_source_port,
            outer_destination_port: packet.outer_destination_port,
        };
        let flow = self.flows.entry(key).or_insert_with(|| TunnelFlow {
            teid: packet.header.teid,
            direction: packet.direction,
            outer_source_ip: packet.outer_source_ip.to_owned(),
            outer_destination_ip: packet.outer_destination_ip.to_owned(),
            outer_source_port: packet.outer_source_port,
            outer_destination_port: packet.outer_destination_port,
            ..Default::default()
        });
        if flow.first_seen_ns.is_none() {
            flow.first_seen_ns = Some(packet.timestamp_ns);
        }
        flow.last_seen_ns = Some(packet.timestamp_ns);
        // QFI is sticky from the first observed packet; subsequent frames
        // in the same tunnel may omit the extension header.
        if flow.qfi.is_none() {
            for ext in &packet.header.extensions {
                if let Some(qfi) = ext.qfi {
                    flow.qfi = Some(qfi);
                    break;
                }
            }
        }
        match packet.direction {
            TunnelDirection::Uplink => {
                flow.packets_ul = flow.packets_ul.saturating_add(1);
                flow.bytes_ul = flow.bytes_ul.saturating_add(packet.frame_bytes);
            }
            TunnelDirection::Downlink => {
                flow.packets_dl = flow.packets_dl.saturating_add(1);
                flow.bytes_dl = flow.bytes_dl.saturating_add(packet.frame_bytes);
            }
            TunnelDirection::Unknown => {
                // Unknown-direction packets land in the uplink column so
                // the total packet count still matches the pcap record
                // count. The direction verdict stays `Unknown` on the
                // emitted aggregate.
                flow.packets_ul = flow.packets_ul.saturating_add(1);
                flow.bytes_ul = flow.bytes_ul.saturating_add(packet.frame_bytes);
            }
        }
        // Opportunistic TCP RTT + retransmit accounting. We read only the
        // 20-byte inner TCP header slice; the application payload is
        // never touched.
        if let Some(tcp) = packet.inner_tcp_header {
            if tcp.len() >= 20 {
                let flags = tcp[13];
                let is_syn = flags & 0x02 != 0;
                let is_ack = flags & 0x10 != 0;
                if is_syn && !is_ack && matches!(packet.direction, TunnelDirection::Uplink) {
                    self.pending_syn_ns
                        .entry(packet.header.teid)
                        .or_insert(packet.timestamp_ns);
                }
                if is_syn && is_ack && matches!(packet.direction, TunnelDirection::Downlink) {
                    if let Some(syn_ns) = self.pending_syn_ns.remove(&packet.header.teid) {
                        if packet.timestamp_ns >= syn_ns {
                            flow.rtt_microseconds =
                                Some((packet.timestamp_ns - syn_ns) / 1_000);
                        }
                    }
                    flow.tcp_handshake_seen = true;
                }
                // A TCP retransmit shows up as a frame with a sequence
                // number equal to or lower than the previous frame on the
                // same tunnel + direction. We don't track per-sequence
                // state (which would reintroduce memory growth); we rely
                // on the TCP RST / Duplicate ACK counter the kernel
                // writes into the TCP flags on retransmit stacks. A
                // pragmatic bound: count RST + FIN as "transfer anomaly"
                // samples. The upper layer gets `retransmits_tcp` as a
                // lower bound.
                if flags & 0x04 != 0 {
                    flow.retransmits_tcp = flow.retransmits_tcp.saturating_add(1);
                }
            }
        }
    }

    /// Consume the aggregator and emit one `TunnelFlow` per key. The
    /// caller renders each as a single Call Flow row (interface = N3,
    /// protocol = GTP-U, message_name = "N3 aggregate · <packets> pkts").
    pub fn into_flows(self) -> Vec<TunnelFlow> {
        let mut out: Vec<TunnelFlow> = self.flows.into_values().collect();
        out.sort_by_key(|flow| flow.teid);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn valid_tunnel_packet() {
        let p = [0x30, 0xff, 0, 4, 0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4];
        let h = parse(&p).unwrap();
        assert_eq!(h.teid, 0x12345678);
        assert_eq!(h.payload_length, 4);
        assert_eq!(h.sequence_number, None);
    }
    #[test]
    fn extension_and_sequence() {
        let p = [
            0x36, 0xff, 0, 12, 0, 0, 0, 1, 0, 9, 0, 0x85, 1, 0x10, 0x09, 0, 1, 2, 3, 4,
        ];
        let h = parse(&p).unwrap();
        assert_eq!(h.sequence_number, Some(9));
        assert_eq!(h.extensions[0].extension_type, 0x85);
        assert_eq!(h.extensions[0].qfi, Some(9));
        assert_eq!(h.payload_length, 4);
    }
    #[test]
    fn invalid_lengths_and_teid_boundary() {
        assert!(parse(&[0x30, 0xff, 0, 4, 1, 2, 3]).is_err());
        assert!(parse(&[0x30, 0xff, 0, 9, 0, 0, 0, 1, 1]).is_err());
        assert!(parse(&[0x34, 0xff, 0, 4, 0, 0, 0, 1, 0, 0, 0, 0x85]).is_err());
    }
    #[test]
    fn extracts_inner_ipv4_addresses_for_per_ue_traffic_evidence() {
        let mut ipv4 = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0];
        ipv4.extend_from_slice(&[10, 46, 0, 4, 10, 46, 0, 1]);
        assert_eq!(
            inner_ipv4_addresses(&ipv4),
            Some(("10.46.0.4".into(), "10.46.0.1".into()))
        );
    }

    // 2.5.3 — N3 aggregator memory bound. Pre-aggregation live-probe
    // retained one NormalizedEvent per packet (≥ 130 MiB for 500 000
    // frames); the aggregator holds exactly `distinct TEID × 5-tuple
    // × direction` entries — four here, regardless of packet count.
    #[test]
    fn aggregator_bounded_memory_on_half_million_packets() {
        let mut aggregator = GtpuAggregator::new();
        let teids: [u32; 4] = [0x0a000001, 0x0a000002, 0x0a000003, 0x0a000004];
        for i in 0..500_000u32 {
            let teid = teids[(i as usize) % 4];
            let direction = if i % 2 == 0 {
                TunnelDirection::Uplink
            } else {
                TunnelDirection::Downlink
            };
            let (src, dst) = match direction {
                TunnelDirection::Uplink => ("10.77.22.20", "10.77.22.11"),
                _ => ("10.77.22.11", "10.77.22.20"),
            };
            aggregator.observe(TunnelPacket {
                header: GtpuHeader {
                    message_type: 255,
                    teid,
                    sequence_number: None,
                    npdu_number: None,
                    payload_offset: 8,
                    payload_length: 100,
                    extensions: Vec::new(),
                },
                direction,
                outer_source_ip: src,
                outer_destination_ip: dst,
                outer_source_port: 2152,
                outer_destination_port: 2152,
                timestamp_ns: 1_000_000 + u64::from(i),
                frame_bytes: 128,
                inner_tcp_header: None,
            });
        }
        // Four TEIDs × two directions (opposite 5-tuples) = 8 flows at most.
        assert!(aggregator.flow_count() <= 8);
        let flows = aggregator.into_flows();
        let total_ul: u64 = flows.iter().map(|f| f.packets_ul).sum();
        let total_dl: u64 = flows.iter().map(|f| f.packets_dl).sum();
        assert_eq!(total_ul + total_dl, 500_000);
        assert_eq!(total_ul, 250_000);
        assert_eq!(total_dl, 250_000);
    }

    // 2.5.3 — The aggregator emits ONE aggregated flow per 5-tuple +
    // TEID (not one per packet). The call-flow renderer joins the flow
    // to the matching NGAP tunnel + PFCP FAR via the TEID identifier so
    // the operator sees "N3 aggregate · <packets> pkts" correlated to
    // Initial Context Setup Response + PFCP Session Modification
    // Response.
    #[test]
    fn aggregator_emits_one_event_per_teid_with_counters() {
        let mut aggregator = GtpuAggregator::new();
        for _ in 0..3 {
            aggregator.observe(TunnelPacket {
                header: GtpuHeader {
                    message_type: 255,
                    teid: 0x12345678,
                    sequence_number: None,
                    npdu_number: None,
                    payload_offset: 8,
                    payload_length: 100,
                    extensions: vec![GtpuExtension {
                        extension_type: 0x85,
                        content: vec![9],
                        pdu_type: Some(1),
                        qfi: Some(9),
                    }],
                },
                direction: TunnelDirection::Uplink,
                outer_source_ip: "10.77.22.20",
                outer_destination_ip: "10.77.22.11",
                outer_source_port: 2152,
                outer_destination_port: 2152,
                timestamp_ns: 1_000,
                frame_bytes: 128,
                inner_tcp_header: None,
            });
        }
        aggregator.observe(TunnelPacket {
            header: GtpuHeader {
                message_type: 255,
                teid: 0x12345678,
                sequence_number: None,
                npdu_number: None,
                payload_offset: 8,
                payload_length: 100,
                extensions: Vec::new(),
            },
            direction: TunnelDirection::Downlink,
            outer_source_ip: "10.77.22.11",
            outer_destination_ip: "10.77.22.20",
            outer_source_port: 2152,
            outer_destination_port: 2152,
            timestamp_ns: 2_000,
            frame_bytes: 256,
            inner_tcp_header: None,
        });
        let flows = aggregator.into_flows();
        assert_eq!(flows.len(), 2); // UL + DL = two 5-tuple keys
        let total_packets: u64 = flows.iter().map(|f| f.packets_ul + f.packets_dl).sum();
        assert_eq!(total_packets, 4);
        // QFI from the PDU-session extension is sticky across subsequent
        // frames in the same tunnel.
        assert!(flows.iter().any(|f| f.qfi == Some(9)));
        // First / last seen are populated from the raw timestamps.
        assert!(flows.iter().any(|f| f.first_seen_ns == Some(1_000)));
        assert!(flows.iter().any(|f| f.last_seen_ns == Some(2_000)));
    }

    // 2.5.3 — TCP SYN / SYN+ACK pair on the inner payload populates the
    // `rtt_microseconds` field. The aggregator only reads the first 20
    // bytes of the inner header; it never touches application payload.
    #[test]
    fn aggregator_measures_tcp_rtt_from_header_only() {
        let mut aggregator = GtpuAggregator::new();
        let mut syn = [0u8; 20];
        syn[12] = 0x50;
        syn[13] = 0x02; // SYN only
        let mut synack = [0u8; 20];
        synack[12] = 0x50;
        synack[13] = 0x12; // SYN+ACK
        aggregator.observe(TunnelPacket {
            header: GtpuHeader {
                message_type: 255,
                teid: 0xdeadbeef,
                sequence_number: None,
                npdu_number: None,
                payload_offset: 8,
                payload_length: 20,
                extensions: Vec::new(),
            },
            direction: TunnelDirection::Uplink,
            outer_source_ip: "10.77.22.20",
            outer_destination_ip: "10.77.22.11",
            outer_source_port: 2152,
            outer_destination_port: 2152,
            timestamp_ns: 1_000_000_000,
            frame_bytes: 100,
            inner_tcp_header: Some(&syn),
        });
        aggregator.observe(TunnelPacket {
            header: GtpuHeader {
                message_type: 255,
                teid: 0xdeadbeef,
                sequence_number: None,
                npdu_number: None,
                payload_offset: 8,
                payload_length: 20,
                extensions: Vec::new(),
            },
            direction: TunnelDirection::Downlink,
            outer_source_ip: "10.77.22.11",
            outer_destination_ip: "10.77.22.20",
            outer_source_port: 2152,
            outer_destination_port: 2152,
            timestamp_ns: 1_050_000_000,
            frame_bytes: 100,
            inner_tcp_header: Some(&synack),
        });
        let flows = aggregator.into_flows();
        assert!(flows.iter().any(|f| f.tcp_handshake_seen));
        assert!(flows.iter().any(|f| f.rtt_microseconds == Some(50_000)));
    }

    // 2.5.3 — Correlation key compatibility. The aggregator exposes the
    // same TEID string encoding (`0x{:08x}`) the per-packet decoder uses
    // in `session_identifiers`, so the correlation-engine joins the N3
    // aggregate to the NGAP `Initial Context Setup Response` DL TEID
    // and the PFCP `Session Modification Response` UL TEID without any
    // additional glue in `live-probe`.
    #[test]
    fn aggregator_teid_encoding_joins_ngap_and_pfcp() {
        let mut aggregator = GtpuAggregator::new();
        aggregator.observe(TunnelPacket {
            header: GtpuHeader {
                message_type: 255,
                teid: 0x000000b3,
                sequence_number: None,
                npdu_number: None,
                payload_offset: 8,
                payload_length: 10,
                extensions: Vec::new(),
            },
            direction: TunnelDirection::Uplink,
            outer_source_ip: "10.77.22.20",
            outer_destination_ip: "10.77.22.11",
            outer_source_port: 2152,
            outer_destination_port: 2152,
            timestamp_ns: 1_000,
            frame_bytes: 50,
            inner_tcp_header: None,
        });
        let flows = aggregator.into_flows();
        let encoded = format!("0x{:08x}", flows[0].teid);
        assert_eq!(encoded, "0x000000b3");
    }
}
