//! 3GPP TS 29.281 GTPv1-U decoder; application payload stays opaque.

use event_schema::{
    sha256_hex, DecodeStatus, Direction, EvidenceReference, EvidenceState, InformationElement,
    NamedValue, NormalizedEvent, Protocol,
};
use plugin_runtime::{
    DecoderCapabilities, DecoderInput, DecoderManifest, DecoderOutput, ProtocolDecoder,
    PLUGIN_API_VERSION,
};

pub const VERSION: &str = "0.1.0";
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
}
