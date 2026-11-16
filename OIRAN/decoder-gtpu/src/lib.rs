//! 3GPP TS 29.281 GTPv1-U decoder; application payload stays opaque.

use event_schema::{
    sha256_hex, DecodeStatus, Direction, EvidenceReference, EvidenceState, InformationElement,
    NamedValue, NormalizedEvent, Protocol,
};
use plugin_runtime::{
    DecoderCapabilities, DecoderInput, DecoderManifest, DecoderOutput, ProtocolDecoder,
    PLUGIN_API_VERSION,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
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
                let mut direction = infer_direction(input);
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
                }, NamedValue {
                    // A GTP-U TEID identifies the receiving tunnel endpoint.
                    name: "tunnel_endpoint_ip".into(),
                    value: input.destination_endpoint.address.clone(),
                    pseudonymized: false,
                }, NamedValue {
                    name: "tunnel_direction".into(),
                    value: direction.as_str().into(),
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
                    // 2.22.1 — 5-tuple interne IPv4/IPv6 + proto + ports après
                    // l'entête GTP-U. La fenêtre réellement lue est limitée à
                    // `payload_length` (borné par snaplen sonde ; cf. polaris.toml
                    // `[userplane] snaplen_n3_bytes`). Les volumes agrégés en
                    // aval restent calculés sur `original_length` (jamais sur
                    // `captured_length`) — invariant OP2.1 #9 6927882355.
                    if let Some(tuple) = parse_inner_five_tuple(
                        &input.payload
                            [header.payload_offset..header.payload_offset + header.payload_length],
                    ) {
                        if direction == Direction::Unknown {
                            direction = infer_direction_from_inner_ips(
                                &tuple.source_ip,
                                &tuple.destination_ip,
                            );
                        }
                        ids.push(NamedValue {
                            name: "inner_source_ip".into(),
                            value: tuple.source_ip.clone(),
                            pseudonymized: false,
                        });
                        ids.push(NamedValue {
                            name: "inner_destination_ip".into(),
                            value: tuple.destination_ip.clone(),
                            pseudonymized: false,
                        });
                        ids.push(NamedValue {
                            name: "inner_ip_version".into(),
                            value: tuple.ip_version.to_string(),
                            pseudonymized: false,
                        });
                        ids.push(NamedValue {
                            name: "inner_l4_proto".into(),
                            value: tuple.l4_proto.to_string(),
                            pseudonymized: false,
                        });
                        if let Some(port) = tuple.source_port {
                            ids.push(NamedValue {
                                name: "inner_src_port".into(),
                                value: port.to_string(),
                                pseudonymized: false,
                            });
                        }
                        if let Some(port) = tuple.destination_port {
                            ids.push(NamedValue {
                                name: "inner_dst_port".into(),
                                value: port.to_string(),
                                pseudonymized: false,
                            });
                        }
                        let ue_ip = match direction {
                            Direction::Uplink => Some(tuple.source_ip.clone()),
                            Direction::Downlink => Some(tuple.destination_ip.clone()),
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
                if let Some(identifier) = ids
                    .iter_mut()
                    .find(|identifier| identifier.name == "tunnel_direction")
                {
                    identifier.value = direction.as_str().into();
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
                    direction,
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

/// 5-tuple interne extrait du payload GTP-U (lot 2.22.1).
/// `source_port` / `destination_port` sont `None` pour les protocoles sans
/// ports (ICMP/ICMPv6, ESP, etc.). La fenêtre lue est strictement bornée par
/// `payload.len()` (reflète la troncature côté sonde) ; aucun octet au-delà
/// n'est jamais touché.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InnerFiveTuple {
    pub ip_version: u8,
    pub source_ip: String,
    pub destination_ip: String,
    pub l4_proto: u8,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
}

pub fn parse_inner_five_tuple(payload: &[u8]) -> Option<InnerFiveTuple> {
    if payload.is_empty() {
        return None;
    }
    match payload[0] >> 4 {
        4 => parse_inner_ipv4(payload),
        6 => parse_inner_ipv6(payload),
        _ => None,
    }
}

fn parse_inner_ipv4(payload: &[u8]) -> Option<InnerFiveTuple> {
    if payload.len() < 20 {
        return None;
    }
    let ihl = usize::from(payload[0] & 0x0f) * 4;
    if ihl < 20 || ihl > payload.len() {
        return None;
    }
    let proto = payload[9];
    let format_ipv4 =
        |bytes: &[u8]| format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);
    let source_ip = format_ipv4(&payload[12..16]);
    let destination_ip = format_ipv4(&payload[16..20]);
    let (src_port, dst_port) = parse_l4_ports(proto, &payload[ihl..]);
    Some(InnerFiveTuple {
        ip_version: 4,
        source_ip,
        destination_ip,
        l4_proto: proto,
        source_port: src_port,
        destination_port: dst_port,
    })
}

fn parse_inner_ipv6(payload: &[u8]) -> Option<InnerFiveTuple> {
    // IPv6 fixed header = 40 octets. On traverse les extension headers
    // hop-by-hop (0), routing (43), fragment (44), destination options (60),
    // AH (51). ESP (50) et final (59) stoppent l'extraction de ports.
    if payload.len() < 40 {
        return None;
    }
    let source_ip = format_ipv6(&payload[8..24]);
    let destination_ip = format_ipv6(&payload[24..40]);
    let mut next_header = payload[6];
    let mut offset: usize = 40;
    let mut hops = 0;
    loop {
        match next_header {
            0 | 43 | 60 | 51 => {
                hops += 1;
                if hops > 16 || offset + 8 > payload.len() {
                    return None;
                }
                let ext_next = payload[offset];
                let hdr_ext_len = usize::from(payload[offset + 1]);
                let ext_len = (hdr_ext_len + 1) * 8;
                if offset + ext_len > payload.len() {
                    return None;
                }
                next_header = ext_next;
                offset += ext_len;
            }
            44 => {
                if offset + 8 > payload.len() {
                    return None;
                }
                let ext_next = payload[offset];
                next_header = ext_next;
                offset += 8;
            }
            _ => break,
        }
    }
    let (src_port, dst_port) = parse_l4_ports(next_header, &payload[offset.min(payload.len())..]);
    Some(InnerFiveTuple {
        ip_version: 6,
        source_ip,
        destination_ip,
        l4_proto: next_header,
        source_port: src_port,
        destination_port: dst_port,
    })
}

fn format_ipv6(bytes: &[u8]) -> String {
    debug_assert_eq!(bytes.len(), 16);
    let mut groups = [0u16; 8];
    for (i, group) in groups.iter_mut().enumerate() {
        *group = u16::from_be_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
    }
    groups
        .iter()
        .map(|g| format!("{g:x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn parse_l4_ports(proto: u8, payload: &[u8]) -> (Option<u16>, Option<u16>) {
    // TCP = 6, UDP = 17, UDP-Lite = 136, DCCP = 33, SCTP = 132.
    // Dans tous ces cas, la paire (src_port, dst_port) occupe les 4
    // premiers octets du header L4. Si le payload est tronqué (snaplen
    // sonde), on renvoie None plutôt qu'un port partiel.
    let has_ports = matches!(proto, 6 | 17 | 33 | 132 | 136);
    if !has_ports || payload.len() < 4 {
        return (None, None);
    }
    (Some(be16(&payload[0..2])), Some(be16(&payload[2..4])))
}

fn infer_direction_from_inner_ips(source: &str, destination: &str) -> Direction {
    // Pools UE lab 5G/LTE (IPv4) + préfixe v6 ULA/GUA conventionnel.
    // Seule une correspondance UE-unique est acceptée ; l'ambiguïté reste
    // UNKNOWN pour éviter de deviner.
    let is_ue = |address: &str| {
        address.starts_with("10.45.")
            || address.starts_with("10.46.")
            || address.starts_with("fd45:")
            || address.starts_with("fd46:")
    };
    match (is_ue(source), is_ue(destination)) {
        (true, false) => Direction::Uplink,
        (false, true) => Direction::Downlink,
        _ => Direction::Unknown,
    }
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
    if (src.contains("gnb") && dst.contains("upf"))
        || (src.contains("enb") && dst.contains("sgw"))
        || (src.contains("sgw") && dst.contains("pgw"))
    {
        Direction::Uplink
    } else if (src.contains("upf") && dst.contains("gnb"))
        || (src.contains("sgw") && dst.contains("enb"))
        || (src.contains("pgw") && dst.contains("sgw"))
    {
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
        // IPv4 header + UDP (proto 17) + ports src=5000 dst=443.
        let mut ipv4 = vec![0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0];
        ipv4.extend_from_slice(&[10, 46, 0, 4, 10, 46, 0, 1]);
        ipv4.extend_from_slice(&[0x13, 0x88, 0x01, 0xbb, 0, 0, 0, 0]); // UDP 5000→443
        let tuple = parse_inner_five_tuple(&ipv4).expect("ipv4 5-tuple");
        assert_eq!(tuple.ip_version, 4);
        assert_eq!(tuple.source_ip, "10.46.0.4");
        assert_eq!(tuple.destination_ip, "10.46.0.1");
        assert_eq!(tuple.l4_proto, 17);
        assert_eq!(tuple.source_port, Some(5000));
        assert_eq!(tuple.destination_port, Some(443));
    }

    #[test]
    fn parses_ipv4_tcp_inner_tuple() {
        let mut ipv4 = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0];
        ipv4.extend_from_slice(&[10, 46, 0, 4, 142, 251, 37, 110]);
        // TCP 49152→443
        ipv4.extend_from_slice(&[0xc0, 0x00, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0]);
        ipv4.extend_from_slice(&[0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
        let tuple = parse_inner_five_tuple(&ipv4).expect("ipv4 tcp");
        assert_eq!(tuple.l4_proto, 6);
        assert_eq!(tuple.source_port, Some(49152));
        assert_eq!(tuple.destination_port, Some(443));
    }

    #[test]
    fn parses_ipv6_udp_inner_tuple() {
        // IPv6 : version 6 + traffic class 0 + flow 0, payload_len 8,
        // next_header 17 (UDP), hop_limit 64, src+dst, UDP 1234→80.
        let mut v6 = vec![0x60, 0, 0, 0, 0, 8, 17, 64];
        v6.extend_from_slice(&[0xfd, 0x45, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        v6.extend_from_slice(&[0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x8a]);
        v6.extend_from_slice(&[0x04, 0xd2, 0x00, 0x50, 0, 0, 0, 0]);
        let tuple = parse_inner_five_tuple(&v6).expect("ipv6 udp");
        assert_eq!(tuple.ip_version, 6);
        assert_eq!(tuple.l4_proto, 17);
        assert_eq!(tuple.source_port, Some(1234));
        assert_eq!(tuple.destination_port, Some(80));
        assert_eq!(tuple.source_ip, "fd45:0:0:0:0:0:0:1");
    }

    #[test]
    fn parses_ipv6_tcp_with_hop_by_hop_extension() {
        // Chaîne : IPv6 (next=0 hop-by-hop) → hop-by-hop (next=6 TCP, len=0 soit 8 oct) → TCP.
        let mut v6 = vec![0x60, 0, 0, 0, 0, 28, 0, 64];
        v6.extend_from_slice(&[0xfd, 0x46, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        v6.extend_from_slice(&[0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x8a]);
        // Hop-by-hop : next=6 TCP, hdr_ext_len=0 (= 8 octets), 6 octets padding.
        v6.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
        // TCP 55555→8080
        v6.extend_from_slice(&[0xd9, 0x03, 0x1f, 0x90, 0, 0, 0, 0, 0, 0, 0, 0]);
        v6.extend_from_slice(&[0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
        let tuple = parse_inner_five_tuple(&v6).expect("ipv6+hopbyhop+tcp");
        assert_eq!(tuple.ip_version, 6);
        assert_eq!(tuple.l4_proto, 6);
        assert_eq!(tuple.source_port, Some(55555));
        assert_eq!(tuple.destination_port, Some(8080));
    }

    #[test]
    fn truncated_payload_returns_none_or_no_ports_but_never_panics() {
        // OP2.1 invariant : aucun octet lu au-delà de la fenêtre.
        // Fenêtre tronquée à 12 oct (header IPv4 incomplet + aucun port).
        let v4_hdr_only = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0];
        let tuple = parse_inner_five_tuple(&v4_hdr_only);
        // Header 20 oct non atteint -> None accepté ; sinon ports doivent être None.
        if let Some(t) = tuple {
            assert_eq!(t.source_port, None, "port partiel interdit");
            assert_eq!(t.destination_port, None, "port partiel interdit");
        }
    }

    #[test]
    fn inner_tuple_unknown_ip_version_returns_none() {
        assert!(parse_inner_five_tuple(&[0]).is_none());
        assert!(parse_inner_five_tuple(&[0x50, 0, 0, 0]).is_none());
    }

    #[test]
    fn infers_s1u_direction_from_enb_and_sgw_roles() {
        let packets = vec![];
        let timestamp = event_schema::ExactTimestamp {
            seconds: 1,
            nanoseconds: 0,
            raw_ticks: 1,
            resolution_base: 10,
            resolution_exponent: 9,
        };
        let payload = [0x30, 0xff, 0, 0, 0, 0, 0, 1];
        let key = event_schema::PseudonymKey::from_bytes([0xaa; 32]);
        let make = |source: &str, destination: &str| DecoderInput {
            capture_id: "sha256:synthetic",
            packet_references: &packets,
            timestamp: &timestamp,
            interface: "S1-U",
            source_endpoint: event_schema::Endpoint {
                address: "192.0.2.1".into(),
                port: Some(2152),
                network_function: Some(source.into()),
            },
            destination_endpoint: event_schema::Endpoint {
                address: "192.0.2.2".into(),
                port: Some(2152),
                network_function: Some(destination.into()),
            },
            payload: &payload,
            raw_payload_reference: "sha256:synthetic",
            pseudonym_key: &key,
        };
        assert_eq!(infer_direction(&make("eNB", "SGW-U")), Direction::Uplink);
        assert_eq!(infer_direction(&make("SGW-U", "eNB")), Direction::Downlink);
    }

    #[test]
    fn gpdu_exposes_teid_receiver_endpoint_and_direction_on_s1u_and_s5u() {
        let packets = vec![];
        let timestamp = event_schema::ExactTimestamp {
            seconds: 1,
            nanoseconds: 0,
            raw_ticks: 1,
            resolution_base: 10,
            resolution_exponent: 9,
        };
        let key = event_schema::PseudonymKey::from_bytes([0xaa; 32]);
        for (interface, source_role, destination_role, destination_ip, teid, expected) in [
            ("S1-U", "eNB", "SGW-U", "10.77.11.13", 0x0000_7804u32, Direction::Uplink),
            ("S1-U", "SGW-U", "eNB", "10.77.11.20", 0x0000_0001u32, Direction::Downlink),
            ("S5-U", "", "", "192.0.2.15", 0x0000_7f6fu32, Direction::Uplink),
            ("S5-U", "", "", "192.0.2.13", 0x0000_be90u32, Direction::Downlink),
        ] {
            let mut payload = vec![0x30, 0xff, 0, 20];
            payload.extend_from_slice(&teid.to_be_bytes());
            let (inner_source, inner_destination) = if expected == Direction::Uplink {
                ([10, 45, 0, 2], [192, 0, 2, 1])
            } else {
                ([192, 0, 2, 1], [10, 45, 0, 2])
            };
            payload.extend_from_slice(&[0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0]);
            payload.extend_from_slice(&inner_source);
            payload.extend_from_slice(&inner_destination);
            let input = DecoderInput {
                capture_id: "sha256:synthetic",
                packet_references: &packets,
                timestamp: &timestamp,
                interface,
                source_endpoint: event_schema::Endpoint {
                    address: "192.0.2.20".into(),
                    port: Some(2152),
                    network_function: Some(source_role.into()),
                },
                destination_endpoint: event_schema::Endpoint {
                    address: destination_ip.into(),
                    port: Some(2152),
                    network_function: Some(destination_role.into()),
                },
                payload: &payload,
                raw_payload_reference: "sha256:synthetic",
                pseudonym_key: &key,
            };
            let output = GtpuDecoder.decode(&input);
            let event = &output.events[0];
            assert_eq!(event.direction, expected);
            assert!(event.session_identifiers.iter().any(|identifier| {
                identifier.name == "teid" && identifier.value == format!("0x{teid:08x}")
            }));
            assert!(event.session_identifiers.iter().any(|identifier| {
                identifier.name == "tunnel_endpoint_ip" && identifier.value == destination_ip
            }));
            assert!(event.session_identifiers.iter().any(|identifier| {
                identifier.name == "tunnel_direction"
                    && identifier.value == expected.as_str()
            }));
        }
    }
}
