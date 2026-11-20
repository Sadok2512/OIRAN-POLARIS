//! 3GPP TS 29.281 GTPv1-U decoder; application payload stays opaque.

use event_schema::{
    sha256_hex, DecodeStatus, Direction, EvidenceReference, EvidenceState, InformationElement,
    NamedValue, NormalizedEvent, Protocol,
};
use plugin_runtime::{
    DecoderCapabilities, DecoderInput, DecoderManifest, DecoderOutput, ProtocolDecoder,
    PLUGIN_API_VERSION,
};
use std::sync::{OnceLock, RwLock};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 2.21.100 (défaut ANR1 #10 7045290646 point (c), ordre #9 7046402022
/// décision c) — pools UE par défaut pour `infer_direction_from_inner_ipv4`.
/// Couvre le DNN par défaut 5G `internet` (10.45/16), l'ancien pool LTE
/// (10.46/16), **et** le DNN `ims` 10.47/16 (jusqu'à 2.21.100 non couvert ⇒
/// trafic voix classé `Unknown` ⇒ non compté UL/DL ⇒ G-PDU manquants en live
/// trace comme mesuré par ANR1).
///
/// L'opérateur d'un lab avec d'autres préfixes UE peut poser
/// `set_ue_ip_pools(…)` avant tout décodage pour surcharger ces défauts.
pub fn default_ue_ip_pools() -> Vec<String> {
    vec!["10.45.".to_owned(), "10.46.".to_owned(), "10.47.".to_owned()]
}

static UE_IP_POOLS: OnceLock<RwLock<Vec<String>>> = OnceLock::new();

fn ue_ip_pools_cell() -> &'static RwLock<Vec<String>> {
    UE_IP_POOLS.get_or_init(|| RwLock::new(default_ue_ip_pools()))
}

/// 2.21.100 — remplace la liste de préfixes IP considérés comme UE côté
/// `infer_direction_from_inner_ipv4`. Appelé par l'orchestrateur
/// (`oiran-api`, `oiran-decode::main`) au démarrage, à partir d'une config
/// `decoder_gtpu_ue_ip_pools` (si présente). Les préfixes sont des chaînes
/// `starts_with` (ex. `"10.45."`, `"10.47."`) — simple et déterministe.
pub fn set_ue_ip_pools(pools: Vec<String>) {
    if let Ok(mut lock) = ue_ip_pools_cell().write() {
        *lock = pools;
    }
}

/// 2.21.100 — true si `address` (IPv4 dotted-quad) commence par l'un des
/// préfixes UE actuellement configurés (ou les défauts si `set_ue_ip_pools`
/// n'a pas été appelé).
pub fn is_ue_address(address: &str) -> bool {
    if let Ok(pools) = ue_ip_pools_cell().read() {
        pools.iter().any(|p| address.starts_with(p.as_str()))
    } else {
        default_ue_ip_pools()
            .iter()
            .any(|p| address.starts_with(p.as_str()))
    }
}
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
                // 2.21.76 (ordre #9 7012275179 §CLAUDE2.D-09) — QFI
                // propagé dans `session_identifiers` du event GTP-U
                // normalisé. Avant 2.21.74 il était uniquement dans
                // l'IE « PDU Session Container » au format
                // `pdu_type=X,qfi=Y`, inexploitable par la session-engine
                // comme clé d'agrégation. Premier QFI valide gagné (une
                // seule session par tunnel dans le cas nominal).
                if let Some(qfi) = header
                    .extensions
                    .iter()
                    .find_map(|ext| ext.qfi)
                {
                    ids.push(NamedValue {
                        name: "qfi".into(),
                        value: qfi.to_string(),
                        pseudonymized: false,
                    });
                }
                if header.message_type == 255 {
                    if let Some((source, destination)) = inner_ipv4_addresses(
                        &input.payload
                            [header.payload_offset..header.payload_offset + header.payload_length],
                    ) {
                        if direction == Direction::Unknown {
                            direction = infer_direction_from_inner_ipv4(&source, &destination);
                        }
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
                        let ue_ip = match direction {
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
                if let Some(identifier) = ids
                    .iter_mut()
                    .find(|identifier| identifier.name == "tunnel_direction")
                {
                    identifier.value = direction.as_str().into();
                }
                let mut event = NormalizedEvent {
                    event_id: String::new(),
                    stable_event_key: String::new(),
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

/// 2.21.100 (ordre #9 7046402022 décision a, design CLAUDE1 #9 7012805654) —
/// descripteur de l'inner UDP exposé pour que l'orchestrateur
/// (`oiran-decode`) puisse router SIP/RTP vers leurs décodeurs sans
/// dupliquer le parse GTP-U + inner IPv4 + inner UDP. Les offsets sont
/// exprimés **dans le packet physique** (base = début du payload GTP-U
/// passé à `extract_inner_udp`), pour que le caller fasse
/// `packet_payload[udp_payload_offset..udp_payload_offset+udp_payload_length]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InnerUdpInfo {
    pub source_ip: String,
    pub destination_ip: String,
    pub source_port: u16,
    pub destination_port: u16,
    /// Offset du payload UDP dans le packet complet (après GTP-U + IPv4 + UDP header).
    pub udp_payload_offset: usize,
    /// Longueur du payload UDP (= udp_length - 8).
    pub udp_payload_length: usize,
}

/// 2.21.100 (ordre #9 7046402022 décision a) — inspecte un paquet G-PDU
/// GTP-U et, si l'inner est IPv4 + UDP, retourne les ports + offsets pour
/// que l'orchestrateur route SIP/RTP vers `SipDecoder` / `RtpFlowAggregator`.
/// `None` si :
///   * le paquet n'est pas un G-PDU valide,
///   * message_type != 255,
///   * l'inner n'est pas IPv4,
///   * l'inner IPv4 protocol != 17 (UDP),
///   * l'inner UDP header est tronqué.
///
/// La fonction est strictement locale (pas d'allocations lourdes, pas
/// d'effet de bord) et peut être appelée pour chaque paquet du pipeline.
pub fn extract_inner_udp(packet_payload: &[u8]) -> Option<InnerUdpInfo> {
    let header = parse(packet_payload).ok()?;
    if header.message_type != 255 {
        return None;
    }
    let inner_start = header.payload_offset;
    let inner_end = inner_start + header.payload_length;
    if inner_end > packet_payload.len() {
        return None;
    }
    let inner = &packet_payload[inner_start..inner_end];
    // Inner IPv4 header.
    if inner.len() < 20 || inner[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(inner[0] & 0x0f) * 4;
    if ihl < 20 || ihl > inner.len() {
        return None;
    }
    let protocol = inner[9];
    if protocol != 17 {
        return None; // non-UDP inner (ICMP, TCP, …) : hors scope 2.21.100.
    }
    let source_ip = format!("{}.{}.{}.{}", inner[12], inner[13], inner[14], inner[15]);
    let destination_ip = format!("{}.{}.{}.{}", inner[16], inner[17], inner[18], inner[19]);
    // Inner UDP header (8 bytes).
    if inner.len() < ihl + 8 {
        return None;
    }
    let source_port = u16::from_be_bytes([inner[ihl], inner[ihl + 1]]);
    let destination_port = u16::from_be_bytes([inner[ihl + 2], inner[ihl + 3]]);
    let udp_length = u16::from_be_bytes([inner[ihl + 4], inner[ihl + 5]]) as usize;
    if udp_length < 8 || ihl + udp_length > inner.len() {
        return None;
    }
    let udp_payload_offset_in_inner = ihl + 8;
    let udp_payload_length = udp_length - 8;
    Some(InnerUdpInfo {
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        udp_payload_offset: inner_start + udp_payload_offset_in_inner,
        udp_payload_length,
    })
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

fn infer_direction_from_inner_ipv4(source: &str, destination: &str) -> Direction {
    // 2.21.100 (ordre #9 7046402022 décision c) — pools UE lus depuis la
    // configuration (static OnceLock<RwLock<Vec<String>>> partagé), défaut
    // 10.45/16 + 10.46/16 + **10.47/16** (DNN IMS). Un futur lab avec
    // d'autres préfixes peut appeler `decoder_gtpu::set_ue_ip_pools` au boot.
    // Seul un match unique côté UE est accepté ; ambigu ⇒ Unknown.
    match (is_ue_address(source), is_ue_address(destination)) {
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
        let mut ipv4 = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0];
        ipv4.extend_from_slice(&[10, 46, 0, 4, 10, 46, 0, 1]);
        assert_eq!(
            inner_ipv4_addresses(&ipv4),
            Some(("10.46.0.4".into(), "10.46.0.1".into()))
        );
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

    /// 2.21.76 (ordre #9 7012275179 §CLAUDE2.D-09) — un paquet GTP-U N3
    /// avec extension PDU Session Container (type `0x85`) et un QFI
    /// doit exposer ce QFI dans `session_identifiers` (`qfi=<n>`). Avant
    /// 2.21.76 il n'y était pas : seule la représentation texte
    /// `pdu_type=X,qfi=Y` dans l'IE existait, inexploitable par la
    /// session-engine comme clé d'agrégation par QFI.
    #[test]
    fn qfi_is_propagated_into_session_identifiers_2_21_76() {
        let packets = vec![];
        let timestamp = event_schema::ExactTimestamp {
            seconds: 1,
            nanoseconds: 0,
            raw_ticks: 1,
            resolution_base: 10,
            resolution_exponent: 9,
        };
        let key = event_schema::PseudonymKey::from_bytes([0xaa; 32]);
        // Paquet du test `extension_and_sequence` : extension 0x85 (PDU
        // Session Container) portant QFI=9.
        let payload = [
            0x36, 0xff, 0, 12, 0, 0, 0, 1, 0, 9, 0, 0x85, 1, 0x10, 0x09, 0, 1, 2, 3, 4,
        ];
        let input = DecoderInput {
            capture_id: "sha256:synthetic",
            packet_references: &packets,
            timestamp: &timestamp,
            interface: "N3",
            source_endpoint: event_schema::Endpoint {
                address: "10.0.0.1".into(),
                port: Some(2152),
                network_function: Some("gNB".into()),
            },
            destination_endpoint: event_schema::Endpoint {
                address: "10.0.0.2".into(),
                port: Some(2152),
                network_function: Some("UPF".into()),
            },
            payload: &payload,
            raw_payload_reference: "sha256:synthetic",
            pseudonym_key: &key,
        };
        let output = GtpuDecoder.decode(&input);
        let event = &output.events[0];
        let qfi = event
            .session_identifiers
            .iter()
            .find(|identifier| identifier.name == "qfi")
            .expect("QFI doit être présent dans session_identifiers");
        assert_eq!(qfi.value, "9");
        assert!(!qfi.pseudonymized, "QFI n'est pas une identité, pas pseudo");
    }

    /// 2.21.100 (défaut ANR1 #10 7045290646 point c, ordre #9 7046402022
    /// décision c) — `is_ue_address` par défaut couvre 10.45/10.46/10.47
    /// (ajout 10.47/16 pour couvrir le DNN IMS, non reconnu avant 2.21.100).
    #[test]
    fn is_ue_address_covers_10_45_46_47_by_default_2_21_100() {
        // Reset aux défauts (test parallèle : le static peut avoir été
        // modifié par un autre test, on reset explicitement).
        set_ue_ip_pools(default_ue_ip_pools());
        assert!(is_ue_address("10.45.0.1"));
        assert!(is_ue_address("10.46.1.42"));
        assert!(is_ue_address("10.47.0.7"), "DNN IMS 10.47/16 doit être reconnu");
        assert!(!is_ue_address("10.48.0.1"));
        assert!(!is_ue_address("8.8.8.8"));
        assert!(!is_ue_address(""));
    }

    /// 2.21.100 — `set_ue_ip_pools` permet à l'opérateur de surcharger les
    /// préfixes par défaut (configuration lab).
    #[test]
    fn set_ue_ip_pools_overrides_defaults_2_21_100() {
        set_ue_ip_pools(vec!["172.16.".into()]);
        assert!(is_ue_address("172.16.0.1"));
        assert!(!is_ue_address("10.45.0.1"), "10.45 n'est plus dans le pool après override");
        // Restaurer défauts pour les autres tests.
        set_ue_ip_pools(default_ue_ip_pools());
    }

    /// 2.21.100 (ordre #9 7046402022 décision a, design CLAUDE1 #9 7012805654) —
    /// `extract_inner_udp` retourne `Some` pour un G-PDU IPv4+UDP valide,
    /// avec src/dst IPs + ports + offset/length UDP payload correctement
    /// calculés.
    #[test]
    fn extract_inner_udp_returns_ipv4_udp_descriptor_2_21_100() {
        // G-PDU GTP-U minimal (header 8 bytes, version 1, pt=1, no flags),
        // TEID = 0x00000042, puis IPv4 (ihl=5, protocol=17 UDP), puis UDP
        // (src_port=5060, dst_port=12345, len=8+4=12), puis 4 bytes de
        // payload "INVI".
        let mut pkt = vec![
            0x30, 0xff, // version/pt/flags, msg_type=G-PDU
            0x00, 0x20, // declared payload length = 32 (28 IP + 4 pad)
            0x00, 0x00, 0x00, 0x42, // TEID
        ];
        // Inner IPv4 header (20 bytes).
        pkt.extend_from_slice(&[
            0x45, 0x00, // version/ihl + ToS
            0x00, 0x20, // total length 32
            0x00, 0x00, 0x00, 0x00, // id + flags
            0x40, 0x11, // TTL + protocol=17 (UDP)
            0x00, 0x00, // checksum
            10, 45, 0, 7, // src = 10.45.0.7 (UE)
            10, 0, 0, 1, // dst = 10.0.0.1
        ]);
        // Inner UDP header + 4-byte payload.
        pkt.extend_from_slice(&[
            0x13, 0xc4, // src port 5060
            0x30, 0x39, // dst port 12345
            0x00, 0x0c, // length 12 (8 + 4)
            0x00, 0x00, // checksum
            b'I', b'N', b'V', b'I', // payload
        ]);
        let info = extract_inner_udp(&pkt).expect("inner UDP must be extracted");
        assert_eq!(info.source_ip, "10.45.0.7");
        assert_eq!(info.destination_ip, "10.0.0.1");
        assert_eq!(info.source_port, 5060);
        assert_eq!(info.destination_port, 12345);
        assert_eq!(info.udp_payload_length, 4);
        // Offset = 8 (GTP-U header) + 20 (IPv4) + 8 (UDP) = 36.
        assert_eq!(info.udp_payload_offset, 36);
        assert_eq!(&pkt[info.udp_payload_offset..info.udp_payload_offset + info.udp_payload_length], b"INVI");
    }

    /// 2.21.100 — `extract_inner_udp` retourne `None` pour :
    /// (1) message_type != 255 (G-PDU), (2) inner non-IPv4, (3) inner
    /// non-UDP, (4) header UDP tronqué.
    #[test]
    fn extract_inner_udp_returns_none_on_mismatches_2_21_100() {
        // (1) Echo Request (message_type = 1) — pas G-PDU.
        let echo = vec![
            0x30, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(extract_inner_udp(&echo), None);
        // (2) G-PDU avec inner IPv6 (v=6).
        let mut ipv6 = vec![0x30, 0xff, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01];
        ipv6.extend_from_slice(&[0x60, 0, 0, 0, 0, 0, 59, 64]); // v=6, next header=59 (no next)
        ipv6.extend_from_slice(&[0; 32]); // 32 bytes to reach declared length of 20
        assert_eq!(extract_inner_udp(&ipv6), None);
        // (3) G-PDU avec inner IPv4 TCP (protocol=6).
        let mut tcp = vec![0x30, 0xff, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01];
        tcp.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06,
            0x00, 0x00, 10, 45, 0, 7, 10, 0, 0, 1,
        ]);
        assert_eq!(extract_inner_udp(&tcp), None);
        // (4) G-PDU IPv4 UDP mais header UDP tronqué (seulement 4 bytes au lieu de 8).
        let mut truncated = vec![0x30, 0xff, 0x00, 0x18, 0x00, 0x00, 0x00, 0x01];
        truncated.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11,
            0x00, 0x00, 10, 45, 0, 7, 10, 0, 0, 1,
        ]);
        truncated.extend_from_slice(&[0x13, 0xc4, 0x30, 0x39]); // seulement 4 bytes UDP
        assert_eq!(extract_inner_udp(&truncated), None);
    }
}
