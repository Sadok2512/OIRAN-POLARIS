//! 3GPP TS 29.244 PFCP header and recursive IE decoder.

use event_schema::{
    pseudonym, sha256_hex, DecodeStatus, Direction, EvidenceReference, EvidenceState,
    InformationElement, NamedValue, NormalizedEvent, Protocol,
};
use plugin_runtime::{
    DecoderCapabilities, DecoderInput, DecoderManifest, DecoderOutput, ProtocolDecoder,
    PLUGIN_API_VERSION,
};

pub const VERSION: &str = "0.2.0";
#[derive(Default)]
pub struct PfcpDecoder;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PfcpMessage {
    pub message_type: u8,
    pub seid: Option<u64>,
    pub sequence_number: u32,
    pub priority: Option<u8>,
    pub ies: Vec<PfcpIe>,
    pub unknown_count: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PfcpIe {
    pub ie_type: u16,
    pub name: String,
    pub value: Vec<u8>,
    pub children: Vec<PfcpIe>,
    pub decoded: Option<String>,
    pub status: DecodeStatus,
}

pub fn parse(payload: &[u8]) -> Result<PfcpMessage, String> {
    if payload.len() < 8 {
        return Err("PFCP header truncated".into());
    }
    let flags = payload[0];
    if flags >> 5 != 1 {
        return Err("unsupported PFCP version".into());
    }
    let total = 4 + be16(&payload[2..4]) as usize;
    if total > payload.len() {
        return Err("declared PFCP length exceeds UDP payload".into());
    }
    let has_seid = flags & 1 != 0;
    let header = if has_seid { 16 } else { 8 };
    if total < header {
        return Err("PFCP header inconsistent with S flag".into());
    }
    let seid = if has_seid {
        Some(be64(&payload[4..12]))
    } else {
        None
    };
    let seq_offset = if has_seid { 12 } else { 4 };
    let sequence_number = ((payload[seq_offset] as u32) << 16)
        | ((payload[seq_offset + 1] as u32) << 8)
        | payload[seq_offset + 2] as u32;
    let priority = if flags & 2 != 0 {
        Some(payload[seq_offset + 3] & 0x0f)
    } else {
        None
    };
    let (mut ies, unknown) = parse_ies(&payload[header..total], 0)?;
    Ok(PfcpMessage {
        message_type: payload[1],
        seid,
        sequence_number,
        priority,
        ies: {
            ies.shrink_to_fit();
            ies
        },
        unknown_count: unknown,
    })
}
fn parse_ies(mut data: &[u8], depth: usize) -> Result<(Vec<PfcpIe>, usize), String> {
    if depth > 8 {
        return Err("PFCP grouped IE nesting exceeds 8".into());
    }
    let mut out = Vec::new();
    let mut unknown = 0;
    while !data.is_empty() {
        if data.len() < 4 {
            return Err("PFCP IE header truncated".into());
        }
        let t = be16(&data[..2]);
        let len = be16(&data[2..4]) as usize;
        if 4 + len > data.len() {
            return Err(format!("PFCP IE {t} length exceeds message"));
        }
        let value = &data[4..4 + len];
        let known = ie_name(t);
        let grouped = is_grouped(t);
        let (children, child_unknown) = if grouped {
            parse_ies(value, depth + 1)?
        } else {
            (Vec::new(), 0)
        };
        unknown += child_unknown;
        let decoded = if grouped {
            None
        } else {
            decode_value(t, value)?
        };
        let status = if grouped {
            if child_unknown == 0 {
                DecodeStatus::Decoded
            } else {
                DecodeStatus::Partial
            }
        } else if known.is_none() {
            DecodeStatus::Unsupported
        } else if decoded.is_some() {
            DecodeStatus::Decoded
        } else {
            DecodeStatus::Partial
        };
        if status != DecodeStatus::Decoded {
            unknown += 1;
        }
        out.push(PfcpIe {
            ie_type: t,
            name: known.unwrap_or("Unknown IE").into(),
            value: value.to_vec(),
            children,
            decoded,
            status,
        });
        data = &data[4 + len..];
    }
    Ok((out, unknown))
}
fn decode_value(t: u16, v: &[u8]) -> Result<Option<String>, String> {
    let short = |need: usize| {
        Err(format!(
            "PFCP IE {t} requires at least {need} byte(s), got {}",
            v.len()
        ))
    };
    let value = match t {
        19 => Some(format!(
            "cause={}",
            *v.first().ok_or_else(|| format!("PFCP IE {t} is empty"))?
        )),
        20 => Some(format!(
            "source_interface={}",
            *v.first().ok_or_else(|| format!("PFCP IE {t} is empty"))? & 0x0f
        )),
        21 => {
            let flags = *v.first().ok_or_else(|| format!("PFCP IE {t} is empty"))?;
            if flags & 0x04 != 0 {
                Some(format!(
                    "f_teid_choose=true,choose_id={}",
                    v.get(1).copied().unwrap_or(0)
                ))
            } else if v.len() >= 5 {
                let ipv4 = if flags & 1 != 0 && v.len() >= 9 {
                    format!(",ipv4={}", ipv4(&v[5..9]))
                } else {
                    String::new()
                };
                Some(format!(
                    "teid=0x{:08x},v4={},v6={}{}",
                    be32(&v[1..5]),
                    flags & 1 != 0,
                    flags & 2 != 0,
                    ipv4
                ))
            } else {
                return short(5);
            }
        }
        22 => Some(format!("network_instance={}", decode_apn(v)?)),
        23 => Some(format!(
            "sdf_filter_flags=0x{:02x},flow_description_sha256={}",
            v.first().copied().unwrap_or(0),
            sha256_hex(v)
        )),
        25 => Some(format!(
            "gate_status=0x{:02x}",
            *v.first().ok_or_else(|| format!("PFCP IE {t} is empty"))?
        )),
        26 | 27 if v.len() >= 10 => Some(format!(
            "uplink_bps={},downlink_bps={}",
            be40(&v[..5]),
            be40(&v[5..10])
        )),
        29 if v.len() >= 4 => Some(format!("precedence={}", be32(v))),
        29 => return short(4),
        31 => Some(format!(
            "volume_threshold_flags=0x{:02x},raw_sha256={}",
            v.first().copied().unwrap_or(0),
            sha256_hex(v)
        )),
        37 => Some(format!("reporting_triggers=0x{}", hex(v))),
        39 => Some(format!("report_type=0x{}", hex(v))),
        42 => Some(format!(
            "destination_interface={}",
            *v.first().ok_or_else(|| format!("PFCP IE {t} is empty"))? & 0x0f
        )),
        43 => Some(format!("up_function_features=0x{}", hex(v))),
        44 => Some(format!("apply_action=0x{}", hex(v))),
        45 => Some(format!("downlink_data_service_information=0x{}", hex(v))),
        56 if v.len() >= 2 => Some(format!("pdr_id={}", be16(v))),
        56 => return short(2),
        57 if v.len() >= 9 => {
            let ip = if v[0] & 2 != 0 && v.len() >= 13 {
                format!(",ipv4={}", ipv4(&v[9..13]))
            } else {
                String::new()
            };
            Some(format!(
                "f_seid=0x{:016x},v4={},v6={}{}",
                be64(&v[1..9]),
                v[0] & 2 != 0,
                v[0] & 1 != 0,
                ip
            ))
        }
        57 => return short(9),
        60 => Some(decode_node_id(v)?),
        62 => Some(format!(
            "measurement_method=0x{:02x}",
            *v.first().ok_or_else(|| format!("PFCP IE {t} is empty"))?
        )),
        63 => Some(format!("usage_report_trigger=0x{}", hex(v))),
        66 => Some(decode_volume_measurement(v)?),
        67 if v.len() >= 4 => Some(format!("duration_measurement={}", be32(v))),
        67 => return short(4),
        69 if v.len() >= 4 => Some(format!("time_of_first_packet_ntp={}", be32(v))),
        69 => return short(4),
        70 if v.len() >= 4 => Some(format!("time_of_last_packet_ntp={}", be32(v))),
        70 => return short(4),
        76 if v.len() >= 4 => Some(format!("end_time_ntp={}", be32(v))),
        76 => return short(4),
        81 if v.len() >= 4 => Some(format!("urr_id={}", be32(v) & 0x7fff_ffff)),
        81 => return short(4),
        84 if v.len() >= 2 => {
            let desc = be16(v);
            let teid = if v.len() >= 6 {
                format!(",teid=0x{:08x}", be32(&v[2..6]))
            } else {
                String::new()
            };
            let ip = if v.len() >= 10 {
                format!(",ipv4={}", ipv4(&v[6..10]))
            } else {
                String::new()
            };
            Some(format!("outer_header_description=0x{desc:04x}{teid}{ip}"))
        }
        84 => return short(2),
        88 => Some(format!(
            "bar_id={}",
            *v.first().ok_or_else(|| format!("PFCP IE {t} is empty"))?
        )),
        89 => Some(format!("cp_function_features=0x{}", hex(v))),
        93 => Some(format!("ue_ip={}", pseudonym("pfcp-ue-ip", v))),
        95 => Some(format!(
            "outer_header_removal={}",
            *v.first().ok_or_else(|| format!("PFCP IE {t} is empty"))?
        )),
        96 if v.len() >= 4 => Some(format!("recovery_time_ntp={}", be32(v))),
        96 => return short(4),
        104 if v.len() >= 4 => Some(format!("usage_report_sequence={}", be32(v))),
        104 => return short(4),
        108 if v.len() >= 4 => Some(format!("far_id={}", be32(v) & 0x7fff_ffff)),
        108 => return short(4),
        109 if v.len() >= 4 => Some(format!("qer_id={}", be32(v) & 0x7fff_ffff)),
        109 => return short(4),
        113 => Some(format!(
            "pdn_type={}",
            *v.first().ok_or_else(|| format!("PFCP IE {t} is empty"))? & 0x07
        )),
        124 => Some(format!(
            "qfi={}",
            *v.first().ok_or_else(|| format!("PFCP IE {t} is empty"))? & 0x3f
        )),
        141 => Some(format!("user_id={}", pseudonym("pfcp-user-id", v))),
        159 => Some(format!("apn_dnn={}", decode_apn(v)?)),
        160 => Some(format!(
            "interface_type={}",
            *v.first().ok_or_else(|| format!("PFCP IE {t} is empty"))? & 0x3f
        )),
        257 if v.len() >= 1 => Some(format!(
            "s_nssai_sst={},sd={}",
            v[0],
            if v.len() >= 4 {
                hex(&v[1..4])
            } else {
                "absent".into()
            }
        )),
        _ => None,
    };
    Ok(value)
}

fn decode_node_id(v: &[u8]) -> Result<String, String> {
    let kind = *v.first().ok_or("PFCP Node ID is empty")? & 0x0f;
    match kind {
        0 if v.len() == 5 => Ok(format!("node_id_ipv4={}.{}.{}.{}", v[1], v[2], v[3], v[4])),
        1 if v.len() == 17 => Ok(format!("node_id_ipv6=0x{}", hex(&v[1..]))),
        2 => Ok(format!("node_id_fqdn={}", decode_apn(&v[1..])?)),
        _ => Err(format!(
            "PFCP Node ID type/length invalid: type={kind}, length={}",
            v.len()
        )),
    }
}

fn decode_volume_measurement(v: &[u8]) -> Result<String, String> {
    let flags = *v.first().ok_or("PFCP Volume Measurement is empty")?;
    let mut pos = 1usize;
    let names = [
        (0x01, "total_volume"),
        (0x02, "uplink_volume"),
        (0x04, "downlink_volume"),
        (0x08, "total_packets"),
        (0x10, "uplink_packets"),
        (0x20, "downlink_packets"),
    ];
    let mut fields = vec![format!("volume_flags=0x{flags:02x}")];
    for (mask, name) in names {
        if flags & mask != 0 {
            if pos + 8 > v.len() {
                return Err(format!("PFCP Volume Measurement truncated at {name}"));
            }
            fields.push(format!("{name}={}", be64(&v[pos..pos + 8])));
            pos += 8;
        }
    }
    if pos != v.len() {
        return Err(format!(
            "PFCP Volume Measurement has {} trailing byte(s)",
            v.len() - pos
        ));
    }
    Ok(fields.join(","))
}

fn decode_apn(v: &[u8]) -> Result<String, String> {
    let mut labels = Vec::new();
    let mut pos = 0;
    while pos < v.len() {
        let len = v[pos] as usize;
        pos += 1;
        if len == 0 || pos + len > v.len() {
            return Err("PFCP APN/DNN label length invalid".into());
        }
        labels.push(
            std::str::from_utf8(&v[pos..pos + len]).map_err(|_| "PFCP APN/DNN is not UTF-8")?,
        );
        pos += len;
    }
    Ok(labels.join("."))
}

fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
fn be40(v: &[u8]) -> u64 {
    v[..5].iter().fold(0u64, |a, b| (a << 8) | u64::from(*b))
}
fn flatten(
    ies: &[PfcpIe],
    prefix: &str,
    out: &mut Vec<InformationElement>,
    ids: &mut Vec<NamedValue>,
) {
    for ie in ies {
        let path = if prefix.is_empty() {
            ie.name.clone()
        } else {
            format!("{prefix}/{}", ie.name)
        };
        if let Some(value) = &ie.decoded {
            let first = value.split(',').next().unwrap_or("");
            let key = first.split('=').next().unwrap_or("");
            if matches!(
                key,
                "pdr_id" | "far_id" | "qer_id" | "teid" | "f_seid" | "ue_ip"
            ) {
                ids.push(NamedValue {
                    name: key.into(),
                    value: first.split_once('=').map(|x| x.1).unwrap_or("").into(),
                    pseudonymized: key == "ue_ip",
                });
            }
        }
        out.push(InformationElement {
            id: Some(ie.ie_type),
            name: path.clone(),
            length: ie.value.len() as u32,
            value: ie.decoded.clone(),
            raw_sha256: Some(sha256_hex(&ie.value)),
            status: ie.status.clone(),
        });
        flatten(&ie.children, &path, out, ids);
    }
}
impl ProtocolDecoder for PfcpDecoder {
    fn manifest(&self) -> DecoderManifest {
        DecoderManifest {
            decoder_name: "decoder-pfcp",
            decoder_version: VERSION,
            api_version: PLUGIN_API_VERSION,
            protocol: Protocol::Pfcp,
            specification: "3GPP TS 29.244",
            deterministic: true,
        }
    }
    fn capabilities(&self) -> DecoderCapabilities {
        DecoderCapabilities {
            message_families: &[
                "Heartbeat",
                "Association Setup",
                "Session Establishment",
                "Session Modification",
                "Session Deletion",
            ],
            preserves_unknown_fields: true,
            supports_extensions: true,
            limitations: &[
                "unknown and release-new IEs are preserved by hash and length",
                "conditional semantic validation is not implemented",
            ],
        }
    }
    fn decode(&self, input: &DecoderInput<'_>) -> DecoderOutput {
        match parse(input.payload) {
            Ok(message) => {
                let mut ids = vec![NamedValue {
                    name: "pfcp_sequence".into(),
                    value: message.sequence_number.to_string(),
                    pseudonymized: false,
                }];
                if let Some(seid) = message.seid {
                    ids.push(NamedValue {
                        name: "seid".into(),
                        value: format!("0x{seid:016x}"),
                        pseudonymized: false,
                    });
                }
                let mut elements = Vec::new();
                flatten(&message.ies, "", &mut elements, &mut ids);
                let status = if message.unknown_count == 0 {
                    DecodeStatus::Decoded
                } else {
                    DecodeStatus::Partial
                };
                let mut errors = Vec::new();
                if message.unknown_count > 0 {
                    errors.push(format!(
                        "{} unknown IE(s) preserved by length and SHA-256",
                        message.unknown_count
                    ));
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
                    protocol: Protocol::Pfcp,
                    message_name: message_name(message.message_type).into(),
                    message_type: message.message_type as u32,
                    procedure_code: None,
                    procedure: None,
                    security_state: None,
                    source_byte_offset: None,
                    source_endpoint: input.source_endpoint.clone(),
                    destination_endpoint: input.destination_endpoint.clone(),
                    direction: infer_direction(input),
                    session_identifiers: ids,
                    information_elements: elements,
                    decoder_name: "decoder-pfcp".into(),
                    decoder_version: VERSION.into(),
                    schema_version: NormalizedEvent::SCHEMA_VERSION,
                    decoding_status: status.clone(),
                    errors: errors.clone(),
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
                    status,
                    events: vec![event],
                    errors,
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
    if src.contains("smf") && dst.contains("upf") {
        Direction::SmfToUpf
    } else if src.contains("upf") && dst.contains("smf") {
        Direction::UpfToSmf
    } else {
        Direction::Unknown
    }
}
fn message_name(t: u8) -> &'static str {
    match t {
        1 => "PFCP Heartbeat Request",
        2 => "PFCP Heartbeat Response",
        5 => "PFCP Association Setup Request",
        6 => "PFCP Association Setup Response",
        50 => "PFCP Session Establishment Request",
        51 => "PFCP Session Establishment Response",
        52 => "PFCP Session Modification Request",
        53 => "PFCP Session Modification Response",
        54 => "PFCP Session Deletion Request",
        55 => "PFCP Session Deletion Response",
        56 => "PFCP Session Report Request",
        57 => "PFCP Session Report Response",
        _ => "Unknown PFCP Message",
    }
}
fn ie_name(t: u16) -> Option<&'static str> {
    Some(match t {
        1 => "Create PDR",
        2 => "PDI",
        3 => "Create FAR",
        4 => "Forwarding Parameters",
        5 => "Duplicating Parameters",
        6 => "Create URR",
        7 => "Create QER",
        8 => "Created PDR",
        9 => "Update PDR",
        10 => "Update FAR",
        11 => "Update Forwarding Parameters",
        12 => "Update BAR",
        14 => "Remove PDR",
        15 => "Remove FAR",
        16 => "Remove URR",
        17 => "Remove QER",
        18 => "Cause Container",
        19 => "Cause",
        20 => "Source Interface",
        21 => "F-TEID",
        22 => "Network Instance",
        23 => "SDF Filter",
        25 => "Gate Status",
        26 => "MBR",
        27 => "GBR",
        29 => "Precedence",
        56 => "PDR ID",
        57 => "F-SEID",
        60 => "Node ID",
        84 => "Outer Header Creation",
        93 => "UE IP Address",
        108 => "FAR ID",
        109 => "QER ID",
        96 => "Recovery Time Stamp",
        31 => "Volume Threshold",
        37 => "Reporting Triggers",
        39 => "Report Type",
        42 => "Destination Interface",
        43 => "UP Function Features",
        44 => "Apply Action",
        45 => "Downlink Data Service Information",
        62 => "Measurement Method",
        63 => "Usage Report Trigger",
        66 => "Volume Measurement",
        67 => "Duration Measurement",
        69 => "Time of First Packet",
        70 => "Time of Last Packet",
        76 => "End Time",
        79 => "Usage Report Session Deletion Response",
        81 => "URR ID",
        83 => "Downlink Data Report",
        85 => "Create BAR",
        88 => "BAR ID",
        89 => "CP Function Features",
        95 => "Outer Header Removal",
        104 => "UR-SEQN",
        113 => "PDN Type",
        124 => "QFI",
        141 => "User ID",
        159 => "APN/DNN",
        160 => "3GPP Interface Type",
        257 => "S-NSSAI",
        _ => return None,
    })
}
fn is_grouped(t: u16) -> bool {
    matches!(t,1..=18|51|54|58|59|68|78..=80|83|85..=87|99|102|118|127..=130)
}
fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b[..8].try_into().expect("eight bytes"))
}
fn ipv4(v: &[u8]) -> String {
    format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3])
}

#[cfg(test)]
mod tests {
    use super::*;
    fn header(t: u8, seid: Option<u64>, ies: &[u8]) -> Vec<u8> {
        let mut v = vec![0x20 | (seid.is_some() as u8), t, 0, 0];
        if let Some(s) = seid {
            v.extend_from_slice(&s.to_be_bytes());
        }
        v.extend_from_slice(&[0, 0, 7, 0]);
        v.extend_from_slice(ies);
        let len = (v.len() - 4) as u16;
        v[2..4].copy_from_slice(&len.to_be_bytes());
        v
    }
    fn ie(t: u16, v: &[u8]) -> Vec<u8> {
        let mut x = Vec::new();
        x.extend_from_slice(&t.to_be_bytes());
        x.extend_from_slice(&(v.len() as u16).to_be_bytes());
        x.extend_from_slice(v);
        x
    }
    #[test]
    fn valid_header_with_and_without_seid() {
        let a = parse(&header(1, None, &[])).unwrap();
        assert_eq!(a.seid, None);
        let b = parse(&header(50, Some(9), &[])).unwrap();
        assert_eq!(b.seid, Some(9));
        assert_eq!(b.sequence_number, 7);
    }
    #[test]
    fn grouped_and_unknown_ie() {
        let child = ie(56, &3u16.to_be_bytes());
        let mut all = ie(1, &child);
        all.extend_from_slice(&ie(65000, &[1, 2]));
        let p = parse(&header(50, Some(1), &all)).unwrap();
        assert_eq!(p.ies[0].children[0].decoded.as_deref(), Some("pdr_id=3"));
        assert_eq!(p.unknown_count, 1);
    }
    #[test]
    fn invalid_length() {
        let mut p = header(1, None, &[]);
        p[2..4].copy_from_slice(&100u16.to_be_bytes());
        assert!(parse(&p).is_err());
        let broken = header(1, None, &[0, 1, 0, 9, 1]);
        assert!(parse(&broken).is_err());
    }
    #[test]
    fn nested_group_and_observed_fields_are_typed() {
        let mut pdi = ie(20, &[1]);
        pdi.extend_from_slice(&ie(21, &[1, 0, 0, 0, 3, 10, 77, 22, 13]));
        let nested = ie(1, &ie(2, &pdi));
        let parsed = parse(&header(50, Some(1), &nested)).unwrap();
        let pdi = &parsed.ies[0].children[0];
        assert_eq!(
            pdi.children[0].decoded.as_deref(),
            Some("source_interface=1")
        );
        assert!(pdi.children[1]
            .decoded
            .as_deref()
            .unwrap()
            .contains("teid=0x00000003"));
        assert_eq!(parsed.unknown_count, 0);
    }
    #[test]
    fn field_level_values_match_reference_representation() {
        assert_eq!(
            decode_value(29, &[0, 0, 0xff, 0xff]).unwrap().as_deref(),
            Some("precedence=65535")
        );
        assert_eq!(
            decode_value(42, &[3]).unwrap().as_deref(),
            Some("destination_interface=3")
        );
        assert_eq!(decode_value(124, &[9]).unwrap().as_deref(), Some("qfi=9"));
        assert_eq!(
            decode_value(159, &[8, b'i', b'n', b't', b'e', b'r', b'n', b'e', b't'])
                .unwrap()
                .as_deref(),
            Some("apn_dnn=internet")
        );
    }
    #[test]
    fn invalid_typed_ie_length_is_rejected() {
        let bad = header(50, Some(1), &ie(29, &[1, 2]));
        assert!(parse(&bad).is_err());
    }
}
