//! 3GPP TS 29.274 GTPv2-C header and IE decoder.
//!
//! Covered procedures: Echo (1/2), Create/Modify/Delete Session (32-37),
//! Create/Delete Bearer (95/96/99/100), Release Access Bearers (170/171).
//!
//! Identity-bearing IEs (IMSI, MSISDN, MEI) are flagged with
//! `pseudonymized: true` and emitted as deterministic pseudonyms derived
//! from the raw bytes; the raw digits are never surfaced.

use event_schema::{
    pseudonym, sha256_hex, DecodeStatus, Direction, EvidenceReference, EvidenceState,
    InformationElement, NamedValue, NormalizedEvent, Protocol,
};
use plugin_runtime::{
    DecoderCapabilities, DecoderInput, DecoderManifest, DecoderOutput, ProtocolDecoder,
    PLUGIN_API_VERSION,
};

pub const VERSION: &str = "0.1.0";
pub const SCHEMA_VERSION: &str = "3GPP TS 29.274";

#[derive(Default)]
pub struct Gtpv2cDecoder;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Gtpv2cIe {
    pub ie_type: u8,
    pub instance: u8,
    pub value: Vec<u8>,
    pub children: Vec<Gtpv2cIe>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Gtpv2cMessage {
    pub message_type: u8,
    pub message_name: &'static str,
    pub teid: Option<u32>,
    pub sequence_number: u32,
    pub ies: Vec<Gtpv2cIe>,
}

pub fn parse(payload: &[u8]) -> Result<Gtpv2cMessage, String> {
    if payload.len() < 8 {
        return Err("GTPv2-C header truncated".into());
    }
    let flags = payload[0];
    let version = flags >> 5;
    if version != 2 {
        return Err("unsupported GTPv2-C version".into());
    }
    let teid_flag = flags & 0x08 != 0;
    let message_type = payload[1];
    let declared = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    let total = declared.checked_add(4).ok_or("declared length overflow")?;
    if total > payload.len() {
        return Err("declared GTPv2-C length exceeds UDP payload".into());
    }
    let (header_len, teid, sequence) = if teid_flag {
        if total < 12 {
            return Err("GTPv2-C header inconsistent with T flag".into());
        }
        let teid = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let seq =
            ((payload[8] as u32) << 16) | ((payload[9] as u32) << 8) | payload[10] as u32;
        (12usize, Some(teid), seq)
    } else {
        let seq =
            ((payload[4] as u32) << 16) | ((payload[5] as u32) << 8) | payload[6] as u32;
        (8usize, None, seq)
    };
    let ies = parse_ies(&payload[header_len..total], 0)?;
    Ok(Gtpv2cMessage {
        message_type,
        message_name: message_name(message_type),
        teid,
        sequence_number: sequence,
        ies,
    })
}

fn parse_ies(mut data: &[u8], depth: usize) -> Result<Vec<Gtpv2cIe>, String> {
    if depth > 4 {
        return Err("GTPv2-C grouped IE nesting exceeds 4".into());
    }
    let mut ies = Vec::new();
    while !data.is_empty() {
        if data.len() < 4 {
            return Err("GTPv2-C IE header truncated".into());
        }
        let ie_type = data[0];
        let length = u16::from_be_bytes([data[1], data[2]]) as usize;
        let instance = data[3] & 0x0f;
        if 4 + length > data.len() {
            return Err(format!("GTPv2-C IE {ie_type} value truncated"));
        }
        let value = data[4..4 + length].to_vec();
        let children = if ie_type == 93 {
            parse_ies(&value, depth + 1)?
        } else {
            Vec::new()
        };
        ies.push(Gtpv2cIe {
            ie_type,
            instance,
            value,
            children,
        });
        data = &data[4 + length..];
    }
    Ok(ies)
}

fn decode_ie(ie: &Gtpv2cIe) -> (Option<String>, DecodeStatus, bool, Option<&'static str>) {
    let name = ie_name(ie.ie_type);
    match ie.ie_type {
        1 => (
            Some(format!("imsi_pseudonym={}", pseudonym("imsi", &ie.value))),
            DecodeStatus::Decoded,
            true,
            name,
        ),
        75 => (
            Some(format!("mei_pseudonym={}", pseudonym("mei", &ie.value))),
            DecodeStatus::Decoded,
            true,
            name,
        ),
        76 => (
            Some(format!(
                "msisdn_pseudonym={}",
                pseudonym("msisdn", &ie.value)
            )),
            DecodeStatus::Decoded,
            true,
            name,
        ),
        2 => decode_cause(&ie.value, name),
        3 => decode_single_byte("recovery", &ie.value, name),
        71 => decode_apn(&ie.value, name),
        72 => decode_ambr(&ie.value, name),
        73 => decode_single_byte("ebi", &ie.value, name),
        79 => decode_paa(&ie.value, name),
        83 => decode_serving_network(&ie.value, name),
        87 => decode_fteid(&ie.value, name),
        93 => (
            Some(format!(
                "bearer_context_children={}",
                ie.children.len()
            )),
            DecodeStatus::Partial,
            false,
            name,
        ),
        _ => (None, DecodeStatus::Unsupported, false, name),
    }
}

fn decode_single_byte(
    name: &'static str,
    v: &[u8],
    ie_name: Option<&'static str>,
) -> (Option<String>, DecodeStatus, bool, Option<&'static str>) {
    if v.len() != 1 {
        return (None, DecodeStatus::Malformed, false, ie_name);
    }
    (
        Some(format!("{name}={}", v[0])),
        DecodeStatus::Decoded,
        false,
        ie_name,
    )
}

fn decode_cause(
    v: &[u8],
    ie_name: Option<&'static str>,
) -> (Option<String>, DecodeStatus, bool, Option<&'static str>) {
    if v.is_empty() {
        return (None, DecodeStatus::Malformed, false, ie_name);
    }
    (
        Some(format!("cause_value={}", v[0])),
        DecodeStatus::Decoded,
        false,
        ie_name,
    )
}

fn decode_apn(
    v: &[u8],
    ie_name: Option<&'static str>,
) -> (Option<String>, DecodeStatus, bool, Option<&'static str>) {
    let mut out = String::new();
    let mut i = 0;
    while i < v.len() {
        let len = v[i] as usize;
        if len == 0 || i + 1 + len > v.len() {
            return (None, DecodeStatus::Malformed, false, ie_name);
        }
        let label = &v[i + 1..i + 1 + len];
        if !label.iter().all(|b| (0x20..=0x7e).contains(b)) {
            return (None, DecodeStatus::Malformed, false, ie_name);
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(std::str::from_utf8(label).unwrap_or("?"));
        i += 1 + len;
    }
    (
        Some(format!("apn={out}")),
        DecodeStatus::Decoded,
        false,
        ie_name,
    )
}

fn decode_ambr(
    v: &[u8],
    ie_name: Option<&'static str>,
) -> (Option<String>, DecodeStatus, bool, Option<&'static str>) {
    if v.len() != 8 {
        return (None, DecodeStatus::Malformed, false, ie_name);
    }
    let ul = u32::from_be_bytes(v[0..4].try_into().expect("four bytes"));
    let dl = u32::from_be_bytes(v[4..8].try_into().expect("four bytes"));
    (
        Some(format!("ambr_uplink_kbps={ul},ambr_downlink_kbps={dl}")),
        DecodeStatus::Decoded,
        false,
        ie_name,
    )
}

fn decode_paa(
    v: &[u8],
    ie_name: Option<&'static str>,
) -> (Option<String>, DecodeStatus, bool, Option<&'static str>) {
    if v.is_empty() {
        return (None, DecodeStatus::Malformed, false, ie_name);
    }
    let pdn_type = v[0] & 0x07;
    let text = match pdn_type {
        1 if v.len() >= 5 => format!(
            "pdn_type=ipv4,ue_ipv4={}.{}.{}.{}",
            v[1], v[2], v[3], v[4]
        ),
        2 if v.len() >= 17 => {
            let mut s = String::from("pdn_type=ipv6,ue_ipv6=");
            for b in &v[2..18.min(v.len())] {
                s.push_str(&format!("{b:02x}"));
            }
            s
        }
        3 => "pdn_type=ipv4v6".into(),
        _ => format!("pdn_type_raw={pdn_type}"),
    };
    (Some(text), DecodeStatus::Decoded, false, ie_name)
}

fn decode_serving_network(
    v: &[u8],
    ie_name: Option<&'static str>,
) -> (Option<String>, DecodeStatus, bool, Option<&'static str>) {
    if v.len() != 3 {
        return (None, DecodeStatus::Malformed, false, ie_name);
    }
    (
        Some(format!("serving_plmn={}", decode_plmn(v))),
        DecodeStatus::Decoded,
        false,
        ie_name,
    )
}

fn decode_fteid(
    v: &[u8],
    ie_name: Option<&'static str>,
) -> (Option<String>, DecodeStatus, bool, Option<&'static str>) {
    if v.len() < 5 {
        return (None, DecodeStatus::Malformed, false, ie_name);
    }
    let flags = v[0];
    let v4 = flags & 0x80 != 0;
    let v6 = flags & 0x40 != 0;
    let iface = flags & 0x3f;
    let teid = u32::from_be_bytes(v[1..5].try_into().expect("four bytes"));
    let mut out = format!("f_teid_iface={iface},f_teid=0x{teid:08x}");
    let mut off = 5;
    if v4 && v.len() >= off + 4 {
        out.push_str(&format!(
            ",ipv4={}.{}.{}.{}",
            v[off],
            v[off + 1],
            v[off + 2],
            v[off + 3]
        ));
        off += 4;
    }
    if v6 && v.len() >= off + 16 {
        out.push_str(",ipv6=");
        for b in &v[off..off + 16] {
            out.push_str(&format!("{b:02x}"));
        }
    }
    (Some(out), DecodeStatus::Decoded, false, ie_name)
}

fn decode_plmn(v: &[u8]) -> String {
    if v.len() != 3 {
        return "invalid".into();
    }
    let mcc = format!("{}{}{}", v[0] & 0x0f, v[0] >> 4, v[1] & 0x0f);
    let d3 = v[1] >> 4;
    let mnc = if d3 == 0x0f {
        format!("{}{}", v[2] & 0x0f, v[2] >> 4)
    } else {
        format!("{}{}{}", v[2] & 0x0f, v[2] >> 4, d3)
    };
    format!("{mcc}-{mnc}")
}

fn message_name(code: u8) -> &'static str {
    match code {
        1 => "EchoRequest",
        2 => "EchoResponse",
        3 => "VersionNotSupportedIndication",
        32 => "CreateSessionRequest",
        33 => "CreateSessionResponse",
        34 => "ModifyBearerRequest",
        35 => "ModifyBearerResponse",
        36 => "DeleteSessionRequest",
        37 => "DeleteSessionResponse",
        95 => "CreateBearerRequest",
        96 => "CreateBearerResponse",
        97 => "UpdateBearerRequest",
        98 => "UpdateBearerResponse",
        99 => "DeleteBearerRequest",
        100 => "DeleteBearerResponse",
        170 => "ReleaseAccessBearersRequest",
        171 => "ReleaseAccessBearersResponse",
        _ => "UnknownGTPv2CProcedure",
    }
}

fn ie_name(code: u8) -> Option<&'static str> {
    Some(match code {
        1 => "IMSI",
        2 => "Cause",
        3 => "Recovery",
        71 => "APN",
        72 => "AMBR",
        73 => "EBI",
        74 => "IP Address",
        75 => "MEI",
        76 => "MSISDN",
        77 => "Indication",
        78 => "PCO",
        79 => "PAA",
        80 => "Bearer QoS",
        82 => "RAT Type",
        83 => "Serving Network",
        86 => "ULI",
        87 => "F-TEID",
        93 => "Bearer Context",
        95 => "Charging ID",
        114 => "UE Time Zone",
        128 => "APN Restriction",
        _ => return None,
    })
}

impl ProtocolDecoder for Gtpv2cDecoder {
    fn manifest(&self) -> DecoderManifest {
        DecoderManifest {
            decoder_name: "decoder-gtpv2c",
            decoder_version: VERSION,
            api_version: PLUGIN_API_VERSION,
            protocol: Protocol::Gtpv2c,
            specification: SCHEMA_VERSION,
            deterministic: true,
        }
    }
    fn capabilities(&self) -> DecoderCapabilities {
        DecoderCapabilities {
            message_families: &[
                "Echo",
                "Create Session",
                "Modify Bearer",
                "Delete Session",
                "Create Bearer",
                "Delete Bearer",
                "Release Access Bearers",
            ],
            preserves_unknown_fields: true,
            supports_extensions: false,
            limitations: &[
                "unknown IE types are preserved by SHA-256 and length",
                "piggybacked message chain is not followed",
                "grouped IE nesting is bounded to depth 4",
            ],
        }
    }
    fn decode(&self, input: &DecoderInput<'_>) -> DecoderOutput {
        match parse(input.payload) {
            Ok(msg) => emit_event(msg, input),
            Err(e) => DecoderOutput {
                status: DecodeStatus::Malformed,
                events: Vec::new(),
                errors: vec![e],
            },
        }
    }
}

fn emit_event(msg: Gtpv2cMessage, input: &DecoderInput<'_>) -> DecoderOutput {
    let mut identifiers = Vec::new();
    let mut elements = Vec::new();
    let mut errors = Vec::new();
    let mut status = DecodeStatus::Decoded;
    if let Some(teid) = msg.teid {
        identifiers.push(NamedValue {
            name: "gtpv2c_teid".into(),
            value: format!("0x{teid:08x}"),
            pseudonymized: false,
        });
    }
    identifiers.push(NamedValue {
        name: "gtpv2c_sequence".into(),
        value: msg.sequence_number.to_string(),
        pseudonymized: false,
    });
    for ie in &msg.ies {
        let (value, ie_status, sensitive, name) = decode_ie(ie);
        if matches!(
            ie_status,
            DecodeStatus::Unsupported | DecodeStatus::Partial
        ) && status == DecodeStatus::Decoded
        {
            status = DecodeStatus::Partial;
        }
        if ie_status == DecodeStatus::Malformed {
            status = DecodeStatus::Malformed;
        }
        if let Some(v) = &value {
            for pair in v.split(',') {
                if let Some((key, val)) = pair.split_once('=') {
                    if matches!(
                        key,
                        "imsi_pseudonym"
                            | "msisdn_pseudonym"
                            | "mei_pseudonym"
                            | "apn"
                            | "serving_plmn"
                            | "f_teid"
                            | "ue_ipv4"
                            | "ue_ipv6"
                            | "ebi"
                    ) {
                        identifiers.push(NamedValue {
                            name: key.into(),
                            value: val.into(),
                            pseudonymized: sensitive,
                        });
                    }
                }
            }
        }
        if name.is_none() {
            errors.push(format!(
                "unknown GTPv2-C IE {} preserved by length and SHA-256",
                ie.ie_type
            ));
        }
        elements.push(InformationElement {
            id: Some(ie.ie_type as u16),
            name: name.unwrap_or("Unknown IE").into(),
            length: ie.value.len() as u32,
            value,
            raw_sha256: Some(sha256_hex(&ie.value)),
            status: ie_status,
        });
        for child in &ie.children {
            let (cv, cs, csens, cname) = decode_ie(child);
            if let Some(v) = &cv {
                for pair in v.split(',') {
                    if let Some((key, val)) = pair.split_once('=') {
                        if matches!(key, "f_teid" | "ue_ipv4" | "ue_ipv6" | "ebi") {
                            identifiers.push(NamedValue {
                                name: format!("bearer_{key}"),
                                value: val.into(),
                                pseudonymized: csens,
                            });
                        }
                    }
                }
            }
            elements.push(InformationElement {
                id: Some(child.ie_type as u16),
                name: cname.unwrap_or("Unknown IE").into(),
                length: child.value.len() as u32,
                value: cv,
                raw_sha256: Some(sha256_hex(&child.value)),
                status: cs,
            });
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
        protocol: Protocol::Gtpv2c,
        message_name: msg.message_name.into(),
        message_type: msg.message_type as u32,
        procedure_code: Some(msg.message_type as u32),
        procedure: None,
        security_state: None,
        source_byte_offset: None,
        source_endpoint: input.source_endpoint.clone(),
        destination_endpoint: input.destination_endpoint.clone(),
        direction: infer_direction(input, msg.message_type),
        session_identifiers: identifiers,
        information_elements: elements,
        decoder_name: "decoder-gtpv2c".into(),
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

fn infer_direction(input: &DecoderInput<'_>, message_type: u8) -> Direction {
    let src = input
        .source_endpoint
        .network_function
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let dst = input
        .destination_endpoint
        .network_function
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    if src.contains("sgw") && dst.contains("pgw") {
        return Direction::Uplink;
    }
    if src.contains("pgw") && dst.contains("sgw") {
        return Direction::Downlink;
    }
    if src.contains("mme") && dst.contains("sgw") {
        return Direction::Uplink;
    }
    if src.contains("sgw") && dst.contains("mme") {
        return Direction::Downlink;
    }
    match message_type {
        32 | 34 | 36 | 170 => Direction::Uplink,
        33 | 35 | 37 | 95 | 99 | 171 => Direction::Downlink,
        _ => Direction::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_schema::{Endpoint, ExactTimestamp, PacketReference};

    fn ie(ie_type: u8, instance: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![ie_type];
        let len = value.len() as u16;
        out.extend_from_slice(&len.to_be_bytes());
        out.push(instance & 0x0f);
        out.extend_from_slice(value);
        out
    }

    fn msg(message_type: u8, teid: Option<u32>, seq: u32, body: &[u8]) -> Vec<u8> {
        let mut header = Vec::new();
        let flags = if teid.is_some() { 0x48 } else { 0x40 }; // version 2, T bit optional
        header.push(flags);
        header.push(message_type);
        let total_len = if teid.is_some() { 8 } else { 4 } + body.len();
        header.extend_from_slice(&(total_len as u16).to_be_bytes());
        if let Some(t) = teid {
            header.extend_from_slice(&t.to_be_bytes());
        }
        header.push((seq >> 16) as u8);
        header.push((seq >> 8) as u8);
        header.push(seq as u8);
        header.push(0);
        header.extend_from_slice(body);
        header
    }

    fn fixtures() -> (Vec<PacketReference>, ExactTimestamp) {
        let p = vec![PacketReference {
            source_file: "synthetic.pcap".into(),
            source_sha256: Some("deadbeef".into()),
            packet_number: 1,
            byte_offset: 0,
            interface_id: 0,
            link_type: Some(276),
            sll2_protocol_type: Some(0x0800),
            sll2_reserved: Some(0),
            sll2_interface_index: Some(1),
            sll2_arphrd_type: Some(1),
            sll2_packet_type: Some(0),
            sll2_address_length: Some(6),
            sll2_address: Some("000000000000".into()),
            captured_length: 128,
            original_length: 128,
        }];
        let t = ExactTimestamp {
            seconds: 1,
            nanoseconds: 0,
            raw_ticks: 1_000_000_000,
            resolution_base: 10,
            resolution_exponent: 9,
        };
        (p, t)
    }

    fn input<'a>(
        bytes: &'a [u8],
        p: &'a [PacketReference],
        t: &'a ExactTimestamp,
        src: &'static str,
        dst: &'static str,
    ) -> DecoderInput<'a> {
        DecoderInput {
            capture_id: "cap-syn".into(),
            packet_references: p,
            timestamp: t,
            interface: "S11".into(),
            source_endpoint: Endpoint {
                address: "10.0.0.1".into(),
                port: Some(2123),
                network_function: Some(src.into()),
            },
            destination_endpoint: Endpoint {
                address: "10.0.0.2".into(),
                port: Some(2123),
                network_function: Some(dst.into()),
            },
            payload: bytes,
            raw_payload_reference: "sha256:synthetic".into(),
        }
    }

    #[test]
    fn echo_request_without_teid_and_echo_response_are_recognised() {
        let req = msg(1, None, 1, &ie(3, 0, &[42]));
        let parsed = parse(&req).expect("echo request parses");
        assert_eq!(parsed.message_name, "EchoRequest");
        assert_eq!(parsed.teid, None);
        assert_eq!(parsed.sequence_number, 1);
        assert_eq!(parsed.ies.len(), 1);

        let rsp = msg(2, None, 1, &ie(3, 0, &[42]));
        assert_eq!(parse(&rsp).unwrap().message_name, "EchoResponse");
    }

    #[test]
    fn create_session_request_flags_identities_as_pseudonymised() {
        // Fully synthetic BCD-encoded IMSI/MSISDN/MEI bytes; not real identities.
        let synthetic_imsi = &[0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12];
        let synthetic_msisdn = &[0x00, 0x10, 0x00, 0x00, 0x00, 0x12];
        let synthetic_mei = &[0x30, 0x53, 0x01, 0x80, 0x12, 0x34, 0x56, 0x78];
        let apn_internet = &[8, b'i', b'n', b't', b'e', b'r', b'n', b'e', b't'];
        let ambr = &[0x00, 0x00, 0x27, 0x10, 0x00, 0x01, 0x86, 0xa0];
        let serving_plmn = &[0x00, 0xf1, 0x10];
        let ebi = &[5];
        let fteid = &[0x86, 0xaa, 0xbb, 0xcc, 0xdd, 10, 0, 0, 1];
        let mut body = Vec::new();
        body.extend_from_slice(&ie(1, 0, synthetic_imsi));
        body.extend_from_slice(&ie(76, 0, synthetic_msisdn));
        body.extend_from_slice(&ie(75, 0, synthetic_mei));
        body.extend_from_slice(&ie(71, 0, apn_internet));
        body.extend_from_slice(&ie(72, 0, ambr));
        body.extend_from_slice(&ie(83, 0, serving_plmn));
        body.extend_from_slice(&ie(73, 0, ebi));
        body.extend_from_slice(&ie(87, 0, fteid));

        let bytes = msg(32, Some(0), 7, &body);
        let (p, t) = fixtures();
        let in_ = input(&bytes, &p, &t, "MME", "SGW");
        let out = Gtpv2cDecoder.decode(&in_);
        assert_eq!(out.events.len(), 1);
        let ev = &out.events[0];
        assert_eq!(ev.message_name, "CreateSessionRequest");
        assert_eq!(ev.direction, Direction::Uplink);
        let imsi = ev
            .session_identifiers
            .iter()
            .find(|v| v.name == "imsi_pseudonym")
            .expect("imsi identifier");
        assert!(imsi.pseudonymized);
        assert!(imsi.value.starts_with("psn-"));
        let msisdn = ev
            .session_identifiers
            .iter()
            .find(|v| v.name == "msisdn_pseudonym")
            .expect("msisdn identifier");
        assert!(msisdn.pseudonymized);
        let mei = ev
            .session_identifiers
            .iter()
            .find(|v| v.name == "mei_pseudonym")
            .expect("mei identifier");
        assert!(mei.pseudonymized);
        let apn = ev
            .session_identifiers
            .iter()
            .find(|v| v.name == "apn")
            .expect("apn identifier");
        assert_eq!(apn.value, "internet");
        assert!(!apn.pseudonymized);
        let plmn = ev
            .session_identifiers
            .iter()
            .find(|v| v.name == "serving_plmn")
            .expect("serving plmn");
        assert_eq!(plmn.value, "001-01");
    }

    #[test]
    fn create_session_response_decodes_paa_and_fteid() {
        let cause = &[16, 0]; // Request accepted
        let paa = &[0x01, 10, 46, 0, 1];
        let fteid = &[0x81, 0x11, 0x22, 0x33, 0x44, 10, 1, 2, 3];
        let mut body = Vec::new();
        body.extend_from_slice(&ie(2, 0, cause));
        body.extend_from_slice(&ie(79, 0, paa));
        body.extend_from_slice(&ie(87, 0, fteid));
        let bytes = msg(33, Some(0xdeadbeef), 7, &body);
        let (p, t) = fixtures();
        let in_ = input(&bytes, &p, &t, "SGW", "MME");
        let out = Gtpv2cDecoder.decode(&in_);
        let ev = &out.events[0];
        assert_eq!(ev.message_name, "CreateSessionResponse");
        assert_eq!(ev.direction, Direction::Downlink);
        let ue = ev
            .session_identifiers
            .iter()
            .find(|v| v.name == "ue_ipv4")
            .expect("ue_ipv4 identifier");
        assert_eq!(ue.value, "10.46.0.1");
    }

    #[test]
    fn modify_delete_release_bearer_message_names() {
        for (code, name) in [
            (34u8, "ModifyBearerRequest"),
            (35, "ModifyBearerResponse"),
            (36, "DeleteSessionRequest"),
            (37, "DeleteSessionResponse"),
            (95, "CreateBearerRequest"),
            (96, "CreateBearerResponse"),
            (99, "DeleteBearerRequest"),
            (100, "DeleteBearerResponse"),
            (170, "ReleaseAccessBearersRequest"),
            (171, "ReleaseAccessBearersResponse"),
        ] {
            let bytes = msg(code, Some(1), 1, &[]);
            assert_eq!(parse(&bytes).unwrap().message_name, name);
        }
    }

    #[test]
    fn bearer_context_grouped_ie_nested_fteid_is_decoded() {
        let fteid = &[0x81, 0x00, 0x00, 0x00, 0x05, 10, 10, 10, 10];
        let ebi = &[5];
        let mut inner = Vec::new();
        inner.extend_from_slice(&ie(73, 0, ebi));
        inner.extend_from_slice(&ie(87, 0, fteid));
        let body = ie(93, 0, &inner);
        let bytes = msg(32, Some(0), 1, &body);
        let (p, tts) = fixtures();
        let in_ = input(&bytes, &p, &tts, "MME", "SGW");
        let out = Gtpv2cDecoder.decode(&in_);
        let ev = &out.events[0];
        assert!(ev
            .information_elements
            .iter()
            .any(|e| e.name == "Bearer Context"));
        assert!(ev
            .information_elements
            .iter()
            .any(|e| e.name == "F-TEID"));
    }

    #[test]
    fn unknown_ie_is_preserved_by_sha256_and_length() {
        let body = ie(220, 0, &[0xaa, 0xbb]);
        let bytes = msg(32, Some(0), 1, &body);
        let (p, t) = fixtures();
        let in_ = input(&bytes, &p, &t, "MME", "SGW");
        let out = Gtpv2cDecoder.decode(&in_);
        let ev = &out.events[0];
        let ie = ev
            .information_elements
            .iter()
            .find(|e| e.id == Some(220))
            .expect("unknown IE preserved");
        assert_eq!(ie.name, "Unknown IE");
        assert_eq!(ie.length, 2);
        assert!(ie.raw_sha256.is_some());
    }

    #[test]
    fn rejects_truncated_header_and_wrong_version() {
        assert!(parse(&[0]).is_err());
        let bad = [0x08, 32, 0, 0, 0, 0, 0, 0];
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn manifest_is_valid_and_declares_gtpv2c() {
        let m = Gtpv2cDecoder.manifest();
        assert_eq!(m.protocol, Protocol::Gtpv2c);
        plugin_runtime::validate_manifest(&m).expect("valid manifest");
    }
}
