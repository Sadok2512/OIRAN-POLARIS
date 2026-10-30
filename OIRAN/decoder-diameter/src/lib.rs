//! Diameter base protocol decoder (RFC 6733) with 3GPP TS 29.272 S6a bindings.
//!
//! Covered command codes (S6a): Update Location (316), Authentication-Information
//! (318), Purge-UE (321), Cancel-Location (317), Notify (323).
//! AVPs User-Name (1 → IMSI) and MSISDN (3GPP vendor 701) are flagged as
//! identity and emitted as pseudonyms; `Visited-PLMN-Id`, `Result-Code`,
//! `Experimental-Result-Code` and the Subscription-Data grouped AVP (envelope)
//! are decoded.

use event_schema::{
    pseudonym, sha256_hex, DecodeStatus, Direction, EvidenceReference, EvidenceState,
    InformationElement, NamedValue, NormalizedEvent, Protocol,
};
use plugin_runtime::{
    DecoderCapabilities, DecoderInput, DecoderManifest, DecoderOutput, ProtocolDecoder,
    PLUGIN_API_VERSION,
};

pub const VERSION: &str = "0.2.0";
pub const SCHEMA_VERSION: &str = "IETF RFC 6733 + 3GPP TS 29.272";

#[derive(Default)]
pub struct DiameterDecoder;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiameterAvp {
    pub code: u32,
    pub vendor_id: Option<u32>,
    pub flags: u8,
    pub value: Vec<u8>,
    pub children: Vec<DiameterAvp>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiameterMessage {
    pub version: u8,
    pub flags: u8,
    pub command_code: u32,
    pub application_id: u32,
    pub hop_by_hop: u32,
    pub end_to_end: u32,
    pub command_name: &'static str,
    pub is_request: bool,
    pub avps: Vec<DiameterAvp>,
}

pub fn parse(payload: &[u8]) -> Result<DiameterMessage, String> {
    if payload.len() < 20 {
        return Err("Diameter header truncated".into());
    }
    let version = payload[0];
    if version != 1 {
        return Err("unsupported Diameter version".into());
    }
    let length = ((payload[1] as usize) << 16)
        | ((payload[2] as usize) << 8)
        | payload[3] as usize;
    if length < 20 || length > payload.len() {
        return Err("Diameter message length inconsistent".into());
    }
    let flags = payload[4];
    let is_request = flags & 0x80 != 0;
    let command_code =
        ((payload[5] as u32) << 16) | ((payload[6] as u32) << 8) | payload[7] as u32;
    let application_id = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let hop_by_hop =
        u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
    let end_to_end =
        u32::from_be_bytes([payload[16], payload[17], payload[18], payload[19]]);
    let avps = parse_avps(&payload[20..length], 0)?;
    Ok(DiameterMessage {
        version,
        flags,
        command_code,
        application_id,
        hop_by_hop,
        end_to_end,
        command_name: command_name(command_code, is_request),
        is_request,
        avps,
    })
}

fn parse_avps(mut data: &[u8], depth: usize) -> Result<Vec<DiameterAvp>, String> {
    if depth > 4 {
        return Err("Diameter AVP grouping exceeds depth 4".into());
    }
    let mut avps = Vec::new();
    while !data.is_empty() {
        if data.len() < 8 {
            return Err("Diameter AVP header truncated".into());
        }
        let code = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let flags = data[4];
        let length = ((data[5] as usize) << 16) | ((data[6] as usize) << 8) | data[7] as usize;
        if length < 8 || length > data.len() {
            return Err(format!("Diameter AVP {code} length inconsistent"));
        }
        let (vendor_id, header_len) = if flags & 0x80 != 0 {
            if length < 12 {
                return Err(format!("Diameter AVP {code} vendor header truncated"));
            }
            (
                Some(u32::from_be_bytes([data[8], data[9], data[10], data[11]])),
                12,
            )
        } else {
            (None, 8)
        };
        let value = data[header_len..length].to_vec();
        let padded = (length + 3) & !3;
        let is_grouped = is_grouped_avp(code, vendor_id);
        let children = if is_grouped {
            parse_avps(&value, depth + 1)?
        } else {
            Vec::new()
        };
        avps.push(DiameterAvp {
            code,
            vendor_id,
            flags,
            value,
            children,
        });
        if padded > data.len() {
            break;
        }
        data = &data[padded..];
    }
    Ok(avps)
}

fn is_grouped_avp(code: u32, vendor_id: Option<u32>) -> bool {
    // Known grouped AVPs in RFC 6733 base and 3GPP S6a (TS 29.272).
    matches!(
        (code, vendor_id),
        (260, None) // Vendor-Specific-Application-Id (RFC 6733 §6.11)
            | (284, None) // Proxy-Info
            | (297, None) // Experimental-Result
            | (1400, Some(10415)) // Subscription-Data
            | (1430, Some(10415)) // APN-Configuration-Profile
            | (1429, Some(10415)) // APN-Configuration
            | (1431, Some(10415)) // AMBR
            | (1620, Some(10415)) // Terminal-Information
            | (1405, Some(10415)) // Authentication-Info
            | (1413, Some(10415)) // Subscriber-Status
    )
}

fn decode_avp(
    avp: &DiameterAvp,
) -> (Option<String>, DecodeStatus, bool, Option<&'static str>) {
    let name = avp_name(avp.code, avp.vendor_id);
    match (avp.code, avp.vendor_id) {
        (1, None) => (
            Some(format!(
                "user_name_pseudonym={}",
                pseudonym("diameter-user-name", &avp.value)
            )),
            DecodeStatus::Decoded,
            true,
            name,
        ),
        (701, Some(10415)) => (
            Some(format!(
                "msisdn_pseudonym={}",
                pseudonym("msisdn", &avp.value)
            )),
            DecodeStatus::Decoded,
            true,
            name,
        ),
        (268, None) => decode_u32("result_code", &avp.value, name),
        (298, None) => decode_u32("experimental_result_code", &avp.value, name),
        (296, None) => decode_octet_string("origin_realm", &avp.value, name),
        (264, None) => decode_octet_string("origin_host", &avp.value, name),
        (293, None) => decode_octet_string("destination_host", &avp.value, name),
        (283, None) => decode_octet_string("destination_realm", &avp.value, name),
        (263, None) => decode_octet_string("session_id", &avp.value, name),
        (277, None) => decode_u32("auth_session_state", &avp.value, name),
        (278, None) => decode_u32("origin_state_id", &avp.value, name),
        (258, None) => decode_u32("auth_application_id", &avp.value, name),
        (259, None) => decode_u32("acct_application_id", &avp.value, name),
        (266, None) => decode_u32("vendor_id", &avp.value, name),
        (260, None) => (
            Some(format!(
                "vendor_specific_application_id_children={}",
                avp.children.len()
            )),
            DecodeStatus::Decoded,
            false,
            name,
        ),
        (1407, Some(10415)) => decode_plmn_avp("visited_plmn_id", &avp.value, name),
        (1400, Some(10415)) => (
            Some(format!(
                "subscription_data_children={}",
                avp.children.len()
            )),
            DecodeStatus::Partial,
            false,
            name,
        ),
        (1404, Some(10415)) => decode_u32("ulr_flags", &avp.value, name),
        (1405, Some(10415)) => (
            Some(format!(
                "authentication_info_children={}",
                avp.children.len()
            )),
            DecodeStatus::Partial,
            false,
            name,
        ),
        (1406, Some(10415)) => decode_u32("rat_type", &avp.value, name),
        (1408, Some(10415)) => decode_u32("sgsn_number", &avp.value, name),
        _ => (None, DecodeStatus::Unsupported, false, name),
    }
}

fn decode_u32(
    name: &'static str,
    v: &[u8],
    ie_name: Option<&'static str>,
) -> (Option<String>, DecodeStatus, bool, Option<&'static str>) {
    if v.len() != 4 {
        return (None, DecodeStatus::Malformed, false, ie_name);
    }
    (
        Some(format!("{name}={}", u32::from_be_bytes([v[0], v[1], v[2], v[3]]))),
        DecodeStatus::Decoded,
        false,
        ie_name,
    )
}

fn decode_octet_string(
    name: &'static str,
    v: &[u8],
    ie_name: Option<&'static str>,
) -> (Option<String>, DecodeStatus, bool, Option<&'static str>) {
    match std::str::from_utf8(v) {
        Ok(s) if !s.is_empty() && s.bytes().all(|b| (0x20..=0x7e).contains(&b)) => (
            Some(format!("{name}={s}")),
            DecodeStatus::Decoded,
            false,
            ie_name,
        ),
        _ => (
            Some(format!("{name}_sha256={}", sha256_hex(v))),
            DecodeStatus::Partial,
            false,
            ie_name,
        ),
    }
}

fn decode_plmn_avp(
    name: &'static str,
    v: &[u8],
    ie_name: Option<&'static str>,
) -> (Option<String>, DecodeStatus, bool, Option<&'static str>) {
    if v.len() != 3 {
        return (None, DecodeStatus::Malformed, false, ie_name);
    }
    let mcc = format!("{}{}{}", v[0] & 0x0f, v[0] >> 4, v[1] & 0x0f);
    let d3 = v[1] >> 4;
    let mnc = if d3 == 0x0f {
        format!("{}{}", v[2] & 0x0f, v[2] >> 4)
    } else {
        format!("{}{}{}", v[2] & 0x0f, v[2] >> 4, d3)
    };
    (
        Some(format!("{name}={mcc}-{mnc}")),
        DecodeStatus::Decoded,
        false,
        ie_name,
    )
}

fn command_name(code: u32, is_request: bool) -> &'static str {
    match (code, is_request) {
        (257, true) => "Capabilities-Exchange-Request",
        (257, false) => "Capabilities-Exchange-Answer",
        (280, true) => "Device-Watchdog-Request",
        (280, false) => "Device-Watchdog-Answer",
        (316, true) => "Update-Location-Request",
        (316, false) => "Update-Location-Answer",
        (317, true) => "Cancel-Location-Request",
        (317, false) => "Cancel-Location-Answer",
        (318, true) => "Authentication-Information-Request",
        (318, false) => "Authentication-Information-Answer",
        (321, true) => "Purge-UE-Request",
        (321, false) => "Purge-UE-Answer",
        (323, true) => "Notify-Request",
        (323, false) => "Notify-Answer",
        _ => "UnknownDiameterCommand",
    }
}

fn avp_name(code: u32, vendor: Option<u32>) -> Option<&'static str> {
    Some(match (code, vendor) {
        (1, None) => "User-Name",
        (258, None) => "Auth-Application-Id",
        (259, None) => "Acct-Application-Id",
        (260, None) => "Vendor-Specific-Application-Id",
        (263, None) => "Session-Id",
        (264, None) => "Origin-Host",
        (266, None) => "Vendor-Id",
        (268, None) => "Result-Code",
        (277, None) => "Auth-Session-State",
        (278, None) => "Origin-State-Id",
        (283, None) => "Destination-Realm",
        (293, None) => "Destination-Host",
        (296, None) => "Origin-Realm",
        (297, None) => "Experimental-Result",
        (298, None) => "Experimental-Result-Code",
        (701, Some(10415)) => "MSISDN",
        (1032, Some(10415)) => "RAT-Type",
        (1400, Some(10415)) => "Subscription-Data",
        (1404, Some(10415)) => "ULR-Flags",
        (1405, Some(10415)) => "Authentication-Info",
        (1406, Some(10415)) => "RAT-Type",
        (1407, Some(10415)) => "Visited-PLMN-Id",
        (1408, Some(10415)) => "SGSN-Number",
        (1413, Some(10415)) => "Subscriber-Status",
        (1429, Some(10415)) => "APN-Configuration",
        (1430, Some(10415)) => "APN-Configuration-Profile",
        (1431, Some(10415)) => "AMBR",
        (1420, Some(10415)) => "QoS-Subscribed",
        (1620, Some(10415)) => "Terminal-Information",
        _ => return None,
    })
}

impl ProtocolDecoder for DiameterDecoder {
    fn manifest(&self) -> DecoderManifest {
        DecoderManifest {
            decoder_name: "decoder-diameter",
            decoder_version: VERSION,
            api_version: PLUGIN_API_VERSION,
            protocol: Protocol::Diameter,
            specification: SCHEMA_VERSION,
            deterministic: true,
        }
    }
    fn capabilities(&self) -> DecoderCapabilities {
        DecoderCapabilities {
            message_families: &[
                "Capabilities-Exchange",
                "Device-Watchdog",
                "Update-Location",
                "Cancel-Location",
                "Authentication-Information",
                "Purge-UE",
                "Notify",
            ],
            preserves_unknown_fields: true,
            supports_extensions: false,
            limitations: &[
                "unknown AVPs are preserved by SHA-256 and length",
                "Subscription-Data and nested grouped AVPs are enumerated but typed only at envelope level",
                "AVP padding is honoured but not validated against the length field",
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

fn emit_event(msg: DiameterMessage, input: &DecoderInput<'_>) -> DecoderOutput {
    let mut identifiers = Vec::new();
    let mut elements = Vec::new();
    let mut errors = Vec::new();
    let mut status = DecodeStatus::Decoded;
    identifiers.push(NamedValue {
        name: "diameter_hop_by_hop".into(),
        value: format!("0x{:08x}", msg.hop_by_hop),
        pseudonymized: false,
    });
    identifiers.push(NamedValue {
        name: "diameter_end_to_end".into(),
        value: format!("0x{:08x}", msg.end_to_end),
        pseudonymized: false,
    });
    identifiers.push(NamedValue {
        name: "diameter_application_id".into(),
        value: msg.application_id.to_string(),
        pseudonymized: false,
    });
    for avp in &msg.avps {
        emit_avp(avp, &mut elements, &mut identifiers, &mut status, &mut errors);
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
        protocol: Protocol::Diameter,
        message_name: msg.command_name.into(),
        message_type: msg.command_code,
        procedure_code: Some(msg.command_code),
        procedure: Some(if msg.is_request { "REQUEST".into() } else { "ANSWER".into() }),
        security_state: None,
        source_byte_offset: None,
        source_endpoint: input.source_endpoint.clone(),
        destination_endpoint: input.destination_endpoint.clone(),
        direction: infer_direction(input, msg.is_request),
        session_identifiers: identifiers,
        information_elements: elements,
        decoder_name: "decoder-diameter".into(),
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

fn emit_avp(
    avp: &DiameterAvp,
    elements: &mut Vec<InformationElement>,
    identifiers: &mut Vec<NamedValue>,
    status: &mut DecodeStatus,
    errors: &mut Vec<String>,
) {
    let (value, avp_status, sensitive, name) = decode_avp(avp);
    if matches!(
        avp_status,
        DecodeStatus::Unsupported | DecodeStatus::Partial
    ) && *status == DecodeStatus::Decoded
    {
        *status = DecodeStatus::Partial;
    }
    if avp_status == DecodeStatus::Malformed {
        *status = DecodeStatus::Malformed;
    }
    if let Some(v) = &value {
        for pair in v.split(',') {
            if let Some((key, val)) = pair.split_once('=') {
                if matches!(
                    key,
                    "user_name_pseudonym"
                        | "msisdn_pseudonym"
                        | "result_code"
                        | "experimental_result_code"
                        | "visited_plmn_id"
                        | "origin_host"
                        | "origin_realm"
                        | "destination_host"
                        | "destination_realm"
                        | "session_id"
                        | "origin_state_id"
                        | "auth_session_state"
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
            "unknown Diameter AVP code={} vendor={:?} preserved by length and SHA-256",
            avp.code, avp.vendor_id
        ));
    }
    elements.push(InformationElement {
        id: u16::try_from(avp.code).ok(),
        name: name.unwrap_or("Unknown AVP").into(),
        length: avp.value.len() as u32,
        value,
        raw_sha256: Some(sha256_hex(&avp.value)),
        status: avp_status,
    });
    for child in &avp.children {
        emit_avp(child, elements, identifiers, status, errors);
    }
}

fn infer_direction(input: &DecoderInput<'_>, is_request: bool) -> Direction {
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
    if src.contains("mme") && dst.contains("hss") {
        return Direction::Uplink;
    }
    if src.contains("hss") && dst.contains("mme") {
        return Direction::Downlink;
    }
    if is_request {
        Direction::Uplink
    } else {
        Direction::Downlink
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_schema::{Endpoint, ExactTimestamp, PacketReference};

    fn avp(code: u32, vendor: Option<u32>, flags: u8, value: &[u8]) -> Vec<u8> {
        let header_len = if vendor.is_some() { 12 } else { 8 };
        let total = header_len + value.len();
        let mut out = Vec::new();
        out.extend_from_slice(&code.to_be_bytes());
        let real_flags = flags | if vendor.is_some() { 0x80 } else { 0 };
        out.push(real_flags);
        out.push((total >> 16) as u8);
        out.push((total >> 8) as u8);
        out.push(total as u8);
        if let Some(v) = vendor {
            out.extend_from_slice(&v.to_be_bytes());
        }
        out.extend_from_slice(value);
        let padding = (4 - (total % 4)) % 4;
        for _ in 0..padding {
            out.push(0);
        }
        out
    }

    fn message(command_code: u32, is_request: bool, application: u32, body: &[u8]) -> Vec<u8> {
        let total = 20 + body.len();
        let mut out = Vec::new();
        out.push(1);
        out.push((total >> 16) as u8);
        out.push((total >> 8) as u8);
        out.push(total as u8);
        let flags = if is_request { 0x80 } else { 0 };
        out.push(flags);
        out.push((command_code >> 16) as u8);
        out.push((command_code >> 8) as u8);
        out.push(command_code as u8);
        out.extend_from_slice(&application.to_be_bytes());
        out.extend_from_slice(&0x11223344u32.to_be_bytes());
        out.extend_from_slice(&0x55667788u32.to_be_bytes());
        out.extend_from_slice(body);
        out
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
            interface: "S6a".into(),
            source_endpoint: Endpoint {
                address: "10.0.0.1".into(),
                port: Some(3868),
                network_function: Some(src.into()),
            },
            destination_endpoint: Endpoint {
                address: "10.0.0.2".into(),
                port: Some(3868),
                network_function: Some(dst.into()),
            },
            payload: bytes,
            raw_payload_reference: "sha256:synthetic".into(),
        }
    }

    #[test]
    fn ulr_flags_user_name_as_pseudonymised_identity() {
        // Synthetic BCD-style User-Name (IMSI-form), not a real identity.
        let synthetic_user_name = b"001010000000012";
        let visited_plmn = &[0x00, 0xf1, 0x10];
        let ulr_flags = &[0x00, 0x00, 0x00, 0x02];
        let mut body = Vec::new();
        body.extend_from_slice(&avp(1, None, 0x40, synthetic_user_name));
        body.extend_from_slice(&avp(1404, Some(10415), 0x40, ulr_flags));
        body.extend_from_slice(&avp(1407, Some(10415), 0x40, visited_plmn));
        let bytes = message(316, true, 16777251, &body);
        let (p, t) = fixtures();
        let in_ = input(&bytes, &p, &t, "MME", "HSS");
        let out = DiameterDecoder.decode(&in_);
        assert_eq!(out.events.len(), 1);
        let ev = &out.events[0];
        assert_eq!(ev.message_name, "Update-Location-Request");
        assert_eq!(ev.direction, Direction::Uplink);
        let user_name = ev
            .session_identifiers
            .iter()
            .find(|v| v.name == "user_name_pseudonym")
            .expect("user_name_pseudonym");
        assert!(user_name.pseudonymized);
        assert!(user_name.value.starts_with("psn-"));
        let plmn = ev
            .session_identifiers
            .iter()
            .find(|v| v.name == "visited_plmn_id")
            .expect("visited_plmn_id");
        assert_eq!(plmn.value, "001-01");
    }

    #[test]
    fn ula_result_code_decoded_and_subscription_data_envelope_preserved() {
        let msisdn = b"\x11\x22\x33\x44";
        let result_code = &[0x00, 0x00, 0x07, 0xd1]; // 2001
        let subscription_data_inner = avp(1032, Some(10415), 0x40, &[0, 0, 0, 1]);
        let mut body = Vec::new();
        body.extend_from_slice(&avp(268, None, 0x40, result_code));
        body.extend_from_slice(&avp(701, Some(10415), 0x40, msisdn));
        body.extend_from_slice(&avp(1400, Some(10415), 0x40, &subscription_data_inner));
        let bytes = message(316, false, 16777251, &body);
        let (p, t) = fixtures();
        let in_ = input(&bytes, &p, &t, "HSS", "MME");
        let out = DiameterDecoder.decode(&in_);
        let ev = &out.events[0];
        assert_eq!(ev.message_name, "Update-Location-Answer");
        assert_eq!(ev.direction, Direction::Downlink);
        let result = ev
            .session_identifiers
            .iter()
            .find(|v| v.name == "result_code")
            .expect("result_code");
        assert_eq!(result.value, "2001");
        let msisdn_id = ev
            .session_identifiers
            .iter()
            .find(|v| v.name == "msisdn_pseudonym")
            .expect("msisdn_pseudonym");
        assert!(msisdn_id.pseudonymized);
        assert!(ev
            .information_elements
            .iter()
            .any(|e| e.name == "Subscription-Data"));
    }

    #[test]
    fn air_pur_clr_nor_message_names() {
        for (code, is_req, name) in [
            (318u32, true, "Authentication-Information-Request"),
            (318, false, "Authentication-Information-Answer"),
            (321, true, "Purge-UE-Request"),
            (321, false, "Purge-UE-Answer"),
            (317, true, "Cancel-Location-Request"),
            (317, false, "Cancel-Location-Answer"),
            (323, true, "Notify-Request"),
            (323, false, "Notify-Answer"),
        ] {
            let bytes = message(code, is_req, 16777251, &[]);
            assert_eq!(parse(&bytes).unwrap().command_name, name);
        }
    }

    #[test]
    fn unknown_avp_is_preserved_by_sha256_and_length() {
        let body = avp(65535, None, 0x40, &[1, 2, 3]);
        let bytes = message(316, true, 16777251, &body);
        let (p, t) = fixtures();
        let in_ = input(&bytes, &p, &t, "MME", "HSS");
        let out = DiameterDecoder.decode(&in_);
        let ev = &out.events[0];
        let unknown = ev
            .information_elements
            .iter()
            .find(|e| e.id == Some(65535))
            .expect("unknown AVP preserved");
        assert_eq!(unknown.name, "Unknown AVP");
        assert_eq!(unknown.length, 3);
    }

    #[test]
    fn rejects_truncated_header_and_bad_version() {
        assert!(parse(&[0]).is_err());
        let mut bad = message(316, true, 16777251, &[]);
        bad[0] = 2;
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn manifest_is_valid_and_declares_diameter() {
        let m = DiameterDecoder.manifest();
        assert_eq!(m.protocol, Protocol::Diameter);
        plugin_runtime::validate_manifest(&m).expect("valid manifest");
    }

    #[test]
    fn base_s6a_avps_keep_decoded_status() {
        // Sanitized synthetic ULR with Session-Id, Origin-Host/Realm, Destination-Realm,
        // Vendor-Specific-Application-Id (grouped: Vendor-Id 10415 + Auth-Application-Id 16777251),
        // Origin-State-Id, Auth-Session-State and User-Name. All identities synthetic (PLMN 001/01).
        let session_id = b"synthetic.mme.example.org;1;1;0";
        let origin_host = b"synthetic.mme.example.org";
        let origin_realm = b"example.org";
        let dest_realm = b"hss.example.org";
        let user_name = b"001010000000012";
        let vendor_id_child = avp(266, None, 0x40, &[0, 0, 0x28, 0xaf]); // 10415
        let auth_app_id_child = avp(258, None, 0x40, &[0x01, 0, 0, 0x23]); // 16777251 (S6a)
        let mut vsai_group = Vec::new();
        vsai_group.extend_from_slice(&vendor_id_child);
        vsai_group.extend_from_slice(&auth_app_id_child);
        let mut body = Vec::new();
        body.extend_from_slice(&avp(263, None, 0x40, session_id));
        body.extend_from_slice(&avp(260, None, 0x40, &vsai_group));
        body.extend_from_slice(&avp(277, None, 0x40, &[0, 0, 0, 1])); // NO_STATE_MAINTAINED
        body.extend_from_slice(&avp(264, None, 0x40, origin_host));
        body.extend_from_slice(&avp(296, None, 0x40, origin_realm));
        body.extend_from_slice(&avp(283, None, 0x40, dest_realm));
        body.extend_from_slice(&avp(278, None, 0x40, &[0, 0, 0x12, 0x34]));
        body.extend_from_slice(&avp(1, None, 0x40, user_name));
        body.extend_from_slice(&avp(1407, Some(10415), 0x40, &[0x00, 0xf1, 0x10]));
        let bytes = message(316, true, 16777251, &body);
        let (p, t) = fixtures();
        let in_ = input(&bytes, &p, &t, "MME", "HSS");
        let out = DiameterDecoder.decode(&in_);
        assert_eq!(out.status, DecodeStatus::Decoded, "status: {:?}", out.status);
        assert!(out.errors.is_empty(), "unexpected errors: {:?}", out.errors);
        let ev = &out.events[0];
        let id = |k: &str| {
            ev.session_identifiers
                .iter()
                .find(|v| v.name == k)
                .map(|v| v.value.clone())
        };
        assert_eq!(id("origin_state_id").as_deref(), Some("4660"));
        assert_eq!(id("auth_session_state").as_deref(), Some("1"));
        assert_eq!(id("origin_host").as_deref(), Some("synthetic.mme.example.org"));
        assert_eq!(id("origin_realm").as_deref(), Some("example.org"));
        assert_eq!(id("destination_realm").as_deref(), Some("hss.example.org"));
        assert!(id("session_id").as_deref().unwrap().starts_with("synthetic.mme"));
        assert!(ev
            .information_elements
            .iter()
            .any(|e| e.name == "Vendor-Specific-Application-Id"));
        assert!(ev
            .information_elements
            .iter()
            .any(|e| e.name == "Auth-Application-Id"));
        assert!(ev
            .information_elements
            .iter()
            .any(|e| e.name == "Vendor-Id"));
        assert!(ev
            .information_elements
            .iter()
            .any(|e| e.name == "Origin-State-Id"));
    }
}
