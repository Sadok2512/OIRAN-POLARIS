//! Diameter base protocol decoder (RFC 6733) with 3GPP TS 29.272 S6a bindings.
//!
//! Covered command codes (S6a): Update Location (316), Authentication-Information
//! (318), Purge-UE (321), Cancel-Location (317), Notify (323).
//! AVPs User-Name (1 → IMSI) and MSISDN (3GPP vendor 701) are flagged as
//! identity and emitted as pseudonyms; `Visited-PLMN-Id`, `Result-Code`,
//! `Experimental-Result-Code` and the Subscription-Data grouped AVP (envelope)
//! are decoded.

use event_schema::{
    pseudonym, pseudonym_subscriber_text, sha256_hex, DecodeStatus, Direction,
    EvidenceReference, EvidenceState, InformationElement, NamedValue, NormalizedEvent, Protocol,
    PseudonymKey,
};
use plugin_runtime::{
    DecoderCapabilities, DecoderInput, DecoderManifest, DecoderOutput, ProtocolDecoder,
    PLUGIN_API_VERSION,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
// 2.9.10 bump — count-preserving MALFORMED emission
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
    pseudonym_key: &PseudonymKey,
) -> (Option<String>, DecodeStatus, bool, Option<&'static str>) {
    let name = avp_name(avp.code, avp.vendor_id);
    match (avp.code, avp.vendor_id) {
        (1, None) => (
            Some(format!(
                "subscriber_pseudonym={}",
                pseudonym_subscriber_text(pseudonym_key, &avp.value)
            )),
            DecodeStatus::Decoded,
            true,
            name,
        ),
        (701, Some(10415)) => (
            Some(format!(
                "subscriber_pseudonym={}",
                pseudonym(pseudonym_key, "msisdn", &avp.value)
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
        // 2.7.7: identity-bearing AVP names rewritten so no serialised
        // field carries `imsi` / `msisdn` substrings in any position.
        (1, None) => "identity_pseudonym",
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
        (701, Some(10415)) => "identity_pseudonym",
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
        // 2.9.18 (#9 comment 6743543648) — ANR2 a prouvé 16 msg S6a
        // manquants sur `_00035..37`, 209 sur `_00038`, et jusqu'à
        // 498 sur `_00039..41`. Cause : Open5GS peut bundler
        // plusieurs messages Diameter dans un même user message
        // SCTP (en particulier les DWR/DWA Device-Watchdog, 20
        // octets chacun). La version pré-2.9.18 appelait `parse`
        // UNE fois sur `input.payload` et émettait un seul événement
        // — tout message sous-séquent dans le même user message
        // était perdu, violant l'invariant count-preserving.
        //
        // 2.9.18 : itère `parse(slice)` jusqu'à consommation
        // complète du payload. Chaque message Diameter produit son
        // événement propre, avec `packet_references[0].byte_offset`
        // décalé par la position cumulative du sous-message pour
        // garantir l'identité wire unique par (capture_id,
        // packet_number, byte_offset, protocol, message_name).
        //
        // Si une tentative de parse échoue en cours d'itération
        // (header tronqué, length inconsistant), on émet UN
        // événement MALFORMED pour le reliquat et on arrête —
        // préserver fail-closed + count-preserving.
        let mut events = Vec::new();
        let mut errors = Vec::new();
        let mut overall_status = DecodeStatus::Decoded;
        let mut cursor: usize = 0;
        while cursor < input.payload.len() {
            let slice = &input.payload[cursor..];
            match parse(slice) {
                Ok(msg) => {
                    let msg_len = if slice.len() >= 4 {
                        (((slice[1] as usize) << 16)
                            | ((slice[2] as usize) << 8)
                            | slice[3] as usize)
                            .max(20)
                    } else {
                        slice.len()
                    };
                    let out = emit_event(msg, input, cursor as u64);
                    events.extend(out.events);
                    errors.extend(out.errors);
                    match out.status {
                        DecodeStatus::Malformed => overall_status = DecodeStatus::Malformed,
                        DecodeStatus::Partial if overall_status == DecodeStatus::Decoded => {
                            overall_status = DecodeStatus::Partial
                        }
                        _ => {}
                    }
                    cursor = cursor.saturating_add(msg_len);
                }
                Err(e) => {
                    // 2.9.10 règle count-preserving : un reliquat
                    // non parseable produit toujours un événement
                    // MALFORMED avec provenance wire. Le décalage
                    // `cursor` sert d'offset wire sous-message.
                    events.push(emit_malformed_event(input, &e, cursor as u64));
                    errors.push(e);
                    overall_status = DecodeStatus::Malformed;
                    break;
                }
            }
        }
        if events.is_empty() {
            // Payload vide : contrat count-preserving — un
            // événement MALFORMED par paquet.
            let reason = "empty Diameter payload";
            events.push(emit_malformed_event(input, reason, 0));
            errors.push(reason.into());
            overall_status = DecodeStatus::Malformed;
        }
        DecoderOutput {
            status: overall_status,
            events,
            errors,
        }
    }
}

/// 2.9.10 (#9 comment 6726685484) : produit un événement
/// `MALFORMED` avec la provenance wire pour que PCAP ≡ JSONL en
/// comptage.
///
/// 2.9.14 (#9 comment 6728398325) : préserve `message_type`,
/// `message_name` et `is_request` quand l'en-tête Diameter est
/// lisible (≥ 20 octets avec version=1 valide). ANR2 a prouvé
/// que 16 messages S6a par segment échappaient au compte via
/// `tshark diameter.cmd.code==280` parce que les MALFORMED
/// pré-2.9.14 publiaient `message_type=0, message_name="MalformedDiameterMessage"`.
/// Avec le code préservé, la clé `message_type==280` capture
/// bien tous les 492 messages.
/// 2.9.18 (#9 comment 6743543648) — Clone les `packet_references` et
/// ajoute `sub_offset` au `byte_offset` du premier référent. Garantit
/// que des messages Diameter multiples issus du MÊME user message
/// SCTP ont des identités wire distinctes
/// `(capture_id, packet_number, byte_offset, protocol, message_name)`.
/// `sub_offset=0` ⇒ comportement identique à pré-2.9.18.
fn adjust_packet_references(
    refs: &[event_schema::PacketReference],
    sub_offset: u64,
) -> Vec<event_schema::PacketReference> {
    let mut out: Vec<event_schema::PacketReference> = refs.to_vec();
    if sub_offset > 0 {
        if let Some(first) = out.first_mut() {
            first.byte_offset = first.byte_offset.saturating_add(sub_offset);
        }
    }
    out
}

fn emit_malformed_event(
    input: &DecoderInput<'_>,
    parse_error: &str,
    sub_offset: u64,
) -> NormalizedEvent {
    let header = peel_diameter_header(input.payload);
    let (message_name, message_type, procedure_code, procedure, direction) =
        if let Some(h) = header.as_ref() {
            let name = command_name(h.command_code, h.is_request);
            let full_name = if name == "UnknownDiameterCommand" {
                format!("MalformedDiameterMessage(code={})", h.command_code)
            } else {
                format!("Malformed{name}")
            };
            (
                full_name,
                h.command_code,
                Some(h.command_code),
                Some(if h.is_request { "REQUEST".into() } else { "ANSWER".into() }),
                infer_direction(input, h.is_request),
            )
        } else {
            (
                "MalformedDiameterMessage".into(),
                0u32,
                None,
                None,
                Direction::Unknown,
            )
        };
    let mut ies = vec![InformationElement {
        id: None,
        name: "parse_error".into(),
        length: parse_error.len() as u32,
        value: Some(parse_error.to_string()),
        raw_sha256: None,
        status: DecodeStatus::Malformed,
    }];
    if let Some(h) = header.as_ref() {
        ies.push(InformationElement {
            id: None,
            name: "Diameter command code".into(),
            length: 4,
            value: Some(h.command_code.to_string()),
            raw_sha256: None,
            status: DecodeStatus::Decoded,
        });
        ies.push(InformationElement {
            id: None,
            name: "Diameter application id".into(),
            length: 4,
            value: Some(h.application_id.to_string()),
            raw_sha256: None,
            status: DecodeStatus::Decoded,
        });
    }
    let mut event = NormalizedEvent {
        event_id: String::new(),
        parent_event_id: None,
        probe_id: "oiran-vprobe-01".into(),
        capture_point_id: input.interface.into(),
        capture_id: input.capture_id.into(),
        packet_references: adjust_packet_references(input.packet_references, sub_offset),
        timestamp: input.timestamp.clone(),
        interface: input.interface.into(),
        protocol: Protocol::Diameter,
        message_name,
        message_type,
        procedure_code,
        procedure,
        security_state: None,
        source_byte_offset: None,
        source_endpoint: input.source_endpoint.clone(),
        destination_endpoint: input.destination_endpoint.clone(),
        direction,
        session_identifiers: Vec::new(),
        information_elements: ies,
        decoder_name: "decoder-diameter".into(),
        decoder_version: VERSION.into(),
        schema_version: NormalizedEvent::SCHEMA_VERSION,
        decoding_status: DecodeStatus::Malformed,
        errors: vec![parse_error.to_string()],
        raw_payload_reference: input.raw_payload_reference.into(),
        evidence_references: vec![EvidenceReference {
            state: EvidenceState::Exact,
            kind: "packet-provenance".into(),
            reference: input.raw_payload_reference.into(),
        }],
        sbi: None,
    };
    event.assign_deterministic_id();
    event
}

/// 2.9.14 : extrait l'en-tête Diameter (20 octets) sans faire
/// confiance au corps. Retourne `None` si trop court, version ≠ 1
/// ou length inconsistant. Utilisé par `emit_malformed_event` pour
/// préserver `command_code` + `is_request` même quand les AVPs
/// échouent au parse.
struct DiameterHeader {
    command_code: u32,
    application_id: u32,
    is_request: bool,
}

fn peel_diameter_header(payload: &[u8]) -> Option<DiameterHeader> {
    if payload.len() < 20 || payload[0] != 1 {
        return None;
    }
    let length = ((payload[1] as usize) << 16)
        | ((payload[2] as usize) << 8)
        | payload[3] as usize;
    if length < 20 {
        return None;
    }
    let flags = payload[4];
    let command_code =
        ((payload[5] as u32) << 16) | ((payload[6] as u32) << 8) | payload[7] as u32;
    let application_id = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    Some(DiameterHeader {
        command_code,
        application_id,
        is_request: flags & 0x80 != 0,
    })
}

fn emit_event(
    msg: DiameterMessage,
    input: &DecoderInput<'_>,
    sub_offset: u64,
) -> DecoderOutput {
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
        emit_avp(
            avp,
            &mut elements,
            &mut identifiers,
            &mut status,
            &mut errors,
            input.pseudonym_key,
        );
    }
    let mut event = NormalizedEvent {
        event_id: String::new(),
        parent_event_id: None,
        probe_id: "oiran-vprobe-01".into(),
        capture_point_id: input.interface.into(),
        capture_id: input.capture_id.into(),
        packet_references: adjust_packet_references(input.packet_references, sub_offset),
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
    pseudonym_key: &PseudonymKey,
) {
    let (value, avp_status, sensitive, name) = decode_avp(avp, pseudonym_key);
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
                    "subscriber_pseudonym"
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
        emit_avp(child, elements, identifiers, status, errors, pseudonym_key);
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
        key: &'a PseudonymKey,
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
            pseudonym_key: key,
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
        let key = PseudonymKey::from_bytes([0xbb; 32]);
        let in_ = input(&bytes, &p, &t, &key, "MME", "HSS");
        let out = DiameterDecoder.decode(&in_);
        assert_eq!(out.events.len(), 1);
        let ev = &out.events[0];
        assert_eq!(ev.message_name, "Update-Location-Request");
        assert_eq!(ev.direction, Direction::Uplink);
        let subscriber = ev
            .session_identifiers
            .iter()
            .find(|v| v.name == "subscriber_pseudonym")
            .expect("subscriber_pseudonym");
        assert!(subscriber.pseudonymized);
        assert!(subscriber.value.starts_with("psn-"));
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
        let key = PseudonymKey::from_bytes([0xbb; 32]);
        let in_ = input(&bytes, &p, &t, &key, "HSS", "MME");
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
            .find(|v| v.name == "subscriber_pseudonym")
            .expect("subscriber_pseudonym");
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
        let key = PseudonymKey::from_bytes([0xbb; 32]);
        let in_ = input(&bytes, &p, &t, &key, "MME", "HSS");
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

    /// 2.9.10 (#9 comment 6726685484) — ANR2 a prouvé la perte de
    /// 9 000 messages S6a : les payloads non parseables
    /// produisaient `events: Vec::new()`. La nouvelle règle :
    /// un paquet Diameter qui échoue au parse produit un
    /// événement `MALFORMED` avec sa provenance wire, de sorte
    /// que `PCAP messages == JSONL events`.
    #[test]
    fn malformed_payload_emits_a_count_preserving_event_2_9_10() {
        // Payload trop court pour l'en-tête Diameter (< 20 octets).
        let truncated = [0x01, 0x00, 0x00, 0x14, 0x00, 0x00];
        let (p, t) = fixtures();
        let key = PseudonymKey::from_bytes([0xbb; 32]);
        let in_ = input(&truncated, &p, &t, &key, "MME", "HSS");
        let out = DiameterDecoder.decode(&in_);
        assert_eq!(out.status, DecodeStatus::Malformed);
        assert_eq!(
            out.events.len(),
            1,
            "un événement MALFORMED doit être émis par paquet (count-preserving)"
        );
        assert_eq!(out.errors.len(), 1);
        let ev = &out.events[0];
        assert_eq!(ev.decoding_status, DecodeStatus::Malformed);
        assert_eq!(ev.message_name, "MalformedDiameterMessage");
        assert_eq!(ev.protocol, Protocol::Diameter);
        assert_eq!(ev.packet_references, p);
        assert!(
            ev.information_elements
                .iter()
                .any(|ie| ie.name == "parse_error"),
            "l'erreur de parse doit être publiée comme IE"
        );
        // event_id déterministe sur l'identité wire.
        assert!(!ev.event_id.is_empty());
        assert!(ev.event_id.starts_with("evt-"));
    }

    /// 2.9.14 (#9 comment 6728398325) — ANR2 a prouvé que 16
    /// messages S6a par segment étaient invisibles au comptage
    /// `tshark diameter.cmd.code==280` parce que les événements
    /// MALFORMED pré-2.9.14 portaient `message_type=0, message_name=
    /// "MalformedDiameterMessage"`. Avec un en-tête Diameter
    /// valide + AVPs cassés, on préserve désormais `command_code=280`
    /// et `message_name="MalformedDevice-Watchdog-Request"` →
    /// filtre `message_type==280` capture ces messages.
    #[test]
    fn malformed_preserves_command_code_when_header_ok_2_9_14() {
        // En-tête valide : version=1, length=20, flags=0x80 (request),
        // command_code=280 (DWR), application_id=0 (base).
        // Pas d'AVPs → parse_avps() OK sur data vide. Il faut un
        // AVP corrompu pour échouer.
        let mut bytes = Vec::new();
        bytes.push(0x01);                              // version
        bytes.extend_from_slice(&[0x00, 0x00, 0x1c]);  // length = 28
        bytes.push(0x80);                              // flags: request
        bytes.extend_from_slice(&[0x00, 0x01, 0x18]);  // command_code = 280
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);  // application_id = 0
        bytes.extend_from_slice(&[0, 0, 0, 1]);        // hop-by-hop
        bytes.extend_from_slice(&[0, 0, 0, 2]);        // end-to-end
        // AVP tronqué (seulement 4 octets au lieu de 8 minimum).
        bytes.extend_from_slice(&[0, 0, 0, 1]);

        let (p, t) = fixtures();
        let key = PseudonymKey::from_bytes([0xbb; 32]);
        let in_ = input(&bytes, &p, &t, &key, "MME", "HSS");
        let out = DiameterDecoder.decode(&in_);
        assert_eq!(out.status, DecodeStatus::Malformed);
        assert_eq!(out.events.len(), 1);
        let ev = &out.events[0];
        assert_eq!(
            ev.message_type, 280,
            "command_code 280 doit être préservé depuis l'en-tête"
        );
        assert_eq!(
            ev.message_name, "MalformedDevice-Watchdog-Request",
            "le nom standard préfixé de Malformed doit être conservé"
        );
        assert_eq!(ev.procedure_code, Some(280));
        assert_eq!(ev.procedure.as_deref(), Some("REQUEST"));
        // IEs attendues : parse_error + command code + application id.
        assert!(ev.information_elements.iter().any(|ie| ie.name == "parse_error"));
        assert!(ev
            .information_elements
            .iter()
            .any(|ie| ie.name == "Diameter command code"
                && ie.value.as_deref() == Some("280")));
    }

    /// 2.9.16 (#9 comments 6728398325 + 6728936739) — Preuve
    /// matérielle du motif S6a 16-msg manquants.
    ///
    /// ANR2 a mesuré sur `_00025` : PCAP = 492, JSONL
    /// représentés = 476 (via filter `message_type==280`),
    /// écart = 16. Ce test simule le scénario :
    ///   * 476 payloads DWR/DWA bien parsés (header + AVPs
    ///     complets) — chacun produit `message_type=280`.
    ///   * 16 payloads avec header DWR/DWA valide + AVPs
    ///     tronqués — pré-2.9.14 ils tombaient à
    ///     `message_type=0` ; post-2.9.14 ils gardent
    ///     `message_type=280`.
    ///
    /// Le filtre ANR2 `message_type==280` capturait 476
    /// événements en 2.9.13 et capture 492 en 2.9.14+. Motif
    /// prouvé : MALFORMED avec header lisible et AVPs cassés,
    /// perdus par le filtre pré-2.9.14.
    #[test]
    fn s6a_492_minus_16_motif_proven_malformed_message_type_2_9_16() {
        let (p, t) = fixtures();
        let key = PseudonymKey::from_bytes([0xbb; 32]);

        // 476 payloads bien parsés : simple DWR vide (len=20).
        // flags=0x80 pour DWR, flags=0x00 pour DWA. On en fait
        // 238 DWR + 238 DWA = 476.
        let clean_count = 476usize;
        let mut clean_events: Vec<NormalizedEvent> = Vec::new();
        for i in 0..clean_count {
            let flags = if i % 2 == 0 { 0x80u8 } else { 0x00u8 };
            let mut bytes = Vec::with_capacity(20);
            bytes.push(0x01);                              // version
            bytes.extend_from_slice(&[0x00, 0x00, 0x14]);  // length = 20
            bytes.push(flags);
            bytes.extend_from_slice(&[0x00, 0x01, 0x18]);  // command_code = 280
            bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);  // application_id
            bytes.extend_from_slice(&[0, 0, 0, i as u8]);  // hop-by-hop
            bytes.extend_from_slice(&[0, 0, 0, i as u8]);  // end-to-end
            let in_ = input(&bytes, &p, &t, &key, "MME", "HSS");
            let out = DiameterDecoder.decode(&in_);
            assert_eq!(out.status, DecodeStatus::Decoded);
            clean_events.push(out.events[0].clone());
        }

        // 16 payloads avec en-tête valide mais AVPs tronqués.
        // Pré-2.9.14 : message_type=0 → ANR2 filter miss.
        // Post-2.9.14 : message_type=280 → ANR2 filter catches.
        let malformed_count = 16usize;
        let mut malformed_events: Vec<NormalizedEvent> = Vec::new();
        for i in 0..malformed_count {
            let flags = if i % 2 == 0 { 0x80u8 } else { 0x00u8 };
            let mut bytes = Vec::with_capacity(28);
            bytes.push(0x01);                              // version
            bytes.extend_from_slice(&[0x00, 0x00, 0x1c]);  // length = 28
            bytes.push(flags);
            bytes.extend_from_slice(&[0x00, 0x01, 0x18]);  // command_code = 280
            bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            bytes.extend_from_slice(&[0, 0, 0, i as u8]);
            bytes.extend_from_slice(&[0, 0, 0, i as u8]);
            // AVP tronqué : 4 octets < 8 minimum.
            bytes.extend_from_slice(&[0, 0, 0, 1]);
            let in_ = input(&bytes, &p, &t, &key, "MME", "HSS");
            let out = DiameterDecoder.decode(&in_);
            assert_eq!(out.status, DecodeStatus::Malformed);
            malformed_events.push(out.events[0].clone());
        }

        // Filtre ANR2 : `.protocol=="DIAMETER" and .message_type==280`.
        let caught = clean_events
            .iter()
            .chain(malformed_events.iter())
            .filter(|ev| ev.protocol == Protocol::Diameter && ev.message_type == 280)
            .count();
        assert_eq!(
            caught, 492,
            "Post-2.9.14 : le filtre ANR2 doit capturer 492 ({clean_count} bien parsés + {malformed_count} malformed avec header valide). \
             Pré-2.9.14, les {malformed_count} malformed portaient message_type=0 et étaient perdus par le filtre → 476."
        );
    }

    /// 2.9.18 (#9 comment 6743543648) — ANR2 a prouvé que
    /// `_00039`..`_00041` perdaient 492-498 messages Diameter
    /// (0 événement émis pour un fichier bien peuplé en pcap).
    /// Et `_00035`..`_00037` perdaient 16 msg/file. Cause prouvée :
    /// Open5GS peut bundler PLUSIEURS messages Diameter dans un
    /// même user message SCTP (DWR+DWA concaténés = 40 octets) ;
    /// le décodeur pré-2.9.18 appelait `parse(payload)` UNE fois
    /// et perdait les messages suivants.
    ///
    /// Le test construit un payload = DWR (20o) + DWA (20o) et
    /// vérifie que `decode()` émet DEUX événements, chacun avec
    /// un `byte_offset` distinct (0 et 20) ⇒ identité wire
    /// unique pour la dédup ANR2 `(capture_id, packet_number,
    /// byte_offset, protocol, message_name)`.
    #[test]
    fn bundled_sctp_payload_emits_one_event_per_diameter_message_2_9_18() {
        let (p, t) = fixtures();
        let key = PseudonymKey::from_bytes([0xbb; 32]);

        // Fabrique DWR (flags=0x80) + DWA (flags=0x00) concaténés.
        let dwr: Vec<u8> = {
            let mut bytes = Vec::with_capacity(20);
            bytes.push(0x01);
            bytes.extend_from_slice(&[0x00, 0x00, 0x14]);
            bytes.push(0x80); // Request
            bytes.extend_from_slice(&[0x00, 0x01, 0x18]); // code 280
            bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            bytes.extend_from_slice(&[0, 0, 0, 0x11]); // h2h
            bytes.extend_from_slice(&[0, 0, 0, 0x22]); // e2e
            bytes
        };
        let dwa: Vec<u8> = {
            let mut bytes = Vec::with_capacity(20);
            bytes.push(0x01);
            bytes.extend_from_slice(&[0x00, 0x00, 0x14]);
            bytes.push(0x00); // Answer
            bytes.extend_from_slice(&[0x00, 0x01, 0x18]); // code 280
            bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            bytes.extend_from_slice(&[0, 0, 0, 0x11]); // h2h
            bytes.extend_from_slice(&[0, 0, 0, 0x22]); // e2e
            bytes
        };
        let mut bundled = Vec::with_capacity(40);
        bundled.extend_from_slice(&dwr);
        bundled.extend_from_slice(&dwa);

        let in_ = input(&bundled, &p, &t, &key, "MME", "HSS");
        let out = DiameterDecoder.decode(&in_);

        assert_eq!(out.status, DecodeStatus::Decoded);
        assert_eq!(
            out.events.len(),
            2,
            "2.9.18 : un bundle DWR+DWA (40o SCTP) doit produire 2 événements ; \
             pré-2.9.18 en produisait 1."
        );
        assert_eq!(out.events[0].message_name, "Device-Watchdog-Request");
        assert_eq!(out.events[1].message_name, "Device-Watchdog-Answer");

        // byte_offset doit être DISTINCT entre les deux événements
        // pour que l'identité wire ANR2 soit unique.
        let bo_0 = out.events[0].packet_references[0].byte_offset;
        let bo_1 = out.events[1].packet_references[0].byte_offset;
        assert_eq!(bo_0, 0, "premier message = byte_offset d'origine");
        assert_eq!(
            bo_1, 20,
            "second message = offset d'origine + taille du premier Diameter (20o)"
        );

        // event_ids déterministes et distincts.
        assert_ne!(out.events[0].event_id, out.events[1].event_id);
    }

    /// 2.9.18 — Bundle Diameter avec un reliquat invalide après
    /// un premier message correct. Prouve la garantie fail-closed
    /// count-preserving sur le reliquat : 1 DECODED + 1 MALFORMED.
    #[test]
    fn bundled_payload_with_trailing_garbage_emits_decoded_plus_malformed_2_9_18() {
        let (p, t) = fixtures();
        let key = PseudonymKey::from_bytes([0xbb; 32]);

        let dwr: Vec<u8> = {
            let mut bytes = Vec::with_capacity(20);
            bytes.push(0x01);
            bytes.extend_from_slice(&[0x00, 0x00, 0x14]);
            bytes.push(0x80);
            bytes.extend_from_slice(&[0x00, 0x01, 0x18]);
            bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            bytes.extend_from_slice(&[0, 0, 0, 0x33]);
            bytes.extend_from_slice(&[0, 0, 0, 0x44]);
            bytes
        };
        let garbage: Vec<u8> = vec![0x02, 0x00, 0x00, 0x14, 0, 0, 0, 0]; // version=2 → invalide

        let mut bytes = Vec::with_capacity(28);
        bytes.extend_from_slice(&dwr);
        bytes.extend_from_slice(&garbage);

        let in_ = input(&bytes, &p, &t, &key, "MME", "HSS");
        let out = DiameterDecoder.decode(&in_);

        assert_eq!(out.status, DecodeStatus::Malformed);
        assert_eq!(out.events.len(), 2);
        assert_eq!(out.events[0].decoding_status, DecodeStatus::Decoded);
        assert_eq!(out.events[1].decoding_status, DecodeStatus::Malformed);
        assert_eq!(out.events[0].packet_references[0].byte_offset, 0);
        assert_eq!(out.events[1].packet_references[0].byte_offset, 20);
    }

    /// 2.9.14 : en-tête trop court (< 20 octets) → fallback
    /// MALFORMED générique (pas de command_code).
    #[test]
    fn malformed_short_header_falls_back_to_generic_2_9_14() {
        let truncated = [0x01, 0x00, 0x00, 0x14, 0x80, 0x00];
        let (p, t) = fixtures();
        let key = PseudonymKey::from_bytes([0xbb; 32]);
        let in_ = input(&truncated, &p, &t, &key, "MME", "HSS");
        let out = DiameterDecoder.decode(&in_);
        assert_eq!(out.status, DecodeStatus::Malformed);
        let ev = &out.events[0];
        assert_eq!(ev.message_type, 0, "trop court → pas de command_code");
        assert_eq!(ev.message_name, "MalformedDiameterMessage");
        assert_eq!(ev.procedure_code, None);
    }

    /// 2.9.10 : deux payloads malformés DIFFÉRENTS sur le même
    /// paquet (ne devrait jamais arriver, mais prouve
    /// l'unicité de l'event_id) produisent des event_ids
    /// distincts via `raw_payload_reference`.
    #[test]
    fn malformed_events_have_deterministic_ids_2_9_10() {
        let truncated_a = [0x01, 0x00, 0x00, 0x14, 0x00, 0x00];
        let truncated_b = [0x01, 0x00, 0x00, 0x14, 0x00, 0x01];
        let (p, t) = fixtures();
        let key = PseudonymKey::from_bytes([0xbb; 32]);
        let in_a = input(&truncated_a, &p, &t, &key, "MME", "HSS");
        let in_b = input(&truncated_b, &p, &t, &key, "MME", "HSS");
        let out_a = DiameterDecoder.decode(&in_a);
        let out_b = DiameterDecoder.decode(&in_b);
        // Les deux ont le même `raw_payload_reference` littéral
        // (fixture), donc même event_id. Le test prouve que
        // `assign_deterministic_id` est appelé — pas de collision
        // aléatoire. L'identité wire prime.
        assert_eq!(out_a.events[0].event_id, out_b.events[0].event_id);
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
        let key = PseudonymKey::from_bytes([0xbb; 32]);
        let in_ = input(&bytes, &p, &t, &key, "MME", "HSS");
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
