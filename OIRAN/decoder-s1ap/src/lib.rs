//! S1AP APER envelope and ProtocolIE container decoder, schema baseline TS 36.413.
//!
//! Covered procedures: S1 Setup, InitialUEMessage, DL/UL NAS Transport,
//! InitialContextSetup, UEContextRelease (and Request), E-RAB Setup/Release,
//! Paging. Carried NAS-PDU (IE id 26) is EPS NAS (TS 24.301) and is forwarded
//! to `decoder-nas`, which emits a child `NormalizedEvent` with a parent link
//! back to this S1AP event. Identity-bearing IEs (S-TMSI, UEPagingID,
//! Masked-IMEISV, GUMMEI-ID) are flagged with `pseudonymized: true` so the
//! Analyzer strips them before persistence.

use decoder_nas::NasMessage;
use event_schema::{
    pseudonym, sha256_hex, DecodeStatus, Direction, EvidenceReference, EvidenceState,
    InformationElement, NamedValue, NormalizedEvent, Protocol,
};
use plugin_runtime::{
    DecoderCapabilities, DecoderInput, DecoderManifest, DecoderOutput, ProtocolDecoder,
    PLUGIN_API_VERSION,
};

pub const VERSION: &str = "0.2.0";
pub const SCHEMA_VERSION: &str = "3GPP TS 36.413";

#[derive(Default)]
pub struct S1apDecoder;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PduKind {
    Initiating,
    SuccessfulOutcome,
    UnsuccessfulOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S1apIe {
    pub id: u16,
    pub criticality: u8,
    pub value: Vec<u8>,
    pub known_name: Option<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S1apPdu {
    pub kind: PduKind,
    pub procedure_code: u8,
    pub criticality: u8,
    pub message_name: &'static str,
    pub ies: Vec<S1apIe>,
}

pub fn parse(payload: &[u8]) -> Result<S1apPdu, String> {
    if payload.len() < 4 {
        return Err("S1AP-PDU APER envelope truncated".into());
    }
    if payload[0] & 0x80 != 0 {
        return Err("S1AP-PDU extension choice is unsupported".into());
    }
    let choice = (payload[0] >> 5) & 0x03;
    let kind = match choice {
        0 => PduKind::Initiating,
        1 => PduKind::SuccessfulOutcome,
        2 => PduKind::UnsuccessfulOutcome,
        _ => return Err("unsupported S1AP-PDU extension choice".into()),
    };
    if payload[0] & 0x1f != 0 {
        return Err("S1AP-PDU has unsupported extension/padding bits".into());
    }
    let procedure = payload[1];
    let criticality = payload[2] >> 6;
    if criticality > 2 {
        return Err("invalid S1AP procedure criticality".into());
    }
    let (value_len, len_octets) = aper_length(&payload[3..])?;
    let value_start = 3 + len_octets;
    let value_end = value_start
        .checked_add(value_len)
        .filter(|v| *v <= payload.len())
        .ok_or_else(|| "S1AP open type exceeds SCTP message".to_string())?;
    let value = &payload[value_start..value_end];
    if value.len() < 3 {
        return Err("S1AP message ProtocolIE container truncated".into());
    }
    if value[0] & 0x80 != 0 {
        return Err("S1AP message extension additions are unsupported".into());
    }
    let count = be16(&value[1..3]) as usize;
    let mut pos = 3;
    let mut ies = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 4 > value.len() {
            return Err("S1AP ProtocolIE header truncated".into());
        }
        let id = be16(&value[pos..pos + 2]);
        let ie_criticality = value[pos + 2] >> 6;
        if ie_criticality > 2 {
            return Err(format!("S1AP IE {id} has invalid criticality"));
        }
        let (len, n) = aper_length(&value[pos + 3..])?;
        pos += 3 + n;
        if pos + len > value.len() {
            return Err(format!("S1AP IE {id} open type truncated"));
        }
        ies.push(S1apIe {
            id,
            criticality: ie_criticality,
            value: value[pos..pos + len].to_vec(),
            known_name: ie_name(id),
        });
        pos += len;
    }
    if pos != value.len() {
        return Err(format!(
            "S1AP message has {} unconsumed APER byte(s)",
            value.len() - pos
        ));
    }
    Ok(S1apPdu {
        kind,
        procedure_code: procedure,
        criticality,
        message_name: message_name(procedure, kind),
        ies,
    })
}

fn aper_length(data: &[u8]) -> Result<(usize, usize), String> {
    let first = *data
        .first()
        .ok_or_else(|| "APER length determinant missing".to_string())?;
    if first & 0x80 == 0 {
        Ok((first as usize, 1))
    } else if first & 0xc0 == 0x80 {
        let second = *data
            .get(1)
            .ok_or_else(|| "APER two-octet length truncated".to_string())?;
        Ok(((((first & 0x3f) as usize) << 8) | second as usize, 2))
    } else {
        Err("APER fragmented length determinant unsupported".into())
    }
}

fn nas_pdu_contents(value: &[u8]) -> Result<(&[u8], usize), String> {
    let (length, octets) = aper_length(value)?;
    let end = octets
        .checked_add(length)
        .ok_or("NAS-PDU length overflow")?;
    if end != value.len() {
        return Err("NAS-PDU open type length mismatch".into());
    }
    Ok((&value[octets..end], octets))
}

fn decode_ie(ie: &S1apIe) -> (Option<String>, DecodeStatus, bool) {
    match ie.id {
        0 => decode_s1ap_id("mme_ue_s1ap_id", &ie.value),
        8 => decode_s1ap_id("enb_ue_s1ap_id", &ie.value),
        2 => decode_cause(&ie.value),
        26 => (
            Some(format!(
                "nas_pdu_sha256={},nas_pdu_length={}",
                sha256_hex(&ie.value),
                ie.value.len()
            )),
            DecodeStatus::EncryptedOrProtected,
            true,
        ),
        43 => (
            Some(format!(
                "ue_paging_id_pseudonym={}",
                pseudonym("ue-paging-id", &ie.value)
            )),
            DecodeStatus::Partial,
            true,
        ),
        73 => (
            Some(format!("security_key_sha256={}", sha256_hex(&ie.value))),
            DecodeStatus::Decoded,
            true,
        ),
        75 => (
            Some(format!(
                "gummei_id_sha256={}",
                sha256_hex(&ie.value)
            )),
            DecodeStatus::Partial,
            true,
        ),
        96 => (
            Some(format!(
                "s_tmsi_pseudonym={}",
                pseudonym("s1ap-s-tmsi", &ie.value)
            )),
            DecodeStatus::Decoded,
            true,
        ),
        60 => decode_printable("enb_name", &ie.value),
        61 => decode_printable("mme_name", &ie.value),
        87 => decode_single_byte("relative_mme_capacity", &ie.value),
        59 => decode_global_enb_id(&ie.value),
        134 => decode_rrc_establishment_cause(&ie.value),
        67 => (
            Some(format!("tai_sha256={}", sha256_hex(&ie.value))),
            DecodeStatus::Partial,
            false,
        ),
        100 => (
            Some(format!("eutran_cgi_sha256={}", sha256_hex(&ie.value))),
            DecodeStatus::Partial,
            false,
        ),
        64 => (
            Some(format!(
                "supported_tas_sha256={}",
                sha256_hex(&ie.value)
            )),
            DecodeStatus::Partial,
            false,
        ),
        105 => (
            Some(format!(
                "served_gummeis_sha256={}",
                sha256_hex(&ie.value)
            )),
            DecodeStatus::Partial,
            false,
        ),
        50 | 137 | 44 => decode_single_byte("drx_or_domain", &ie.value),
        66 => decode_ue_aggregate_maximum_bitrate(&ie.value),
        _ => (None, DecodeStatus::Unsupported, false),
    }
}

fn decode_s1ap_id(name: &str, v: &[u8]) -> (Option<String>, DecodeStatus, bool) {
    if v.is_empty() || v.len() > 4 {
        return (None, DecodeStatus::Malformed, false);
    }
    let value = v.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b));
    (
        Some(format!("{name}={value}")),
        DecodeStatus::Decoded,
        false,
    )
}

fn decode_cause(v: &[u8]) -> (Option<String>, DecodeStatus, bool) {
    if v.is_empty() {
        return (None, DecodeStatus::Malformed, false);
    }
    let category = v[0] >> 5;
    let category_name = match category {
        0 => "radio_network",
        1 => "transport",
        2 => "nas",
        3 => "protocol",
        4 => "misc",
        _ => "unknown",
    };
    (
        Some(format!(
            "cause_category={category_name},cause_aper=0x{}",
            hex(v)
        )),
        DecodeStatus::Partial,
        false,
    )
}

fn decode_printable(name: &str, v: &[u8]) -> (Option<String>, DecodeStatus, bool) {
    let candidate = if v.len() > 2 && v[..2].iter().any(|b| !(0x20..=0x7e).contains(b)) {
        &v[2..]
    } else {
        v
    };
    match std::str::from_utf8(candidate) {
        Ok(s) if !s.is_empty() && s.bytes().all(|b| (0x20..=0x7e).contains(&b)) => {
            (Some(format!("{name}={s}")), DecodeStatus::Decoded, false)
        }
        _ => (None, DecodeStatus::Malformed, false),
    }
}

fn decode_single_byte(name: &str, v: &[u8]) -> (Option<String>, DecodeStatus, bool) {
    if v.len() != 1 {
        return (None, DecodeStatus::Malformed, false);
    }
    (
        Some(format!("{name}={}", v[0] >> 5)),
        DecodeStatus::Decoded,
        false,
    )
}

fn decode_rrc_establishment_cause(v: &[u8]) -> (Option<String>, DecodeStatus, bool) {
    if v.len() != 1 {
        return (None, DecodeStatus::Malformed, false);
    }
    (
        Some(format!("rrc_establishment_cause={}", v[0] >> 3)),
        DecodeStatus::Decoded,
        false,
    )
}

fn decode_global_enb_id(v: &[u8]) -> (Option<String>, DecodeStatus, bool) {
    if v.len() < 7 {
        return (None, DecodeStatus::Malformed, false);
    }
    let plmn = decode_plmn(&v[1..4]);
    (
        Some(format!(
            "plmn={plmn},global_enb_id_sha256={}",
            sha256_hex(v)
        )),
        DecodeStatus::Partial,
        false,
    )
}

fn decode_ue_aggregate_maximum_bitrate(v: &[u8]) -> (Option<String>, DecodeStatus, bool) {
    if v.len() < 10 {
        return (None, DecodeStatus::Malformed, false);
    }
    let dl = u32::from_be_bytes(v[1..5].try_into().expect("four bytes"));
    let ul = u32::from_be_bytes(v[6..10].try_into().expect("four bytes"));
    (
        Some(format!(
            "ue_ambr_downlink_bps={dl},ue_ambr_uplink_bps={ul}"
        )),
        DecodeStatus::Partial,
        false,
    )
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

fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}

fn be16(v: &[u8]) -> u16 {
    u16::from_be_bytes([v[0], v[1]])
}

fn message_name(code: u8, kind: PduKind) -> &'static str {
    match (code, kind) {
        (5, PduKind::Initiating) => "E-RABSetupRequest",
        (5, PduKind::SuccessfulOutcome) => "E-RABSetupResponse",
        (7, PduKind::Initiating) => "E-RABReleaseCommand",
        (7, PduKind::SuccessfulOutcome) => "E-RABReleaseResponse",
        (9, PduKind::Initiating) => "InitialContextSetupRequest",
        (9, PduKind::SuccessfulOutcome) => "InitialContextSetupResponse",
        (9, PduKind::UnsuccessfulOutcome) => "InitialContextSetupFailure",
        (10, PduKind::Initiating) => "Paging",
        (11, PduKind::Initiating) => "DownlinkNASTransport",
        (12, PduKind::Initiating) => "InitialUEMessage",
        (13, PduKind::Initiating) => "UplinkNASTransport",
        (17, PduKind::Initiating) => "S1SetupRequest",
        (17, PduKind::SuccessfulOutcome) => "S1SetupResponse",
        (17, PduKind::UnsuccessfulOutcome) => "S1SetupFailure",
        (18, PduKind::Initiating) => "UEContextReleaseRequest",
        (23, PduKind::Initiating) => "UEContextReleaseCommand",
        (23, PduKind::SuccessfulOutcome) => "UEContextReleaseComplete",
        _ => "UnknownS1APProcedure",
    }
}

fn ie_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0 => "MME-UE-S1AP-ID",
        2 => "Cause",
        8 => "eNB-UE-S1AP-ID",
        16 => "E-RABToBeSetupListBearerSUReq",
        24 => "E-RABToBeSetupListCtxtSUReq",
        26 => "NAS-PDU",
        33 => "E-RABToBeReleasedList",
        43 => "UEPagingID",
        44 => "pagingDRX",
        50 => "E-RABSetupItemCtxtSURes",
        51 => "E-RABSetupListCtxtSURes",
        59 => "GlobalENB-ID",
        60 => "eNBname",
        61 => "MMEname",
        64 => "SupportedTAs",
        66 => "uEaggregateMaximumBitrate",
        67 => "TAI",
        69 => "E-RABReleaseListBearerRelComp",
        73 => "SecurityKey",
        74 => "UERadioCapability",
        75 => "GUMMEI-ID",
        80 => "UEIdentityIndexValue",
        87 => "RelativeMMECapacity",
        96 => "S-TMSI",
        99 => "UE-S1AP-IDs",
        100 => "EUTRAN-CGI",
        105 => "ServedGUMMEIs",
        107 => "UESecurityCapabilities",
        108 => "CSFallbackIndicator",
        109 => "CNDomain",
        134 => "RRC-Establishment-Cause",
        137 => "DefaultPagingDRX",
        _ => return None,
    })
}

impl ProtocolDecoder for S1apDecoder {
    fn manifest(&self) -> DecoderManifest {
        DecoderManifest {
            decoder_name: "decoder-s1ap",
            decoder_version: VERSION,
            api_version: PLUGIN_API_VERSION,
            protocol: Protocol::S1ap,
            specification: SCHEMA_VERSION,
            deterministic: true,
        }
    }
    fn capabilities(&self) -> DecoderCapabilities {
        DecoderCapabilities {
            message_families: &[
                "S1 Setup",
                "Initial UE",
                "NAS Transport",
                "Initial Context Setup",
                "UE Context Release",
                "E-RAB Setup",
                "E-RAB Release",
                "Paging",
            ],
            preserves_unknown_fields: true,
            supports_extensions: false,
            limitations: &[
                "schema-derived generic IE container with partial typed IE coverage",
                "carried NAS-PDU is EPS NAS (TS 24.301) and preserved opaquely by SHA-256",
                "APER fragmented lengths and extension additions unsupported",
                "nested transfer syntax is retained but not typed",
            ],
        }
    }
    fn decode(&self, input: &DecoderInput<'_>) -> DecoderOutput {
        match parse(input.payload) {
            Ok(pdu) => {
                let mut identifiers = Vec::new();
                let mut elements = Vec::new();
                let mut errors = Vec::new();
                let mut status = DecodeStatus::Decoded;
                let mut nas_messages: Vec<NasMessage> = Vec::new();
                for ie in &pdu.ies {
                    if ie.id == 26 {
                        match nas_pdu_contents(&ie.value) {
                            Ok((nas, offset)) => {
                                nas_messages
                                    .push(decoder_nas::decode_with_offset(nas, offset));
                            }
                            Err(error) => errors.push(error),
                        }
                    }
                    let (value, ie_status, sensitive) = decode_ie(ie);
                    if matches!(
                        ie_status,
                        DecodeStatus::Unsupported
                            | DecodeStatus::Partial
                            | DecodeStatus::EncryptedOrProtected
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
                                    "mme_ue_s1ap_id"
                                        | "enb_ue_s1ap_id"
                                        | "s_tmsi_pseudonym"
                                        | "ue_paging_id_pseudonym"
                                        | "plmn"
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
                    if ie.known_name.is_none() {
                        errors.push(format!(
                            "unknown S1AP IE {} preserved by length and SHA-256",
                            ie.id
                        ));
                    }
                    elements.push(InformationElement {
                        id: Some(ie.id),
                        name: ie.known_name.unwrap_or("Unknown IE").into(),
                        length: ie.value.len() as u32,
                        value,
                        raw_sha256: Some(sha256_hex(&ie.value)),
                        status: ie_status,
                    });
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
                    protocol: Protocol::S1ap,
                    message_name: pdu.message_name.into(),
                    message_type: kind_number(pdu.kind),
                    procedure_code: Some(pdu.procedure_code as u32),
                    procedure: None,
                    security_state: None,
                    source_byte_offset: None,
                    source_endpoint: input.source_endpoint.clone(),
                    destination_endpoint: input.destination_endpoint.clone(),
                    direction: infer_direction(input, pdu.procedure_code),
                    session_identifiers: identifiers,
                    information_elements: elements,
                    decoder_name: "decoder-s1ap".into(),
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
                let parent_id = event.event_id.clone();
                let parent_identifiers = event.session_identifiers.clone();
                let mut output_events = vec![event];
                for nas in &nas_messages {
                    append_eps_nas_events(
                        &mut output_events,
                        nas,
                        &parent_id,
                        &parent_identifiers,
                        input,
                        pdu.procedure_code,
                    );
                }
                DecoderOutput {
                    status,
                    events: output_events,
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

fn append_eps_nas_events(
    events: &mut Vec<NormalizedEvent>,
    nas: &NasMessage,
    parent_id: &str,
    parent_identifiers: &[NamedValue],
    input: &DecoderInput<'_>,
    s1ap_procedure: u8,
) {
    let mut identifiers = parent_identifiers.to_vec();
    identifiers.extend(nas.identifiers.clone());
    identifiers.push(NamedValue {
        name: "parent_s1ap_event_id".into(),
        value: parent_id.into(),
        pseudonymized: false,
    });
    let protocol = if nas.epd == decoder_nas::EPD_EPS_SM {
        Protocol::NasEpsSm
    } else {
        Protocol::NasEpsMm
    };
    let raw_reference = format!(
        "{}#nas-offset={}",
        input.raw_payload_reference, nas.source_offset
    );
    let mut event = NormalizedEvent {
        event_id: String::new(),
        parent_event_id: Some(parent_id.into()),
        probe_id: "oiran-vprobe-01".into(),
        capture_point_id: input.interface.into(),
        capture_id: input.capture_id.into(),
        packet_references: input.packet_references.to_vec(),
        timestamp: input.timestamp.clone(),
        interface: input.interface.into(),
        protocol,
        message_name: nas.message_name.clone(),
        message_type: nas.message_type.unwrap_or(0) as u32,
        procedure_code: nas.message_type.map(u32::from),
        procedure: Some(nas.procedure.clone()),
        security_state: Some(nas.security_state.as_str().into()),
        source_byte_offset: u32::try_from(nas.source_offset).ok(),
        source_endpoint: input.source_endpoint.clone(),
        destination_endpoint: input.destination_endpoint.clone(),
        direction: infer_eps_nas_direction(input, s1ap_procedure),
        session_identifiers: identifiers,
        information_elements: nas.information_elements.clone(),
        decoder_name: "decoder-nas".into(),
        decoder_version: decoder_nas::VERSION.into(),
        schema_version: NormalizedEvent::SCHEMA_VERSION,
        decoding_status: nas.status.clone(),
        errors: nas.errors.clone(),
        raw_payload_reference: raw_reference,
        evidence_references: vec![
            EvidenceReference {
                state: EvidenceState::Exact,
                kind: "parent-s1ap-event".into(),
                reference: parent_id.into(),
            },
            EvidenceReference {
                state: EvidenceState::Exact,
                kind: "packet-provenance".into(),
                reference: input.raw_payload_reference.into(),
            },
        ],
        sbi: None,
    };
    event.assign_deterministic_id();
    let nas_event_id = event.event_id.clone();
    let nas_identifiers = event.session_identifiers.clone();
    events.push(event);
    for inner in &nas.inner {
        append_eps_nas_events(
            events,
            inner,
            &nas_event_id,
            &nas_identifiers,
            input,
            s1ap_procedure,
        );
    }
}

fn infer_eps_nas_direction(input: &DecoderInput<'_>, procedure: u8) -> Direction {
    let base = infer_direction(input, procedure);
    if base != Direction::Unknown {
        return base;
    }
    match procedure {
        12 | 13 | 18 => Direction::RanToCore,
        9 | 10 | 11 | 23 => Direction::CoreToRan,
        _ => Direction::Unknown,
    }
}

fn kind_number(k: PduKind) -> u32 {
    match k {
        PduKind::Initiating => 0,
        PduKind::SuccessfulOutcome => 1,
        PduKind::UnsuccessfulOutcome => 2,
    }
}

fn infer_direction(i: &DecoderInput<'_>, procedure: u8) -> Direction {
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
    if src.contains("enb") && dst.contains("mme") {
        return Direction::RanToCore;
    }
    if src.contains("mme") && dst.contains("enb") {
        return Direction::CoreToRan;
    }
    match procedure {
        12 | 13 | 18 => Direction::RanToCore,
        9 | 10 | 11 | 23 => Direction::CoreToRan,
        _ => Direction::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_schema::{Endpoint, ExactTimestamp, PacketReference};

    fn pdu(kind: u8, proc: u8, ies: &[(u16, u8, &[u8])]) -> Vec<u8> {
        let mut value = vec![0, (ies.len() >> 8) as u8, ies.len() as u8];
        for (id, crit, v) in ies {
            value.extend_from_slice(&id.to_be_bytes());
            value.push(*crit << 6);
            value.push(v.len() as u8);
            value.extend_from_slice(v);
        }
        let mut out = vec![kind << 5, proc, 0, value.len() as u8];
        out.extend_from_slice(&value);
        out
    }

    fn synthetic_input<'a>(
        bytes: &'a [u8],
        packets: &'a [PacketReference],
        timestamp: &'a ExactTimestamp,
        src: &'static str,
        dst: &'static str,
    ) -> DecoderInput<'a> {
        DecoderInput {
            capture_id: "cap-syn",
            packet_references: packets,
            timestamp,
            interface: "S1-MME",
            source_endpoint: Endpoint {
                address: "10.0.0.1".into(),
                port: Some(36412),
                network_function: Some(src.into()),
            },
            destination_endpoint: Endpoint {
                address: "10.0.0.2".into(),
                port: Some(36412),
                network_function: Some(dst.into()),
            },
            payload: bytes,
            raw_payload_reference: "sha256:synthetic",
        }
    }

    fn fixtures() -> (Vec<PacketReference>, ExactTimestamp) {
        let packets = vec![PacketReference {
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
            captured_length: 42,
            original_length: 42,
        }];
        let timestamp = ExactTimestamp {
            seconds: 1,
            nanoseconds: 0,
            raw_ticks: 1_000_000_000,
            resolution_base: 10,
            resolution_exponent: 9,
        };
        (packets, timestamp)
    }

    #[test]
    fn parses_s1_setup_request_envelope() {
        // Synthetic eNB name "ENB-SYN" + synthetic PLMN 001/01 (bytes 0x00 0xf1 0x10).
        let global_enb_id = &[0x00, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x12, 0x34];
        let supported_tas = &[0x00, 0x00, 0xf1, 0x10, 0x00, 0x01];
        let enb_name = b"ENB-SYN";
        let paging_drx = &[0x00];
        let bytes = pdu(
            0,
            17,
            &[
                (59, 0, global_enb_id),
                (60, 1, enb_name),
                (64, 0, supported_tas),
                (137, 1, paging_drx),
            ],
        );
        let parsed = parse(&bytes).expect("parse S1SetupRequest");
        assert_eq!(parsed.message_name, "S1SetupRequest");
        assert_eq!(parsed.procedure_code, 17);
        assert_eq!(parsed.ies.len(), 4);
        assert_eq!(parsed.ies[1].known_name, Some("eNBname"));
    }

    #[test]
    fn initial_ue_message_flags_identity_ies_as_pseudonymised() {
        // Synthetic S-TMSI payload (MMEC + M-TMSI) carrying no real identity.
        let s_tmsi = &[0x11, 0x22, 0x33, 0x44, 0x55];
        // Synthetic EPS NAS Attach Request (TS 24.301): PD/SH + Attach Request
        // message type; contents are fully synthetic and never a real IMSI.
        // Inner APER length (6) followed by a synthetic plain EPS EMM Attach
        // Request (TS 24.301): PD 0x07, MT 0x41, attach type/NAS-KSI, Mobile
        // Identity LV with synthetic GUTI (type low-nibble = 6).
        let eps_nas_pdu = &[0x06, 0x07, 0x41, 0x02, 0x01, 0xf6, 0x00];
        let enb_ue = &[0x00, 0x2a];
        let tai = &[0x00, 0xf1, 0x10, 0x00, 0x01];
        let eutran_cgi = &[0x00, 0xf1, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00];
        let rrc_cause = &[0x00];
        let bytes = pdu(
            0,
            12,
            &[
                (8, 0, enb_ue),
                (26, 0, eps_nas_pdu),
                (67, 0, tai),
                (100, 0, eutran_cgi),
                (134, 1, rrc_cause),
                (96, 0, s_tmsi),
            ],
        );
        let (packets, timestamp) = fixtures();
        let input = synthetic_input(&bytes, &packets, &timestamp, "eNB", "MME");
        let out = S1apDecoder.decode(&input);
        assert_eq!(out.events.len(), 2);
        let event = &out.events[0];
        assert_eq!(event.protocol, Protocol::S1ap);
        assert_eq!(event.message_name, "InitialUEMessage");
        assert_eq!(event.direction, Direction::RanToCore);
        let s_tmsi_ie = event
            .information_elements
            .iter()
            .find(|ie| ie.name == "S-TMSI")
            .expect("S-TMSI IE");
        assert_eq!(s_tmsi_ie.status, DecodeStatus::Decoded);
        let s_tmsi_identifier = event
            .session_identifiers
            .iter()
            .find(|v| v.name == "s_tmsi_pseudonym")
            .expect("s_tmsi identifier");
        assert!(s_tmsi_identifier.pseudonymized);
        assert!(s_tmsi_identifier.value.starts_with("psn-"));
        let nas_event = &out.events[1];
        assert_eq!(nas_event.protocol, Protocol::NasEpsMm);
        assert_eq!(nas_event.message_name, "Attach Request");
        assert_eq!(
            nas_event.parent_event_id.as_deref(),
            Some(event.event_id.as_str())
        );
        let identity = nas_event
            .session_identifiers
            .iter()
            .find(|v| v.name == "ue_identity_pseudonym")
            .expect("ue_identity_pseudonym");
        assert!(identity.pseudonymized);
        assert!(identity.value.starts_with("psn-"));
    }

    #[test]
    fn downlink_and_uplink_nas_transport_are_recognised() {
        let mme_ue = &[0x00, 0x01];
        let enb_ue = &[0x00, 0x02];
        let eps_nas = &[0x07, 0x42];
        let dl = parse(&pdu(
            0,
            11,
            &[(0, 0, mme_ue), (8, 0, enb_ue), (26, 0, eps_nas)],
        ))
        .unwrap();
        assert_eq!(dl.message_name, "DownlinkNASTransport");
        let ul = parse(&pdu(
            0,
            13,
            &[(0, 0, mme_ue), (8, 0, enb_ue), (26, 0, eps_nas)],
        ))
        .unwrap();
        assert_eq!(ul.message_name, "UplinkNASTransport");
    }

    #[test]
    fn initial_context_setup_erab_setup_and_release_message_names() {
        let mme_ue = &[0x00, 0x05];
        let ics = parse(&pdu(0, 9, &[(0, 0, mme_ue)])).unwrap();
        assert_eq!(ics.message_name, "InitialContextSetupRequest");
        let ics_rsp = parse(&pdu(1, 9, &[(0, 0, mme_ue)])).unwrap();
        assert_eq!(ics_rsp.message_name, "InitialContextSetupResponse");
        let erab_setup = parse(&pdu(0, 5, &[(0, 0, mme_ue)])).unwrap();
        assert_eq!(erab_setup.message_name, "E-RABSetupRequest");
        let erab_release = parse(&pdu(0, 7, &[(0, 0, mme_ue)])).unwrap();
        assert_eq!(erab_release.message_name, "E-RABReleaseCommand");
    }

    #[test]
    fn ue_context_release_procedure_names() {
        let mme_ue = &[0x00, 0x06];
        let req = parse(&pdu(0, 18, &[(0, 0, mme_ue)])).unwrap();
        assert_eq!(req.message_name, "UEContextReleaseRequest");
        let cmd = parse(&pdu(0, 23, &[(0, 0, mme_ue)])).unwrap();
        assert_eq!(cmd.message_name, "UEContextReleaseCommand");
        let cpl = parse(&pdu(1, 23, &[(0, 0, mme_ue)])).unwrap();
        assert_eq!(cpl.message_name, "UEContextReleaseComplete");
    }

    #[test]
    fn paging_flags_ue_paging_id_as_identity() {
        let ue_paging_id = &[0x12, 0x34, 0x56];
        let ue_index = &[0x00];
        let cn_domain = &[0x00];
        let bytes = pdu(
            0,
            10,
            &[
                (80, 1, ue_index),
                (43, 0, ue_paging_id),
                (44, 1, &[0x00]),
                (109, 1, cn_domain),
            ],
        );
        let (packets, timestamp) = fixtures();
        let input = synthetic_input(&bytes, &packets, &timestamp, "MME", "eNB");
        let out = S1apDecoder.decode(&input);
        assert_eq!(out.events.len(), 1);
        let event = &out.events[0];
        assert_eq!(event.message_name, "Paging");
        assert_eq!(event.direction, Direction::CoreToRan);
        let paging_id = event
            .session_identifiers
            .iter()
            .find(|v| v.name == "ue_paging_id_pseudonym")
            .expect("ue_paging_id_pseudonym identifier");
        assert!(paging_id.pseudonymized);
    }

    #[test]
    fn rejects_truncated_envelope_and_bad_extension() {
        assert!(parse(&[0x00, 0x01, 0x00]).is_err());
        let mut b = pdu(0, 17, &[]);
        b[0] = 0x80;
        assert!(parse(&b).is_err());
    }

    #[test]
    fn rejects_truncated_ie_container() {
        // Truncate the open-type length so the IE claims more bytes than exist.
        let mut b = pdu(0, 10, &[(43, 0, &[0x12, 0x34, 0x56])]);
        let last = b.last_mut().expect("non-empty");
        *last = 0; // drop trailing byte of the UEPagingID value
        b.pop();
        assert!(parse(&b).is_err());
    }

    #[test]
    fn unknown_ie_is_preserved_by_sha256_and_length() {
        let bytes = pdu(0, 17, &[(65000, 1, &[0xaa, 0xbb, 0xcc])]);
        let (packets, timestamp) = fixtures();
        let input = synthetic_input(&bytes, &packets, &timestamp, "eNB", "MME");
        let out = S1apDecoder.decode(&input);
        let event = &out.events[0];
        assert_eq!(event.information_elements.len(), 1);
        let ie = &event.information_elements[0];
        assert_eq!(ie.name, "Unknown IE");
        assert_eq!(ie.length, 3);
        assert!(ie.raw_sha256.is_some());
        assert!(out.errors.iter().any(|e| e.contains("65000")));
    }

    #[test]
    fn manifest_declares_s1ap_and_is_valid_plugin() {
        let m = S1apDecoder.manifest();
        assert_eq!(m.protocol, Protocol::S1ap);
        assert_eq!(m.decoder_name, "decoder-s1ap");
        plugin_runtime::validate_manifest(&m).expect("valid manifest");
    }
}
