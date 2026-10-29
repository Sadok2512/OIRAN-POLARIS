//! Native, bounded 5G and EPS NAS envelope and observed-message decoder.
//! Specification baseline: 3GPP TS 24.501 Release 17 (5G); TS 24.301 (EPS).

use event_schema::{pseudonym, sha256_hex, DecodeStatus, InformationElement, NamedValue};

pub const VERSION: &str = "0.3.1";
pub const SPECIFICATION: &str = "3GPP TS 24.501 Release 17 + 3GPP TS 24.301";
pub const EPD_5GMM: u8 = 0x7e;
pub const EPD_5GSM: u8 = 0x2e;
pub const EPD_EPS_MM: u8 = 0x07; // low-nibble marker in TS 24.301
pub const EPD_EPS_SM: u8 = 0x02; // low-nibble marker in TS 24.301

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityState {
    Plain,
    IntegrityProtected,
    Ciphered,
    IntegrityProtectedCiphered,
    Unknown,
}

impl SecurityState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "PLAIN",
            Self::IntegrityProtected => "INTEGRITY_PROTECTED",
            Self::Ciphered => "CIPHERED",
            Self::IntegrityProtectedCiphered => "INTEGRITY_PROTECTED_CIPHERED",
            Self::Unknown => "UNKNOWN_SECURITY_STATE",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NasMessage {
    pub epd: u8,
    pub security_header_type: u8,
    pub security_state: SecurityState,
    pub message_type: Option<u8>,
    pub message_name: String,
    pub procedure: String,
    pub pdu_session_id: Option<u8>,
    pub pti: Option<u8>,
    pub cause: Option<u8>,
    pub identifiers: Vec<NamedValue>,
    pub information_elements: Vec<InformationElement>,
    pub status: DecodeStatus,
    pub errors: Vec<String>,
    pub source_offset: usize,
    pub inner: Vec<NasMessage>,
}

pub fn decode(payload: &[u8]) -> NasMessage {
    decode_at(payload, 0, 0)
}

pub fn decode_with_offset(payload: &[u8], source_offset: usize) -> NasMessage {
    decode_at(payload, source_offset, 0)
}

fn decode_at(payload: &[u8], source_offset: usize, depth: u8) -> NasMessage {
    if depth > 4 {
        return malformed(
            payload,
            source_offset,
            "NAS container nesting limit exceeded",
        );
    }
    let Some(&epd) = payload.first() else {
        return malformed(payload, source_offset, "NAS payload is empty");
    };
    match epd {
        EPD_5GMM => decode_5gmm(payload, source_offset, depth),
        EPD_5GSM => decode_5gsm(payload, source_offset),
        _ if epd & 0x0f == EPD_EPS_MM => decode_eps_mm(payload, source_offset, depth),
        _ if epd & 0x0f == EPD_EPS_SM => decode_eps_sm(payload, source_offset),
        _ => NasMessage {
            epd,
            security_header_type: 0,
            security_state: SecurityState::Unknown,
            message_type: None,
            message_name: "Unsupported NAS protocol discriminator".into(),
            procedure: "UNKNOWN".into(),
            pdu_session_id: None,
            pti: None,
            cause: None,
            identifiers: vec![nv(
                "extended_protocol_discriminator",
                format!("0x{epd:02x}"),
            )],
            information_elements: preserved(
                payload,
                "Unsupported NAS payload",
                DecodeStatus::Unsupported,
            ),
            status: DecodeStatus::Unsupported,
            errors: vec![format!(
                "unsupported NAS extended protocol discriminator 0x{epd:02x}"
            )],
            source_offset,
            inner: Vec::new(),
        },
    }
}

fn decode_5gmm(payload: &[u8], source_offset: usize, depth: u8) -> NasMessage {
    if payload.len() < 2 {
        return malformed(payload, source_offset, "5GMM security header is truncated");
    }
    let security_header_type = payload[1] & 0x0f;
    let security_state = match security_header_type {
        0 => SecurityState::Plain,
        1 | 3 => SecurityState::IntegrityProtected,
        2 | 4 => SecurityState::IntegrityProtectedCiphered,
        _ => SecurityState::Unknown,
    };
    if security_header_type != 0 {
        if payload.len() < 7 {
            return malformed(
                payload,
                source_offset,
                "protected 5GMM envelope is truncated",
            );
        }
        let mut ies = vec![ie(
            "NAS message authentication code",
            &payload[2..6],
            None,
            DecodeStatus::Decoded,
        )];
        ies.push(ie(
            "Sequence number",
            &payload[6..7],
            Some(payload[6].to_string()),
            DecodeStatus::Decoded,
        ));
        if matches!(security_header_type, 2 | 4) {
            ies.push(ie(
                "Ciphered NAS payload",
                &payload[7..],
                None,
                DecodeStatus::EncryptedOrProtected,
            ));
            return NasMessage {
                epd: EPD_5GMM,
                security_header_type,
                security_state,
                message_type: None,
                message_name: "Protected 5GMM message".into(),
                procedure: "PROTECTED_NAS".into(),
                pdu_session_id: None,
                pti: None,
                cause: None,
                identifiers: vec![nv("security_header_type", security_header_type.to_string())],
                information_elements: ies,
                status: DecodeStatus::EncryptedOrProtected,
                errors: vec!["inner NAS payload not decoded: ciphering context and integrity verification are unavailable".into()],
                source_offset,
                inner: Vec::new(),
            };
        }
        let mut inner = decode_at(&payload[7..], source_offset + 7, depth + 1);
        inner.security_header_type = security_header_type;
        inner.security_state = security_state;
        inner.information_elements.splice(0..0, ies);
        inner.errors.push(
            "NAS integrity was not verified because no authorized security context was supplied"
                .into(),
        );
        if inner.status == DecodeStatus::Decoded {
            inner.status = DecodeStatus::Partial;
        }
        return inner;
    }
    if payload.len() < 3 {
        return malformed(payload, source_offset, "plain 5GMM header is truncated");
    }
    let mt = payload[2];
    let (name, procedure) = mm_name(mt);
    let mut msg = NasMessage {
        epd: EPD_5GMM,
        security_header_type,
        security_state,
        message_type: Some(mt),
        message_name: name.into(),
        procedure: procedure.into(),
        pdu_session_id: None,
        pti: None,
        cause: None,
        identifiers: vec![nv("extended_protocol_discriminator", "0x7e")],
        information_elements: Vec::new(),
        status: if name.starts_with("Unknown") {
            DecodeStatus::Unsupported
        } else {
            DecodeStatus::Decoded
        },
        errors: Vec::new(),
        source_offset,
        inner: Vec::new(),
    };
    parse_5gmm_body(&mut msg, payload, depth);
    msg
}

fn parse_5gmm_body(msg: &mut NasMessage, payload: &[u8], depth: u8) {
    let mt = msg.message_type.unwrap_or_default();
    match mt {
        0x41 => {
            if payload.len() < 6 {
                return mark_truncated(msg, "Registration Request mandatory fields");
            }
            msg.information_elements.push(ie(
                "5GS registration type / ngKSI",
                &payload[3..4],
                Some(format!(
                    "registration_type={},ngksi={}",
                    payload[3] & 0x07,
                    payload[3] >> 4
                )),
                DecodeStatus::Decoded,
            ));
            let len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
            if 6 + len > payload.len() {
                return mark_truncated(msg, "5GS mobile identity");
            }
            msg.information_elements.push(ie(
                "5GS mobile identity",
                &payload[6..6 + len],
                Some(format!(
                    "pseudonym={}",
                    pseudonym("nas-5gs-mobile-identity", &payload[6..6 + len])
                )),
                DecodeStatus::Decoded,
            ));
            msg.identifiers.push(NamedValue {
                name: "ue_identity_pseudonym".into(),
                value: pseudonym("nas-5gs-mobile-identity", &payload[6..6 + len]),
                pseudonymized: true,
            });
            parse_optional_tlvs(msg, &payload[6 + len..], 6 + len);
        }
        0x44 | 0x4e | 0x59 => {
            if payload.len() < 4 {
                return mark_truncated(msg, "mandatory 5GMM cause");
            }
            msg.cause = Some(payload[3]);
            msg.identifiers
                .push(nv("5gmm_cause", payload[3].to_string()));
            msg.information_elements.push(ie(
                "5GMM cause",
                &payload[3..4],
                Some(payload[3].to_string()),
                DecodeStatus::Decoded,
            ));
            parse_optional_tlvs(msg, &payload[4..], 4);
        }
        0x56 => {
            if payload.len() < 5 {
                return mark_truncated(msg, "Authentication Request mandatory fields");
            }
            msg.information_elements.push(ie(
                "ngKSI",
                &payload[3..4],
                Some((payload[3] & 0x07).to_string()),
                DecodeStatus::Decoded,
            ));
            let len = payload[4] as usize;
            if 5 + len > payload.len() {
                return mark_truncated(msg, "ABBA");
            }
            msg.information_elements.push(ie(
                "ABBA",
                &payload[5..5 + len],
                None,
                DecodeStatus::Decoded,
            ));
            parse_optional_tlvs(msg, &payload[5 + len..], 5 + len);
        }
        0x5d => {
            // TS 24.501 §8.2.25 Security Mode Command: mandatory fields are
            // Selected NAS security algorithms (V, 1), ngKSI + spare half-octet
            // (V, 1) and Replayed UE security capabilities (LV, 3-9).
            if payload.len() < 6 {
                return mark_truncated(msg, "Security Mode Command mandatory fields");
            }
            msg.information_elements.push(ie(
                "Selected NAS security algorithms",
                &payload[3..4],
                Some(format!(
                    "ciphering=0x{:x},integrity=0x{:x}",
                    payload[3] >> 4,
                    payload[3] & 0x0f
                )),
                DecodeStatus::Decoded,
            ));
            msg.information_elements.push(ie(
                "ngKSI",
                &payload[4..5],
                Some((payload[4] & 0x07).to_string()),
                DecodeStatus::Decoded,
            ));
            let replayed_len = payload[5] as usize;
            if 6 + replayed_len > payload.len() {
                return mark_truncated(msg, "Replayed UE security capabilities");
            }
            msg.information_elements.push(ie(
                "Replayed UE security capabilities",
                &payload[6..6 + replayed_len],
                decode_ue_security_capability(&payload[6..6 + replayed_len]),
                DecodeStatus::Decoded,
            ));
            parse_optional_tlvs(msg, &payload[6 + replayed_len..], 6 + replayed_len);
        }
        0x57 | 0x5e | 0x5f | 0x42 | 0x43 | 0x45 | 0x46 | 0x47 | 0x48 | 0x4c | 0x4d
        | 0x54 | 0x55 | 0x5b | 0x5c => parse_optional_tlvs(msg, &payload[3..], 3),
        0x67 | 0x68 => {
            if payload.len() < 6 {
                return mark_truncated(msg, "NAS transport payload container header");
            }
            let container_type = payload[3] & 0x0f;
            let len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
            if 6 + len > payload.len() {
                return mark_truncated(msg, "NAS transport payload container");
            }
            msg.information_elements.push(ie(
                "Payload container type",
                &payload[3..4],
                Some(container_type.to_string()),
                DecodeStatus::Decoded,
            ));
            msg.information_elements.push(ie(
                "Payload container",
                &payload[6..6 + len],
                None,
                DecodeStatus::Decoded,
            ));
            if container_type == 1 {
                msg.inner.push(decode_at(
                    &payload[6..6 + len],
                    msg.source_offset + 6,
                    depth + 1,
                ));
            }
            parse_optional_tlvs(msg, &payload[6 + len..], 6 + len);
        }
        _ => {
            if payload.len() > 3 {
                msg.information_elements.extend(preserved(
                    &payload[3..],
                    "Unparsed 5GMM body",
                    DecodeStatus::Unsupported,
                ));
                if msg.status == DecodeStatus::Decoded {
                    msg.status = DecodeStatus::Partial;
                }
            }
        }
    }
}

fn decode_5gsm(payload: &[u8], source_offset: usize) -> NasMessage {
    if payload.len() < 4 {
        return malformed(payload, source_offset, "5GSM header is truncated");
    }
    let pdu = payload[1];
    let pti = payload[2];
    let mt = payload[3];
    let (name, procedure) = sm_name(mt);
    let mut msg = NasMessage {
        epd: EPD_5GSM,
        security_header_type: 0,
        security_state: SecurityState::Plain,
        message_type: Some(mt),
        message_name: name.into(),
        procedure: procedure.into(),
        pdu_session_id: Some(pdu),
        pti: Some(pti),
        cause: None,
        identifiers: vec![
            nv("pdu_session_id", pdu.to_string()),
            nv("pti", pti.to_string()),
        ],
        information_elements: Vec::new(),
        status: if name.starts_with("Unknown") {
            DecodeStatus::Unsupported
        } else {
            DecodeStatus::Decoded
        },
        errors: Vec::new(),
        source_offset,
        inner: Vec::new(),
    };
    match mt {
        0xc1 => {
            if payload.len() < 6 {
                mark_truncated(&mut msg, "PDU Session Establishment Request integrity rate");
                return msg;
            }
            msg.information_elements.push(ie(
                "Integrity protection maximum data rate",
                &payload[4..6],
                None,
                DecodeStatus::Decoded,
            ));
            parse_optional_tlvs(&mut msg, &payload[6..], 6);
        }
        0xc2 => {
            if payload.len() < 7 {
                mark_truncated(
                    &mut msg,
                    "PDU Session Establishment Accept mandatory fields",
                );
                return msg;
            }
            msg.information_elements.push(ie(
                "Selected SSC mode / PDU session type",
                &payload[4..5],
                Some(format!(
                    "ssc_mode={},pdu_session_type={}",
                    (payload[4] >> 4) & 0x07,
                    payload[4] & 0x07
                )),
                DecodeStatus::Decoded,
            ));
            let qos_len = u16::from_be_bytes([payload[5], payload[6]]) as usize;
            if 7 + qos_len > payload.len() {
                mark_truncated(&mut msg, "Authorized QoS rules");
                return msg;
            }
            msg.information_elements.push(ie(
                "Authorized QoS rules",
                &payload[7..7 + qos_len],
                None,
                DecodeStatus::Partial,
            ));
            parse_optional_tlvs(&mut msg, &payload[7 + qos_len..], 7 + qos_len);
        }
        0xc3 | 0xc7 | 0xcb | 0xd2 | 0xd4 | 0xd6 => {
            if payload.len() < 5 {
                mark_truncated(&mut msg, "mandatory 5GSM cause");
                return msg;
            }
            msg.cause = Some(payload[4]);
            msg.identifiers
                .push(nv("5gsm_cause", payload[4].to_string()));
            msg.information_elements.push(ie(
                "5GSM cause",
                &payload[4..5],
                Some(payload[4].to_string()),
                DecodeStatus::Decoded,
            ));
            parse_optional_tlvs(&mut msg, &payload[5..], 5);
        }
        _ => parse_optional_tlvs(&mut msg, &payload[4..], 4),
    }
    msg
}

fn parse_optional_tlvs(msg: &mut NasMessage, bytes: &[u8], base: usize) {
    let mut pos = 0usize;
    while pos < bytes.len() {
        let octet = bytes[pos];
        if octet & 0x80 != 0 {
            msg.information_elements.push(ie(
                &format!("Type 1 IEI 0x{:x}", octet >> 4),
                &bytes[pos..pos + 1],
                Some((octet & 0x0f).to_string()),
                DecodeStatus::Decoded,
            ));
            pos += 1;
            continue;
        }
        // Type 3 RAND has a one-octet IEI and a fixed 16-octet value.
        if octet == 0x21 {
            if pos + 17 > bytes.len() {
                mark_truncated(msg, "RAND");
                return;
            }
            msg.information_elements.push(InformationElement {
                id: Some(0x21),
                name: "RAND".into(),
                length: 16,
                value: None,
                raw_sha256: Some(sha256_hex(&bytes[pos + 1..pos + 17])),
                status: DecodeStatus::Decoded,
            });
            pos += 17;
            continue;
        }
        if pos + 2 > bytes.len() {
            mark_truncated(msg, &format!("optional IE header at offset {}", base + pos));
            return;
        }
        let iei = octet;
        let (header, len) = if matches!(iei, 0x7b | 0x78 | 0x79) {
            if pos + 3 > bytes.len() {
                mark_truncated(msg, "TLV-E length");
                return;
            }
            (
                3usize,
                u16::from_be_bytes([bytes[pos + 1], bytes[pos + 2]]) as usize,
            )
        } else {
            (2usize, bytes[pos + 1] as usize)
        };
        if pos + header + len > bytes.len() {
            mark_truncated(msg, &format!("optional IE 0x{iei:02x}"));
            return;
        }
        let value = &bytes[pos + header..pos + header + len];
        let (name, decoded, status) = match iei {
            0x25 => ("DNN", decode_dnn(value), DecodeStatus::Decoded),
            0x22 => ("S-NSSAI", decode_snssai(value), DecodeStatus::Decoded),
            0x59 => (
                "5GSM cause",
                value.first().map(u8::to_string),
                DecodeStatus::Decoded,
            ),
            0x29 => (
                "PDU address",
                decode_pdu_address(value),
                DecodeStatus::Partial,
            ),
            0x2a => ("Session AMBR", None, DecodeStatus::Partial),
            0x2e => (
                "UE security capability",
                decode_ue_security_capability(value),
                DecodeStatus::Decoded,
            ),
            0x36 => (
                "Additional 5G security information",
                decode_additional_5g_security_information(value),
                DecodeStatus::Decoded,
            ),
            0x21 => ("RAND", None, DecodeStatus::Decoded),
            0x20 => ("AUTN", None, DecodeStatus::Decoded),
            0x2d => (
                "Authentication response parameter",
                None,
                DecodeStatus::Decoded,
            ),
            0x30 => (
                "Authentication failure parameter",
                None,
                DecodeStatus::Decoded,
            ),
            _ => ("Unknown optional IE", None, DecodeStatus::Unsupported),
        };
        if iei == 0x25 {
            if let Some(ref dnn) = decoded {
                msg.identifiers.push(nv("dnn", dnn.clone()));
            }
        }
        if iei == 0x59 && msg.cause.is_none() {
            msg.cause = value.first().copied();
            if let Some(cause) = msg.cause {
                msg.identifiers.push(nv("5gsm_cause", cause.to_string()));
            }
        }
        if iei == 0x22 {
            if let Some(ref snssai) = decoded {
                msg.identifiers.push(nv("s_nssai", snssai.clone()));
            }
        }
        msg.information_elements.push(InformationElement {
            id: Some(iei as u16),
            name: name.into(),
            length: value.len() as u32,
            value: decoded,
            raw_sha256: Some(sha256_hex(value)),
            status: status.clone(),
        });
        if status == DecodeStatus::Unsupported && msg.status == DecodeStatus::Decoded {
            msg.status = DecodeStatus::Partial;
        }
        pos += header + len;
    }
}

fn decode_dnn(value: &[u8]) -> Option<String> {
    let mut pos = 0usize;
    let mut labels = Vec::new();
    while pos < value.len() {
        let len = *value.get(pos)? as usize;
        pos += 1;
        let label = value.get(pos..pos + len)?;
        if !label
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return None;
        }
        labels.push(String::from_utf8(label.to_vec()).ok()?);
        pos += len;
    }
    Some(labels.join("."))
}

fn decode_snssai(value: &[u8]) -> Option<String> {
    match value {
        [sst] => Some(format!("sst={sst}")),
        [sst, sd @ ..] if sd.len() == 3 => Some(format!(
            "sst={sst},sd={:02x}{:02x}{:02x}",
            sd[0], sd[1], sd[2]
        )),
        _ => None,
    }
}

fn decode_pdu_address(value: &[u8]) -> Option<String> {
    match value {
        [kind, a, b, c, d] => Some(format!("type={},address={a}.{b}.{c}.{d}", kind & 0x07)),
        _ => None,
    }
}

/// Decode UE security capability (TS 24.501 §9.11.3.54): first two octets are the 5G
/// NR encryption/integrity algorithm bitmaps; additional pairs encode EPS algorithms.
fn decode_ue_security_capability(value: &[u8]) -> Option<String> {
    if value.len() < 2 {
        return None;
    }
    let mut parts = vec![
        format!("nr_encryption=0x{:02x}", value[0]),
        format!("nr_integrity=0x{:02x}", value[1]),
    ];
    if value.len() >= 4 {
        parts.push(format!("eutra_encryption=0x{:02x}", value[2]));
        parts.push(format!("eutra_integrity=0x{:02x}", value[3]));
    }
    Some(parts.join(","))
}

/// Decode Additional 5G security information (TS 24.501 §9.11.3.12). Single octet
/// carrying RINMR (bit 1) and HDP (bit 2); upper bits are spare.
fn decode_additional_5g_security_information(value: &[u8]) -> Option<String> {
    let byte = *value.first()?;
    Some(format!(
        "rinmr={},hdp={}",
        (byte & 0x02) >> 1,
        (byte & 0x04) >> 2
    ))
}

/// Decode EPS UE network capability (TS 24.301 §9.9.3.34). Mandatory bytes 0..=1
/// carry EEA/EIA algorithm bitmaps; additional bytes carry UMTS and GPRS capability
/// bytes which are reported only as length-preserved provenance when present.
fn decode_eps_ue_network_capability(value: &[u8]) -> Option<String> {
    if value.len() < 2 {
        return None;
    }
    let mut parts = vec![
        format!("eea=0x{:02x}", value[0]),
        format!("eia=0x{:02x}", value[1]),
    ];
    if value.len() >= 3 {
        parts.push(format!("uea=0x{:02x}", value[2]));
    }
    if value.len() >= 4 {
        parts.push(format!("uia=0x{:02x}", value[3]));
    }
    if value.len() >= 5 {
        parts.push(format!("gea=0x{:02x}", value[4]));
    }
    Some(parts.join(","))
}

fn mm_name(mt: u8) -> (&'static str, &'static str) {
    match mt {
        0x41 => ("Registration Request", "REGISTRATION"),
        0x42 => ("Registration Accept", "REGISTRATION"),
        0x43 => ("Registration Complete", "REGISTRATION"),
        0x44 => ("Registration Reject", "REGISTRATION"),
        0x45 | 0x47 => ("Deregistration Request", "DEREGISTRATION"),
        0x46 | 0x48 => ("Deregistration Accept", "DEREGISTRATION"),
        0x4c => ("Service Request", "SERVICE"),
        0x4d => ("Service Accept", "SERVICE"),
        0x4e => ("Service Reject", "SERVICE"),
        0x54 => ("Configuration Update Command", "CONFIGURATION_UPDATE"),
        0x55 => ("Configuration Update Complete", "CONFIGURATION_UPDATE"),
        0x56 => ("Authentication Request", "AUTHENTICATION"),
        0x57 => ("Authentication Response", "AUTHENTICATION"),
        0x59 => ("Authentication Failure", "AUTHENTICATION"),
        0x5b => ("Identity Request", "IDENTITY"),
        0x5c => ("Identity Response", "IDENTITY"),
        0x5d => ("Security Mode Command", "SECURITY_MODE"),
        0x5e => ("Security Mode Complete", "SECURITY_MODE"),
        0x5f => ("Security Mode Reject", "SECURITY_MODE"),
        0x67 => ("UL NAS Transport", "NAS_TRANSPORT"),
        0x68 => ("DL NAS Transport", "NAS_TRANSPORT"),
        _ => ("Unknown 5GMM message", "UNKNOWN"),
    }
}

fn sm_name(mt: u8) -> (&'static str, &'static str) {
    match mt {
        0xc1 => (
            "PDU Session Establishment Request",
            "PDU_SESSION_ESTABLISHMENT",
        ),
        0xc2 => (
            "PDU Session Establishment Accept",
            "PDU_SESSION_ESTABLISHMENT",
        ),
        0xc3 => (
            "PDU Session Establishment Reject",
            "PDU_SESSION_ESTABLISHMENT",
        ),
        0xc5 => (
            "PDU Session Authentication Command",
            "PDU_SESSION_AUTHENTICATION",
        ),
        0xc6 => (
            "PDU Session Authentication Complete",
            "PDU_SESSION_AUTHENTICATION",
        ),
        0xc7 => (
            "PDU Session Authentication Result",
            "PDU_SESSION_AUTHENTICATION",
        ),
        0xc9 => (
            "PDU Session Modification Request",
            "PDU_SESSION_MODIFICATION",
        ),
        0xca => (
            "PDU Session Modification Reject",
            "PDU_SESSION_MODIFICATION",
        ),
        0xcb => (
            "PDU Session Modification Command",
            "PDU_SESSION_MODIFICATION",
        ),
        0xcc => (
            "PDU Session Modification Complete",
            "PDU_SESSION_MODIFICATION",
        ),
        0xcd => (
            "PDU Session Modification Command Reject",
            "PDU_SESSION_MODIFICATION",
        ),
        0xd1 => ("PDU Session Release Request", "PDU_SESSION_RELEASE"),
        0xd2 => ("PDU Session Release Reject", "PDU_SESSION_RELEASE"),
        0xd3 => ("PDU Session Release Command", "PDU_SESSION_RELEASE"),
        0xd4 => ("PDU Session Release Complete", "PDU_SESSION_RELEASE"),
        0xd6 => ("5GSM Status", "PDU_SESSION_STATUS"),
        _ => ("Unknown 5GSM message", "UNKNOWN"),
    }
}

fn nv(name: &str, value: impl Into<String>) -> NamedValue {
    NamedValue {
        name: name.into(),
        value: value.into(),
        pseudonymized: false,
    }
}
fn ie(name: &str, raw: &[u8], value: Option<String>, status: DecodeStatus) -> InformationElement {
    InformationElement {
        id: None,
        name: name.into(),
        length: raw.len() as u32,
        value,
        raw_sha256: Some(sha256_hex(raw)),
        status,
    }
}
fn preserved(raw: &[u8], name: &str, status: DecodeStatus) -> Vec<InformationElement> {
    vec![ie(name, raw, None, status)]
}
fn mark_truncated(msg: &mut NasMessage, what: &str) {
    msg.status = DecodeStatus::Malformed;
    msg.errors.push(format!("truncated {what}"));
}
fn malformed(raw: &[u8], source_offset: usize, error: &str) -> NasMessage {
    NasMessage {
        epd: raw.first().copied().unwrap_or(0),
        security_header_type: 0,
        security_state: SecurityState::Unknown,
        message_type: None,
        message_name: "Malformed NAS message".into(),
        procedure: "UNKNOWN".into(),
        pdu_session_id: None,
        pti: None,
        cause: None,
        identifiers: Vec::new(),
        information_elements: preserved(raw, "Malformed NAS payload", DecodeStatus::Malformed),
        status: DecodeStatus::Malformed,
        errors: vec![error.into()],
        source_offset,
        inner: Vec::new(),
    }
}

fn decode_eps_mm(payload: &[u8], source_offset: usize, depth: u8) -> NasMessage {
    if payload.len() < 2 {
        return malformed(payload, source_offset, "EPS EMM header is truncated");
    }
    let security_header_type = payload[0] >> 4;
    let security_state = match security_header_type {
        0 => SecurityState::Plain,
        1 | 3 => SecurityState::IntegrityProtected,
        2 | 4 => SecurityState::IntegrityProtectedCiphered,
        12 => SecurityState::Plain, // Service Request short form
        _ => SecurityState::Unknown,
    };
    if security_header_type == 12 {
        // Service Request short form (TS 24.301 §9.3.1a): plain-text message.
        return NasMessage {
            epd: EPD_EPS_MM,
            security_header_type,
            security_state,
            message_type: Some(0x4e),
            message_name: "EPS Service Request".into(),
            procedure: "EPS_SERVICE_REQUEST".into(),
            pdu_session_id: None,
            pti: None,
            cause: None,
            identifiers: vec![nv("extended_protocol_discriminator", "0x07")],
            information_elements: preserved(
                payload,
                "EPS Service Request body",
                DecodeStatus::Decoded,
            ),
            status: DecodeStatus::Decoded,
            errors: Vec::new(),
            source_offset,
            inner: Vec::new(),
        };
    }
    if security_header_type != 0 {
        if payload.len() < 7 {
            return malformed(
                payload,
                source_offset,
                "protected EPS EMM envelope is truncated",
            );
        }
        let mut ies = vec![ie(
            "NAS message authentication code",
            &payload[1..5],
            None,
            DecodeStatus::Decoded,
        )];
        ies.push(ie(
            "Sequence number",
            &payload[5..6],
            Some(payload[5].to_string()),
            DecodeStatus::Decoded,
        ));
        if matches!(security_header_type, 2 | 4) {
            ies.push(ie(
                "Ciphered NAS payload",
                &payload[6..],
                None,
                DecodeStatus::EncryptedOrProtected,
            ));
            return NasMessage {
                epd: EPD_EPS_MM,
                security_header_type,
                security_state,
                message_type: None,
                message_name: "Protected EPS EMM message".into(),
                procedure: "PROTECTED_NAS".into(),
                pdu_session_id: None,
                pti: None,
                cause: None,
                identifiers: vec![nv("security_header_type", security_header_type.to_string())],
                information_elements: ies,
                status: DecodeStatus::EncryptedOrProtected,
                errors: vec!["inner EPS NAS payload not decoded: ciphering context and integrity verification are unavailable".into()],
                source_offset,
                inner: Vec::new(),
            };
        }
        let mut inner = decode_at(&payload[6..], source_offset + 6, depth + 1);
        inner.security_header_type = security_header_type;
        inner.security_state = security_state;
        inner.information_elements.splice(0..0, ies);
        inner.errors.push(
            "NAS integrity was not verified because no authorized security context was supplied"
                .into(),
        );
        if inner.status == DecodeStatus::Decoded {
            inner.status = DecodeStatus::Partial;
        }
        return inner;
    }
    // Plain EPS EMM: byte 0 = PD, byte 1 = message type.
    let mt = payload[1];
    let (name, procedure) = mm_eps_name(mt);
    let mut msg = NasMessage {
        epd: EPD_EPS_MM,
        security_header_type,
        security_state,
        message_type: Some(mt),
        message_name: name.into(),
        procedure: procedure.into(),
        pdu_session_id: None,
        pti: None,
        cause: None,
        identifiers: vec![nv("extended_protocol_discriminator", "0x07")],
        information_elements: Vec::new(),
        status: if name.starts_with("Unknown") {
            DecodeStatus::Unsupported
        } else {
            DecodeStatus::Decoded
        },
        errors: Vec::new(),
        source_offset,
        inner: Vec::new(),
    };
    parse_eps_mm_body(&mut msg, payload);
    msg
}

fn parse_eps_mm_body(msg: &mut NasMessage, payload: &[u8]) {
    // payload[0] = PD byte, payload[1] = message type.
    let body = &payload[2..];
    match msg.message_type.unwrap_or_default() {
        0x41 => {
            // Attach Request: EPS attach type/NAS-KSI (1 byte), EPS mobile identity LV.
            if body.len() < 2 {
                return mark_truncated(msg, "Attach Request mandatory fields");
            }
            msg.information_elements.push(ie(
                "EPS attach type / NAS key set identifier",
                &body[0..1],
                Some(format!(
                    "attach_type={},nas_ksi={}",
                    body[0] & 0x07,
                    body[0] >> 4
                )),
                DecodeStatus::Decoded,
            ));
            let len = body[1] as usize;
            if 2 + len > body.len() {
                return mark_truncated(msg, "EPS mobile identity");
            }
            attach_eps_mobile_identity(msg, &body[2..2 + len]);
        }
        0x48 => {
            // TAU Request: EPS update type/NAS-KSI (1 byte), old GUTI LV.
            if body.len() < 2 {
                return mark_truncated(msg, "TAU Request mandatory fields");
            }
            msg.information_elements.push(ie(
                "EPS update type / NAS key set identifier",
                &body[0..1],
                Some(format!(
                    "update_type={},nas_ksi={}",
                    body[0] & 0x07,
                    body[0] >> 4
                )),
                DecodeStatus::Decoded,
            ));
            let len = body[1] as usize;
            if 2 + len > body.len() {
                return mark_truncated(msg, "Old GUTI");
            }
            attach_eps_mobile_identity(msg, &body[2..2 + len]);
        }
        0x45 => {
            // Detach Request: Detach type (1 byte), EPS mobile identity LV.
            if body.len() < 2 {
                return mark_truncated(msg, "Detach Request mandatory fields");
            }
            msg.information_elements.push(ie(
                "Detach type / NAS key set identifier",
                &body[0..1],
                Some(format!(
                    "detach_type={},nas_ksi={}",
                    body[0] & 0x07,
                    body[0] >> 4
                )),
                DecodeStatus::Decoded,
            ));
            let len = body[1] as usize;
            if 2 + len > body.len() {
                return mark_truncated(msg, "EPS mobile identity");
            }
            attach_eps_mobile_identity(msg, &body[2..2 + len]);
        }
        0x57 => {
            // Identity Response: Mobile identity LV (variable).
            if body.is_empty() {
                return mark_truncated(msg, "Identity Response body");
            }
            let len = body[0] as usize;
            if 1 + len > body.len() {
                return mark_truncated(msg, "Mobile identity");
            }
            attach_eps_mobile_identity(msg, &body[1..1 + len]);
        }
        0x52 => {
            // Authentication Request: NAS-KSI (1), RAND (16), AUTN LV.
            if body.len() < 1 + 16 + 1 {
                return mark_truncated(msg, "Authentication Request body");
            }
            msg.information_elements.push(ie(
                "RAND",
                &body[1..17],
                Some(format!("rand_sha256={}", sha256_hex(&body[1..17]))),
                DecodeStatus::Decoded,
            ));
            let autn_len = body[17] as usize;
            if 18 + autn_len > body.len() {
                return mark_truncated(msg, "AUTN");
            }
            msg.information_elements.push(ie(
                "AUTN",
                &body[18..18 + autn_len],
                Some(format!(
                    "autn_sha256={}",
                    sha256_hex(&body[18..18 + autn_len])
                )),
                DecodeStatus::Decoded,
            ));
        }
        0x5c => {
            // TS 24.301 §8.5 Security Mode Command: Selected NAS security algorithms (V, 1),
            // NAS key set identifier + spare half octet (V, 1), Replayed UE security
            // capabilities (LV, 3-6). Optional TLVs follow at variable positions.
            if body.len() < 3 {
                return mark_truncated(msg, "EPS Security Mode Command mandatory fields");
            }
            let selected = body[0];
            msg.information_elements.push(ie(
                "Selected NAS security algorithms",
                &body[0..1],
                Some(format!(
                    "ciphering=EEA{},integrity=EIA{}",
                    (selected >> 4) & 0x07,
                    selected & 0x07
                )),
                DecodeStatus::Decoded,
            ));
            let ksi = body[1];
            msg.information_elements.push(ie(
                "NAS key set identifier",
                &body[1..2],
                Some(format!(
                    "nas_ksi={},tsc={}",
                    ksi & 0x07,
                    (ksi >> 3) & 0x01
                )),
                DecodeStatus::Decoded,
            ));
            let replayed_len = body[2] as usize;
            if 3 + replayed_len > body.len() {
                return mark_truncated(msg, "Replayed UE security capabilities");
            }
            let replayed = &body[3..3 + replayed_len];
            msg.information_elements.push(ie(
                "Replayed UE security capabilities",
                replayed,
                decode_eps_ue_network_capability(replayed),
                DecodeStatus::Decoded,
            ));
            let trailing = &body[3 + replayed_len..];
            if !trailing.is_empty() {
                msg.information_elements.push(ie(
                    "EPS Security Mode Command optional IEs",
                    trailing,
                    Some(format!("body_sha256={}", sha256_hex(trailing))),
                    DecodeStatus::Partial,
                ));
                if msg.status == DecodeStatus::Decoded {
                    msg.status = DecodeStatus::Partial;
                }
            }
        }
        _ => {
            msg.information_elements.push(ie(
                "EPS EMM body",
                body,
                Some(format!("body_sha256={}", sha256_hex(body))),
                if msg.status == DecodeStatus::Decoded {
                    DecodeStatus::Partial
                } else {
                    msg.status.clone()
                },
            ));
            if msg.status == DecodeStatus::Decoded {
                msg.status = DecodeStatus::Partial;
            }
        }
    }
}

fn attach_eps_mobile_identity(msg: &mut NasMessage, value: &[u8]) {
    let identity_type = value.first().map(|b| b & 0x07).unwrap_or(0);
    let identity_name = match identity_type {
        1 => "IMSI",
        2 => "IMEI",
        3 => "IMEISV",
        6 => "GUTI",
        _ => "Unknown EPS mobile identity",
    };
    let pseudo = pseudonym("nas-eps-mobile-identity", value);
    msg.information_elements.push(InformationElement {
        id: None,
        name: "EPS mobile identity".into(),
        length: value.len() as u32,
        value: Some(format!(
            "identity_type={identity_name},pseudonym={pseudo}"
        )),
        raw_sha256: Some(sha256_hex(value)),
        status: DecodeStatus::Decoded,
    });
    msg.identifiers.push(NamedValue {
        name: "ue_identity_pseudonym".into(),
        value: pseudo,
        pseudonymized: true,
    });
    msg.identifiers.push(NamedValue {
        name: "eps_mobile_identity_type".into(),
        value: identity_name.into(),
        pseudonymized: false,
    });
}

fn decode_eps_sm(payload: &[u8], source_offset: usize) -> NasMessage {
    if payload.len() < 3 {
        return malformed(payload, source_offset, "EPS ESM header is truncated");
    }
    let ebi = payload[0] >> 4;
    let pti = payload[1];
    let mt = payload[2];
    let (name, procedure) = sm_eps_name(mt);
    let body = &payload[3..];
    let mut msg = NasMessage {
        epd: EPD_EPS_SM,
        security_header_type: 0,
        security_state: SecurityState::Plain,
        message_type: Some(mt),
        message_name: name.into(),
        procedure: procedure.into(),
        pdu_session_id: Some(ebi),
        pti: Some(pti),
        cause: None,
        identifiers: vec![
            nv("extended_protocol_discriminator", "0x02"),
            nv("eps_bearer_identity", ebi.to_string()),
            nv("procedure_transaction_identity", pti.to_string()),
        ],
        information_elements: vec![ie(
            "EPS ESM body",
            body,
            Some(format!("body_sha256={}", sha256_hex(body))),
            DecodeStatus::Decoded,
        )],
        status: if name.starts_with("Unknown") {
            DecodeStatus::Unsupported
        } else {
            DecodeStatus::Decoded
        },
        errors: Vec::new(),
        source_offset,
        inner: Vec::new(),
    };
    // For PDN Connectivity Request (0xd0), extract PDN type (half octet in body[0]).
    if mt == 0xd0 && !body.is_empty() {
        let pdn_type = body[0] & 0x0f;
        msg.identifiers.push(nv(
            "pdn_type",
            match pdn_type {
                1 => "ipv4",
                2 => "ipv6",
                3 => "ipv4v6",
                _ => "unknown",
            },
        ));
    }
    msg
}

fn mm_eps_name(mt: u8) -> (&'static str, &'static str) {
    match mt {
        0x41 => ("Attach Request", "EPS_ATTACH"),
        0x42 => ("Attach Accept", "EPS_ATTACH"),
        0x43 => ("Attach Complete", "EPS_ATTACH"),
        0x44 => ("Attach Reject", "EPS_ATTACH"),
        0x45 => ("Detach Request", "EPS_DETACH"),
        0x46 => ("Detach Accept", "EPS_DETACH"),
        0x48 => ("Tracking Area Update Request", "EPS_TAU"),
        0x49 => ("Tracking Area Update Accept", "EPS_TAU"),
        0x4a => ("Tracking Area Update Complete", "EPS_TAU"),
        0x4b => ("Tracking Area Update Reject", "EPS_TAU"),
        0x4c => ("Extended Service Request", "EPS_SERVICE_REQUEST"),
        0x4d => ("Service Reject", "EPS_SERVICE_REQUEST"),
        0x4e => ("EPS Service Request", "EPS_SERVICE_REQUEST"),
        0x50 => ("GUTI Reallocation Command", "EPS_GUTI_REALLOCATION"),
        0x51 => ("GUTI Reallocation Complete", "EPS_GUTI_REALLOCATION"),
        0x52 => ("Authentication Request", "EPS_AUTHENTICATION"),
        0x53 => ("Authentication Response", "EPS_AUTHENTICATION"),
        0x54 => ("Authentication Reject", "EPS_AUTHENTICATION"),
        0x55 => ("Authentication Failure", "EPS_AUTHENTICATION"),
        0x56 => ("Identity Request", "EPS_IDENTITY"),
        0x57 => ("Identity Response", "EPS_IDENTITY"),
        0x5c => ("Security Mode Command", "EPS_SECURITY_MODE"),
        0x5d => ("Security Mode Complete", "EPS_SECURITY_MODE"),
        0x5e => ("Security Mode Reject", "EPS_SECURITY_MODE"),
        0x60 => ("EMM Status", "EPS_EMM_STATUS"),
        0x61 => ("EMM Information", "EPS_EMM_INFORMATION"),
        0x62 => ("Downlink NAS Transport", "EPS_NAS_TRANSPORT"),
        0x63 => ("Uplink NAS Transport", "EPS_NAS_TRANSPORT"),
        0x64 => ("CS Service Notification", "EPS_CS_SERVICE_NOTIFICATION"),
        0x68 => (
            "Downlink Generic NAS Transport",
            "EPS_GENERIC_NAS_TRANSPORT",
        ),
        0x69 => (
            "Uplink Generic NAS Transport",
            "EPS_GENERIC_NAS_TRANSPORT",
        ),
        _ => ("Unknown EPS EMM message", "UNKNOWN"),
    }
}

fn sm_eps_name(mt: u8) -> (&'static str, &'static str) {
    match mt {
        0xc1 => (
            "Activate Default EPS Bearer Context Request",
            "EPS_DEFAULT_BEARER_ACTIVATE",
        ),
        0xc2 => (
            "Activate Default EPS Bearer Context Accept",
            "EPS_DEFAULT_BEARER_ACTIVATE",
        ),
        0xc3 => (
            "Activate Default EPS Bearer Context Reject",
            "EPS_DEFAULT_BEARER_ACTIVATE",
        ),
        0xc5 => (
            "Activate Dedicated EPS Bearer Context Request",
            "EPS_DEDICATED_BEARER_ACTIVATE",
        ),
        0xc6 => (
            "Activate Dedicated EPS Bearer Context Accept",
            "EPS_DEDICATED_BEARER_ACTIVATE",
        ),
        0xc7 => (
            "Activate Dedicated EPS Bearer Context Reject",
            "EPS_DEDICATED_BEARER_ACTIVATE",
        ),
        0xc9 => ("Modify EPS Bearer Context Request", "EPS_BEARER_MODIFY"),
        0xca => ("Modify EPS Bearer Context Accept", "EPS_BEARER_MODIFY"),
        0xcb => ("Modify EPS Bearer Context Reject", "EPS_BEARER_MODIFY"),
        0xcd => (
            "Deactivate EPS Bearer Context Request",
            "EPS_BEARER_DEACTIVATE",
        ),
        0xce => (
            "Deactivate EPS Bearer Context Accept",
            "EPS_BEARER_DEACTIVATE",
        ),
        0xd0 => ("PDN Connectivity Request", "EPS_PDN_CONNECTIVITY"),
        0xd1 => ("PDN Connectivity Reject", "EPS_PDN_CONNECTIVITY"),
        0xd2 => ("PDN Disconnect Request", "EPS_PDN_DISCONNECT"),
        0xd3 => ("PDN Disconnect Reject", "EPS_PDN_DISCONNECT"),
        0xd9 => ("ESM Information Request", "EPS_ESM_INFO"),
        0xda => ("ESM Information Response", "EPS_ESM_INFO"),
        0xdb => ("Notification", "EPS_ESM_NOTIFICATION"),
        0xe8 => ("ESM Status", "EPS_ESM_STATUS"),
        _ => ("Unknown EPS ESM message", "UNKNOWN"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatches_observed_plain_5gmm() {
        let r = decode(&hex("7e00446f"));
        assert_eq!(r.message_name, "Registration Reject");
        assert_eq!(r.cause, Some(111));
        assert_eq!(r.security_state, SecurityState::Plain);
    }

    #[test]
    fn classifies_protected_and_refuses_ciphertext() {
        let r = decode(&hex("7e0211223344017e0043"));
        assert_eq!(r.security_state, SecurityState::IntegrityProtectedCiphered);
        assert_eq!(r.status, DecodeStatus::EncryptedOrProtected);
        assert!(r.message_type.is_none());
    }

    #[test]
    fn parses_integrity_only_inner_without_claiming_verification() {
        let r = decode(&hex("7e0111223344017e0043"));
        assert_eq!(r.message_name, "Registration Complete");
        assert_eq!(r.status, DecodeStatus::Partial);
        assert!(r.errors.iter().any(|e| e.contains("not verified")));
    }

    #[test]
    fn decodes_nested_5gsm_and_dnn() {
        let r = decode(&hex(
            "7e00670100162e0101c1ffff91a1280100250908696e7465726e6574",
        ));
        assert_eq!(r.inner.len(), 1);
        let sm = &r.inner[0];
        assert_eq!(sm.pdu_session_id, Some(1));
        assert_eq!(sm.pti, Some(1));
        assert!(sm
            .identifiers
            .iter()
            .any(|v| v.name == "dnn" && v.value == "internet"));
    }

    #[test]
    fn malformed_and_unknown_inputs_never_panic() {
        for bytes in [
            vec![],
            vec![0x7e],
            vec![0x7e, 2],
            vec![0x2e, 1, 1],
            vec![0xff, 1],
        ] {
            let _ = decode(&bytes);
        }
        assert_eq!(decode(&[0x7e]).status, DecodeStatus::Malformed);
        assert_eq!(decode(&[0xff]).status, DecodeStatus::Unsupported);
    }

    #[test]
    fn all_security_header_classes_are_explicit() {
        assert_eq!(
            decode(&hex("7e0111223344017e0043")).security_state,
            SecurityState::IntegrityProtected
        );
        assert_eq!(
            decode(&hex("7e021122334401aabb")).security_state,
            SecurityState::IntegrityProtectedCiphered
        );
        assert_eq!(
            decode(&hex("7e0311223344017e0043")).security_state,
            SecurityState::IntegrityProtected
        );
        assert_eq!(
            decode(&hex("7e041122334401aabb")).security_state,
            SecurityState::IntegrityProtectedCiphered
        );
        assert_eq!(
            decode(&hex("7e0f1122334401")).security_state,
            SecurityState::Unknown
        );
    }

    #[test]
    fn observed_message_identity_tables_are_stable() {
        for (message_type, name) in [
            (0x41, "Registration Request"),
            (0x42, "Registration Accept"),
            (0x43, "Registration Complete"),
            (0x44, "Registration Reject"),
            (0x56, "Authentication Request"),
            (0x57, "Authentication Response"),
            (0x59, "Authentication Failure"),
            (0x5d, "Security Mode Command"),
            (0x5e, "Security Mode Complete"),
            (0x5f, "Security Mode Reject"),
            (0x67, "UL NAS Transport"),
            (0x68, "DL NAS Transport"),
        ] {
            assert_eq!(mm_name(message_type).0, name);
        }
        for (message_type, name) in [
            (0xc1, "PDU Session Establishment Request"),
            (0xc2, "PDU Session Establishment Accept"),
            (0xc3, "PDU Session Establishment Reject"),
            (0xcb, "PDU Session Modification Command"),
            (0xcc, "PDU Session Modification Complete"),
            (0xd1, "PDU Session Release Request"),
            (0xd3, "PDU Session Release Command"),
            (0xd4, "PDU Session Release Complete"),
            (0xd6, "5GSM Status"),
        ] {
            assert_eq!(sm_name(message_type).0, name);
        }
    }

    #[test]
    fn truncated_tlv_and_tlve_are_malformed() {
        assert_eq!(decode(&hex("2e0101d12509")).status, DecodeStatus::Malformed);
        assert_eq!(
            decode(&hex("2e0101d17b0004aabb")).status,
            DecodeStatus::Malformed
        );
    }

    #[test]
    fn duplicate_and_unknown_ies_are_preserved() {
        let r = decode(&hex("2e0101d159012a59022b2c"));
        assert_eq!(r.cause, Some(0x2a));
        assert!(r.information_elements.len() >= 2);
    }

    #[test]
    fn registration_request_decodes_ue_security_capability_iei_2e() {
        // 7e 00 41 → plain 5GMM Registration Request.
        // Mandatory: 09 (reg_type/ngKSI), length 0004, 5GS mobile identity 00112233.
        // Optional TLV: 2e (UE security capability) length 04 value 80 80 e0 f0.
        let bytes = hex("7e004109000400112233 2e048080e0f0".replace(' ', "").as_str());
        let r = decode(&bytes);
        assert_eq!(r.message_name, "Registration Request");
        assert_eq!(r.status, DecodeStatus::Decoded, "status: {:?}", r.status);
        let ie_ue = r
            .information_elements
            .iter()
            .find(|e| e.name == "UE security capability")
            .expect("UE security capability IE");
        let value = ie_ue.value.as_deref().expect("decoded value");
        assert!(value.contains("nr_encryption=0x80"), "{value}");
        assert!(value.contains("nr_integrity=0x80"), "{value}");
        assert!(value.contains("eutra_encryption=0xe0"), "{value}");
        assert!(value.contains("eutra_integrity=0xf0"), "{value}");
    }

    #[test]
    fn security_mode_command_decodes_mandatory_fields_and_additional_info_iei_36() {
        // Plain 5GMM Security Mode Command (0x7e 00 5d):
        //   Selected NAS security algorithms: 0x22 → ciphering=2 (NEA2), integrity=2 (NIA2).
        //   ngKSI + spare: 0x01 → ngKSI=1.
        //   Replayed UE security capability LV: len=4 value 80 80 e0 f0.
        //   Optional: 36 (Additional 5G security info) length 1 value 02 → rinmr=1, hdp=0.
        let bytes = hex(
            "7e005d220104 8080e0f0 3601 02"
                .replace(' ', "")
                .as_str(),
        );
        let r = decode(&bytes);
        assert_eq!(r.message_name, "Security Mode Command");
        assert_eq!(r.status, DecodeStatus::Decoded, "status: {:?}", r.status);
        let sel = r
            .information_elements
            .iter()
            .find(|e| e.name == "Selected NAS security algorithms")
            .expect("Selected NAS algs IE");
        let sel_v = sel.value.as_deref().expect("decoded value");
        assert!(sel_v.contains("ciphering=0x2"), "{sel_v}");
        assert!(sel_v.contains("integrity=0x2"), "{sel_v}");
        let replayed = r
            .information_elements
            .iter()
            .find(|e| e.name == "Replayed UE security capabilities")
            .expect("Replayed UE security capability IE");
        let replayed_v = replayed.value.as_deref().expect("decoded value");
        assert!(replayed_v.contains("nr_encryption=0x80"), "{replayed_v}");
        let addl = r
            .information_elements
            .iter()
            .find(|e| e.name == "Additional 5G security information")
            .expect("Additional 5G security info IE");
        let addl_v = addl.value.as_deref().expect("decoded value");
        assert!(addl_v.contains("rinmr=1"), "{addl_v}");
        assert!(addl_v.contains("hdp=0"), "{addl_v}");
    }

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks_exact(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    // ---------- EPS NAS (TS 24.301) tests ----------

    #[test]
    fn eps_attach_request_flags_mobile_identity_as_pseudonymised() {
        // Synthetic payload: byte 0 = 0x07 (PD EMM, sec header 0),
        // byte 1 = 0x41 (Attach Request), byte 2 = 0x01 (attach type/NAS-KSI),
        // byte 3 = 0x08 length, next 8 bytes = synthetic IMSI (type 1).
        // Length-byte 0x08 then 8-byte identity whose first byte 0x09 encodes
        // identity type = IMSI (low 3 bits = 1).
        let synthetic_imsi_lv = [0x08, 0x09, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x12];
        let mut bytes = vec![0x07, 0x41, 0x01];
        bytes.extend_from_slice(&synthetic_imsi_lv);
        let r = decode(&bytes);
        assert_eq!(r.epd, EPD_EPS_MM);
        assert_eq!(r.message_name, "Attach Request");
        assert_eq!(r.procedure, "EPS_ATTACH");
        let identity = r
            .identifiers
            .iter()
            .find(|v| v.name == "ue_identity_pseudonym")
            .expect("ue_identity_pseudonym");
        assert!(identity.pseudonymized);
        assert!(identity.value.starts_with("psn-"));
        let identity_type = r
            .identifiers
            .iter()
            .find(|v| v.name == "eps_mobile_identity_type")
            .expect("eps_mobile_identity_type");
        assert_eq!(identity_type.value, "IMSI");
    }

    #[test]
    fn eps_tau_request_flags_old_guti_as_pseudonymised() {
        // GUTI identity type = 6, trailing 10 bytes synthetic.
        // Length-byte 0x0b then 11-byte identity whose first byte 0xf6 encodes
        // identity type = GUTI (low 3 bits = 6).
        let synthetic_guti_lv = [
            0x0b, 0xf6, 0x00, 0xf1, 0x10, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78, 0x00,
        ];
        let mut bytes = vec![0x07, 0x48, 0x01];
        bytes.extend_from_slice(&synthetic_guti_lv);
        let r = decode(&bytes);
        assert_eq!(r.message_name, "Tracking Area Update Request");
        let identity_type = r
            .identifiers
            .iter()
            .find(|v| v.name == "eps_mobile_identity_type")
            .expect("eps_mobile_identity_type");
        assert_eq!(identity_type.value, "GUTI");
    }

    #[test]
    fn eps_detach_request_and_identity_response_are_recognised() {
        let detach = decode(&[0x07, 0x45, 0x01, 0x05, 0xf5, 0x12, 0x34, 0x56, 0x78]);
        assert_eq!(detach.message_name, "Detach Request");
        assert_eq!(detach.procedure, "EPS_DETACH");

        let identity_rsp = decode(&[0x07, 0x57, 0x05, 0xf1, 0x11, 0x22, 0x33, 0x44]);
        assert_eq!(identity_rsp.message_name, "Identity Response");
        assert!(identity_rsp
            .identifiers
            .iter()
            .any(|v| v.name == "ue_identity_pseudonym" && v.pseudonymized));
    }

    #[test]
    fn eps_authentication_request_separates_rand_and_autn() {
        let mut bytes = vec![0x07, 0x52, 0x01];
        bytes.extend_from_slice(&[0u8; 16]); // RAND
        bytes.push(16); // AUTN length
        bytes.extend_from_slice(&[0u8; 16]); // AUTN
        let r = decode(&bytes);
        assert_eq!(r.message_name, "Authentication Request");
        assert!(r.information_elements.iter().any(|e| e.name == "RAND"));
        assert!(r.information_elements.iter().any(|e| e.name == "AUTN"));
    }

    #[test]
    fn eps_security_mode_command_decodes_mandatory_fields_per_ts24301() {
        // Byte 0 = 0x07 (PD EMM), byte 1 = 0x5C (Security Mode Command).
        // Body: 0x12 = Selected NAS security algorithms (ciphering=EEA1, integrity=EIA2).
        //       0x05 = NAS KSI (ksi=5, tsc=0).
        //       0x05 = Replayed UE sec cap length.
        //       0xf0 0xe0 0x80 0x40 0x20 = EEA bitmap / EIA / UEA / UIA / GEA bytes.
        let bytes = &[
            0x07, 0x5c, 0x12, 0x05, 0x05, 0xf0, 0xe0, 0x80, 0x40, 0x20,
        ];
        let r = decode(bytes);
        assert_eq!(r.message_name, "Security Mode Command");
        assert_eq!(r.status, DecodeStatus::Decoded, "status: {:?}", r.status);
        let sel = r
            .information_elements
            .iter()
            .find(|e| e.name == "Selected NAS security algorithms")
            .expect("Selected NAS algs IE");
        let sel_v = sel.value.as_deref().expect("decoded value");
        assert!(sel_v.contains("ciphering=EEA1"), "{sel_v}");
        assert!(sel_v.contains("integrity=EIA2"), "{sel_v}");
        let ksi = r
            .information_elements
            .iter()
            .find(|e| e.name == "NAS key set identifier")
            .expect("NAS KSI IE");
        let ksi_v = ksi.value.as_deref().expect("decoded value");
        assert!(ksi_v.contains("nas_ksi=5"), "{ksi_v}");
        assert!(ksi_v.contains("tsc=0"), "{ksi_v}");
        let replayed = r
            .information_elements
            .iter()
            .find(|e| e.name == "Replayed UE security capabilities")
            .expect("Replayed UE sec cap IE");
        let replayed_v = replayed.value.as_deref().expect("decoded value");
        assert!(replayed_v.contains("eea=0xf0"), "{replayed_v}");
        assert!(replayed_v.contains("eia=0xe0"), "{replayed_v}");
        assert!(replayed_v.contains("uea=0x80"), "{replayed_v}");
        assert!(replayed_v.contains("uia=0x40"), "{replayed_v}");
        assert!(replayed_v.contains("gea=0x20"), "{replayed_v}");
    }

    #[test]
    fn eps_security_mode_command_truncated_mandatory_fields_are_malformed() {
        let short = &[0x07, 0x5c, 0x12, 0x05];
        let r = decode(short);
        assert_eq!(r.message_name, "Security Mode Command");
        assert_eq!(r.status, DecodeStatus::Malformed);
    }

    #[test]
    fn eps_service_request_short_form_is_decoded_plain() {
        // Service Request short form: byte 0 = 0xc7 (sec header type 12, PD 0x07).
        let bytes = &[0xc7, 0xaa, 0xbb, 0xcc];
        let r = decode(bytes);
        assert_eq!(r.message_name, "EPS Service Request");
        assert_eq!(r.security_header_type, 12);
    }

    #[test]
    fn eps_esm_pdn_connectivity_request_decodes_pdn_type() {
        // byte 0 = 0x52 (EBI=5, PD=0x02); byte 1 = 1 (PTI); byte 2 = 0xd0;
        // body[0] low nibble = 1 (ipv4).
        let r = decode(&[0x52, 0x01, 0xd0, 0x01, 0x00, 0x01]);
        assert_eq!(r.epd, EPD_EPS_SM);
        assert_eq!(r.message_name, "PDN Connectivity Request");
        assert_eq!(r.pdu_session_id, Some(5));
        assert_eq!(r.pti, Some(1));
        let pdn_type = r
            .identifiers
            .iter()
            .find(|v| v.name == "pdn_type")
            .expect("pdn_type");
        assert_eq!(pdn_type.value, "ipv4");
    }

    #[test]
    fn eps_esm_activate_default_bearer_request_name() {
        let r = decode(&[0x52, 0x01, 0xc1, 0x00, 0x00, 0x00]);
        assert_eq!(r.message_name, "Activate Default EPS Bearer Context Request");
        assert_eq!(r.procedure, "EPS_DEFAULT_BEARER_ACTIVATE");
    }

    #[test]
    fn eps_mm_name_and_sm_name_tables_are_stable() {
        for (mt, name) in [
            (0x41u8, "Attach Request"),
            (0x42, "Attach Accept"),
            (0x45, "Detach Request"),
            (0x48, "Tracking Area Update Request"),
            (0x52, "Authentication Request"),
            (0x5c, "Security Mode Command"),
        ] {
            assert_eq!(mm_eps_name(mt).0, name);
        }
        for (mt, name) in [
            (0xd0u8, "PDN Connectivity Request"),
            (0xc1, "Activate Default EPS Bearer Context Request"),
            (0xcd, "Deactivate EPS Bearer Context Request"),
        ] {
            assert_eq!(sm_eps_name(mt).0, name);
        }
    }
}
