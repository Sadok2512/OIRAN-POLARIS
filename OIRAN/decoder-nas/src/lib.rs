//! Native, bounded 5G NAS envelope and observed-message decoder.
//! Specification baseline: 3GPP TS 24.501 Release 17.

use event_schema::{pseudonym, sha256_hex, DecodeStatus, InformationElement, NamedValue};

pub const VERSION: &str = "0.1.0";
pub const SPECIFICATION: &str = "3GPP TS 24.501 Release 17";
pub const EPD_5GMM: u8 = 0x7e;
pub const EPD_5GSM: u8 = 0x2e;

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
        0x57 | 0x5d | 0x5e | 0x5f | 0x42 | 0x43 | 0x45 | 0x46 | 0x47 | 0x48 | 0x4c | 0x4d
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

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks_exact(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }
}
