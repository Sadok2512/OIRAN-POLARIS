//! NGAP APER envelope and ProtocolIE container decoder, schema baseline TS 38.413 V17.3.0.

pub mod aper;
mod transfer;

pub use transfer::{
    decode_pdu_session_resource_setup_request_transfer,
    decode_pdu_session_resource_setup_response_transfer, AllocationAndRetention,
    AssociatedQosFlowItem, AssociatedQosFlowMapping, CauseKind, FailedQosFlow, GbrQosInformation,
    GtpTunnel, QosCharacteristics, QosFlowLevelQosParams, QosFlowPerTnlInfo,
    QosFlowSetupRequestItem, RequestTransfer, ResponseTransfer, SecurityResultDecoded,
    UpTransportLayerInformation,
};

use decoder_nas::NasMessage;
use event_schema::{
    pseudonym, sha256_hex, DecodeStatus, Direction, EvidenceReference, EvidenceState,
    InformationElement, NamedValue, NormalizedEvent, Protocol,
};
use plugin_runtime::{
    DecoderCapabilities, DecoderInput, DecoderManifest, DecoderOutput, ProtocolDecoder,
    PLUGIN_API_VERSION,
};

pub const VERSION: &str = "0.5.0";
pub const SCHEMA_VERSION: &str = "3GPP TS 38.413 V17.3.0";
pub const SCHEMA_SHA256: &str = "b705532dd52674fce67ccc01df7bd17a8412341ea82740c164029a5b545f04d2";
#[derive(Default)]
pub struct NgapDecoder;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PduKind {
    Initiating,
    SuccessfulOutcome,
    UnsuccessfulOutcome,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NgapIe {
    pub id: u16,
    pub criticality: u8,
    pub value: Vec<u8>,
    pub known_name: Option<&'static str>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NgapPdu {
    pub kind: PduKind,
    pub procedure_code: u8,
    pub criticality: u8,
    pub message_name: &'static str,
    pub ies: Vec<NgapIe>,
}

pub fn parse(payload: &[u8]) -> Result<NgapPdu, String> {
    if payload.len() < 4 {
        return Err("NGAP-PDU APER envelope truncated".into());
    }
    if payload[0] & 0x80 != 0 {
        return Err("NGAP-PDU extension choice is unsupported".into());
    }
    let choice = (payload[0] >> 5) & 0x03;
    let kind = match choice {
        0 => PduKind::Initiating,
        1 => PduKind::SuccessfulOutcome,
        2 => PduKind::UnsuccessfulOutcome,
        _ => return Err("unsupported NGAP-PDU extension choice".into()),
    };
    if payload[0] & 0x1f != 0 {
        return Err("NGAP-PDU has unsupported extension/padding bits".into());
    }
    let procedure = payload[1];
    let criticality = payload[2] >> 6;
    if criticality > 2 {
        return Err("invalid NGAP procedure criticality".into());
    }
    let (value_len, len_octets) = aper_length(&payload[3..])?;
    let value_start = 3 + len_octets;
    let value_end = value_start
        .checked_add(value_len)
        .filter(|v| *v <= payload.len())
        .ok_or_else(|| "NGAP open type exceeds SCTP message".to_string())?;
    let value = &payload[value_start..value_end];
    if value.len() < 3 {
        return Err("NGAP message ProtocolIE container truncated".into());
    }
    if value[0] & 0x80 != 0 {
        return Err("NGAP message extension additions are unsupported".into());
    }
    let count = be16(&value[1..3]) as usize;
    let mut pos = 3;
    let mut ies = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 4 > value.len() {
            return Err("NGAP ProtocolIE header truncated".into());
        }
        let id = be16(&value[pos..pos + 2]);
        let ie_criticality = value[pos + 2] >> 6;
        if ie_criticality > 2 {
            return Err(format!("NGAP IE {id} has invalid criticality"));
        }
        let (len, n) = aper_length(&value[pos + 3..])?;
        pos += 3 + n;
        if pos + len > value.len() {
            return Err(format!("NGAP IE {id} open type truncated"));
        }
        ies.push(NgapIe {
            id,
            criticality: ie_criticality,
            value: value[pos..pos + len].to_vec(),
            known_name: ie_name(id),
        });
        pos += len;
    }
    if pos != value.len() {
        return Err(format!(
            "NGAP message has {} unconsumed APER byte(s)",
            value.len() - pos
        ));
    }
    Ok(NgapPdu {
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
fn decode_ie(ie: &NgapIe) -> (Option<String>, DecodeStatus, bool) {
    match ie.id {
        0 => decode_allowed_nssai(&ie.value),
        1 => decode_printable("amf_name", &ie.value),
        10 => {
            if ie.value.is_empty() || ie.value.len() > 8 {
                (None, DecodeStatus::Malformed, false)
            } else {
                (
                    Some(format!("amf_ue_ngap_id={}", unsigned(&ie.value))),
                    DecodeStatus::Decoded,
                    false,
                )
            }
        }
        85 => {
            if ie.value.is_empty() || ie.value.len() > 8 {
                (None, DecodeStatus::Malformed, false)
            } else {
                (
                    Some(format!("ran_ue_ngap_id={}", unsigned(&ie.value))),
                    DecodeStatus::Decoded,
                    false,
                )
            }
        }
        38 => {
            let Ok((nas, _)) = nas_pdu_contents(&ie.value) else {
                return (None, DecodeStatus::Malformed, true);
            };
            // TS 24.501 places the security-header type in the high nibble of
            // octet 2. The NGAP decoder has fully decoded the NAS-PDU envelope
            // once its APER length is bounded; the child NAS event carries the
            // independent protected/partial status of the nested payload.
            let protected = nas.get(1).map(|v| v >> 4 != 0).unwrap_or(false);
            (
                Some(if protected {
                    format!("nas_protected=true,pseudonym={}", pseudonym("nas-pdu", nas))
                } else {
                    format!(
                        "nas_protected=false,pseudonym={}",
                        pseudonym("nas-pdu", nas)
                    )
                }),
                DecodeStatus::Decoded,
                true,
            )
        }
        26 => (
            Some(format!(
                "five_g_s_tmsi={}",
                pseudonym("five-g-s-tmsi", &ie.value)
            )),
            DecodeStatus::Decoded,
            true,
        ),
        15 => decode_cause(&ie.value),
        21 => decode_single_enum("default_paging_drx", &ie.value),
        27 => decode_global_ran_node_id(&ie.value),
        28 => decode_guami(&ie.value),
        34 => (
            Some(format!(
                "masked_imeisv={}",
                pseudonym("masked-imeisv", &ie.value)
            )),
            DecodeStatus::Decoded,
            true,
        ),
        53..=79 | 133 => decode_pdu_session_list(ie.id, &ie.value),
        80 => (
            Some(format!(
                "plmn_support_list_sha256={}",
                sha256_hex(&ie.value)
            )),
            DecodeStatus::Partial,
            false,
        ),
        82 => decode_printable("ran_node_name", &ie.value),
        86 => decode_single_enum("relative_amf_capacity", &ie.value),
        90 => decode_rrc_establishment_cause(&ie.value),
        94 => (
            Some(format!("security_key_sha256={}", sha256_hex(&ie.value))),
            DecodeStatus::Decoded,
            true,
        ),
        96 => (
            Some(format!(
                "served_guami_list_sha256={}",
                sha256_hex(&ie.value)
            )),
            DecodeStatus::Partial,
            false,
        ),
        102 => (
            Some(format!(
                "supported_ta_list_sha256={}",
                sha256_hex(&ie.value)
            )),
            DecodeStatus::Partial,
            false,
        ),
        110 | 130 => decode_aggregate_bitrate(&ie.value),
        112 => decode_single_enum("ue_context_request", &ie.value),
        113 => decode_single_enum("paging_priority", &ie.value),
        114 => decode_ue_ngap_ids(&ie.value),
        117 => (
            Some(format!(
                "ue_radio_capability_sha256={}",
                sha256_hex(&ie.value)
            )),
            DecodeStatus::Decoded,
            true,
        ),
        119 => decode_security_capabilities(&ie.value),
        121 => decode_user_location(&ie.value),
        134 => decode_single_enum("pdu_session_type", &ie.value),
        141 => (
            Some(format!(
                "warning_area_coordinates_sha256={}",
                sha256_hex(&ie.value)
            )),
            DecodeStatus::Partial,
            false,
        ),
        _ => (None, DecodeStatus::Unsupported, false),
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

fn pdu_session_nas_contents(ie: &NgapIe) -> Option<(&[u8], usize)> {
    if !matches!(ie.id, 71 | 74) || ie.value.len() < 5 {
        return None;
    }
    let (length, length_octets) = aper_length(&ie.value[3..]).ok()?;
    let start = 3 + length_octets;
    let end = start.checked_add(length)?;
    let nas = ie.value.get(start..end)?;
    matches!(
        nas.first().copied(),
        Some(decoder_nas::EPD_5GMM) | Some(decoder_nas::EPD_5GSM)
    )
    .then_some((nas, start))
}

fn decode_allowed_nssai(v: &[u8]) -> (Option<String>, DecodeStatus, bool) {
    let mut bits = BitReader::new(v);
    let count = match bits.read(3) {
        Some(n) => n + 1,
        None => return malformed(),
    };
    if count != 1 {
        return (
            Some(format!("allowed_nssai_count={count}")),
            DecodeStatus::Partial,
            false,
        );
    }
    if bits.read(1) != Some(0) || bits.read(1) != Some(0) || bits.read(1) != Some(0) {
        return unsupported();
    }
    let has_sd = match bits.read(1) {
        Some(v) => v != 0,
        None => return malformed(),
    };
    if bits.read(1) != Some(0) {
        return unsupported();
    }
    let sst = match bits.read(8) {
        Some(v) => v,
        None => return malformed(),
    };
    let sd = if has_sd {
        match bits.read(24) {
            Some(v) => format!("{v:06x}"),
            None => return malformed(),
        }
    } else {
        "absent".into()
    };
    (
        Some(format!("allowed_nssai_count=1,sst={sst},sd={sd}")),
        DecodeStatus::Decoded,
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
        _ => malformed(),
    }
}

fn decode_cause(v: &[u8]) -> (Option<String>, DecodeStatus, bool) {
    match (v.first().copied().map(|b| b >> 5), v.len()) {
        (Some(0), 2) => (
            Some(format!(
                "cause_category=radio_network,cause_value={}",
                (((v[0] & 0x1f) as u16) << 2) | (v[1] >> 6) as u16
            )),
            DecodeStatus::Decoded,
            false,
        ),
        (Some(2), 1) => (
            Some(format!(
                "cause_category=nas,cause_value={}",
                (v[0] & 0x0f) >> 2
            )),
            DecodeStatus::Decoded,
            false,
        ),
        _ => (
            Some(format!("cause_aper=0x{}", hex(v))),
            DecodeStatus::Partial,
            false,
        ),
    }
}

fn decode_ue_ngap_ids(v: &[u8]) -> (Option<String>, DecodeStatus, bool) {
    if v.len() != 4 {
        return unsupported();
    }
    (
        Some(format!(
            "amf_ue_ngap_id={},ran_ue_ngap_id={}",
            be16(&v[..2]),
            be16(&v[2..])
        )),
        DecodeStatus::Decoded,
        false,
    )
}

fn decode_global_ran_node_id(v: &[u8]) -> (Option<String>, DecodeStatus, bool) {
    if v.len() < 7 {
        return malformed();
    }
    let plmn = decode_plmn(&v[1..4]);
    (
        Some(format!(
            "plmn={plmn},global_ran_node_id_sha256={}",
            sha256_hex(v)
        )),
        DecodeStatus::Partial,
        false,
    )
}

fn decode_guami(v: &[u8]) -> (Option<String>, DecodeStatus, bool) {
    if v.len() != 7 {
        return malformed();
    }
    (
        Some(format!(
            "plmn={},amf_region={},amf_set_id={},amf_pointer={}",
            decode_plmn(&v[1..4]),
            v[4],
            be16(&v[5..]) >> 6,
            be16(&v[5..]) & 0x3f
        )),
        DecodeStatus::Decoded,
        false,
    )
}

fn decode_pdu_session_list(id: u16, v: &[u8]) -> (Option<String>, DecodeStatus, bool) {
    if v.len() < 3 {
        return malformed();
    }
    let (ip_label, teid_label) = pdu_session_tunnel_labels(id);
    let mut value = format!(
        "pdu_session_id={},nested_transfer_sha256={}",
        v[2],
        sha256_hex(&v[3..])
    );
    // Best-effort tunnel/pdu-session-type extraction from the opaque bytes,
    // kept so operators keep seeing a direction-tagged TEID even when the
    // real APER walker cannot reach the transfer OCTET STRING content.
    if let Some((ip, teid)) = decode_up_transport_tunnel(&v[3..]) {
        value.push_str(&format!(",{ip_label}={ip},{teid_label}=0x{teid:x}"));
    }
    if let Some(session_type) = decode_pdu_session_type_marker(&v[3..]) {
        value.push_str(&format!(",pdu_session_type={session_type}"));
    }
    // Call the real X.691 ALIGNED PER walker on the inner transfer bytes
    // whenever they are extractable. The outer PDUSessionResourceSetupItem*
    // SEQUENCE encoding places the OCTET STRING transfer at a predictable
    // offset for the canonical "no NAS-PDU, SST-only s-NSSAI" case; when the
    // extraction heuristic fails we fall back to the structural marker.
    if id == 75 {
        if let Some((transfer, _)) = extract_response_transfer_bytes(v) {
            let decoded = transfer::decode_pdu_session_resource_setup_response_transfer(transfer);
            append_response_summary(&mut value, &decoded);
        }
    } else if id == 74 {
        if let Some((transfer, _)) = extract_request_transfer_bytes(v) {
            let decoded = transfer::decode_pdu_session_resource_setup_request_transfer(transfer);
            append_request_summary(&mut value, &decoded);
        }
    }
    (Some(value), DecodeStatus::Partial, false)
}

/// Extract the PDUSessionResourceSetupResponseTransfer OCTET STRING content
/// from a PDUSessionResourceSetupListSURes (IE 75) value, assuming the
/// canonical outer layout: `[count-1][SEQUENCE preamble][pDUSessionID][length
/// determinant][... transfer bytes ...]`. Returns the transfer slice and the
/// offset where it starts inside `v`.
fn extract_response_transfer_bytes(v: &[u8]) -> Option<(&[u8], usize)> {
    if v.len() < 5 {
        return None;
    }
    let len = v[3] as usize;
    if 4 + len > v.len() {
        return None;
    }
    Some((&v[4..4 + len], 4))
}

/// Extract the PDUSessionResourceSetupRequestTransfer OCTET STRING content
/// from a PDUSessionResourceSetupListSUReq (IE 74) value. The canonical layout
/// is `[count-1][SEQUENCE preamble][pDUSessionID][optional NAS-PDU][s-NSSAI]
/// [length determinant][... transfer bytes ...]`. We skip NAS-PDU when the
/// preamble bit indicates its presence, and skip s-NSSAI as 3 octets (SST-only
/// form) or 6 octets (SST+SD form). The heuristic matches the sanitized
/// synthetic captures observed on the laboratory probe; non-canonical layouts
/// fall through and callers rely on the structural marker fallback.
fn extract_request_transfer_bytes(v: &[u8]) -> Option<(&[u8], usize)> {
    if v.len() < 5 {
        return None;
    }
    let preamble = v[1];
    let nas_pdu_present = preamble & 0x40 != 0;
    let mut cursor = 3usize;
    if nas_pdu_present {
        let nas_len = *v.get(cursor)? as usize;
        cursor = cursor.checked_add(1 + nas_len)?;
    }
    // s-NSSAI: try 3 octets first (SST-only), then 6 (SST+SD) if the length
    // determinant that follows looks implausible as a transfer size.
    for snssai_len in [3usize, 6] {
        let after_snssai = cursor.checked_add(snssai_len)?;
        if after_snssai >= v.len() {
            continue;
        }
        let len = v[after_snssai] as usize;
        if len == 0 || after_snssai + 1 + len > v.len() {
            continue;
        }
        return Some((&v[after_snssai + 1..after_snssai + 1 + len], after_snssai + 1));
    }
    None
}

fn append_response_summary(value: &mut String, decoded: &transfer::ResponseTransfer) {
    for (i, qfi) in decoded.dl.qfis.iter().enumerate() {
        value.push_str(&format!(",dl_qfi_{}={}", i, qfi.qfi));
        if let Some(mapping) = &qfi.mapping_indication {
            value.push_str(&format!(",dl_qfi_{i}_mapping={:?}", mapping));
        }
    }
    for (i, tnl) in decoded.additional_dl.iter().enumerate() {
        if let Some(ip) = tnl.tunnel.ipv4_address() {
            value.push_str(&format!(",additional_dl_ip_{i}={ip}"));
        }
        if let Some(teid) = tnl.tunnel.teid() {
            value.push_str(&format!(",additional_dl_teid_{i}=0x{teid:x}"));
        }
        for (j, qfi) in tnl.qfis.iter().enumerate() {
            value.push_str(&format!(",additional_dl_{i}_qfi_{j}={}", qfi.qfi));
        }
    }
    if let Some(sec) = &decoded.security {
        value.push_str(&format!(
            ",security_integrity={},security_confidentiality={}",
            sec.integrity, sec.confidentiality
        ));
    }
    for (i, failed) in decoded.failed.iter().enumerate() {
        value.push_str(&format!(
            ",failed_qfi_{i}={},failed_cause_{i}={:?}",
            failed.qfi, failed.cause
        ));
    }
    for e in &decoded.errors {
        value.push_str(&format!(",ngap_transfer_error={}", e.replace(',', ";")));
    }
}

fn append_request_summary(value: &mut String, decoded: &transfer::RequestTransfer) {
    if let Some(ip) = decoded.ul_tunnel.ipv4_address() {
        value.push_str(&format!(",transfer_ul_ip={ip}"));
    }
    if let Some(teid) = decoded.ul_tunnel.teid() {
        value.push_str(&format!(",transfer_ul_teid=0x{teid:x}"));
    }
    if let Some(pt) = decoded.pdu_session_type {
        value.push_str(&format!(",transfer_pdu_session_type={pt}"));
    }
    for (i, flow) in decoded.qos_flows.iter().enumerate() {
        value.push_str(&format!(",qfi_{}={}", i, flow.qfi));
        if let transfer::QosCharacteristics::NonDynamic5QI { five_qi, .. } =
            &flow.qos_params.characteristics
        {
            value.push_str(&format!(",five_qi_{}={}", i, five_qi));
        }
        value.push_str(&format!(
            ",arp_priority_{}={},arp_capability_{}={},arp_vulnerability_{}={}",
            i,
            flow.qos_params.arp.priority,
            i,
            flow.qos_params.arp.capability,
            i,
            flow.qos_params.arp.vulnerability
        ));
    }
    for e in &decoded.errors {
        value.push_str(&format!(",ngap_transfer_error={}", e.replace(',', ";")));
    }
}

fn pdu_session_tunnel_labels(id: u16) -> (&'static str, &'static str) {
    match id {
        // PDUSessionResourceSetupListSUReq: AMF→gNB, carries UL NG-U UP TNL (UPF side).
        74 => ("tunnel_ip_ul", "gtp_teid_ul"),
        // PDUSessionResourceSetupListSURes: gNB→AMF, carries DL NG-U UP TNL (gNB side).
        75 => ("tunnel_ip_dl", "gtp_teid_dl"),
        // PDUSessionResourceSetupListCxtReq (71) and other list IEs: direction depends on
        // the enclosing procedure; keep neutral labels so they remain usable.
        _ => ("tunnel_endpoint_ip", "gtp_teid"),
    }
}

/// Scan the nested PDUSessionResource*Transfer OCTET STRING for the PDU Session Type
/// IE marker. IE id 134 is a 1-octet ENUMERATED (ipv4=0, ipv6=1, ipv4v6=2, ethernet=3,
/// unstructured=4), encoded in APER as the top three bits of a single octet. Requiring
/// the full `[00 86 crit 01 <val>]` prefix prevents arbitrary bytes from being evidence.
fn decode_pdu_session_type_marker(v: &[u8]) -> Option<&'static str> {
    v.windows(5).find_map(|w| {
        if w[0..2] != [0x00, 0x86] || w[2] & 0x3f != 0 || w[3] != 1 {
            return None;
        }
        match w[4] >> 5 {
            0 => Some("ipv4"),
            1 => Some("ipv6"),
            2 => Some("ipv4v6"),
            3 => Some("ethernet"),
            4 => Some("unstructured"),
            _ => None,
        }
    })
}

/// Detect the presence of the QoSFlowSetupRequestList / QoSFlowPerTNLInformation IE
/// container (id 136 = 0x0088) inside the nested transfer. We only report presence
/// because the inner QFI bitfield cannot be decoded without full APER walking.
// Canonical "one-octet-per-primitive" walkers have been removed in 0.5.0.
// The real X.691-compliant walker lives in `transfer.rs` and is exposed via
// `decode_pdu_session_resource_setup_{request,response}_transfer`. These are
// called from `decode_pdu_session_list` with best-effort transfer-byte
// extraction. The old marker-based IE 136 / IE 0x005e scan has also been
// removed because the PDUSessionResourceSetup*Transfer OCTET STRING contents
// are NOT ProtocolIE-Containers but direct SEQUENCEs with named fields
// (TS 38.413 §9.3.4.1 / §9.3.4.9) — the "IE marker" bytes we were pattern
// matching never existed in a well-formed APER payload. Non-matching layouts
// now fall back to the SHA-256 provenance that `decode_pdu_session_list` keeps
// emitting unconditionally.

/// Decode the observed NGAP UPTransportLayerInformation GTP tunnel open type.
/// The marker is the protocol IE id 139 followed by its validated ten-byte
/// open type. Requiring the complete structural prefix prevents an arbitrary
/// four-byte sequence inside encrypted N1 content from becoming evidence.
fn decode_up_transport_tunnel(v: &[u8]) -> Option<(std::net::Ipv4Addr, u32)> {
    v.windows(14).find_map(|window| {
        if window[0..2] != [0x00, 0x8b]
            || window[2] & 0x3f != 0
            || window[3] != 10
            || window[4..6] != [0x01, 0xf0]
        {
            return None;
        }
        let ip = std::net::Ipv4Addr::new(window[6], window[7], window[8], window[9]);
        let teid = u32::from_be_bytes(window[10..14].try_into().ok()?);
        Some((ip, teid))
    })
}

fn decode_rrc_establishment_cause(v: &[u8]) -> (Option<String>, DecodeStatus, bool) {
    if v.len() != 1 {
        return malformed();
    }
    (
        Some(format!("rrc_establishment_cause={}", v[0] >> 3)),
        DecodeStatus::Decoded,
        false,
    )
}

fn decode_single_enum(name: &str, v: &[u8]) -> (Option<String>, DecodeStatus, bool) {
    if v.len() != 1 {
        return malformed();
    }
    (
        Some(format!("{name}={}", v[0] >> 5)),
        DecodeStatus::Decoded,
        false,
    )
}

fn decode_aggregate_bitrate(v: &[u8]) -> (Option<String>, DecodeStatus, bool) {
    let (dl, ul) = match v.len() {
        8 => (
            u64::from(u32::from_be_bytes(v[..4].try_into().expect("four bytes"))),
            u64::from(u32::from_be_bytes(v[4..].try_into().expect("four bytes"))),
        ),
        10 => (be40(&v[..5]), be40(&v[5..])),
        _ => return malformed(),
    };
    (
        Some(format!("downlink_bps={dl},uplink_bps={ul}")),
        DecodeStatus::Decoded,
        false,
    )
}

fn decode_security_capabilities(v: &[u8]) -> (Option<String>, DecodeStatus, bool) {
    let mut b = BitReader::new(v);
    if b.read(1) != Some(0) || b.read(1) != Some(0) {
        return unsupported();
    }
    let mut masks = [0u64; 4];
    for mask in &mut masks {
        if b.read(1) != Some(0) {
            return unsupported();
        }
        *mask = match b.read(16) {
            Some(v) => v,
            None => return malformed(),
        };
    }
    (Some(format!("nr_encryption=0x{:04x},nr_integrity=0x{:04x},eutra_encryption=0x{:04x},eutra_integrity=0x{:04x}", masks[0], masks[1], masks[2], masks[3])), DecodeStatus::Decoded, false)
}

fn decode_user_location(v: &[u8]) -> (Option<String>, DecodeStatus, bool) {
    if v.len() != 15 && v.len() != 19 {
        return unsupported();
    }
    if v[0] & 0xe0 != 0x40 {
        return unsupported();
    }
    let nr_cell = be40(&v[4..9]) >> 4;
    let timestamp = if v.len() == 19 {
        format!(
            ",location_timestamp={}",
            u32::from_be_bytes(v[15..19].try_into().expect("four bytes"))
        )
    } else {
        String::new()
    };
    (
        Some(format!(
            "plmn={},nr_cell_id=0x{nr_cell:09x},tai_plmn={},tac=0x{:06x}{timestamp}",
            decode_plmn(&v[1..4]),
            decode_plmn(&v[9..12]),
            ((v[12] as u32) << 16) | ((v[13] as u32) << 8) | v[14] as u32
        )),
        DecodeStatus::Decoded,
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

fn malformed() -> (Option<String>, DecodeStatus, bool) {
    (None, DecodeStatus::Malformed, false)
}
fn unsupported() -> (Option<String>, DecodeStatus, bool) {
    (None, DecodeStatus::Unsupported, false)
}
fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
fn be40(v: &[u8]) -> u64 {
    v[..5].iter().fold(0u64, |a, b| (a << 8) | u64::from(*b))
}

struct BitReader<'a> {
    data: &'a [u8],
    bit: usize,
}
impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, bit: 0 }
    }
    fn read(&mut self, width: usize) -> Option<u64> {
        if width > 64 || self.bit.checked_add(width)? > self.data.len() * 8 {
            return None;
        }
        let mut value = 0u64;
        for _ in 0..width {
            value = (value << 1) | u64::from((self.data[self.bit / 8] >> (7 - self.bit % 8)) & 1);
            self.bit += 1;
        }
        Some(value)
    }
}
impl ProtocolDecoder for NgapDecoder {
    fn manifest(&self) -> DecoderManifest {
        DecoderManifest {
            decoder_name: "decoder-ngap",
            decoder_version: VERSION,
            api_version: PLUGIN_API_VERSION,
            protocol: Protocol::Ngap,
            specification: SCHEMA_VERSION,
            deterministic: true,
        }
    }
    fn capabilities(&self) -> DecoderCapabilities {
        DecoderCapabilities {
            message_families: &[
                "NG Setup",
                "Initial UE",
                "NAS Transport",
                "Initial Context Setup",
                "PDU Session Resource Setup",
                "UE Context Release",
            ],
            preserves_unknown_fields: true,
            supports_extensions: false,
            limitations: &[
                "schema-derived generic IE container with partial typed IE coverage",
                "nested PDU session SM transfers are partially typed: UP TNL (UL/DL \
                 direction via IE 74/75), PDU session type and QoS flow setup presence \
                 are detected by structural markers; QFI, QoS profile and secondary \
                 fields are retained as SHA-256 provenance",
                "APER fragmented lengths and extension additions unsupported",
                "NAS contents are not decrypted",
            ],
        }
    }
    fn decode(&self, input: &DecoderInput<'_>) -> DecoderOutput {
        match parse(input.payload) {
            Ok(pdu) => {
                let mut identifiers = Vec::new();
                let mut elements = Vec::new();
                let mut errors = Vec::new();
                let mut nas_messages = Vec::new();
                let mut status = DecodeStatus::Decoded;
                for ie in &pdu.ies {
                    if ie.id == 38 {
                        match nas_pdu_contents(&ie.value) {
                            Ok((nas, offset)) => {
                                nas_messages.push(decoder_nas::decode_with_offset(nas, offset))
                            }
                            Err(error) => errors.push(error),
                        }
                    } else if let Some((nas, offset)) = pdu_session_nas_contents(ie) {
                        nas_messages.push(decoder_nas::decode_with_offset(nas, offset));
                    }
                    let (value, ie_status, sensitive) = decode_ie(ie);
                    if matches!(
                        ie_status,
                        DecodeStatus::Unsupported
                            | DecodeStatus::Partial
                            | DecodeStatus::EncryptedOrProtected
                    ) {
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
                                    "amf_ue_ngap_id" | "ran_ue_ngap_id" | "five_g_s_tmsi"
                                ) || matches!(
                                    key,
                                    "pdu_session_id" | "sst" | "sd" | "nr_cell_id" | "tac" | "plmn"
                                ) || matches!(
                                    key,
                                    "tunnel_endpoint_ip"
                                        | "tunnel_ip_ul"
                                        | "tunnel_ip_dl"
                                        | "gtp_teid"
                                        | "gtp_teid_ul"
                                        | "gtp_teid_dl"
                                        | "pdu_session_type"
                                ) || key.starts_with("qfi_")
                                    || key.starts_with("five_qi_")
                                    || key.starts_with("arp_priority_")
                                    || key.starts_with("arp_capability_")
                                    || key.starts_with("arp_vulnerability_")
                                {
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
                            "unknown NGAP IE {} preserved by length and SHA-256",
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
                    protocol: Protocol::Ngap,
                    message_name: pdu.message_name.into(),
                    message_type: kind_number(pdu.kind),
                    procedure_code: Some(pdu.procedure_code as u32),
                    procedure: None,
                    security_state: None,
                    source_byte_offset: None,
                    source_endpoint: input.source_endpoint.clone(),
                    destination_endpoint: input.destination_endpoint.clone(),
                    direction: infer_direction(input),
                    session_identifiers: identifiers,
                    information_elements: elements,
                    decoder_name: "decoder-ngap".into(),
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
                    append_nas_events(
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

fn append_nas_events(
    events: &mut Vec<NormalizedEvent>,
    nas: &NasMessage,
    parent_id: &str,
    parent_identifiers: &[NamedValue],
    input: &DecoderInput<'_>,
    ngap_procedure: u8,
) {
    let mut identifiers = parent_identifiers.to_vec();
    identifiers.extend(nas.identifiers.clone());
    identifiers.push(NamedValue {
        name: "parent_ngap_event_id".into(),
        value: parent_id.into(),
        pseudonymized: false,
    });
    let protocol = if nas.epd == decoder_nas::EPD_5GSM {
        Protocol::Nas5gsm
    } else {
        Protocol::Nas5gmm
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
        direction: infer_nas_direction(input, ngap_procedure),
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
                kind: "parent-ngap-event".into(),
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
        append_nas_events(
            events,
            inner,
            &nas_event_id,
            &nas_identifiers,
            input,
            ngap_procedure,
        );
    }
}

fn infer_nas_direction(input: &DecoderInput<'_>, ngap_procedure: u8) -> Direction {
    let inferred = infer_direction(input);
    if inferred != Direction::Unknown {
        return inferred;
    }
    match ngap_procedure {
        15 | 46 => Direction::RanToCore,
        4 | 14 | 29 => Direction::CoreToRan,
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
    if src.contains("gnb") && dst.contains("amf") {
        Direction::RanToCore
    } else if src.contains("amf") && dst.contains("gnb") {
        Direction::CoreToRan
    } else {
        Direction::Unknown
    }
}
fn unsigned(v: &[u8]) -> u64 {
    v.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b))
}
fn be16(v: &[u8]) -> u16 {
    u16::from_be_bytes([v[0], v[1]])
}
fn message_name(code: u8, kind: PduKind) -> &'static str {
    match (code, kind) {
        (4, PduKind::Initiating) => "DownlinkNASTransport",
        (14, PduKind::Initiating) => "InitialContextSetupRequest",
        (14, PduKind::SuccessfulOutcome) => "InitialContextSetupResponse",
        (14, PduKind::UnsuccessfulOutcome) => "InitialContextSetupFailure",
        (15, PduKind::Initiating) => "InitialUEMessage",
        (21, PduKind::Initiating) => "NGSetupRequest",
        (21, PduKind::SuccessfulOutcome) => "NGSetupResponse",
        (21, PduKind::UnsuccessfulOutcome) => "NGSetupFailure",
        (29, PduKind::Initiating) => "PDUSessionResourceSetupRequest",
        (29, PduKind::SuccessfulOutcome) => "PDUSessionResourceSetupResponse",
        (29, PduKind::UnsuccessfulOutcome) => "PDUSessionResourceSetupFailure",
        (41, PduKind::Initiating) => "UEContextReleaseCommand",
        (41, PduKind::SuccessfulOutcome) => "UEContextReleaseComplete",
        (42, PduKind::Initiating) => "UEContextReleaseRequest",
        (44, PduKind::Initiating) => "UERadioCapabilityInfoIndication",
        (46, PduKind::Initiating) => "UplinkNASTransport",
        _ => "UnknownNGAPProcedure",
    }
}
fn ie_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0 => "AllowedNSSAI",
        1 => "AMFName",
        10 => "AMF-UE-NGAP-ID",
        15 => "Cause",
        26 => "FiveG-S-TMSI",
        27 => "GlobalRANNodeID",
        28 => "GUAMI",
        38 => "NAS-PDU",
        21 => "DefaultPagingDRX",
        34 => "MaskedIMEISV",
        53 => "PDUSessionResourceAdmittedList",
        55 => "PDUSessionResourceFailedToSetupListCxtRes",
        60 => "PDUSessionResourceListCxtRelCpl",
        67 => "PDUSessionResourceReleasedListNot",
        70 => "PDUSessionResourceReleasedListRelRes",
        71 => "PDUSessionResourceSetupListCxtReq",
        72 => "PDUSessionResourceSetupListCxtRes",
        74 => "PDUSessionResourceSetupListSUReq",
        75 => "PDUSessionResourceSetupListSURes",
        79 => "PDUSessionResourceToReleaseListRelCmd",
        80 => "PLMNSupportList",
        82 => "RANNodeName",
        85 => "RAN-UE-NGAP-ID",
        90 => "RRCEstablishmentCause",
        94 => "SecurityKey",
        96 => "ServedGUAMIList",
        102 => "SupportedTAList",
        110 => "UEAggregateMaximumBitRate",
        112 => "UEContextRequest",
        113 => "RANPagingPriority",
        114 => "UE-NGAP-IDs",
        117 => "UERadioCapability",
        119 => "UESecurityCapabilities",
        121 => "UserLocationInformation",
        130 => "PDUSessionAggregateMaximumBitRate",
        133 => "PDUSessionResourceListCxtRelReq",
        134 => "PDUSessionType",
        141 => "WarningAreaCoordinates",
        _ => return None,
    })
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
    #[test]
    fn valid_aper_and_optional_ie() {
        let b = pdu(
            0,
            15,
            &[(85, 0, &[0, 4]), (38, 0, &[2, 0x7e, 0]), (112, 1, &[0])],
        );
        let p = parse(&b).unwrap();
        assert_eq!(p.message_name, "InitialUEMessage");
        assert_eq!(p.ies.len(), 3);
        assert_eq!(decode_ie(&p.ies[0]).0.as_deref(), Some("ran_ue_ngap_id=4"));
    }
    #[test]
    fn unknown_ie_is_preserved() {
        let p = parse(&pdu(0, 46, &[(65000, 1, &[1, 2, 3])])).unwrap();
        assert_eq!(p.ies[0].known_name, None);
        assert_eq!(p.ies[0].value, [1, 2, 3]);
    }
    #[test]
    fn nested_sequence_choice_and_optional_fields() {
        let (allowed, status, _) = decode_allowed_nssai(&[0x02, 0x01, 0x01, 0x02, 0x03]);
        assert_eq!(status, DecodeStatus::Decoded);
        assert_eq!(
            allowed.as_deref(),
            Some("allowed_nssai_count=1,sst=1,sd=010203")
        );
        let (location, status, _) = decode_user_location(&[
            0x50, 0x00, 0xf1, 0x10, 0, 0, 0, 1, 0, 0x00, 0xf1, 0x10, 0, 0, 0xc8,
        ]);
        assert_eq!(status, DecodeStatus::Decoded);
        assert!(location.unwrap().contains("nr_cell_id=0x000000010"));
    }
    #[test]
    fn security_capabilities_and_unknown_extension_are_explicit() {
        let (value, status, _) =
            decode_security_capabilities(&[0x1c, 0x00, 0x0e, 0x00, 0x07, 0x00, 0x03, 0x80, 0x00]);
        assert_eq!(status, DecodeStatus::Decoded);
        assert!(value.unwrap().contains("nr_encryption=0xe000"));
        assert_eq!(
            decode_allowed_nssai(&[0x10, 0]).1,
            DecodeStatus::Unsupported
        );
    }
    #[test]
    fn malformed_nested_aper_is_rejected() {
        assert_eq!(decode_allowed_nssai(&[0]).1, DecodeStatus::Malformed);
        assert_eq!(
            decode_user_location(&[0x50, 0]).1,
            DecodeStatus::Unsupported
        );
        let (session, status, _) = decode_pdu_session_list(74, &[0, 0x40, 1, 0xaa]);
        assert_eq!(status, DecodeStatus::Partial);
        assert!(session.unwrap().starts_with("pdu_session_id=1,"));
    }

    #[test]
    fn aggregate_bitrate_accepts_observed_32_bit_and_schema_40_bit_forms() {
        let (value, status, _) =
            decode_aggregate_bitrate(&[0x08, 0x0f, 0xfd, 0xc0, 0x20, 0x0f, 0xfd, 0xc0]);
        assert_eq!(status, DecodeStatus::Decoded);
        assert_eq!(
            value.as_deref(),
            Some("downlink_bps=135265728,uplink_bps=537918912")
        );

        let (value, status, _) =
            decode_aggregate_bitrate(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a]);
        assert_eq!(status, DecodeStatus::Decoded);
        assert_eq!(
            value.as_deref(),
            Some("downlink_bps=4328719365,uplink_bps=25887770890")
        );
        assert_eq!(decode_aggregate_bitrate(&[0; 9]).1, DecodeStatus::Malformed);
    }
    #[test]
    fn malformed_and_unsupported_extension() {
        assert!(parse(&[0, 1, 2]).is_err());
        assert!(parse(&pdu(3, 1, &[])).is_err());
        let mut b = pdu(0, 1, &[]);
        b[4] = 0x80;
        assert!(parse(&b).is_err());
    }

    #[test]
    fn nas_pdu_emits_provenance_linked_child_event() {
        let bytes = pdu(
            0,
            15,
            &[(85, 0, &[0, 3]), (38, 0, &[4, 0x7e, 0x00, 0x44, 0x6f])],
        );
        let packets = vec![PacketReference {
            source_file: "fixture.pcap".into(),
            source_sha256: Some("abc".into()),
            packet_number: 7,
            byte_offset: 20,
            interface_id: 0,
            link_type: Some(276),
            sll2_protocol_type: Some(0x0800),
            sll2_reserved: Some(0),
            sll2_interface_index: Some(2),
            sll2_arphrd_type: Some(1),
            sll2_packet_type: Some(0),
            sll2_address_length: Some(6),
            sll2_address: Some("000000000000".into()),
            captured_length: 90,
            original_length: 90,
        }];
        let timestamp = ExactTimestamp {
            seconds: 1,
            nanoseconds: 2,
            raw_ticks: 1_000_000_002,
            resolution_base: 10,
            resolution_exponent: 9,
        };
        let input = DecoderInput {
            capture_id: "cap",
            packet_references: &packets,
            timestamp: &timestamp,
            interface: "N2",
            source_endpoint: Endpoint {
                address: "10.0.0.1".into(),
                port: Some(38412),
                network_function: Some("gNB".into()),
            },
            destination_endpoint: Endpoint {
                address: "10.0.0.2".into(),
                port: Some(38412),
                network_function: Some("AMF".into()),
            },
            payload: &bytes,
            raw_payload_reference: "sha256:packet",
        };
        let output = NgapDecoder.decode(&input);
        assert_eq!(output.events.len(), 2);
        assert_eq!(output.events[1].protocol, Protocol::Nas5gmm);
        assert_eq!(output.events[1].message_name, "Registration Reject");
        assert_eq!(
            output.events[1].parent_event_id.as_deref(),
            Some(output.events[0].event_id.as_str())
        );
        assert_eq!(
            output.events[1].packet_references,
            output.events[0].packet_references
        );
    }

    #[test]
    fn pdu_session_nas_container_is_bounded_by_aper_length() {
        let ie = NgapIe {
            id: 74,
            criticality: 0,
            value: vec![0x00, 0x40, 0x01, 0x04, 0x7e, 0x00, 0x44, 0x6f, 0xaa],
            known_name: Some("PDUSessionResourceSetupListSUReq"),
        };
        let (nas, offset) = pdu_session_nas_contents(&ie).unwrap();
        assert_eq!(offset, 4);
        assert_eq!(nas, [0x7e, 0x00, 0x44, 0x6f]);
    }
}
#[test]
fn up_transport_tunnel_is_structurally_normalized() {
    let bytes = [
        0xaa, 0x00, 0x8b, 0x00, 0x0a, 0x01, 0xf0, 10, 77, 22, 13, 0, 0, 0xb3, 0xb5,
    ];
    let (ip, teid) = decode_up_transport_tunnel(&bytes).expect("tunnel");
    assert_eq!(ip.to_string(), "10.77.22.13");
    assert_eq!(teid, 0xb3b5);
}

#[test]
fn arbitrary_endpoint_bytes_are_not_tunnel_evidence() {
    let bytes = [10, 77, 22, 13, 0, 0, 0xb3, 0xb5];
    assert!(decode_up_transport_tunnel(&bytes).is_none());
}

#[test]
fn pdu_session_su_req_tags_ul_tunnel_and_session_type() {
    // Synthetic SUReq item: count=0 (1 item), SEQUENCE preamble=0, pDUSessionID=5,
    // then an all-zero prefix padded ahead of recognizable [00 86 00 01 00] (ipv4)
    // and the UP-Transport-Layer-Information marker [00 8b 00 0a 01 f0 ip teid].
    let v = [
        0x00, 0x00, 0x05, // count, preamble, pDUSessionID=5
        0x00, 0x00, 0x00, // s-NSSAI (sst=0, no sd) rough padding
        // id-PDUSessionType marker (IE 134 inside nested transfer): ipv4=0b000xxxxx
        0x00, 0x86, 0x00, 0x01, 0x00,
        // UL NG-U UP TNL Information marker (IE 139 inside nested transfer):
        0x00, 0x8b, 0x00, 0x0a, 0x01, 0xf0,
        10, 77, 11, 22, // transportLayerAddress (IPv4)
        0x00, 0x00, 0xca, 0xfe, // gTP-TEID
    ];
    let (out, status, sensitive) = decode_pdu_session_list(74, &v);
    assert_eq!(status, DecodeStatus::Partial);
    assert!(!sensitive);
    let out = out.expect("some");
    assert!(out.contains("pdu_session_id=5"), "{out}");
    assert!(out.contains("tunnel_ip_ul=10.77.11.22"), "{out}");
    assert!(out.contains("gtp_teid_ul=0xcafe"), "{out}");
    assert!(out.contains("pdu_session_type=ipv4"), "{out}");
}

#[test]
fn pdu_session_su_res_tags_dl_tunnel() {
    let v = [
        0x00, 0x00, 0x07, // count, preamble, pDUSessionID=7
        0x00, 0x00, // padding before transfer OCTET STRING
        0x00, 0x8b, 0x00, 0x0a, 0x01, 0xf0,
        192, 0, 2, 1, // transportLayerAddress (IPv4, TEST-NET-1)
        0x00, 0x00, 0xbe, 0xef, // gTP-TEID
    ];
    let (out, status, _) = decode_pdu_session_list(75, &v);
    assert_eq!(status, DecodeStatus::Partial);
    let out = out.expect("some");
    assert!(out.contains("pdu_session_id=7"), "{out}");
    assert!(out.contains("tunnel_ip_dl=192.0.2.1"), "{out}");
    assert!(out.contains("gtp_teid_dl=0xbeef"), "{out}");
}

#[test]
fn pdu_session_type_marker_does_not_match_arbitrary_bytes() {
    assert_eq!(decode_pdu_session_type_marker(&[0x00, 0x86, 0x40, 0x01, 0x00]), Some("ipv4"));
    assert_eq!(decode_pdu_session_type_marker(&[0x00, 0x86, 0x00, 0x01, 0x40]), Some("ipv4v6"));
    // Length byte != 1 → rejected.
    assert!(decode_pdu_session_type_marker(&[0x00, 0x86, 0x00, 0x02, 0x00]).is_none());
    // Low bits of criticality must be zero.
    assert!(decode_pdu_session_type_marker(&[0x00, 0x86, 0x01, 0x01, 0x00]).is_none());
    // Reserved enum value → rejected.
    assert!(decode_pdu_session_type_marker(&[0x00, 0x86, 0x00, 0x01, 0xa0]).is_none());
}

// The old canonical "one-octet-per-primitive" fixture builders and tests have
// been removed in 0.5.0: see `tests/aper_transfer_fixtures.rs` for the new
// asn1tools-grounded fixtures that exercise the real X.691 walker.
