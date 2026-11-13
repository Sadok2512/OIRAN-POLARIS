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
    is_withheld_key_material, pseudonym, sha256_hex, DecodeStatus, Direction, EvidenceReference,
    EvidenceState, InformationElement, NamedValue, NormalizedEvent, Protocol, PseudonymKey,
};
use plugin_runtime::{
    DecoderCapabilities, DecoderInput, DecoderManifest, DecoderOutput, ProtocolDecoder,
    PLUGIN_API_VERSION,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
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
    pub message_name: String,
    pub ies: Vec<S1apIe>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ErabTunnel {
    erab_id: u8,
    transport_layer_address: String,
    teid: u32,
}

/// Minimal aligned-PER reader for the four E-RAB list types decoded below.
/// It deliberately supports only root values: unknown extension additions are
/// rejected instead of being guessed or scanned byte-wise.
struct AperBits<'a> {
    bytes: &'a [u8],
    bit: usize,
}

impl<'a> AperBits<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, bit: 0 }
    }

    fn read_bit(&mut self) -> Result<bool, String> {
        if self.bit >= self.bytes.len().saturating_mul(8) {
            return Err("E-RAB APER value truncated".into());
        }
        let value = self.bytes[self.bit / 8] & (0x80 >> (self.bit % 8)) != 0;
        self.bit += 1;
        Ok(value)
    }

    fn read_bits(&mut self, count: usize) -> Result<u64, String> {
        if count > 64 {
            return Err("E-RAB APER integer exceeds 64 bits".into());
        }
        let mut value = 0u64;
        for _ in 0..count {
            value = (value << 1) | u64::from(self.read_bit()?);
        }
        Ok(value)
    }

    fn align(&mut self) {
        self.bit = (self.bit + 7) & !7;
    }

    fn read_octets(&mut self, count: usize) -> Result<&'a [u8], String> {
        self.align();
        let start = self.bit / 8;
        let end = start
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| "E-RAB APER octet string truncated".to_string())?;
        self.bit = end * 8;
        Ok(&self.bytes[start..end])
    }

    fn read_open_type(&mut self) -> Result<&'a [u8], String> {
        self.align();
        let start = self.bit / 8;
        let (length, octets) = aper_length(&self.bytes[start..])?;
        self.bit = (start + octets) * 8;
        self.read_octets(length)
    }
}

fn decode_erab_list(id: u16, value: &[u8]) -> Result<Vec<ErabTunnel>, String> {
    let (expected_item_id, request_with_qos, nas_optional) = match id {
        24 => (52, true, true),  // E-RABToBeSetupListCtxtSUReq
        51 => (50, false, false), // E-RABSetupListCtxtSURes
        16 => (17, true, false), // E-RABToBeSetupListBearerSUReq
        28 => (39, false, false), // E-RABSetupListBearerSURes
        _ => return Err(format!("S1AP IE {id} is not an E-RAB setup list")),
    };
    let mut bits = AperBits::new(value);
    let count = bits.read_bits(8)? as usize + 1;
    bits.align();
    let mut tunnels = Vec::with_capacity(count);
    for _ in 0..count {
        let item_id = bits.read_bits(16)? as u16;
        if item_id != expected_item_id {
            return Err(format!(
                "unexpected E-RAB list item id {item_id}, expected {expected_item_id}"
            ));
        }
        let criticality = bits.read_bits(2)?;
        if criticality > 2 {
            return Err("invalid E-RAB item criticality".into());
        }
        bits.align();
        let item = bits.read_open_type()?;
        tunnels.push(decode_erab_item(item, request_with_qos, nas_optional)?);
    }
    Ok(tunnels)
}

fn decode_erab_item(
    value: &[u8],
    request_with_qos: bool,
    nas_optional: bool,
) -> Result<ErabTunnel, String> {
    let mut bits = AperBits::new(value);
    if bits.read_bit()? {
        return Err("extended E-RAB item is unsupported".into());
    }
    let nas_present = if nas_optional { bits.read_bit()? } else { false };
    if bits.read_bit()? {
        return Err("E-RAB item extension container is unsupported".into());
    }
    if bits.read_bit()? {
        return Err("extended E-RAB-ID is unsupported".into());
    }
    let erab_id = bits.read_bits(4)? as u8;

    if request_with_qos {
        skip_erab_qos(&mut bits)?;
    }
    let transport_layer_address = decode_transport_layer_address(&mut bits)?;
    let teid_bytes = bits.read_octets(4)?;
    let teid = u32::from_be_bytes(teid_bytes.try_into().expect("four-byte GTP-TEID"));
    if teid == 0 {
        return Err("E-RAB GTP-TEID is zero".into());
    }

    // The optional/mandatory NAS-PDU follows GTP-TEID. It is intentionally
    // not decoded, hashed, copied or returned by this function.
    let _ = nas_present;
    Ok(ErabTunnel {
        erab_id,
        transport_layer_address,
        teid,
    })
}

fn skip_erab_qos(bits: &mut AperBits<'_>) -> Result<(), String> {
    if bits.read_bit()? {
        return Err("extended E-RAB QoS parameters are unsupported".into());
    }
    let gbr_present = bits.read_bit()?;
    if bits.read_bit()? {
        return Err("E-RAB QoS extension container is unsupported".into());
    }
    bits.align();
    let _qci = bits.read_bits(8)?;
    if bits.read_bit()? {
        return Err("extended allocation/retention priority is unsupported".into());
    }
    if bits.read_bit()? {
        return Err("allocation/retention extension container is unsupported".into());
    }
    let _priority_level = bits.read_bits(4)?;
    let _pre_emption_capability = bits.read_bit()?;
    let _pre_emption_vulnerability = bits.read_bit()?;
    if gbr_present {
        return Err("GBR E-RAB QoS parameters are unsupported".into());
    }
    Ok(())
}

fn decode_transport_layer_address(bits: &mut AperBits<'_>) -> Result<String, String> {
    if bits.read_bit()? {
        return Err("extended TransportLayerAddress is unsupported".into());
    }
    let bit_length = bits.read_bits(8)? as usize + 1;
    if bit_length != 32 {
        return Err(format!(
            "TransportLayerAddress has {bit_length} bits, expected IPv4/32"
        ));
    }
    let address = bits.read_octets(4)?;
    Ok(format!(
        "{}.{}.{}.{}",
        address[0], address[1], address[2], address[3]
    ))
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

/// Libellé TS 36.413 d'un couple (procedureCode, PduKind). Les procédures
/// connues renvoient leur nom canonique ; les codes non mappés retombent
/// sur « S1AP proc <code> <kind> (non mappé) » pour que le `procedureCode`
/// numérique reste observable depuis le livrable API — cf. ANR2 ladder
/// écart 3 (msg09 = code 22, UECapabilityInfoIndication).
fn pdu_kind_label(kind: PduKind) -> &'static str {
    match kind {
        PduKind::Initiating => "initiating",
        PduKind::SuccessfulOutcome => "successfulOutcome",
        PduKind::UnsuccessfulOutcome => "unsuccessfulOutcome",
    }
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

fn decode_ie(ie: &S1apIe, pseudonym_key: &PseudonymKey) -> (Option<String>, DecodeStatus, bool) {
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
            Some(pseudonym(pseudonym_key, "ue-paging-id", &ie.value)),
            DecodeStatus::Partial,
            true,
        ),
        // 2.7.11: SecurityKey carries KeNB*/NH/NCC material. The decoder
        // emits nothing from the raw bytes — no hash, no fragment, no
        // length-prefixed view. The IE is rebuilt downstream by
        // `InformationElement::withheld(ie.id, ie.value.len())`.
        73 => (None, DecodeStatus::Decoded, true),
        75 => (
            Some(format!(
                "gummei_id_sha256={}",
                sha256_hex(&ie.value)
            )),
            DecodeStatus::Partial,
            true,
        ),
        96 => (
            Some(pseudonym(pseudonym_key, "s1ap-s-tmsi", &ie.value)),
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

fn message_name(code: u8, kind: PduKind) -> String {
    // TS 36.413 v16+ §9.1 — table des Elementary Procedures.
    // Audit complet appliqué par le lot « analyzer ladder écarts 1-4 ».
    let canonical: Option<&'static str> = match (code, kind) {
        (0, PduKind::Initiating) => Some("HandoverRequired"),
        (0, PduKind::SuccessfulOutcome) => Some("HandoverCommand"),
        (0, PduKind::UnsuccessfulOutcome) => Some("HandoverPreparationFailure"),
        (1, PduKind::Initiating) => Some("HandoverRequest"),
        (1, PduKind::SuccessfulOutcome) => Some("HandoverRequestAcknowledge"),
        (1, PduKind::UnsuccessfulOutcome) => Some("HandoverFailure"),
        (2, PduKind::Initiating) => Some("HandoverNotify"),
        (3, PduKind::Initiating) => Some("PathSwitchRequest"),
        (3, PduKind::SuccessfulOutcome) => Some("PathSwitchRequestAcknowledge"),
        (3, PduKind::UnsuccessfulOutcome) => Some("PathSwitchRequestFailure"),
        (4, PduKind::Initiating) => Some("HandoverCancel"),
        (4, PduKind::SuccessfulOutcome) => Some("HandoverCancelAcknowledge"),
        (5, PduKind::Initiating) => Some("E-RABSetupRequest"),
        (5, PduKind::SuccessfulOutcome) => Some("E-RABSetupResponse"),
        (6, PduKind::Initiating) => Some("E-RABModifyRequest"),
        (6, PduKind::SuccessfulOutcome) => Some("E-RABModifyResponse"),
        (7, PduKind::Initiating) => Some("E-RABReleaseCommand"),
        (7, PduKind::SuccessfulOutcome) => Some("E-RABReleaseResponse"),
        (8, PduKind::Initiating) => Some("E-RABReleaseIndication"),
        (9, PduKind::Initiating) => Some("InitialContextSetupRequest"),
        (9, PduKind::SuccessfulOutcome) => Some("InitialContextSetupResponse"),
        (9, PduKind::UnsuccessfulOutcome) => Some("InitialContextSetupFailure"),
        (10, PduKind::Initiating) => Some("Paging"),
        (11, PduKind::Initiating) => Some("DownlinkNASTransport"),
        (12, PduKind::Initiating) => Some("InitialUEMessage"),
        (13, PduKind::Initiating) => Some("UplinkNASTransport"),
        (14, PduKind::Initiating) => Some("Reset"),
        (14, PduKind::SuccessfulOutcome) => Some("ResetAcknowledge"),
        (15, PduKind::Initiating) => Some("ErrorIndication"),
        (16, PduKind::Initiating) => Some("NASNonDeliveryIndication"),
        (17, PduKind::Initiating) => Some("S1SetupRequest"),
        (17, PduKind::SuccessfulOutcome) => Some("S1SetupResponse"),
        (17, PduKind::UnsuccessfulOutcome) => Some("S1SetupFailure"),
        (18, PduKind::Initiating) => Some("UEContextReleaseRequest"),
        (19, PduKind::Initiating) => Some("DownlinkS1CDMA2000Tunneling"),
        (20, PduKind::Initiating) => Some("UplinkS1CDMA2000Tunneling"),
        (21, PduKind::Initiating) => Some("UEContextModificationRequest"),
        (21, PduKind::SuccessfulOutcome) => Some("UEContextModificationResponse"),
        (21, PduKind::UnsuccessfulOutcome) => Some("UEContextModificationFailure"),
        // Ajouté lot ladder : msg09 de la capture lab (pkt 31, procedureCode
        // 22, initiating) retombait sur « UnknownS1APProcedure » faute
        // d'entrée dans cette table.
        (22, PduKind::Initiating) => Some("UECapabilityInfoIndication"),
        (23, PduKind::Initiating) => Some("UEContextReleaseCommand"),
        (23, PduKind::SuccessfulOutcome) => Some("UEContextReleaseComplete"),
        (24, PduKind::Initiating) => Some("ENBStatusTransfer"),
        (25, PduKind::Initiating) => Some("MMEStatusTransfer"),
        (26, PduKind::Initiating) => Some("DeactivateTrace"),
        (27, PduKind::Initiating) => Some("TraceStart"),
        (28, PduKind::Initiating) => Some("TraceFailureIndication"),
        (29, PduKind::Initiating) => Some("ENBConfigurationUpdate"),
        (29, PduKind::SuccessfulOutcome) => Some("ENBConfigurationUpdateAcknowledge"),
        (29, PduKind::UnsuccessfulOutcome) => Some("ENBConfigurationUpdateFailure"),
        (30, PduKind::Initiating) => Some("MMEConfigurationUpdate"),
        (30, PduKind::SuccessfulOutcome) => Some("MMEConfigurationUpdateAcknowledge"),
        (30, PduKind::UnsuccessfulOutcome) => Some("MMEConfigurationUpdateFailure"),
        (31, PduKind::Initiating) => Some("LocationReportingControl"),
        (32, PduKind::Initiating) => Some("LocationReportingFailureIndication"),
        (33, PduKind::Initiating) => Some("LocationReport"),
        (34, PduKind::Initiating) => Some("OverloadStart"),
        (35, PduKind::Initiating) => Some("OverloadStop"),
        (36, PduKind::Initiating) => Some("WriteReplaceWarningRequest"),
        (36, PduKind::SuccessfulOutcome) => Some("WriteReplaceWarningResponse"),
        (37, PduKind::Initiating) => Some("ENBDirectInformationTransfer"),
        (38, PduKind::Initiating) => Some("MMEDirectInformationTransfer"),
        (39, PduKind::Initiating) => Some("PrivateMessage"),
        (40, PduKind::Initiating) => Some("ENBConfigurationTransfer"),
        (41, PduKind::Initiating) => Some("MMEConfigurationTransfer"),
        (42, PduKind::Initiating) => Some("CellTrafficTrace"),
        (43, PduKind::Initiating) => Some("KillRequest"),
        (43, PduKind::SuccessfulOutcome) => Some("KillResponse"),
        (44, PduKind::Initiating) => Some("DownlinkUEAssociatedLPPaTransport"),
        (45, PduKind::Initiating) => Some("UplinkUEAssociatedLPPaTransport"),
        (46, PduKind::Initiating) => Some("DownlinkNonUEAssociatedLPPaTransport"),
        (47, PduKind::Initiating) => Some("UplinkNonUEAssociatedLPPaTransport"),
        (48, PduKind::Initiating) => Some("UERadioCapabilityMatchRequest"),
        (48, PduKind::SuccessfulOutcome) => Some("UERadioCapabilityMatchResponse"),
        (49, PduKind::Initiating) => Some("PWSRestartIndication"),
        (50, PduKind::Initiating) => Some("E-RABModificationIndication"),
        (50, PduKind::SuccessfulOutcome) => Some("E-RABModificationConfirm"),
        (51, PduKind::Initiating) => Some("PWSFailureIndication"),
        (52, PduKind::Initiating) => Some("RerouteNASRequest"),
        (53, PduKind::Initiating) => Some("UEContextModificationIndication"),
        (53, PduKind::SuccessfulOutcome) => Some("UEContextModificationConfirm"),
        (54, PduKind::Initiating) => Some("ConnectionEstablishmentIndication"),
        (55, PduKind::Initiating) => Some("UEContextSuspendRequest"),
        (55, PduKind::SuccessfulOutcome) => Some("UEContextSuspendResponse"),
        (56, PduKind::Initiating) => Some("UEContextResumeRequest"),
        (56, PduKind::SuccessfulOutcome) => Some("UEContextResumeResponse"),
        (56, PduKind::UnsuccessfulOutcome) => Some("UEContextResumeFailure"),
        (57, PduKind::Initiating) => Some("NASDeliveryIndication"),
        (58, PduKind::Initiating) => Some("RetrieveUEInformation"),
        (59, PduKind::Initiating) => Some("UEInformationTransfer"),
        (60, PduKind::Initiating) => Some("ENBCPRelocationIndication"),
        (61, PduKind::Initiating) => Some("MMECPRelocationIndication"),
        (62, PduKind::Initiating) => Some("SecondaryRATDataUsageReport"),
        (63, PduKind::Initiating) => Some("UERadioCapabilityIDMappingRequest"),
        (63, PduKind::SuccessfulOutcome) => Some("UERadioCapabilityIDMappingResponse"),
        _ => None,
    };
    match canonical {
        Some(name) => name.to_string(),
        None => format!("S1AP proc {code} ({}, non mappé)", pdu_kind_label(kind)),
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
        28 => "E-RABSetupListBearerSURes",
        33 => "E-RABToBeReleasedList",
        // 2.7.7: identity-bearing IE names replaced by `identity_pseudonym`
        // so the serialised event never carries `tmsi`/`imsi`/`imei` even
        // in an `information_elements[].name` position. See the privacy
        // contract with POLARIS 0.29.16.
        43 => "identity_pseudonym",
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
        75 => "GUMMEI_Context_Identifier",
        80 => "UEIdentityIndexValue",
        87 => "RelativeMMECapacity",
        96 => "identity_pseudonym",
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
                    // Initial Context Setup can carry both a top-level
                    // SecurityKey (KeNB) and NAS-PDU. Neither is exported in
                    // any form: no bytes, digest, length marker or NAS child.
                    if pdu.procedure_code == 9 && matches!(ie.id, 26 | 73) {
                        continue;
                    }
                    if ie.id == 26 {
                        match nas_pdu_contents(&ie.value) {
                            Ok((nas, offset)) => {
                                nas_messages.push(decoder_nas::decode_with_offset(
                                    nas,
                                    offset,
                                    input.pseudonym_key,
                                ));
                            }
                            Err(error) => errors.push(error),
                        }
                    }
                    let erab_list = matches!(ie.id, 16 | 24 | 28 | 51);
                    let (value, ie_status, sensitive) = if erab_list {
                        match decode_erab_list(ie.id, &ie.value) {
                            Ok(tunnels) => {
                                for tunnel in &tunnels {
                                    for (name, value) in [
                                        ("erab_id", tunnel.erab_id.to_string()),
                                        ("erab_teid", format!("0x{:08x}", tunnel.teid)),
                                        (
                                            "transport_layer_address",
                                            tunnel.transport_layer_address.clone(),
                                        ),
                                        (
                                            "tunnel_endpoint_ip",
                                            tunnel.transport_layer_address.clone(),
                                        ),
                                    ] {
                                        identifiers.push(NamedValue {
                                            name: name.into(),
                                            value,
                                            pseudonymized: false,
                                        });
                                    }
                                }
                                let value = tunnels
                                    .iter()
                                    .map(|tunnel| {
                                        format!(
                                            "erab_id={},transport_layer_address={},erab_teid=0x{:08x}",
                                            tunnel.erab_id,
                                            tunnel.transport_layer_address,
                                            tunnel.teid
                                        )
                                    })
                                    .collect::<Vec<_>>()
                                    .join(";");
                                (Some(value), DecodeStatus::Decoded, false)
                            }
                            Err(error) => {
                                errors.push(format!("{}: {error}", ie.known_name.unwrap_or("E-RAB list")));
                                (None, DecodeStatus::Unsupported, false)
                            }
                        }
                    } else {
                        decode_ie(ie, input.pseudonym_key)
                    };
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
                        if matches!(ie.known_name, Some("identity_pseudonym")) {
                            identifiers.push(NamedValue {
                                name: "subscriber_pseudonym".into(),
                                value: v.clone(),
                                pseudonymized: true,
                            });
                        }
                        for pair in v.split(',') {
                            if let Some((key, val)) = pair.split_once('=') {
                                if matches!(
                                    key,
                                    "mme_ue_s1ap_id"
                                        | "enb_ue_s1ap_id"
                                        | "subscriber_pseudonym"
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
                    if is_withheld_key_material("decoder-s1ap", ie.id) {
                        elements.push(InformationElement::withheld(
                            Some(ie.id),
                            ie.value.len() as u32,
                        ));
                    } else {
                        elements.push(InformationElement {
                            id: Some(ie.id),
                            name: ie.known_name.unwrap_or("Unknown IE").into(),
                            length: ie.value.len() as u32,
                            value,
                            // E-RAB request lists can contain a nested NAS-PDU.
                            // The typed bearer coordinates are sufficient
                            // evidence; never retain a digest of the container.
                            raw_sha256: if erab_list {
                                None
                            } else {
                                Some(sha256_hex(&ie.value))
                            },
                            status: ie_status,
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
                    protocol: Protocol::S1ap,
                    message_name: pdu.message_name.clone(),
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

fn infer_eps_nas_direction(input: &DecoderInput<'_>, _procedure: u8) -> Direction {
    // 2.14.4 (ANR2 ladder écart 1) : la direction NAS suit toujours la
    // direction du S1AP porteur, qui elle-même suit strictement le
    // transport. Aucun fallback sur le procedureCode S1AP — il inversait
    // les msg11 (InitialContextSetupResponse eNB→MME) et msg16
    // (UEContextReleaseComplete eNB→MME) de la capture lab.
    infer_direction_from_transport(input)
}

fn kind_number(k: PduKind) -> u32 {
    match k {
        PduKind::Initiating => 0,
        PduKind::SuccessfulOutcome => 1,
        PduKind::UnsuccessfulOutcome => 2,
    }
}

fn infer_direction(i: &DecoderInput<'_>, _procedure: u8) -> Direction {
    // 2.14.4 (ANR2 ladder écart 1) : direction = transport, jamais déduite
    // du nom de procédure. Le code pré-2.14.4 bricolait un fallback
    // procedureCode → (RanToCore | CoreToRan) quand le `network_function`
    // n'était pas résolu, ce qui inversait msg11 et msg16 (deux procédures
    // eNB→MME classées CoreToRan à tort).
    infer_direction_from_transport(i)
}

fn infer_direction_from_transport(i: &DecoderInput<'_>) -> Direction {
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
    let src_is_ran = src.contains("enb") || src.contains("gnb");
    let src_is_core = src.contains("mme") || src.contains("amf");
    let dst_is_ran = dst.contains("enb") || dst.contains("gnb");
    let dst_is_core = dst.contains("mme") || dst.contains("amf");
    if src_is_ran && dst_is_core {
        return Direction::RanToCore;
    }
    if src_is_core && dst_is_ran {
        return Direction::CoreToRan;
    }
    Direction::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_psn_32(value: &str) -> bool {
        value.len() == 36
            && value.starts_with("psn-")
            && value[4..].bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }
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

    #[derive(Default)]
    struct TestBits {
        bytes: Vec<u8>,
        bit: usize,
    }

    impl TestBits {
        fn push_bit(&mut self, value: bool) {
            if self.bit % 8 == 0 {
                self.bytes.push(0);
            }
            if value {
                let last = self.bytes.len() - 1;
                self.bytes[last] |= 0x80 >> (self.bit % 8);
            }
            self.bit += 1;
        }
        fn push_bits(&mut self, value: u64, count: usize) {
            for shift in (0..count).rev() {
                self.push_bit((value >> shift) & 1 != 0);
            }
        }
        fn align(&mut self) {
            while self.bit % 8 != 0 {
                self.push_bit(false);
            }
        }
        fn push_octets(&mut self, value: &[u8]) {
            self.align();
            for byte in value {
                self.push_bits(u64::from(*byte), 8);
            }
        }
        fn finish(mut self) -> Vec<u8> {
            self.align();
            self.bytes
        }
    }

    fn erab_item(
        erab_id: u8,
        address: [u8; 4],
        teid: u32,
        with_qos: bool,
        nas_optional: bool,
    ) -> Vec<u8> {
        let mut bits = TestBits::default();
        bits.push_bit(false); // SEQUENCE extension marker
        if nas_optional {
            bits.push_bit(false); // NAS-PDU absent
        }
        bits.push_bit(false); // IE-Extensions absent
        bits.push_bit(false); // E-RAB-ID root value
        bits.push_bits(u64::from(erab_id), 4);
        if with_qos {
            bits.push_bit(false); // QoS extension marker
            bits.push_bit(false); // GBR absent
            bits.push_bit(false); // QoS IE-Extensions absent
            bits.align();
            bits.push_bits(9, 8); // QCI 9
            bits.push_bit(false); // ARP extension marker
            bits.push_bit(false); // ARP IE-Extensions absent
            bits.push_bits(15, 4); // priority level
            bits.push_bit(false); // pre-emption capability
            bits.push_bit(false); // pre-emption vulnerability
        }
        bits.push_bit(false); // TransportLayerAddress root length
        bits.push_bits(31, 8); // 32 bits, lower bound is one
        bits.push_octets(&address);
        bits.push_octets(&teid.to_be_bytes());
        bits.finish()
    }

    fn erab_list(item_id: u16, item: &[u8]) -> Vec<u8> {
        let mut bits = TestBits::default();
        bits.push_bits(0, 8); // one item (1..256)
        bits.align();
        bits.push_bits(u64::from(item_id), 16);
        bits.push_bits(1, 2); // criticality ignore
        bits.align();
        bits.push_octets(&[item.len() as u8]);
        bits.push_octets(item);
        bits.finish()
    }

    fn synthetic_input<'a>(
        bytes: &'a [u8],
        packets: &'a [PacketReference],
        timestamp: &'a ExactTimestamp,
        key: &'a PseudonymKey,
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
            pseudonym_key: key,
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
        let key = PseudonymKey::from_bytes([0x11; 32]);
        let input = synthetic_input(&bytes, &packets, &timestamp, &key, "eNB", "MME");
        let out = S1apDecoder.decode(&input);
        assert_eq!(out.events.len(), 2);
        let event = &out.events[0];
        assert_eq!(event.protocol, Protocol::S1ap);
        assert_eq!(event.message_name, "InitialUEMessage");
        assert_eq!(event.direction, Direction::RanToCore);
        let identity_ie = event
            .information_elements
            .iter()
            .find(|ie| ie.name == "identity_pseudonym")
            .expect("identity_pseudonym IE");
        assert_eq!(identity_ie.status, DecodeStatus::Decoded);
        assert!(identity_ie
            .value
            .as_deref()
            .map(is_psn_32)
            .unwrap_or(false));
        let subscriber = event
            .session_identifiers
            .iter()
            .find(|v| v.name == "subscriber_pseudonym")
            .expect("subscriber_pseudonym identifier");
        assert!(subscriber.pseudonymized);
        assert!(subscriber.value.starts_with("psn-"));
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
            .find(|v| v.name == "subscriber_pseudonym")
            .expect("subscriber_pseudonym");
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
    fn decodes_ics_request_and_response_erab_tunnels_without_sensitive_ies() {
        let request_item = erab_item(5, [10, 77, 11, 13], 0x0000_7804, true, true);
        let response_item = erab_item(5, [10, 77, 11, 20], 0x0000_0001, false, false);
        let request_list = erab_list(52, &request_item);
        let response_list = erab_list(50, &response_item);
        let security_key = [0x5a; 32];
        let nas = [0x02, 0x07, 0x42];
        let request = pdu(
            0,
            9,
            &[(24, 0, &request_list), (26, 0, &nas), (73, 0, &security_key)],
        );
        let response = pdu(1, 9, &[(51, 1, &response_list)]);
        let (packets, timestamp) = fixtures();
        let key = PseudonymKey::from_bytes([0x11; 32]);

        for (bytes, src, dst, address, teid) in [
            (&request, "MME", "eNB", "10.77.11.13", "0x00007804"),
            (&response, "eNB", "MME", "10.77.11.20", "0x00000001"),
        ] {
            let input = synthetic_input(bytes, &packets, &timestamp, &key, src, dst);
            let output = S1apDecoder.decode(&input);
            assert_eq!(output.status, DecodeStatus::Decoded);
            assert_eq!(output.events.len(), 1, "ICS must not emit a NAS child");
            let event = &output.events[0];
            assert_eq!(
                event
                    .session_identifiers
                    .iter()
                    .find(|value| value.name == "erab_teid")
                    .map(|value| value.value.as_str()),
                Some(teid)
            );
            assert_eq!(
                event
                    .session_identifiers
                    .iter()
                    .find(|value| value.name == "transport_layer_address")
                    .map(|value| value.value.as_str()),
                Some(address)
            );
            let json = event.to_json();
            assert!(!json.contains("NAS-PDU"));
            assert!(!json.contains("SecurityKey"));
            assert!(!json.contains(&sha256_hex(&security_key)));
        }
    }

    #[test]
    fn decodes_erab_setup_request_and_response_lists() {
        let request_item = erab_item(5, [192, 0, 2, 13], 0x0102_0304, true, false);
        let response_item = erab_item(5, [192, 0, 2, 20], 0x0506_0708, false, false);
        for (kind, list_id, item_id, item, expected) in [
            (0, 16, 17, request_item.as_slice(), "0x01020304"),
            (1, 28, 39, response_item.as_slice(), "0x05060708"),
        ] {
            let list = erab_list(item_id, item);
            let bytes = pdu(kind, 5, &[(list_id, 1, &list)]);
            let (packets, timestamp) = fixtures();
            let key = PseudonymKey::from_bytes([0x22; 32]);
            let input = synthetic_input(&bytes, &packets, &timestamp, &key, "MME", "eNB");
            let output = S1apDecoder.decode(&input);
            assert_eq!(output.status, DecodeStatus::Decoded);
            assert!(output.events[0]
                .session_identifiers
                .iter()
                .any(|value| value.name == "erab_teid" && value.value == expected));
        }
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
        let key = PseudonymKey::from_bytes([0x11; 32]);
        let input = synthetic_input(&bytes, &packets, &timestamp, &key, "MME", "eNB");
        let out = S1apDecoder.decode(&input);
        assert_eq!(out.events.len(), 1);
        let event = &out.events[0];
        assert_eq!(event.message_name, "Paging");
        assert_eq!(event.direction, Direction::CoreToRan);
        let paging_id = event
            .session_identifiers
            .iter()
            .find(|v| v.name == "subscriber_pseudonym")
            .expect("subscriber_pseudonym identifier");
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
        let key = PseudonymKey::from_bytes([0x11; 32]);
        let input = synthetic_input(&bytes, &packets, &timestamp, &key, "eNB", "MME");
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

    #[test]
    fn initial_context_setup_request_omits_security_key_payload_entirely() {
        // 2.7.11: SecurityKey (S1AP IE 73) carries KeNB*/NH/NCC. The
        // normalised event must keep the IE's length but surface no bytes,
        // no hash and no sibling identifier. Synthetic 32-byte value stands
        // in for KeNB* — the raw bytes are a pattern 0x4B, 0x65...; the
        // test proves they do not reach the exported event.
        let mme_ue = &[0x00, 0x01];
        let security_key = [0x4b, 0x65, 0x4e, 0x42, 0x2a, 0x53, 0x59, 0x4e, 0x54, 0x48, 0x45,
            0x54, 0x49, 0x43, 0x4b, 0x65, 0x59, 0x4d, 0x41, 0x54, 0x45, 0x52, 0x49, 0x41, 0x4c,
            0x33, 0x32, 0x62, 0x79, 0x74, 0x65, 0x73];
        let bytes = pdu(0, 9, &[(0, 0, mme_ue), (73, 0, &security_key)]);
        let (packets, timestamp) = fixtures();
        let key = PseudonymKey::from_bytes([0x11; 32]);
        let input = synthetic_input(&bytes, &packets, &timestamp, &key, "MME", "eNB");
        let out = S1apDecoder.decode(&input);
        assert_eq!(out.events.len(), 1);
        let event = &out.events[0];
        assert_eq!(event.message_name, "InitialContextSetupRequest");
        assert!(event
            .information_elements
            .iter()
            .all(|ie| ie.id != Some(73) && ie.id != Some(26)));
        // No session identifier carries the key or its hash.
        for sid in &event.session_identifiers {
            assert!(
                !sid.name.contains("security_key") && !sid.value.contains("security_key"),
                "session identifier leaks security_key: {sid:?}"
            );
            assert!(
                !sid.value.contains("4b654e42"),
                "session identifier leaks raw key bytes: {sid:?}"
            );
        }
        // Serialised event contains no fragment of the raw key bytes and
        // no digest of them.
        let serialised = event.to_json();
        assert!(!serialised.contains("4b654e42"));
        assert!(!serialised.contains("security_key_sha256"));
        // The hex representation of the raw key must not appear anywhere.
        let hex = security_key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(!serialised.contains(&hex));
        let sha256 = {
            let mut h = event_schema::Sha256Hasher::new();
            h.update(&security_key);
            h.finish_hex()
        };
        assert!(
            !serialised.contains(&sha256),
            "serialised event contains the sha256 of the raw SecurityKey"
        );
    }
}
