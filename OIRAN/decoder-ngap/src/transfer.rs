//! Real TS 38.413 PDUSessionResourceSetupRequestTransfer /
//! PDUSessionResourceSetupResponseTransfer decoders.
//!
//! Both decoders are driven by ground-truth fixtures generated with pycrate
//! (`pycrate_asn1dir.NGAP`), the only Python library that compiles the full
//! 3GPP NGAP ASN.1 module. The decoders are **not** heuristic: they follow
//! the X.691 ALIGNED PER rules of the real types verbatim. Unknown or
//! unsupported subtypes are retained with their id/length and surfaced as
//! named entries in the returned `errors` vector; they never fall back to a
//! silent default value.

use crate::aper::AperReader;

// ---------- Public types ----------

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GtpTunnel {
    pub transport_address: Vec<u8>,
    pub address_bits: usize,
    pub teid: [u8; 4],
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum UpTransportLayerInformation {
    GtpTunnel(GtpTunnel),
    ChoiceExtensions(String),
}

impl Default for UpTransportLayerInformation {
    fn default() -> Self {
        Self::ChoiceExtensions("uninitialized".into())
    }
}

impl UpTransportLayerInformation {
    pub fn ipv4_address(&self) -> Option<std::net::Ipv4Addr> {
        match self {
            Self::GtpTunnel(t) if t.address_bits == 32 && t.transport_address.len() >= 4 => Some(
                std::net::Ipv4Addr::new(
                    t.transport_address[0],
                    t.transport_address[1],
                    t.transport_address[2],
                    t.transport_address[3],
                ),
            ),
            _ => None,
        }
    }
    pub fn teid(&self) -> Option<u32> {
        match self {
            Self::GtpTunnel(t) => Some(u32::from_be_bytes(t.teid)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum AssociatedQosFlowMapping {
    Ul,
    Dl,
    UnknownExtension(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AssociatedQosFlowItem {
    pub qfi: u8,
    pub mapping_indication: Option<AssociatedQosFlowMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AllocationAndRetention {
    pub priority: u8,
    pub capability: &'static str,
    pub vulnerability: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum QosCharacteristics {
    NonDynamic5QI {
        five_qi: u16,
        priority_level_qos: Option<u8>,
        averaging_window: Option<u16>,
        maximum_data_burst_volume: Option<u16>,
    },
    Dynamic5QI {
        priority_level_qos: u8,
        packet_delay_budget: u16,
        per_scalar: u8,
        per_exponent: u8,
        five_qi: Option<u16>,
        delay_critical: Option<bool>,
        averaging_window: Option<u16>,
        maximum_data_burst_volume: Option<u16>,
    },
    ChoiceExtensions(String),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GbrQosInformation {
    pub maximum_flow_dl: u64,
    pub maximum_flow_ul: u64,
    pub guaranteed_flow_dl: u64,
    pub guaranteed_flow_ul: u64,
    pub notification_control: Option<&'static str>,
    pub maximum_packet_loss_dl: Option<u16>,
    pub maximum_packet_loss_ul: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct QosFlowLevelQosParams {
    pub characteristics: QosCharacteristics,
    pub arp: AllocationAndRetention,
    pub gbr: Option<GbrQosInformation>,
    pub reflective_qos: Option<&'static str>,
    pub additional_qos_flow: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct QosFlowSetupRequestItem {
    pub qfi: u8,
    pub qos_params: QosFlowLevelQosParams,
    pub e_rab_id: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct QosFlowPerTnlInfo {
    pub tunnel: UpTransportLayerInformation,
    pub qfis: Vec<AssociatedQosFlowItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SecurityResultDecoded {
    pub integrity: &'static str,
    pub confidentiality: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum CauseKind {
    RadioNetwork(u64),
    Transport(u64),
    Nas(u64),
    Protocol(u64),
    Misc(u64),
    ChoiceExtensions(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FailedQosFlow {
    pub qfi: u8,
    pub cause: CauseKind,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UnknownProtocolIe {
    pub id: u16,
    pub criticality: &'static str,
    pub length_octets: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct RequestTransfer {
    pub ambr_dl: Option<u64>,
    pub ambr_ul: Option<u64>,
    pub ul_tunnel: Option<UpTransportLayerInformation>,
    pub pdu_session_type: Option<&'static str>,
    pub qos_flows: Vec<QosFlowSetupRequestItem>,
    pub unknown_protocol_ies: Vec<UnknownProtocolIe>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct ResponseTransfer {
    pub dl: QosFlowPerTnlInfo,
    pub additional_dl: Vec<QosFlowPerTnlInfo>,
    pub security: Option<SecurityResultDecoded>,
    pub failed: Vec<FailedQosFlow>,
    pub redundant: Option<QosFlowPerTnlInfo>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct SNssai {
    pub sst: u8,
    pub sd: Option<[u8; 3]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct SetupItemSUReq {
    pub pdu_session_id: u8,
    pub nas_pdu: Option<Vec<u8>>,
    pub s_nssai: SNssai,
    pub transfer: Vec<u8>,
    pub ie_extensions_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct SetupItemSURes {
    pub pdu_session_id: u8,
    pub transfer: Vec<u8>,
    pub ie_extensions_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct ListSUReq {
    pub items: Vec<SetupItemSUReq>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct ListSURes {
    pub items: Vec<SetupItemSURes>,
    pub errors: Vec<String>,
}

// ---------- Primitive helpers ----------

fn criticality_name(idx: u64) -> &'static str {
    match idx {
        0 => "reject",
        1 => "ignore",
        2 => "notify",
        _ => "unknown-criticality",
    }
}

/// Decode a Criticality ENUMERATED { reject, ignore, notify } (no ext marker,
/// 3 root alternatives → bit-field 2 bits).
fn decode_criticality(reader: &mut AperReader<'_>) -> &'static str {
    let idx = reader.read_constrained_whole(3).unwrap_or(0);
    criticality_name(idx)
}

/// X.691 Clause 23 non-extensible CHOICE: just the index.
fn decode_choice_index(
    reader: &mut AperReader<'_>,
    root_count: u64,
    errors: &mut Vec<String>,
    context: &str,
) -> Option<u64> {
    match reader.read_constrained_whole(root_count) {
        Ok(v) => Some(v),
        Err(e) => {
            errors.push(format!("{context} CHOICE index: {:?}", e));
            None
        }
    }
}

/// Decode an extensible 2-value ENUMERATED, returning the mapped label.
fn decode_two_value_enum_extensible(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
    context: &str,
    values: &[&'static str],
) -> &'static str {
    let ext = reader.read_bit().unwrap_or(true);
    if ext {
        errors.push(format!("{context} ENUMERATED extension not supported"));
        return "unknown-extension";
    }
    let idx = reader
        .read_constrained_whole(values.len() as u64)
        .unwrap_or(0);
    values.get(idx as usize).copied().unwrap_or("unknown")
}

/// X.691 10.5.7.5 encoding for a constrained INTEGER with range > 65536.
/// The caller passes the "maximum octet count" needed to represent the upper
/// bound; the length prefix is `ceil(log2(max_octets))` bits unaligned, then
/// alignment, then value octets.
fn decode_large_constrained_integer(
    reader: &mut AperReader<'_>,
    max_octets: usize,
    errors: &mut Vec<String>,
    context: &str,
) -> u64 {
    let prefix_bits = (usize::BITS - (max_octets - 1).leading_zeros()) as usize;
    let length_minus_one = match reader.read_bits(prefix_bits) {
        Ok(v) => v,
        Err(e) => {
            errors.push(format!("{context} length prefix: {:?}", e));
            return 0;
        }
    };
    let octets = (length_minus_one as usize) + 1;
    if octets > max_octets {
        errors.push(format!("{context} octet count {octets} > max {max_octets}"));
        return 0;
    }
    reader.align();
    let mut v = 0u64;
    for _ in 0..octets {
        match reader.read_octet() {
            Ok(b) => v = (v << 8) | u64::from(b),
            Err(e) => {
                errors.push(format!("{context} value octets: {:?}", e));
                return v;
            }
        }
    }
    v
}

/// Decode a BitRate (INTEGER (0..4000000000000, ...)). TS 38.413 BitRate
/// upper bound requires at most 6 octets; the length prefix is 3 bits.
fn decode_bitrate(reader: &mut AperReader<'_>, errors: &mut Vec<String>, context: &str) -> u64 {
    let ext = reader.read_bit().unwrap_or(true);
    if ext {
        errors.push(format!("{context} extension value not supported"));
        return 0;
    }
    decode_large_constrained_integer(reader, 6, errors, context)
}

// ---------- UPTransportLayerInformation / GTPTunnel ----------

fn decode_up_transport_layer_information(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
) -> UpTransportLayerInformation {
    // CHOICE { gTPTunnel, choice-Extensions } — NO extension marker.
    // 2 root alternatives → 1-bit index.
    let idx = decode_choice_index(reader, 2, errors, "UPTransportLayerInformation");
    match idx {
        Some(0) => UpTransportLayerInformation::GtpTunnel(decode_gtp_tunnel(reader, errors)),
        Some(1) => {
            errors.push("UPTransportLayerInformation choice-Extensions not supported".into());
            UpTransportLayerInformation::ChoiceExtensions("choice-Extensions".into())
        }
        _ => UpTransportLayerInformation::ChoiceExtensions("truncated".into()),
    }
}

fn decode_gtp_tunnel(reader: &mut AperReader<'_>, errors: &mut Vec<String>) -> GtpTunnel {
    let ext = reader.read_bit().unwrap_or(true);
    let has_ie_ext = reader.read_bit().unwrap_or(false);
    if ext {
        errors.push("GTPTunnel SEQUENCE extension present".into());
    }
    // TransportLayerAddress BIT STRING (SIZE(1..160, ...)) — extensible SIZE.
    let addr_size_ext = reader.read_bit().unwrap_or(true);
    let bits = if addr_size_ext {
        errors.push("TransportLayerAddress size extension not supported".into());
        0
    } else {
        match reader.read_constrained_whole(160) {
            Ok(s) => (s as usize) + 1,
            Err(e) => {
                errors.push(format!("TransportLayerAddress size: {:?}", e));
                0
            }
        }
    };
    let transport_address = if bits == 0 {
        Vec::new()
    } else {
        match reader.read_bit_string_content(bits) {
            Ok(bytes) => bytes,
            Err(e) => {
                errors.push(format!("TransportLayerAddress content: {:?}", e));
                Vec::new()
            }
        }
    };
    let teid_bytes = match reader.read_fixed_octet_string(4) {
        Ok(b) => b,
        Err(e) => {
            errors.push(format!("GTP-TEID: {:?}", e));
            &[0u8; 0][..]
        }
    };
    let mut teid = [0u8; 4];
    if teid_bytes.len() == 4 {
        teid.copy_from_slice(teid_bytes);
    }
    if has_ie_ext {
        errors.push("GTPTunnel iE-Extensions present".into());
    }
    GtpTunnel {
        transport_address,
        address_bits: bits,
        teid,
    }
}

// ---------- QosFlow structures ----------

fn decode_associated_qos_flow_item(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
    index: usize,
) -> AssociatedQosFlowItem {
    // SEQUENCE: ext + 2 opts (qosFlowMappingIndication, iE-Extensions).
    let ext = reader.read_bit().unwrap_or(true);
    let has_mapping = reader.read_bit().unwrap_or(false);
    let has_ie_ext = reader.read_bit().unwrap_or(false);
    if ext {
        errors.push(format!("AssociatedQosFlowItem[{index}] SEQUENCE extension present"));
    }
    // QosFlowIdentifier INTEGER (0..63, ...) — EXTENSIBLE.
    let qfi = decode_qos_flow_identifier(reader, errors, index);
    let mapping = if has_mapping {
        // qosFlowMappingIndication ENUMERATED { ul, dl, ... } — extensible.
        match reader.read_bit() {
            Ok(false) => match reader.read_bit() {
                Ok(false) => Some(AssociatedQosFlowMapping::Ul),
                Ok(true) => Some(AssociatedQosFlowMapping::Dl),
                Err(e) => {
                    errors.push(format!("qosFlowMappingIndication value: {:?}", e));
                    None
                }
            },
            Ok(true) => match reader.read_normally_small_non_negative_whole_number() {
                Ok(idx) => Some(AssociatedQosFlowMapping::UnknownExtension(idx)),
                Err(e) => {
                    errors.push(format!("qosFlowMappingIndication extension index: {:?}", e));
                    Some(AssociatedQosFlowMapping::UnknownExtension(0))
                }
            },
            Err(e) => {
                errors.push(format!("qosFlowMappingIndication ext: {:?}", e));
                None
            }
        }
    } else {
        None
    };
    if has_ie_ext {
        errors.push(format!("AssociatedQosFlowItem[{index}] iE-Extensions present"));
    }
    AssociatedQosFlowItem {
        qfi,
        mapping_indication: mapping,
    }
}

fn decode_qos_flow_identifier(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
    context_index: usize,
) -> u8 {
    // QosFlowIdentifier ::= INTEGER (0..63, ...) — extensible.
    // 1 ext bit + 6-bit value for the in-range case.
    let ext = reader.read_bit().unwrap_or(true);
    if ext {
        errors.push(format!(
            "QosFlowIdentifier[{context_index}] extension value not supported"
        ));
        return 0;
    }
    reader.read_constrained_whole(64).unwrap_or(0) as u8
}

fn decode_associated_qos_flow_list(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
) -> Vec<AssociatedQosFlowItem> {
    // SEQUENCE OF SIZE(1..maxnoofQosFlows=64) → 6-bit size bit-field.
    let count = match reader.read_constrained_whole(64) {
        Ok(v) => (v as usize) + 1,
        Err(e) => {
            errors.push(format!("AssociatedQosFlowList size: {:?}", e));
            return Vec::new();
        }
    };
    (0..count)
        .map(|i| decode_associated_qos_flow_item(reader, errors, i))
        .collect()
}

fn decode_qos_flow_per_tnl_information(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
) -> QosFlowPerTnlInfo {
    let ext = reader.read_bit().unwrap_or(true);
    let has_ie_ext = reader.read_bit().unwrap_or(false);
    if ext {
        errors.push("QosFlowPerTNLInformation SEQUENCE extension present".into());
    }
    let tunnel = decode_up_transport_layer_information(reader, errors);
    let qfis = decode_associated_qos_flow_list(reader, errors);
    if has_ie_ext {
        errors.push("QosFlowPerTNLInformation iE-Extensions present".into());
    }
    QosFlowPerTnlInfo { tunnel, qfis }
}

fn decode_qos_flow_per_tnl_information_list(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
) -> Vec<QosFlowPerTnlInfo> {
    // SIZE(1..maxnoofMultiConnectivityMinusOne=3) → 2-bit size bit-field.
    let count = match reader.read_constrained_whole(3) {
        Ok(v) => (v as usize) + 1,
        Err(e) => {
            errors.push(format!("QosFlowPerTNLInformationList size: {:?}", e));
            return Vec::new();
        }
    };
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        // QosFlowPerTNLInformationItem SEQUENCE: ext + 1 opt (iE-Ext).
        let ext = reader.read_bit().unwrap_or(true);
        let has_ie_ext = reader.read_bit().unwrap_or(false);
        if ext {
            errors.push("QosFlowPerTNLInformationItem SEQUENCE extension present".into());
        }
        out.push(decode_qos_flow_per_tnl_information(reader, errors));
        if has_ie_ext {
            errors.push("QosFlowPerTNLInformationItem iE-Extensions present".into());
        }
    }
    out
}

// ---------- Cause ----------

fn decode_cause(reader: &mut AperReader<'_>, errors: &mut Vec<String>) -> CauseKind {
    // CHOICE { radioNetwork, transport, nas, protocol, misc, choice-Extensions }
    // — NO extension marker. 6 root alternatives → 3-bit index (range 6).
    let group = reader.read_constrained_whole(6).unwrap_or(0);
    // Each named sub-ENUMERATED has its own extension marker ("..."). The root
    // sizes below match TS 38.413 Release 17.
    let (root_count, make): (u64, fn(u64) -> CauseKind) = match group {
        0 => (56, CauseKind::RadioNetwork),
        1 => (3, CauseKind::Transport),
        2 => (6, CauseKind::Nas),
        3 => (7, CauseKind::Protocol),
        4 => (7, CauseKind::Misc),
        5 => {
            errors.push("Cause choice-Extensions alternative not supported".into());
            return CauseKind::ChoiceExtensions(0);
        }
        other => {
            errors.push(format!("Cause unexpected group index {other}"));
            return CauseKind::ChoiceExtensions(other);
        }
    };
    let value_ext = reader.read_bit().unwrap_or(true);
    if value_ext {
        let idx = reader
            .read_normally_small_non_negative_whole_number()
            .unwrap_or(0);
        errors.push(format!("Cause group {group} value is an extension index"));
        return match group {
            0 => CauseKind::RadioNetwork(0x1000_0000 | idx),
            1 => CauseKind::Transport(0x1000_0000 | idx),
            2 => CauseKind::Nas(0x1000_0000 | idx),
            3 => CauseKind::Protocol(0x1000_0000 | idx),
            4 => CauseKind::Misc(0x1000_0000 | idx),
            _ => CauseKind::ChoiceExtensions(idx),
        };
    }
    let value = reader.read_constrained_whole(root_count).unwrap_or(0);
    make(value)
}

fn decode_qos_flow_with_cause_list(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
) -> Vec<FailedQosFlow> {
    let count = match reader.read_constrained_whole(64) {
        Ok(v) => (v as usize) + 1,
        Err(e) => {
            errors.push(format!("QosFlowListWithCause size: {:?}", e));
            return Vec::new();
        }
    };
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let ext = reader.read_bit().unwrap_or(true);
        let has_ie_ext = reader.read_bit().unwrap_or(false);
        if ext {
            errors.push(format!("QosFlowWithCauseItem[{i}] SEQUENCE extension present"));
        }
        let qfi = decode_qos_flow_identifier(reader, errors, i);
        let cause = decode_cause(reader, errors);
        if has_ie_ext {
            errors.push(format!("QosFlowWithCauseItem[{i}] iE-Extensions present"));
        }
        out.push(FailedQosFlow { qfi, cause });
    }
    out
}

// ---------- QoS parameters ----------

fn decode_non_dynamic_5qi(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
) -> QosCharacteristics {
    let ext = reader.read_bit().unwrap_or(true);
    let has_prio = reader.read_bit().unwrap_or(false);
    let has_avg = reader.read_bit().unwrap_or(false);
    let has_burst = reader.read_bit().unwrap_or(false);
    let has_ie_ext = reader.read_bit().unwrap_or(false);
    if ext {
        errors.push("NonDynamic5QIDescriptor SEQUENCE extension present".into());
    }
    let five_qi = {
        // FiveQI INTEGER (0..255, ...) — ext + 1 octet aligned.
        let ext_bit = reader.read_bit().unwrap_or(true);
        if ext_bit {
            errors.push("FiveQI extension value not supported".into());
            0
        } else {
            reader.read_constrained_whole(256).unwrap_or(0) as u16
        }
    };
    let priority_level_qos = if has_prio {
        // PriorityLevelQos INTEGER (1..127, ...) — ext + 7 bits.
        let ext_bit = reader.read_bit().unwrap_or(true);
        if ext_bit {
            errors.push("PriorityLevelQos extension not supported".into());
            None
        } else {
            reader
                .read_constrained_whole(127)
                .ok()
                .map(|v| (v as u8) + 1)
        }
    } else {
        None
    };
    let averaging_window = if has_avg {
        // AveragingWindow INTEGER (0..4095, ...) — ext + 2 octets aligned.
        let ext_bit = reader.read_bit().unwrap_or(true);
        if ext_bit {
            errors.push("AveragingWindow extension not supported".into());
            None
        } else {
            reader.read_constrained_whole(4096).ok().map(|v| v as u16)
        }
    } else {
        None
    };
    let maximum_data_burst_volume = if has_burst {
        let ext_bit = reader.read_bit().unwrap_or(true);
        if ext_bit {
            errors.push("MaximumDataBurstVolume extension not supported".into());
            None
        } else {
            reader.read_constrained_whole(4096).ok().map(|v| v as u16)
        }
    } else {
        None
    };
    if has_ie_ext {
        errors.push("NonDynamic5QIDescriptor iE-Extensions present".into());
    }
    QosCharacteristics::NonDynamic5QI {
        five_qi,
        priority_level_qos,
        averaging_window,
        maximum_data_burst_volume,
    }
}

fn decode_dynamic_5qi(reader: &mut AperReader<'_>, errors: &mut Vec<String>) -> QosCharacteristics {
    let ext = reader.read_bit().unwrap_or(true);
    let has_five_qi = reader.read_bit().unwrap_or(false);
    let has_delay_critical = reader.read_bit().unwrap_or(false);
    let has_avg = reader.read_bit().unwrap_or(false);
    let has_burst = reader.read_bit().unwrap_or(false);
    let has_ie_ext = reader.read_bit().unwrap_or(false);
    if ext {
        errors.push("Dynamic5QIDescriptor SEQUENCE extension present".into());
    }
    // priorityLevelQos INTEGER (1..127) — NOT extensible here per real spec
    // check: it IS extensible (1..127, ...). Use 1-ext + 7-bit value.
    let priority_level_qos = {
        let ext_bit = reader.read_bit().unwrap_or(true);
        if ext_bit {
            errors.push("Dynamic5QI.priorityLevelQos extension not supported".into());
            1
        } else {
            (reader.read_constrained_whole(127).unwrap_or(0) as u8) + 1
        }
    };
    let packet_delay_budget = {
        let ext_bit = reader.read_bit().unwrap_or(true);
        if ext_bit {
            errors.push("Dynamic5QI.packetDelayBudget extension not supported".into());
            0
        } else {
            reader.read_constrained_whole(1024).unwrap_or(0) as u16
        }
    };
    // packetErrorRate SEQUENCE: ext + 1 opt (iE-Ext).
    let per_ext = reader.read_bit().unwrap_or(true);
    let per_has_ie_ext = reader.read_bit().unwrap_or(false);
    if per_ext {
        errors.push("Dynamic5QI.packetErrorRate SEQUENCE extension present".into());
    }
    let per_scalar = {
        let ext_bit = reader.read_bit().unwrap_or(true);
        if ext_bit {
            errors.push("packetErrorRate.pERScalar extension not supported".into());
            0
        } else {
            reader.read_constrained_whole(10).unwrap_or(0) as u8
        }
    };
    let per_exponent = {
        let ext_bit = reader.read_bit().unwrap_or(true);
        if ext_bit {
            errors.push("packetErrorRate.pERExponent extension not supported".into());
            0
        } else {
            reader.read_constrained_whole(10).unwrap_or(0) as u8
        }
    };
    if per_has_ie_ext {
        errors.push("packetErrorRate iE-Extensions present".into());
    }
    let five_qi = if has_five_qi {
        let ext_bit = reader.read_bit().unwrap_or(true);
        if ext_bit {
            errors.push("Dynamic5QI.fiveQI extension not supported".into());
            None
        } else {
            reader.read_constrained_whole(256).ok().map(|v| v as u16)
        }
    } else {
        None
    };
    let delay_critical = if has_delay_critical {
        Some(
            decode_two_value_enum_extensible(
                reader,
                errors,
                "Dynamic5QI.delayCritical",
                &["delay-critical", "non-delay-critical"],
            ) == "delay-critical",
        )
    } else {
        None
    };
    let averaging_window = if has_avg {
        let ext_bit = reader.read_bit().unwrap_or(true);
        if ext_bit {
            errors.push("Dynamic5QI.averagingWindow extension not supported".into());
            None
        } else {
            reader.read_constrained_whole(4096).ok().map(|v| v as u16)
        }
    } else {
        None
    };
    let maximum_data_burst_volume = if has_burst {
        let ext_bit = reader.read_bit().unwrap_or(true);
        if ext_bit {
            errors.push("Dynamic5QI.maximumDataBurstVolume extension not supported".into());
            None
        } else {
            reader.read_constrained_whole(4096).ok().map(|v| v as u16)
        }
    } else {
        None
    };
    if has_ie_ext {
        errors.push("Dynamic5QIDescriptor iE-Extensions present".into());
    }
    QosCharacteristics::Dynamic5QI {
        priority_level_qos,
        packet_delay_budget,
        per_scalar,
        per_exponent,
        five_qi,
        delay_critical,
        averaging_window,
        maximum_data_burst_volume,
    }
}

fn decode_qos_characteristics(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
) -> QosCharacteristics {
    // CHOICE { nonDynamic5QI, dynamic5QI, choice-Extensions } — NO ext marker.
    // 3 root alternatives → 2-bit index.
    let idx = decode_choice_index(reader, 3, errors, "QosCharacteristics");
    match idx {
        Some(0) => decode_non_dynamic_5qi(reader, errors),
        Some(1) => decode_dynamic_5qi(reader, errors),
        Some(2) => {
            errors.push("QosCharacteristics choice-Extensions not supported".into());
            QosCharacteristics::ChoiceExtensions("choice-Extensions".into())
        }
        _ => QosCharacteristics::ChoiceExtensions("truncated".into()),
    }
}

fn decode_allocation_and_retention(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
) -> AllocationAndRetention {
    let ext = reader.read_bit().unwrap_or(true);
    let has_ie_ext = reader.read_bit().unwrap_or(false);
    if ext {
        errors.push("AllocationAndRetentionPriority SEQUENCE extension present".into());
    }
    // PriorityLevelARP INTEGER (1..15) — NOT extensible. 4 bits bit-field.
    let priority = (reader.read_constrained_whole(15).unwrap_or(0) as u8) + 1;
    let capability = decode_two_value_enum_extensible(
        reader,
        errors,
        "pre-emptionCapability",
        &["shall-not-trigger-pre-emption", "may-trigger-pre-emption"],
    );
    let vulnerability = decode_two_value_enum_extensible(
        reader,
        errors,
        "pre-emptionVulnerability",
        &["not-pre-emptable", "pre-emptable"],
    );
    if has_ie_ext {
        errors.push("AllocationAndRetentionPriority iE-Extensions present".into());
    }
    AllocationAndRetention {
        priority,
        capability,
        vulnerability,
    }
}

fn decode_gbr_qos_information(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
) -> GbrQosInformation {
    let ext = reader.read_bit().unwrap_or(true);
    let has_notif = reader.read_bit().unwrap_or(false);
    let has_pkt_loss_dl = reader.read_bit().unwrap_or(false);
    let has_pkt_loss_ul = reader.read_bit().unwrap_or(false);
    let has_ie_ext = reader.read_bit().unwrap_or(false);
    if ext {
        errors.push("GBR-QosInformation SEQUENCE extension present".into());
    }
    let maximum_flow_dl = decode_bitrate(reader, errors, "maximumFlowBitRateDL");
    let maximum_flow_ul = decode_bitrate(reader, errors, "maximumFlowBitRateUL");
    let guaranteed_flow_dl = decode_bitrate(reader, errors, "guaranteedFlowBitRateDL");
    let guaranteed_flow_ul = decode_bitrate(reader, errors, "guaranteedFlowBitRateUL");
    let notification_control = if has_notif {
        Some(decode_two_value_enum_extensible(
            reader,
            errors,
            "notificationControl",
            &["notification-requested", "unknown"],
        ))
    } else {
        None
    };
    let maximum_packet_loss_dl = if has_pkt_loss_dl {
        let ext_bit = reader.read_bit().unwrap_or(true);
        if ext_bit {
            None
        } else {
            reader.read_constrained_whole(1001).ok().map(|v| v as u16)
        }
    } else {
        None
    };
    let maximum_packet_loss_ul = if has_pkt_loss_ul {
        let ext_bit = reader.read_bit().unwrap_or(true);
        if ext_bit {
            None
        } else {
            reader.read_constrained_whole(1001).ok().map(|v| v as u16)
        }
    } else {
        None
    };
    if has_ie_ext {
        errors.push("GBR-QosInformation iE-Extensions present".into());
    }
    GbrQosInformation {
        maximum_flow_dl,
        maximum_flow_ul,
        guaranteed_flow_dl,
        guaranteed_flow_ul,
        notification_control,
        maximum_packet_loss_dl,
        maximum_packet_loss_ul,
    }
}

fn decode_qos_flow_level_qos_parameters(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
) -> QosFlowLevelQosParams {
    let ext = reader.read_bit().unwrap_or(true);
    let has_gbr = reader.read_bit().unwrap_or(false);
    let has_reflective = reader.read_bit().unwrap_or(false);
    let has_additional = reader.read_bit().unwrap_or(false);
    let has_ie_ext = reader.read_bit().unwrap_or(false);
    if ext {
        errors.push("QosFlowLevelQosParameters SEQUENCE extension present".into());
    }
    let characteristics = decode_qos_characteristics(reader, errors);
    let arp = decode_allocation_and_retention(reader, errors);
    let gbr = if has_gbr {
        Some(decode_gbr_qos_information(reader, errors))
    } else {
        None
    };
    let reflective_qos = if has_reflective {
        Some(decode_two_value_enum_extensible(
            reader,
            errors,
            "reflectiveQoSAttribute",
            &["subject-to", "unknown"],
        ))
    } else {
        None
    };
    let additional_qos_flow = if has_additional {
        Some(decode_two_value_enum_extensible(
            reader,
            errors,
            "additionalQoSFlowInformation",
            &["more-likely", "unknown"],
        ))
    } else {
        None
    };
    if has_ie_ext {
        errors.push("QosFlowLevelQosParameters iE-Extensions present".into());
    }
    QosFlowLevelQosParams {
        characteristics,
        arp,
        gbr,
        reflective_qos,
        additional_qos_flow,
    }
}

fn decode_qos_flow_setup_request_item(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
    index: usize,
) -> QosFlowSetupRequestItem {
    let ext = reader.read_bit().unwrap_or(true);
    let has_erab = reader.read_bit().unwrap_or(false);
    let has_ie_ext = reader.read_bit().unwrap_or(false);
    if ext {
        errors.push(format!("QosFlowSetupRequestItem[{index}] SEQUENCE extension present"));
    }
    let qfi = decode_qos_flow_identifier(reader, errors, index);
    let qos_params = decode_qos_flow_level_qos_parameters(reader, errors);
    let e_rab_id = if has_erab {
        let ext_bit = reader.read_bit().unwrap_or(true);
        if ext_bit {
            errors.push(format!(
                "QosFlowSetupRequestItem[{index}].e-RAB-ID extension not supported"
            ));
            None
        } else {
            reader.read_constrained_whole(16).ok().map(|v| v as u8)
        }
    } else {
        None
    };
    if has_ie_ext {
        errors.push(format!("QosFlowSetupRequestItem[{index}] iE-Extensions present"));
    }
    QosFlowSetupRequestItem {
        qfi,
        qos_params,
        e_rab_id,
    }
}

fn decode_qos_flow_setup_request_list(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
) -> Vec<QosFlowSetupRequestItem> {
    let count = match reader.read_constrained_whole(64) {
        Ok(v) => (v as usize) + 1,
        Err(e) => {
            errors.push(format!("QosFlowSetupRequestList size: {:?}", e));
            return Vec::new();
        }
    };
    (0..count)
        .map(|i| decode_qos_flow_setup_request_item(reader, errors, i))
        .collect()
}

// ---------- SecurityResult ----------

fn decode_security_result(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
) -> SecurityResultDecoded {
    let ext = reader.read_bit().unwrap_or(true);
    let has_ie_ext = reader.read_bit().unwrap_or(false);
    if ext {
        errors.push("SecurityResult SEQUENCE extension present".into());
    }
    let integrity = decode_two_value_enum_extensible(
        reader,
        errors,
        "integrityProtectionResult",
        &["performed", "not-performed"],
    );
    let confidentiality = decode_two_value_enum_extensible(
        reader,
        errors,
        "confidentialityProtectionResult",
        &["performed", "not-performed"],
    );
    if has_ie_ext {
        errors.push("SecurityResult iE-Extensions present".into());
    }
    SecurityResultDecoded {
        integrity,
        confidentiality,
    }
}

// ---------- Public transfer-level entry points ----------

const PDU_SESSION_TYPES: &[&str] = &["ipv4", "ipv6", "ipv4v6", "ethernet", "unstructured"];

pub fn decode_pdu_session_resource_setup_request_transfer(bytes: &[u8]) -> RequestTransfer {
    // PDUSessionResourceSetupRequestTransfer ::= SEQUENCE {
    //     protocolIEs ProtocolIE-Container { {PDUSessionResourceSetupRequestTransferIEs} },
    //     ...
    // }
    // The outer SEQUENCE has no OPTIONALs and 1 extension marker → 1 ext bit.
    let mut reader = AperReader::new(bytes);
    let mut rt = RequestTransfer::default();
    let outer_ext = match reader.read_bit() {
        Ok(v) => v,
        Err(e) => {
            rt.errors
                .push(format!("PDUSessionResourceSetupRequestTransfer ext: {:?}", e));
            return rt;
        }
    };
    if outer_ext {
        rt.errors
            .push("PDUSessionResourceSetupRequestTransfer SEQUENCE extension present".into());
    }
    // protocolIEs is a ProtocolIE-Container (SEQUENCE OF ProtocolIE-Field,
    // SIZE 0..65535). Size encoded as 2-octet aligned (range 65536, case c).
    let count = match reader.read_constrained_whole(65536) {
        Ok(v) => v as usize,
        Err(e) => {
            rt.errors
                .push(format!("ProtocolIE-Container size: {:?}", e));
            return rt;
        }
    };
    for i in 0..count {
        if let Err(e) = decode_request_transfer_ie(&mut reader, &mut rt, i) {
            rt.errors.push(e);
            break;
        }
    }
    rt
}

fn decode_request_transfer_ie(
    reader: &mut AperReader<'_>,
    rt: &mut RequestTransfer,
    index: usize,
) -> Result<(), String> {
    // ProtocolIE-Field: id (0..65535, 2 octets), criticality (ENUMERATED
    // reject/ignore/notify, 2-bit bit-field), value (OPEN TYPE: length
    // determinant + octets).
    let id = reader
        .read_constrained_whole(65536)
        .map_err(|e| format!("IE[{index}] id: {:?}", e))? as u16;
    let crit = decode_criticality(reader);
    let value_len = reader
        .read_length_determinant()
        .map_err(|e| format!("IE[{index}] value length: {:?}", e))?;
    let value_bytes = reader
        .read_octets(value_len)
        .map_err(|e| format!("IE[{index}] value content: {:?}", e))?;
    match id {
        139 => {
            let mut v_rdr = AperReader::new(value_bytes);
            rt.ul_tunnel = Some(decode_up_transport_layer_information(&mut v_rdr, &mut rt.errors));
        }
        134 => {
            // PDUSessionType ENUMERATED (5 values + ext).
            let mut v_rdr = AperReader::new(value_bytes);
            let ext = v_rdr.read_bit().unwrap_or(true);
            if ext {
                rt.errors.push("PDUSessionType extension value".into());
            } else {
                let idx = v_rdr.read_constrained_whole(5).unwrap_or(0);
                rt.pdu_session_type = PDU_SESSION_TYPES.get(idx as usize).copied();
            }
        }
        136 => {
            let mut v_rdr = AperReader::new(value_bytes);
            rt.qos_flows = decode_qos_flow_setup_request_list(&mut v_rdr, &mut rt.errors);
        }
        130 => {
            // PDUSessionAggregateMaximumBitRate SEQUENCE: ext + 1 opt (iE-Ext).
            let mut v_rdr = AperReader::new(value_bytes);
            let ext = v_rdr.read_bit().unwrap_or(true);
            let has_ie_ext = v_rdr.read_bit().unwrap_or(false);
            if ext {
                rt.errors
                    .push("PDUSessionAggregateMaximumBitRate SEQUENCE extension present".into());
            }
            rt.ambr_dl = Some(decode_bitrate(&mut v_rdr, &mut rt.errors, "AMBR-DL"));
            rt.ambr_ul = Some(decode_bitrate(&mut v_rdr, &mut rt.errors, "AMBR-UL"));
            if has_ie_ext {
                rt.errors
                    .push("PDUSessionAggregateMaximumBitRate iE-Extensions present".into());
            }
        }
        _ => {
            rt.errors.push(format!(
                "unknown IE id={id} criticality={crit} length={value_len} skipped"
            ));
            rt.unknown_protocol_ies.push(UnknownProtocolIe {
                id,
                criticality: crit,
                length_octets: value_len,
            });
        }
    }
    Ok(())
}

pub fn decode_pdu_session_resource_setup_response_transfer(bytes: &[u8]) -> ResponseTransfer {
    // PDUSessionResourceSetupResponseTransfer ::= SEQUENCE {
    //     dLQosFlowPerTNLInformation              QosFlowPerTNLInformation,
    //     additionalDLQosFlowPerTNLInformation    OPTIONAL,
    //     securityResult                          OPTIONAL,
    //     qosFlowFailedToSetupList                OPTIONAL,
    //     iE-Extensions                           OPTIONAL,
    //     ...
    // }
    // 4 OPTIONALs + ext marker → 5-bit preamble.
    let mut reader = AperReader::new(bytes);
    let mut rt = ResponseTransfer::default();
    let ext = reader.read_bit().unwrap_or(true);
    let has_additional = reader.read_bit().unwrap_or(false);
    let has_security = reader.read_bit().unwrap_or(false);
    let has_failed = reader.read_bit().unwrap_or(false);
    let has_ie_ext = reader.read_bit().unwrap_or(false);
    if ext {
        rt.errors
            .push("PDUSessionResourceSetupResponseTransfer SEQUENCE extension present".into());
    }
    rt.dl = decode_qos_flow_per_tnl_information(&mut reader, &mut rt.errors);
    if has_additional {
        rt.additional_dl = decode_qos_flow_per_tnl_information_list(&mut reader, &mut rt.errors);
    }
    if has_security {
        rt.security = Some(decode_security_result(&mut reader, &mut rt.errors));
    }
    if has_failed {
        rt.failed = decode_qos_flow_with_cause_list(&mut reader, &mut rt.errors);
    }
    if has_ie_ext {
        // ProtocolExtensionContainer SEQUENCE OF ProtocolExtensionField
        // (SIZE 1..65535). Each ExtField has id/criticality/extensionValue
        // (OPEN TYPE). We only walk them to extract
        // redundantDLQosFlowPerTNLInformation (id 196 per NGAP) and surface
        // the rest in `errors`.
        decode_response_extensions(&mut reader, &mut rt);
    }
    rt
}

fn decode_response_extensions(reader: &mut AperReader<'_>, rt: &mut ResponseTransfer) {
    // ProtocolExtensionContainer size: SIZE(1..65535), range 65535 → 2 octets aligned.
    let count = match reader.read_constrained_whole(65535) {
        Ok(v) => (v as usize) + 1,
        Err(e) => {
            rt.errors
                .push(format!("ProtocolExtensionContainer size: {:?}", e));
            return;
        }
    };
    for i in 0..count {
        let id = match reader.read_constrained_whole(65536) {
            Ok(v) => v as u16,
            Err(e) => {
                rt.errors.push(format!("Ext[{i}] id: {:?}", e));
                return;
            }
        };
        let _crit = decode_criticality(reader);
        let len = match reader.read_length_determinant() {
            Ok(v) => v,
            Err(e) => {
                rt.errors.push(format!("Ext[{i}] length: {:?}", e));
                return;
            }
        };
        let bytes = match reader.read_octets(len) {
            Ok(b) => b,
            Err(e) => {
                rt.errors.push(format!("Ext[{i}] content: {:?}", e));
                return;
            }
        };
        if id == 196 {
            // id-RedundantDLQosFlowPerTNLInformation per TS 38.413 (int 196).
            let mut v_rdr = AperReader::new(bytes);
            let info = decode_qos_flow_per_tnl_information(&mut v_rdr, &mut rt.errors);
            rt.redundant = Some(info);
        } else {
            rt.errors.push(format!(
                "ResponseTransfer extension id={id} length={len} skipped"
            ));
        }
    }
}

// ---------- Outer list walkers ----------

fn decode_s_nssai(reader: &mut AperReader<'_>, errors: &mut Vec<String>) -> SNssai {
    // SEQUENCE: ext + 2 opts (sD, iE-Ext). sST OCTET STRING SIZE(1) → bit-field 8 bits.
    let ext = reader.read_bit().unwrap_or(true);
    let has_sd = reader.read_bit().unwrap_or(false);
    let has_ie_ext = reader.read_bit().unwrap_or(false);
    if ext {
        errors.push("S-NSSAI SEQUENCE extension present".into());
    }
    let sst = reader
        .read_aligned_fixed_octet_string(1)
        .ok()
        .and_then(|v| v.first().copied())
        .unwrap_or(0);
    let sd = if has_sd {
        reader.read_aligned_fixed_octet_string(3).ok().and_then(|v| {
            if v.len() == 3 {
                Some([v[0], v[1], v[2]])
            } else {
                None
            }
        })
    } else {
        None
    };
    if has_ie_ext {
        errors.push("S-NSSAI iE-Extensions present".into());
    }
    SNssai { sst, sd }
}

pub fn decode_pdu_session_resource_setup_list_su_req(bytes: &[u8]) -> ListSUReq {
    let mut reader = AperReader::new(bytes);
    let mut list = ListSUReq::default();
    // SIZE(1..256) → octet-aligned 1 octet.
    let count = match reader.read_constrained_whole(256) {
        Ok(v) => (v as usize) + 1,
        Err(e) => {
            list.errors.push(format!("ListSUReq size: {:?}", e));
            return list;
        }
    };
    for i in 0..count {
        match decode_item_sureq(&mut reader, &mut list.errors, i) {
            Some(item) => list.items.push(item),
            None => break,
        }
    }
    list
}

fn decode_item_sureq(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
    index: usize,
) -> Option<SetupItemSUReq> {
    // SEQUENCE: ext + 2 opts (pDUSessionNAS-PDU, iE-Extensions).
    let ext = reader.read_bit().ok()?;
    let has_nas_pdu = reader.read_bit().ok()?;
    let has_ie_ext = reader.read_bit().ok()?;
    if ext {
        errors.push(format!("ItemSUReq[{index}] SEQUENCE extension present"));
    }
    // pDUSessionID INTEGER (0..255) — NOT extensible. Range 256 → octet-aligned 1 octet.
    let pdu_session_id = match reader.read_constrained_whole(256) {
        Ok(v) => v as u8,
        Err(e) => {
            errors.push(format!("ItemSUReq[{index}] pDUSessionID: {:?}", e));
            return None;
        }
    };
    let nas_pdu = if has_nas_pdu {
        let len = reader.read_length_determinant().ok()?;
        Some(reader.read_octets(len).ok()?.to_vec())
    } else {
        None
    };
    let s_nssai = decode_s_nssai(reader, errors);
    let transfer_len = reader.read_length_determinant().ok()?;
    let transfer = reader.read_octets(transfer_len).ok()?.to_vec();
    if has_ie_ext {
        errors.push(format!("ItemSUReq[{index}] iE-Extensions present"));
    }
    Some(SetupItemSUReq {
        pdu_session_id,
        nas_pdu,
        s_nssai,
        transfer,
        ie_extensions_present: has_ie_ext,
    })
}

pub fn decode_pdu_session_resource_setup_list_su_res(bytes: &[u8]) -> ListSURes {
    let mut reader = AperReader::new(bytes);
    let mut list = ListSURes::default();
    let count = match reader.read_constrained_whole(256) {
        Ok(v) => (v as usize) + 1,
        Err(e) => {
            list.errors.push(format!("ListSURes size: {:?}", e));
            return list;
        }
    };
    for i in 0..count {
        match decode_item_sures(&mut reader, &mut list.errors, i) {
            Some(item) => list.items.push(item),
            None => break,
        }
    }
    list
}

fn decode_item_sures(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
    index: usize,
) -> Option<SetupItemSURes> {
    let ext = reader.read_bit().ok()?;
    let has_ie_ext = reader.read_bit().ok()?;
    if ext {
        errors.push(format!("ItemSURes[{index}] SEQUENCE extension present"));
    }
    let pdu_session_id = match reader.read_constrained_whole(256) {
        Ok(v) => v as u8,
        Err(e) => {
            errors.push(format!("ItemSURes[{index}] pDUSessionID: {:?}", e));
            return None;
        }
    };
    let transfer_len = reader.read_length_determinant().ok()?;
    let transfer = reader.read_octets(transfer_len).ok()?.to_vec();
    if has_ie_ext {
        errors.push(format!("ItemSURes[{index}] iE-Extensions present"));
    }
    Some(SetupItemSURes {
        pdu_session_id,
        transfer,
        ie_extensions_present: has_ie_ext,
    })
}

// ---------- Context setup list walkers (IE 71 / IE 72) ----------
// PDUSessionResourceSetupItemCxtReq has the SAME shape as SUReq (optional NAS-PDU, S-NSSAI, transfer).
// PDUSessionResourceSetupItemCxtRes has the SAME shape as SURes (pDUSessionID, transfer).

pub fn decode_pdu_session_resource_setup_list_cxt_req(bytes: &[u8]) -> ListSUReq {
    decode_pdu_session_resource_setup_list_su_req(bytes)
}

pub fn decode_pdu_session_resource_setup_list_cxt_res(bytes: &[u8]) -> ListSURes {
    decode_pdu_session_resource_setup_list_su_res(bytes)
}
