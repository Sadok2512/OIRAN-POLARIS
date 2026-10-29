//! TS 38.413 PDUSessionResourceSetupRequestTransfer and
//! PDUSessionResourceSetupResponseTransfer bit-accurate APER decoders.
//!
//! Decoders consume raw transfer-content bytes (the OCTET STRING payload inside
//! PDUSessionResourceSetupItemSUReq / SURes) and return a strongly typed tree
//! together with an `errors` vector that *names each unsupported field* instead
//! of silently rejecting the whole payload. Fixtures that drive these decoders
//! are generated with `asn1tools` (Python, codec `per`) against the minimal
//! ASN.1 subset documented in `tests/fixtures/ngap_transfer_fixtures.rs`.

use crate::aper::{AperError, AperReader};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GtpTunnel {
    pub transport_address: Vec<u8>,
    pub address_bits: usize,
    pub teid: [u8; 4],
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum UpTransportLayerInformation {
    GtpTunnel(GtpTunnel),
    Unsupported(String),
}

impl Default for UpTransportLayerInformation {
    fn default() -> Self {
        Self::Unsupported("uninitialized".into())
    }
}

impl UpTransportLayerInformation {
    /// Return the IPv4 string representation of the transport layer address when
    /// the tunnel is a GTPTunnel with a 32-bit address.
    pub fn ipv4_address(&self) -> Option<std::net::Ipv4Addr> {
        match self {
            Self::GtpTunnel(tunnel) if tunnel.address_bits == 32 && tunnel.transport_address.len() >= 4 => {
                Some(std::net::Ipv4Addr::new(
                    tunnel.transport_address[0],
                    tunnel.transport_address[1],
                    tunnel.transport_address[2],
                    tunnel.transport_address[3],
                ))
            }
            _ => None,
        }
    }

    pub fn teid(&self) -> Option<u32> {
        match self {
            Self::GtpTunnel(tunnel) => Some(u32::from_be_bytes(tunnel.teid)),
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
    Unsupported(String),
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
    UnknownGroup(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FailedQosFlow {
    pub qfi: u8,
    pub cause: CauseKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct RequestTransfer {
    pub ul_tunnel: UpTransportLayerInformation,
    pub pdu_session_type: Option<&'static str>,
    pub qos_flows: Vec<QosFlowSetupRequestItem>,
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

// --- primitive decoders ---------------------------------------------------

fn record_err<T>(errors: &mut Vec<String>, context: &str, result: Result<T, AperError>) -> Option<T> {
    match result {
        Ok(v) => Some(v),
        Err(e) => {
            errors.push(format!("{context}: {:?}", e));
            None
        }
    }
}

fn decode_up_transport_layer_information(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
) -> UpTransportLayerInformation {
    // CHOICE: 1 ext bit; if ext=0 and 1 root alternative there is no index.
    let ext = match reader.read_bit() {
        Ok(b) => b,
        Err(e) => {
            errors.push(format!("UPTransportLayerInformation CHOICE ext: {:?}", e));
            return UpTransportLayerInformation::Unsupported(
                "truncated choice extension marker".into(),
            );
        }
    };
    if ext {
        errors.push(
            "UPTransportLayerInformation extension alternative (not gTPTunnel) not supported"
                .into(),
        );
        return UpTransportLayerInformation::Unsupported("choice-extension".into());
    }
    // GTPTunnel SEQUENCE.
    let seq_ext = reader.read_bit().unwrap_or(true);
    let has_ie_ext = reader.read_bit().unwrap_or(false);
    if seq_ext {
        errors.push("GTPTunnel SEQUENCE extension present (not supported)".into());
    }
    let addr_ext = reader.read_bit().unwrap_or(true);
    if addr_ext {
        errors.push("TransportLayerAddress BIT STRING extension present (not supported)".into());
        return UpTransportLayerInformation::Unsupported("transport-address-ext".into());
    }
    let Some(size_minus_one) = record_err(
        errors,
        "TransportLayerAddress size",
        reader.read_constrained_whole(160),
    ) else {
        return UpTransportLayerInformation::Unsupported("transport-address-size".into());
    };
    let bits = (size_minus_one as usize) + 1;
    let Some(address_bytes) = record_err(
        errors,
        "TransportLayerAddress bits",
        reader.read_bit_string_content(bits),
    ) else {
        return UpTransportLayerInformation::Unsupported("transport-address-bits".into());
    };
    let Some(teid_bytes) = record_err(errors, "GTP-TEID", reader.read_fixed_octet_string(4)) else {
        return UpTransportLayerInformation::Unsupported("gtp-teid".into());
    };
    let mut teid = [0u8; 4];
    teid.copy_from_slice(teid_bytes);
    if has_ie_ext {
        errors.push("GTPTunnel iE-Extensions present (not supported)".into());
    }
    UpTransportLayerInformation::GtpTunnel(GtpTunnel {
        transport_address: address_bytes,
        address_bits: bits,
        teid,
    })
}

fn decode_associated_qos_flow_list(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
) -> Vec<AssociatedQosFlowItem> {
    // SIZE(1..maxnoofQosFlows=64).
    let Some(size_minus_one) = record_err(
        errors,
        "AssociatedQosFlowList size",
        reader.read_constrained_whole(64),
    ) else {
        return Vec::new();
    };
    let count = (size_minus_one as usize) + 1;
    let mut items = Vec::with_capacity(count);
    for i in 0..count {
        // SEQUENCE: ext + 2 opts (mapping, iE-Ext).
        let ext = reader.read_bit().unwrap_or(true);
        let has_mapping = reader.read_bit().unwrap_or(false);
        let has_ie_ext = reader.read_bit().unwrap_or(false);
        if ext {
            errors.push(format!("AssociatedQosFlowItem[{i}] SEQUENCE extension present"));
        }
        let Some(qfi) = record_err(
            errors,
            &format!("AssociatedQosFlowItem[{i}] qfi"),
            reader.read_constrained_whole(64),
        ) else {
            return items;
        };
        let mapping = if has_mapping {
            // ENUMERATED { ul, dl, ... } with extension marker.
            // Root part: 1 bit value (ul=0, dl=1).
            // Extension additions: 1-bit prefix flag + NSNNWN carrying the
            // extension index (TS 38.413 extensions beyond the root).
            match reader.read_bit() {
                Ok(e_ext) if !e_ext => match reader.read_bit() {
                    Ok(false) => Some(AssociatedQosFlowMapping::Ul),
                    Ok(true) => Some(AssociatedQosFlowMapping::Dl),
                    Err(e) => {
                        errors.push(format!("qosFlowMappingIndication value: {:?}", e));
                        None
                    }
                },
                Ok(_) => match reader.read_normally_small_non_negative_whole_number() {
                    Ok(idx) => Some(AssociatedQosFlowMapping::UnknownExtension(idx)),
                    Err(e) => {
                        errors.push(format!(
                            "qosFlowMappingIndication extension index: {:?}", e
                        ));
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
            errors.push(format!("AssociatedQosFlowItem[{i}] iE-Extensions present"));
        }
        items.push(AssociatedQosFlowItem {
            qfi: qfi as u8,
            mapping_indication: mapping,
        });
    }
    items
}

fn decode_qos_flow_per_tnl_information(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
) -> QosFlowPerTnlInfo {
    // SEQUENCE: ext + 1 opt (iE-Ext).
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

fn decode_qos_flow_per_tnl_information_item(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
) -> QosFlowPerTnlInfo {
    // QosFlowPerTNLInformationItem SEQUENCE: ext + 1 opt (iE-Ext).
    let ext = reader.read_bit().unwrap_or(true);
    let has_ie_ext = reader.read_bit().unwrap_or(false);
    if ext {
        errors.push("QosFlowPerTNLInformationItem SEQUENCE extension present".into());
    }
    let info = decode_qos_flow_per_tnl_information(reader, errors);
    if has_ie_ext {
        errors.push("QosFlowPerTNLInformationItem iE-Extensions present".into());
    }
    info
}

fn decode_qos_flow_per_tnl_information_list(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
) -> Vec<QosFlowPerTnlInfo> {
    // SIZE(1..maxnoofMultiConnectivityMinusOne=3).
    let Some(size_minus_one) = record_err(
        errors,
        "QosFlowPerTNLInformationList size",
        reader.read_constrained_whole(3),
    ) else {
        return Vec::new();
    };
    let count = (size_minus_one as usize) + 1;
    (0..count)
        .map(|_| decode_qos_flow_per_tnl_information_item(reader, errors))
        .collect()
}

fn decode_cause(reader: &mut AperReader<'_>, errors: &mut Vec<String>) -> CauseKind {
    // CHOICE { radioNetwork, transport, nas, protocol, misc, ... }: 5 root
    // alternatives (ceil(log2(5))=3 bits) + ext marker.
    let ext = reader.read_bit().unwrap_or(true);
    if ext {
        errors.push("Cause choice-extension present (unknown cause group)".into());
        return CauseKind::UnknownGroup(0);
    }
    let group = reader
        .read_constrained_whole(5)
        .unwrap_or(0);
    // Each alternative is an ENUMERATED with its own extension marker.
    let value_ext = reader.read_bit().unwrap_or(true);
    if value_ext {
        errors.push("Cause value in extension not supported".into());
        return CauseKind::UnknownGroup(group);
    }
    // Range depends on group. Use the maximum root count we know; the
    // walker only needs the value index, not the enum string label.
    let (range, mapper): (u64, fn(u64) -> CauseKind) = match group {
        0 => (7, CauseKind::RadioNetwork),
        1 => (2, CauseKind::Transport),
        2 => (4, CauseKind::Nas),
        3 => (7, CauseKind::Protocol),
        4 => (6, CauseKind::Misc),
        other => {
            errors.push(format!("Cause group {other} not in the schema"));
            return CauseKind::UnknownGroup(other);
        }
    };
    let value = reader.read_constrained_whole(range).unwrap_or(0);
    mapper(value)
}

fn decode_qos_flow_with_cause_list(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
) -> Vec<FailedQosFlow> {
    let Some(size_minus_one) = record_err(
        errors,
        "QosFlowListWithCause size",
        reader.read_constrained_whole(64),
    ) else {
        return Vec::new();
    };
    let count = (size_minus_one as usize) + 1;
    let mut items = Vec::with_capacity(count);
    for i in 0..count {
        let ext = reader.read_bit().unwrap_or(true);
        let has_ie_ext = reader.read_bit().unwrap_or(false);
        if ext {
            errors.push(format!("QosFlowWithCauseItem[{i}] SEQUENCE extension present"));
        }
        let qfi = reader
            .read_constrained_whole(64)
            .unwrap_or(0) as u8;
        let cause = decode_cause(reader, errors);
        if has_ie_ext {
            errors.push(format!("QosFlowWithCauseItem[{i}] iE-Extensions present"));
        }
        items.push(FailedQosFlow { qfi, cause });
    }
    items
}

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

fn decode_allocation_and_retention(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
) -> AllocationAndRetention {
    let ext = reader.read_bit().unwrap_or(true);
    let has_ie_ext = reader.read_bit().unwrap_or(false);
    if ext {
        errors.push("AllocationAndRetentionPriority SEQUENCE extension present".into());
    }
    let priority = reader
        .read_extensible_integer(1, 15)
        .map(|v| v as u8)
        .unwrap_or_else(|e| {
            errors.push(format!("priorityLevelARP: {:?}", e));
            1
        });
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
    let five_qi = reader
        .read_extensible_integer(0, 255)
        .map(|v| v as u16)
        .unwrap_or_else(|e| {
            errors.push(format!("NonDynamic5QI.fiveQI: {:?}", e));
            0
        });
    let priority_level_qos = if has_prio {
        reader
            .read_extensible_integer(1, 127)
            .map(|v| v as u8)
            .ok()
    } else {
        None
    };
    let averaging_window = if has_avg {
        reader
            .read_extensible_integer(0, 4095)
            .map(|v| v as u16)
            .ok()
    } else {
        None
    };
    let maximum_data_burst_volume = if has_burst {
        reader
            .read_extensible_integer(0, 4095)
            .map(|v| v as u16)
            .ok()
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

fn decode_dynamic_5qi(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
) -> QosCharacteristics {
    let ext = reader.read_bit().unwrap_or(true);
    let has_five_qi = reader.read_bit().unwrap_or(false);
    let has_delay_critical = reader.read_bit().unwrap_or(false);
    let has_avg = reader.read_bit().unwrap_or(false);
    let has_burst = reader.read_bit().unwrap_or(false);
    let has_ie_ext = reader.read_bit().unwrap_or(false);
    if ext {
        errors.push("Dynamic5QIDescriptor SEQUENCE extension present".into());
    }
    let priority_level_qos = reader
        .read_constrained_integer(1, 127)
        .map(|v| v as u8)
        .unwrap_or_else(|e| {
            errors.push(format!("Dynamic5QI.priorityLevelQos: {:?}", e));
            1
        });
    let packet_delay_budget = reader
        .read_extensible_integer(0, 1023)
        .map(|v| v as u16)
        .unwrap_or_else(|e| {
            errors.push(format!("Dynamic5QI.packetDelayBudget: {:?}", e));
            0
        });
    // packetErrorRate SEQUENCE: ext + 1 opt (iE-Ext). Fields pERScalar/pERExponent.
    let per_seq_ext = reader.read_bit().unwrap_or(true);
    let per_has_ie_ext = reader.read_bit().unwrap_or(false);
    if per_seq_ext {
        errors.push("Dynamic5QI.packetErrorRate SEQUENCE extension present".into());
    }
    let per_scalar = reader
        .read_extensible_integer(0, 9)
        .map(|v| v as u8)
        .unwrap_or_else(|e| {
            errors.push(format!("packetErrorRate.pERScalar: {:?}", e));
            0
        });
    let per_exponent = reader
        .read_extensible_integer(0, 9)
        .map(|v| v as u8)
        .unwrap_or_else(|e| {
            errors.push(format!("packetErrorRate.pERExponent: {:?}", e));
            0
        });
    if per_has_ie_ext {
        errors.push("Dynamic5QI.packetErrorRate iE-Extensions present".into());
    }
    let five_qi = if has_five_qi {
        reader
            .read_extensible_integer(0, 255)
            .map(|v| v as u16)
            .ok()
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
        reader
            .read_extensible_integer(0, 4095)
            .map(|v| v as u16)
            .ok()
    } else {
        None
    };
    let maximum_data_burst_volume = if has_burst {
        reader
            .read_extensible_integer(0, 4095)
            .map(|v| v as u16)
            .ok()
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
    // CHOICE { nonDynamic5QI, dynamic5QI, ... }: 2 root alternatives + ext.
    let ext = reader.read_bit().unwrap_or(true);
    if ext {
        errors.push("QosCharacteristics choice-extension present (not supported)".into());
        return QosCharacteristics::Unsupported("choice-extension".into());
    }
    let index = reader.read_constrained_whole(2).unwrap_or(0);
    match index {
        0 => decode_non_dynamic_5qi(reader, errors),
        1 => decode_dynamic_5qi(reader, errors),
        _ => {
            errors.push("QosCharacteristics unexpected choice index".into());
            QosCharacteristics::Unsupported(format!("choice index {index}"))
        }
    }
}

fn decode_bitrate_extensible(reader: &mut AperReader<'_>, errors: &mut Vec<String>, name: &str) -> u64 {
    // INTEGER (0..4000000000000, ...). For aligned PER with range > 65536,
    // X.691 10.5.7.5 encodes the number of value octets minus 1 as an unaligned
    // bit-field of ceil(log2(max_octets)) bits. For BitRate the schema allows
    // up to 6 octets (42-bit maximum), so the length prefix is 3 bits.
    let ext = reader.read_bit().unwrap_or(true);
    if ext {
        errors.push(format!("{name} extension value not supported"));
        return 0;
    }
    let length_minus_one = match reader.read_bits(3) {
        Ok(v) => v,
        Err(e) => {
            errors.push(format!("{name} length prefix: {:?}", e));
            return 0;
        }
    };
    let octets = (length_minus_one as usize) + 1;
    if octets > 6 {
        errors.push(format!("{name} octet count {octets} out of schema range"));
        return 0;
    }
    reader.align();
    let mut v = 0u64;
    for _ in 0..octets {
        match reader.read_octet() {
            Ok(b) => v = (v << 8) | u64::from(b),
            Err(e) => {
                errors.push(format!("{name} value: {:?}", e));
                return v;
            }
        }
    }
    v
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
    let maximum_flow_dl = decode_bitrate_extensible(reader, errors, "maximumFlowBitRateDL");
    let maximum_flow_ul = decode_bitrate_extensible(reader, errors, "maximumFlowBitRateUL");
    let guaranteed_flow_dl = decode_bitrate_extensible(reader, errors, "guaranteedFlowBitRateDL");
    let guaranteed_flow_ul = decode_bitrate_extensible(reader, errors, "guaranteedFlowBitRateUL");
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
        reader
            .read_extensible_integer(0, 1000)
            .map(|v| v as u16)
            .ok()
    } else {
        None
    };
    let maximum_packet_loss_ul = if has_pkt_loss_ul {
        reader
            .read_extensible_integer(0, 1000)
            .map(|v| v as u16)
            .ok()
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
) -> QosFlowSetupRequestItem {
    let ext = reader.read_bit().unwrap_or(true);
    let has_erab = reader.read_bit().unwrap_or(false);
    let has_ie_ext = reader.read_bit().unwrap_or(false);
    if ext {
        errors.push("QosFlowSetupRequestItem SEQUENCE extension present".into());
    }
    let qfi = reader.read_constrained_whole(64).unwrap_or(0) as u8;
    let qos_params = decode_qos_flow_level_qos_parameters(reader, errors);
    let e_rab_id = if has_erab {
        reader
            .read_extensible_integer(0, 15)
            .map(|v| v as u8)
            .ok()
    } else {
        None
    };
    if has_ie_ext {
        errors.push("QosFlowSetupRequestItem iE-Extensions present".into());
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
    let Some(size_minus_one) = record_err(
        errors,
        "QosFlowSetupRequestList size",
        reader.read_constrained_whole(64),
    ) else {
        return Vec::new();
    };
    let count = (size_minus_one as usize) + 1;
    (0..count)
        .map(|_| decode_qos_flow_setup_request_item(reader, errors))
        .collect()
}

// --- public entry points --------------------------------------------------

const PDU_SESSION_TYPES: &[&str] = &["ipv4", "ipv6", "ipv4v6", "ethernet", "unstructured"];

pub fn decode_pdu_session_resource_setup_request_transfer(bytes: &[u8]) -> RequestTransfer {
    let mut reader = AperReader::new(bytes);
    let mut errors = Vec::new();
    // PDUSessionResourceSetupRequestTransfer SEQUENCE with 9 OPTIONALs
    // (pDUSessionAggregateMaximumBitRate, additionalULNGU-UP-TNLInformation,
    // dataForwardingNotPossible, securityIndication, networkInstance,
    // commonNetworkInstance) plus extensible. The schema has:
    //   pDUSessionAggregateMaximumBitRate OPTIONAL,
    //   uLNGU-UP-TNLInformation,
    //   additionalULNGU-UP-TNLInformation OPTIONAL,
    //   dataForwardingNotPossible OPTIONAL,
    //   pDUSessionType,
    //   securityIndication OPTIONAL,
    //   networkInstance OPTIONAL,
    //   qosFlowSetupRequestList,
    //   commonNetworkInstance OPTIONAL,
    //   ...
    // → 6 OPTIONAL fields.
    let ext = reader.read_bit().unwrap_or(true);
    let has_ambr = reader.read_bit().unwrap_or(false);
    let has_add_tnl = reader.read_bit().unwrap_or(false);
    let has_data_fwd = reader.read_bit().unwrap_or(false);
    let has_sec_ind = reader.read_bit().unwrap_or(false);
    let has_net_inst = reader.read_bit().unwrap_or(false);
    let has_common_net = reader.read_bit().unwrap_or(false);
    if ext {
        errors.push("PDUSessionResourceSetupRequestTransfer SEQUENCE extension present".into());
    }
    if has_ambr {
        // SEQUENCE PDUSessionAggregateMaximumBitRate: ext + 1 opt (iE-Ext).
        let ambr_ext = reader.read_bit().unwrap_or(true);
        let ambr_ie_ext = reader.read_bit().unwrap_or(false);
        if ambr_ext {
            errors.push("PDUSessionAggregateMaximumBitRate SEQUENCE extension present".into());
        }
        let _dl = decode_bitrate_extensible(&mut reader, &mut errors, "pduSessionAmbr-DL");
        let _ul = decode_bitrate_extensible(&mut reader, &mut errors, "pduSessionAmbr-UL");
        if ambr_ie_ext {
            errors.push("PDUSessionAggregateMaximumBitRate iE-Extensions present".into());
        }
    }
    let ul_tunnel = decode_up_transport_layer_information(&mut reader, &mut errors);
    if has_add_tnl {
        errors.push("additionalULNGU-UP-TNLInformation present (not decoded)".into());
    }
    if has_data_fwd {
        // ENUMERATED { data-forwarding-not-possible, ... }: 1 ext + 0 bits.
        if reader.read_bit().unwrap_or(true) {
            errors.push("dataForwardingNotPossible extension present".into());
        }
    }
    // pDUSessionType ENUMERATED (5 values + ext).
    let pdu_type_ext = reader.read_bit().unwrap_or(true);
    let pdu_session_type = if pdu_type_ext {
        errors.push("pDUSessionType extension not supported".into());
        None
    } else {
        let idx = reader.read_constrained_whole(5).unwrap_or(0);
        PDU_SESSION_TYPES.get(idx as usize).copied()
    };
    if has_sec_ind {
        errors.push("securityIndication present (not decoded)".into());
    }
    if has_net_inst {
        let _ = reader.read_extensible_integer(1, 256);
    }
    let qos_flows = decode_qos_flow_setup_request_list(&mut reader, &mut errors);
    if has_common_net {
        errors.push("commonNetworkInstance present (not decoded)".into());
    }
    RequestTransfer {
        ul_tunnel,
        pdu_session_type,
        qos_flows,
        errors,
    }
}

pub fn decode_pdu_session_resource_setup_response_transfer(bytes: &[u8]) -> ResponseTransfer {
    let mut reader = AperReader::new(bytes);
    let mut errors = Vec::new();
    // SEQUENCE: ext + 5 OPTIONALs (additionalDL, security, failed, redundant, iE-Ext).
    let ext = reader.read_bit().unwrap_or(true);
    let has_additional = reader.read_bit().unwrap_or(false);
    let has_security = reader.read_bit().unwrap_or(false);
    let has_failed = reader.read_bit().unwrap_or(false);
    let has_redundant = reader.read_bit().unwrap_or(false);
    let has_ie_ext = reader.read_bit().unwrap_or(false);
    if ext {
        errors.push("PDUSessionResourceSetupResponseTransfer SEQUENCE extension present".into());
    }
    let dl = decode_qos_flow_per_tnl_information(&mut reader, &mut errors);
    let additional_dl = if has_additional {
        decode_qos_flow_per_tnl_information_list(&mut reader, &mut errors)
    } else {
        Vec::new()
    };
    let security = if has_security {
        Some(decode_security_result(&mut reader, &mut errors))
    } else {
        None
    };
    let failed = if has_failed {
        decode_qos_flow_with_cause_list(&mut reader, &mut errors)
    } else {
        Vec::new()
    };
    let redundant = if has_redundant {
        Some(decode_qos_flow_per_tnl_information(&mut reader, &mut errors))
    } else {
        None
    };
    if has_ie_ext {
        errors.push("PDUSessionResourceSetupResponseTransfer iE-Extensions present".into());
    }
    ResponseTransfer {
        dl,
        additional_dl,
        security,
        failed,
        redundant,
        errors,
    }
}

/// Decode S-NSSAI (TS 38.413 §9.3.1.24).
/// SEQUENCE { sST OCTET STRING SIZE(1), sD OCTET STRING SIZE(3) OPTIONAL,
///            iE-Extensions OPTIONAL, ... }
fn decode_s_nssai(reader: &mut AperReader<'_>, errors: &mut Vec<String>) -> SNssai {
    let ext = reader.read_bit().unwrap_or(true);
    let has_sd = reader.read_bit().unwrap_or(false);
    let has_ie_ext = reader.read_bit().unwrap_or(false);
    if ext {
        errors.push("S-NSSAI SEQUENCE extension present".into());
    }
    // sST is OCTET STRING SIZE(1) → bit-field, unaligned (X.691 Clause 17.5
    // case b).
    let sst = match reader.read_aligned_fixed_octet_string(1) {
        Ok(v) => v.first().copied().unwrap_or(0),
        Err(e) => {
            errors.push(format!("S-NSSAI sST: {:?}", e));
            0
        }
    };
    let sd = if has_sd {
        // sD is OCTET STRING SIZE(3) → octet-aligned content.
        match reader.read_aligned_fixed_octet_string(3) {
            Ok(bytes) if bytes.len() == 3 => Some([bytes[0], bytes[1], bytes[2]]),
            Ok(_) => {
                errors.push("S-NSSAI sD unexpected length".into());
                None
            }
            Err(e) => {
                errors.push(format!("S-NSSAI sD: {:?}", e));
                None
            }
        }
    } else {
        None
    };
    if has_ie_ext {
        errors.push("S-NSSAI iE-Extensions present".into());
    }
    SNssai { sst, sd }
}

/// Decode PDUSessionResourceSetupListSUReq (TS 38.413 §9.3.1.1):
///   SEQUENCE (SIZE(1..256)) OF PDUSessionResourceSetupItemSUReq.
/// Each item is a SEQUENCE whose optional preamble carries the pDUSessionNAS-PDU
/// and iE-Extensions presence flags. The transfer OCTET STRING is extracted
/// verbatim per the APER semi-constrained length determinant rules.
pub fn decode_pdu_session_resource_setup_list_su_req(bytes: &[u8]) -> ListSUReq {
    let mut reader = AperReader::new(bytes);
    let mut errors = Vec::new();
    // SEQUENCE OF size: SIZE(1..256), range 256 → octet-aligned 1 octet
    // (X.691 10.5.7.4 case c).
    let size_minus_one = match reader.read_constrained_whole(256) {
        Ok(v) => v,
        Err(e) => {
            errors.push(format!("ListSUReq size: {:?}", e));
            return ListSUReq { items: Vec::new(), errors };
        }
    };
    let count = (size_minus_one as usize) + 1;
    let mut items = Vec::with_capacity(count);
    for i in 0..count {
        match decode_item_sureq(&mut reader, &mut errors, i) {
            Some(item) => items.push(item),
            None => break,
        }
    }
    ListSUReq { items, errors }
}

fn decode_item_sureq(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
    index: usize,
) -> Option<SetupItemSUReq> {
    // SEQUENCE preamble: ext + 2 opts (pDUSessionNAS-PDU, iE-Extensions).
    let ext = reader.read_bit().ok()?;
    let has_nas_pdu = reader.read_bit().ok()?;
    let has_ie_ext = reader.read_bit().ok()?;
    if ext {
        errors.push(format!(
            "PDUSessionResourceSetupItemSUReq[{index}] SEQUENCE extension present"
        ));
    }
    // pDUSessionID: INTEGER (0..255), range 256 → octet-aligned 1 octet.
    let pdu_session_id = match reader.read_constrained_whole(256) {
        Ok(v) => v as u8,
        Err(e) => {
            errors.push(format!("ItemSUReq[{index}] pDUSessionID: {:?}", e));
            return None;
        }
    };
    let nas_pdu = if has_nas_pdu {
        // NAS-PDU is OCTET STRING with no size constraint: length determinant
        // (1 or 2 octets) + octet-aligned content.
        let len = match reader.read_length_determinant() {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!("ItemSUReq[{index}] NAS-PDU length: {:?}", e));
                return None;
            }
        };
        match reader.read_octets(len) {
            Ok(bytes) => Some(bytes.to_vec()),
            Err(e) => {
                errors.push(format!("ItemSUReq[{index}] NAS-PDU content: {:?}", e));
                return None;
            }
        }
    } else {
        None
    };
    let s_nssai = decode_s_nssai(reader, errors);
    // pDUSessionResourceSetupRequestTransfer: OCTET STRING, length determinant.
    let transfer_len = match reader.read_length_determinant() {
        Ok(v) => v,
        Err(e) => {
            errors.push(format!("ItemSUReq[{index}] transfer length: {:?}", e));
            return None;
        }
    };
    let transfer = match reader.read_octets(transfer_len) {
        Ok(bytes) => bytes.to_vec(),
        Err(e) => {
            errors.push(format!("ItemSUReq[{index}] transfer content: {:?}", e));
            return None;
        }
    };
    if has_ie_ext {
        errors.push(format!(
            "PDUSessionResourceSetupItemSUReq[{index}] iE-Extensions present"
        ));
    }
    Some(SetupItemSUReq {
        pdu_session_id,
        nas_pdu,
        s_nssai,
        transfer,
        ie_extensions_present: has_ie_ext,
    })
}

/// Decode PDUSessionResourceSetupListSURes (TS 38.413 §9.3.1.2):
///   SEQUENCE (SIZE(1..256)) OF PDUSessionResourceSetupItemSURes.
pub fn decode_pdu_session_resource_setup_list_su_res(bytes: &[u8]) -> ListSURes {
    let mut reader = AperReader::new(bytes);
    let mut errors = Vec::new();
    let size_minus_one = match reader.read_constrained_whole(256) {
        Ok(v) => v,
        Err(e) => {
            errors.push(format!("ListSURes size: {:?}", e));
            return ListSURes { items: Vec::new(), errors };
        }
    };
    let count = (size_minus_one as usize) + 1;
    let mut items = Vec::with_capacity(count);
    for i in 0..count {
        match decode_item_sures(&mut reader, &mut errors, i) {
            Some(item) => items.push(item),
            None => break,
        }
    }
    ListSURes { items, errors }
}

fn decode_item_sures(
    reader: &mut AperReader<'_>,
    errors: &mut Vec<String>,
    index: usize,
) -> Option<SetupItemSURes> {
    // SEQUENCE preamble: ext + 1 opt (iE-Extensions).
    let ext = reader.read_bit().ok()?;
    let has_ie_ext = reader.read_bit().ok()?;
    if ext {
        errors.push(format!(
            "PDUSessionResourceSetupItemSURes[{index}] SEQUENCE extension present"
        ));
    }
    let pdu_session_id = match reader.read_constrained_whole(256) {
        Ok(v) => v as u8,
        Err(e) => {
            errors.push(format!("ItemSURes[{index}] pDUSessionID: {:?}", e));
            return None;
        }
    };
    let transfer_len = match reader.read_length_determinant() {
        Ok(v) => v,
        Err(e) => {
            errors.push(format!("ItemSURes[{index}] transfer length: {:?}", e));
            return None;
        }
    };
    let transfer = match reader.read_octets(transfer_len) {
        Ok(bytes) => bytes.to_vec(),
        Err(e) => {
            errors.push(format!("ItemSURes[{index}] transfer content: {:?}", e));
            return None;
        }
    };
    if has_ie_ext {
        errors.push(format!(
            "PDUSessionResourceSetupItemSURes[{index}] iE-Extensions present"
        ));
    }
    Some(SetupItemSURes {
        pdu_session_id,
        transfer,
        ie_extensions_present: has_ie_ext,
    })
}
