//! Deterministic reconstruction of UE, PDU, PFCP and GTP-U state from normalized events.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{self, BufRead};

pub const VERSION: &str = "0.4.0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PacketRef {
    pub source_file: String,
    pub packet_number: u64,
    pub byte_offset: u64,
    pub interface_id: u32,
    pub captured_length: u32,
    pub original_length: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventRecord {
    pub event_id: String,
    pub parent_event_id: Option<String>,
    pub capture_id: String,
    pub capture_point_id: String,
    pub timestamp: String,
    pub timestamp_ns: i128,
    pub raw_ticks: u64,
    pub interface: String,
    pub protocol: String,
    pub message_name: String,
    pub source_address: String,
    pub destination_address: String,
    pub source_participant: String,
    pub destination_participant: String,
    pub direction: String,
    pub identifiers: Vec<(String, String)>,
    pub information_elements: Value,
    pub decoding_status: String,
    pub decoder_name: String,
    pub decoder_version: String,
    pub raw_payload_reference: String,
    pub packet_references: Vec<PacketRef>,
    pub errors: Vec<String>,
    pub source_json: Value,
}

impl EventRecord {
    pub fn identifier_values(&self, name: &str) -> Vec<&str> {
        self.identifiers
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }
    pub fn first_identifier(&self, name: &str) -> Option<&str> {
        self.identifiers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
    pub fn packet_number(&self) -> u64 {
        self.packet_references
            .first()
            .map(|p| p.packet_number)
            .unwrap_or(0)
    }
    pub fn has_provenance(&self) -> bool {
        !self.capture_id.is_empty()
            && !self.raw_payload_reference.is_empty()
            && !self.packet_references.is_empty()
            && self
                .packet_references
                .iter()
                .all(|p| p.packet_number > 0 && !p.source_file.is_empty())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UeContext {
    pub pseudonym: String,
    pub amf_ue_ngap_id: Option<String>,
    pub ran_ue_ngap_id: Option<String>,
    pub pdu_session_id: Option<String>,
    pub state: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PfcpSession {
    pub smf_f_seid: Option<String>,
    pub upf_f_seid: Option<String>,
    pub pdr_ids: Vec<String>,
    pub far_ids: Vec<String>,
    pub qer_ids: Vec<String>,
    pub state: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GtpuTunnel {
    pub teid: String,
    pub endpoint: Option<String>,
    pub direction: String,
    pub packet_count: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Association {
    Session,
    Background,
    Unmatched,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reconstruction {
    pub session_id: String,
    pub ue: UeContext,
    pub pfcp: PfcpSession,
    pub tunnels: Vec<GtpuTunnel>,
    pub events: Vec<EventRecord>,
    pub association: BTreeMap<String, Association>,
    pub duplicate_event_ids: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ReconstructionHints {
    pub ue_pseudonym: Option<String>,
    pub uplink_teid: Option<String>,
    pub downlink_teid: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredUeContext {
    pub context_id: String,
    pub pseudonym: String,
    pub ran_ue_ngap_id: Option<String>,
    pub amf_ue_ngap_id: Option<String>,
    pub ran_endpoint: String,
    pub amf_endpoint: String,
    pub association_id: String,
    pub lifecycle_generation: u32,
    pub state: String,
    pub first_timestamp_ns: i128,
    pub last_timestamp_ns: i128,
    pub event_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredPduSession {
    pub session_id: String,
    pub ue_context_id: String,
    pub pdu_session_id: String,
    pub dnn: Option<String>,
    pub snssai: Option<String>,
    pub state: String,
    pub establishment_timestamp_ns: i128,
    pub release_timestamp_ns: Option<i128>,
    pub interfaces: Vec<String>,
    pub correlation_status: String,
    pub event_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredPfcpSession {
    pub pfcp_session_id: String,
    pub smf_endpoint: String,
    pub upf_endpoint: String,
    pub seids: Vec<String>,
    pub pdr_ids: Vec<String>,
    pub far_ids: Vec<String>,
    pub tunnel_ids: Vec<String>,
    pub state: String,
    pub first_timestamp_ns: i128,
    pub last_timestamp_ns: i128,
    pub event_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredGtpuTunnel {
    pub tunnel_id: String,
    pub teid: String,
    pub source_endpoint: String,
    pub destination_endpoint: String,
    pub direction: String,
    pub related_pfcp_session: Option<String>,
    pub first_timestamp_ns: i128,
    pub last_timestamp_ns: i128,
    pub packet_count: usize,
    pub byte_count: u64,
    pub event_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcedureInstance {
    pub procedure_id: String,
    pub procedure_type: String,
    pub ue_context_id: String,
    pub pdu_session_id: Option<String>,
    pub start_timestamp_ns: i128,
    pub end_timestamp_ns: i128,
    pub event_ids: Vec<String>,
    pub result: String,
    pub start_event_id: String,
    pub end_event_id: Option<String>,
    pub duration_ns: i128,
    pub failure_cause: Option<String>,
    pub missing_evidence: Vec<String>,
    pub evidence: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryResult {
    pub ue_contexts: Vec<DiscoveredUeContext>,
    pub pdu_sessions: Vec<DiscoveredPduSession>,
    pub pfcp_sessions: Vec<DiscoveredPfcpSession>,
    pub gtpu_tunnels: Vec<DiscoveredGtpuTunnel>,
    pub procedures: Vec<ProcedureInstance>,
    pub background_event_ids: Vec<String>,
    pub unmatched_event_ids: Vec<String>,
    pub duplicate_observations: Vec<String>,
    pub event_accounting: BTreeMap<String, usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LteTunnelCounters {
    pub teid: String,
    pub uplink_packets: usize,
    pub downlink_packets: usize,
    pub unknown_direction_packets: usize,
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LteSession {
    pub session_id: String,
    pub technology: String,
    pub ue_pseudonym: String,
    pub enb_ue_s1ap_id: Option<String>,
    pub mme_ue_s1ap_id: Option<String>,
    pub eps_bearer_ids: Vec<String>,
    pub s11_f_teids: Vec<String>,
    pub tunnels: Vec<LteTunnelCounters>,
    pub procedures: Vec<String>,
    pub interfaces: Vec<String>,
    pub state: String,
    pub event_ids: Vec<String>,
    pub limitations: Vec<String>,
}

/// Builds a deterministic LTE preparation view from normalized S1AP/EPS NAS,
/// S11 and S1-U events. It deliberately does not infer UE identity from timing
/// and does not claim an S1AP/S11 bridge until an explicit bearer identifier is
/// emitted by both decoders.
pub fn discover_lte_sessions(events: &[EventRecord]) -> Vec<LteSession> {
    let mut lte = events
        .iter()
        .filter(|event| {
            matches!(event.interface.as_str(), "S1-MME" | "S11" | "S1-U")
                && matches!(
                    event.protocol.as_str(),
                    "S1AP" | "NAS-EPS-MM" | "NAS-EPS-SM" | "GTPv2-C" | "GTP-U"
                )
        })
        .collect::<Vec<_>>();
    lte.sort_by_key(|event| (event.timestamp_ns, event.packet_number(), &event.event_id));
    let Some(anchor) = lte.iter().copied().find(|event| event.protocol == "S1AP") else {
        return Vec::new();
    };
    let enb = lte
        .iter()
        .find_map(|event| event.first_identifier("enb_ue_s1ap_id"))
        .map(str::to_owned);
    let mme = lte
        .iter()
        .find_map(|event| event.first_identifier("mme_ue_s1ap_id"))
        .map(str::to_owned);
    let ue_pseudonym = lte
        .iter()
        .find_map(|event| event.first_identifier("imsi_pseudonym"))
        .map(str::to_owned)
        .unwrap_or_else(|| {
            stable_id(
                "LTE-UE",
                &format!("{}|{:?}|{:?}", anchor.capture_id, enb, mme),
            )
        });
    let collect_ids = |names: &[&str]| {
        let mut values = BTreeSet::new();
        for event in &lte {
            for (name, value) in &event.identifiers {
                if names.contains(&name.as_str()) {
                    values.insert(value.clone());
                }
            }
        }
        values.into_iter().collect::<Vec<_>>()
    };
    let eps_bearer_ids = collect_ids(&["eps_bearer_identity", "ebi", "bearer_ebi"]);
    let s11_f_teids = collect_ids(&["f_teid", "bearer_f_teid"]);
    let mut tunnel_map: BTreeMap<String, LteTunnelCounters> = BTreeMap::new();
    for event in lte
        .iter()
        .filter(|event| event.interface == "S1-U" && event.protocol == "GTP-U")
    {
        let Some(teid) = event.first_identifier("teid") else {
            continue;
        };
        let counters = tunnel_map.entry(teid.to_owned()).or_insert(LteTunnelCounters {
            teid: teid.to_owned(),
            uplink_packets: 0,
            downlink_packets: 0,
            unknown_direction_packets: 0,
            bytes: 0,
        });
        match event.direction.as_str() {
            "UPLINK" | "RAN_TO_CORE" => counters.uplink_packets += 1,
            "DOWNLINK" | "CORE_TO_RAN" => counters.downlink_packets += 1,
            _ => counters.unknown_direction_packets += 1,
        }
        counters.bytes += event
            .packet_references
            .first()
            .map(|packet| u64::from(packet.captured_length))
            .unwrap_or(0);
    }
    let procedures = lte
        .iter()
        .map(|event| event.message_name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let interfaces = lte
        .iter()
        .map(|event| event.interface.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let released = procedures
        .iter()
        .any(|name| name.contains("Detach") || name == "UEContextReleaseComplete");
    let bearer_ready = procedures
        .iter()
        .any(|name| name == "E-RABSetupResponse" || name == "InitialContextSetupResponse");
    let state = if released {
        "RELEASED"
    } else if bearer_ready && !tunnel_map.is_empty() {
        "ACTIVE_WITH_USER_PLANE"
    } else {
        "INCOMPLETE"
    };
    vec![LteSession {
        session_id: stable_id(
            "lte-session",
            &format!("{}|{}|{:?}|{:?}", anchor.capture_id, ue_pseudonym, enb, mme),
        ),
        technology: "LTE".into(),
        ue_pseudonym,
        enb_ue_s1ap_id: enb,
        mme_ue_s1ap_id: mme,
        eps_bearer_ids,
        s11_f_teids,
        tunnels: tunnel_map.into_values().collect(),
        procedures,
        interfaces,
        state: state.into(),
        event_ids: lte.iter().map(|event| event.event_id.clone()).collect(),
        limitations: vec![
            "Synthetic preparation only; real LTE evidence requires ANR1 certification".into(),
            "No timestamp-only S1AP/S11/S1-U identity association is performed".into(),
        ],
    }]
}

pub fn load_jsonl<R: BufRead>(reader: R) -> Result<Vec<EventRecord>, String> {
    let mut events = Vec::new();
    for (line_no, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("line {}: {e}", line_no + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(&line)
            .map_err(|e| format!("line {}: invalid JSON: {e}", line_no + 1))?;
        events.push(parse_event(value).map_err(|e| format!("line {}: {e}", line_no + 1))?);
    }
    deterministic_sort(&mut events);
    Ok(events)
}

pub fn load_path(path: &std::path::Path) -> Result<Vec<EventRecord>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    load_jsonl(io::BufReader::new(file))
}

fn parse_event(v: Value) -> Result<EventRecord, String> {
    let string = |path: &[&str]| -> Result<String, String> {
        let mut p = &v;
        for key in path {
            p = p
                .get(*key)
                .ok_or_else(|| format!("missing {}", path.join(".")))?;
        }
        p.as_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| format!("{} is not a string", path.join(".")))
    };
    let timestamp = v.get("timestamp").ok_or("missing timestamp")?;
    let seconds = timestamp
        .get("seconds")
        .and_then(Value::as_i64)
        .ok_or("missing timestamp.seconds")?;
    let nanos = timestamp
        .get("nanoseconds")
        .and_then(Value::as_u64)
        .ok_or("missing timestamp.nanoseconds")?;
    let raw_ticks = timestamp
        .get("raw_ticks")
        .and_then(Value::as_u64)
        .ok_or("missing timestamp.raw_ticks")?;
    let endpoint = |name: &str| -> Result<(String, String), String> {
        let e = v.get(name).ok_or_else(|| format!("missing {name}"))?;
        Ok((
            e.get("address")
                .and_then(Value::as_str)
                .unwrap_or("UNKNOWN")
                .to_owned(),
            e.get("network_function")
                .and_then(Value::as_str)
                .unwrap_or("Unknown endpoint")
                .to_owned(),
        ))
    };
    let (source_address, source_participant) = endpoint("source_endpoint")?;
    let (destination_address, destination_participant) = endpoint("destination_endpoint")?;
    let identifiers = v
        .get("session_identifiers")
        .and_then(Value::as_array)
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|x| {
            Some((
                x.get("name")?.as_str()?.to_owned(),
                x.get("value")?.as_str()?.to_owned(),
            ))
        })
        .collect();
    let packet_references: Vec<PacketRef> = serde_json::from_value(
        v.get("packet_references")
            .cloned()
            .ok_or("missing packet_references")?,
    )
    .map_err(|e| format!("invalid packet_references: {e}"))?;
    let errors = v
        .get("errors")
        .and_then(Value::as_array)
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect();
    // Keep only the top-level fields consumed after normalization. Retaining
    // the complete source JSON duplicated the (potentially large)
    // information-elements tree already stored on EventRecord and caused the
    // continuous importer to exceed its 256 MiB service cgroup while building
    // session/call-flow indexes.
    let mut compact_source = serde_json::Map::new();
    for key in ["schema_version", "procedure", "sbi"] {
        if let Some(value) = v.get(key) {
            compact_source.insert(key.to_string(), value.clone());
        }
    }
    Ok(EventRecord {
        event_id: string(&["event_id"])?,
        parent_event_id: v
            .get("parent_event_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        capture_id: string(&["capture_id"])?,
        capture_point_id: string(&["capture_point_id"])?,
        timestamp: timestamp
            .get("display")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        timestamp_ns: i128::from(seconds) * 1_000_000_000 + i128::from(nanos),
        raw_ticks,
        interface: string(&["interface"])?,
        protocol: string(&["protocol"])?,
        message_name: string(&["message_name"])?,
        source_address,
        destination_address,
        source_participant,
        destination_participant,
        direction: string(&["direction"])?,
        identifiers,
        information_elements: v
            .get("information_elements")
            .cloned()
            .unwrap_or(Value::Array(Vec::new())),
        decoding_status: string(&["decoding_status"])?,
        decoder_name: string(&["decoder_name"])?,
        decoder_version: string(&["decoder_version"])?,
        raw_payload_reference: string(&["raw_payload_reference"])?,
        packet_references,
        errors,
        source_json: Value::Object(compact_source),
    })
}

pub fn deterministic_sort(events: &mut [EventRecord]) {
    events.sort_by(|a, b| {
        (a.timestamp_ns, a.packet_number(), &a.interface, &a.event_id).cmp(&(
            b.timestamp_ns,
            b.packet_number(),
            &b.interface,
            &b.event_id,
        ))
    });
}

pub fn reconstruct(mut events: Vec<EventRecord>, hints: ReconstructionHints) -> Reconstruction {
    deterministic_sort(&mut events);
    let duplicate_event_ids = duplicate_ids(&events);
    let pdu_anchor = events
        .iter()
        .find(|e| e.protocol == "NGAP" && e.message_name.contains("PDUSessionResourceSetup"));
    let ran = pdu_anchor
        .and_then(|e| e.first_identifier("ran_ue_ngap_id"))
        .map(ToOwned::to_owned);
    let amf = pdu_anchor
        .and_then(|e| e.first_identifier("amf_ue_ngap_id"))
        .map(ToOwned::to_owned);
    let pdu = pdu_anchor
        .and_then(|e| e.first_identifier("pdu_session_id"))
        .map(ToOwned::to_owned);
    let pseudonym = hints.ue_pseudonym.unwrap_or_else(|| {
        format!(
            "UE-{:08x}",
            stable_hash(format!("{:?}|{:?}", ran, amf).as_bytes()) as u32
        )
    });

    let mut pfcp_sequences = BTreeSet::new();
    let mut seids = BTreeSet::new();
    for e in &events {
        if e.protocol == "PFCP"
            && (e.message_name.contains("Session Establishment")
                || e.message_name.contains("Session Modification"))
        {
            if let Some(x) = e.first_identifier("pfcp_sequence") {
                pfcp_sequences.insert(x.to_owned());
            }
            for name in ["seid", "f_seid"] {
                for x in e.identifier_values(name) {
                    if x != "0x0000000000000000" {
                        seids.insert(x.to_owned());
                    }
                }
            }
        }
    }
    let teid_records = collect_pfcp_tunnels(&events);
    let mut association = BTreeMap::new();
    for e in &events {
        let value = match e.protocol.as_str() {
            "NGAP" => {
                let same_ran = ran
                    .as_deref()
                    .map(|x| e.identifier_values("ran_ue_ngap_id").contains(&x))
                    .unwrap_or(false);
                let same_amf = amf
                    .as_deref()
                    .map(|x| e.identifier_values("amf_ue_ngap_id").contains(&x))
                    .unwrap_or(false);
                if same_ran || same_amf {
                    Association::Session
                } else {
                    Association::Background
                }
            }
            "PFCP" => {
                let session_message = e.message_name.contains("Session Establishment")
                    || e.message_name.contains("Session Modification")
                    || e.message_name.contains("Session Deletion");
                let same_seq = e
                    .first_identifier("pfcp_sequence")
                    .map(|x| pfcp_sequences.contains(x))
                    .unwrap_or(false);
                let same_seid = e
                    .identifiers
                    .iter()
                    .any(|(n, x)| (n == "seid" || n == "f_seid") && seids.contains(x));
                if session_message && (same_seq || same_seid) {
                    Association::Session
                } else {
                    Association::Background
                }
            }
            "GTP-U" => {
                let teid = e.first_identifier("teid");
                if teid_records.iter().any(|(t, endpoint)| {
                    Some(t.as_str()) == teid
                        && (endpoint.is_none()
                            || endpoint.as_ref() == Some(&e.source_address)
                            || endpoint.as_ref() == Some(&e.destination_address))
                }) {
                    Association::Session
                } else {
                    Association::Unmatched
                }
            }
            _ => Association::Unmatched,
        };
        association.insert(e.event_id.clone(), value);
    }

    let mut tunnels = Vec::new();
    for (teid, endpoint) in teid_records {
        let matching: Vec<_> = events
            .iter()
            .filter(|e| e.protocol == "GTP-U" && e.first_identifier("teid") == Some(&teid))
            .collect();
        if matching.is_empty() {
            continue;
        }
        let direction = matching
            .first()
            .map(|e| e.direction.clone())
            .unwrap_or_else(|| "UNKNOWN".into());
        tunnels.push(GtpuTunnel {
            teid,
            endpoint,
            direction,
            packet_count: matching.len(),
        });
    }
    if tunnels.is_empty() {
        for (teid, direction) in [
            (hints.uplink_teid, "UPLINK"),
            (hints.downlink_teid, "DOWNLINK"),
        ] {
            if let Some(teid) = teid {
                let packet_count = events
                    .iter()
                    .filter(|e| e.first_identifier("teid") == Some(teid.as_str()))
                    .count();
                tunnels.push(GtpuTunnel {
                    teid,
                    endpoint: None,
                    direction: direction.into(),
                    packet_count,
                });
            }
        }
    }
    tunnels.sort_by(|a, b| a.teid.cmp(&b.teid));

    let ids = |name: &str| -> Vec<String> {
        let mut values = BTreeSet::new();
        for e in &events {
            if association.get(&e.event_id) == Some(&Association::Session) {
                for x in e.identifier_values(name) {
                    values.insert(x.to_owned());
                }
            }
        }
        values.into_iter().collect()
    };
    let f_seids = ids("f_seid");
    let has_pdu_response = events
        .iter()
        .any(|e| e.message_name == "PDUSessionResourceSetupResponse");
    let has_user_plane = tunnels.iter().any(|t| t.packet_count > 0);
    Reconstruction {
        session_id: format!(
            "5g-{}-pdu-{}",
            pseudonym,
            pdu.as_deref().unwrap_or("unknown")
        ),
        ue: UeContext {
            pseudonym,
            amf_ue_ngap_id: amf,
            ran_ue_ngap_id: ran,
            pdu_session_id: pdu,
            state: if has_pdu_response && has_user_plane {
                "ACTIVE_WITH_USER_PLANE"
            } else if has_pdu_response {
                "ACTIVE_NO_USER_PLANE_OBSERVED"
            } else {
                "INCOMPLETE"
            }
            .into(),
        },
        pfcp: PfcpSession {
            smf_f_seid: f_seids.first().cloned(),
            upf_f_seid: f_seids.get(1).cloned(),
            pdr_ids: ids("pdr_id"),
            far_ids: ids("far_id"),
            qer_ids: ids("qer_id"),
            state: if events
                .iter()
                .any(|e| e.message_name == "PFCP Session Establishment Response")
            {
                "ESTABLISHED"
            } else {
                "INCOMPLETE"
            }
            .into(),
        },
        tunnels,
        events,
        association,
        duplicate_event_ids,
    }
}

/// Discovers independently scoped UE, PDU, PFCP and GTP-U state without assuming
/// a single subscriber or a single PDU session. The function is deterministic and
/// side-effect free so repeated ingestion of the same observations is idempotent.
pub fn discover_sessions(events: &mut Vec<EventRecord>) -> DiscoveryResult {
    deterministic_sort(events);
    let duplicate_observations = duplicate_observation_keys(events);
    let mut seen = HashSet::new();
    events.retain(|event| seen.insert(observation_key(event)));

    let mut contexts: Vec<DiscoveredUeContext> = Vec::new();
    let mut event_context: BTreeMap<String, String> = BTreeMap::new();
    let mut generations: BTreeMap<String, u32> = BTreeMap::new();

    for event in events.iter().filter(|event| event.protocol == "NGAP") {
        let ran = event.first_identifier("ran_ue_ngap_id").map(str::to_owned);
        let amf = event.first_identifier("amf_ue_ngap_id").map(str::to_owned);
        if ran.is_none() && amf.is_none() {
            continue;
        }
        let (ran_endpoint, amf_endpoint) = ngap_endpoints(event);
        let association_id = format!(
            "{}:{}:{}",
            event.capture_point_id, ran_endpoint, amf_endpoint
        );
        let matching = contexts.iter().position(|context| {
            context.state != "RELEASED"
                && context.association_id == association_id
                && ((ran.is_some() && context.ran_ue_ngap_id == ran)
                    || (amf.is_some() && context.amf_ue_ngap_id == amf))
        });
        let index = if let Some(index) = matching {
            index
        } else {
            let identity = format!(
                "{}|{}|{}",
                association_id,
                ran.as_deref().unwrap_or("unknown"),
                amf.as_deref().unwrap_or("unknown")
            );
            let generation = generations.entry(identity.clone()).or_default();
            *generation += 1;
            let context_id = stable_id("uectx", &format!("{identity}|{generation}"));
            contexts.push(DiscoveredUeContext {
                pseudonym: stable_id("UE", &context_id),
                context_id,
                ran_ue_ngap_id: ran.clone(),
                amf_ue_ngap_id: amf.clone(),
                ran_endpoint: ran_endpoint.clone(),
                amf_endpoint: amf_endpoint.clone(),
                association_id: association_id.clone(),
                lifecycle_generation: *generation,
                state: "OBSERVED".into(),
                first_timestamp_ns: event.timestamp_ns,
                last_timestamp_ns: event.timestamp_ns,
                event_ids: Vec::new(),
            });
            contexts.len() - 1
        };
        let context = &mut contexts[index];
        if context.ran_ue_ngap_id.is_none() {
            context.ran_ue_ngap_id = ran;
        }
        if context.amf_ue_ngap_id.is_none() {
            context.amf_ue_ngap_id = amf;
        }
        context.last_timestamp_ns = event.timestamp_ns;
        context.event_ids.push(event.event_id.clone());
        event_context.insert(event.event_id.clone(), context.context_id.clone());
        if event.message_name.contains("UEContextReleaseComplete") {
            context.state = "RELEASED".into();
        } else if event.message_name.contains("InitialUEMessage") {
            context.state = "REGISTERING".into();
        } else if event.message_name.contains("InitialContextSetupResponse") {
            context.state = "ACTIVE".into();
        }
    }

    // NAS events are logical children of an NGAP event and inherit the exact UE
    // context of that parent. They never create a context from time proximity.
    // Iterate to resolve a nested 5GSM child whose direct parent is a 5GMM event.
    let mut unresolved_nas = events
        .iter()
        .filter(|event| matches!(event.protocol.as_str(), "NAS-5GMM" | "NAS-5GSM"))
        .collect::<Vec<_>>();
    loop {
        let before = unresolved_nas.len();
        unresolved_nas.retain(|event| {
            let Some(parent) = event.parent_event_id.as_ref() else {
                return true;
            };
            let Some(context_id) = event_context.get(parent).cloned() else {
                return true;
            };
            let Some(context) = contexts
                .iter_mut()
                .find(|value| value.context_id == context_id)
            else {
                return true;
            };
            context.last_timestamp_ns = context.last_timestamp_ns.max(event.timestamp_ns);
            context.event_ids.push(event.event_id.clone());
            event_context.insert(event.event_id.clone(), context_id);
            false
        });
        if unresolved_nas.is_empty() || unresolved_nas.len() == before {
            break;
        }
    }

    let event_by_id: BTreeMap<_, _> = events
        .iter()
        .map(|event| (event.event_id.clone(), event))
        .collect();
    let mut pdu_sessions = Vec::new();
    let mut procedures = Vec::new();
    for context in &contexts {
        let mut pdu_events: BTreeMap<String, Vec<&EventRecord>> = BTreeMap::new();
        let mut context_only = Vec::new();
        for id in &context.event_ids {
            let Some(event) = event_by_id.get(id) else {
                continue;
            };
            if let Some(pdu_id) = event.first_identifier("pdu_session_id") {
                pdu_events.entry(pdu_id.to_owned()).or_default().push(event);
            } else {
                context_only.push(*event);
            }
        }
        procedures.extend(discover_procedures(context, None, &context_only));
        for (pdu_id, mut related) in pdu_events {
            related.sort_by_key(|event| event.timestamp_ns);
            let session_key = format!("{}|pdu={pdu_id}", context.context_id);
            let session_id = stable_id("5g-session", &session_key);
            let released = related
                .iter()
                .find(|event| event.message_name.contains("Release"));
            let established = related.iter().any(|event| {
                event
                    .message_name
                    .contains("PDUSessionResourceSetupResponse")
                    || event.message_name.contains("PDUSessionEstablishmentAccept")
            });
            let mut interfaces = related
                .iter()
                .map(|event| event.interface.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            interfaces.sort();
            let dnn = first_identifier_from(&related, &["dnn", "network_instance"]);
            let snssai = first_identifier_from(&related, &["snssai", "s_nssai"]);
            let session = DiscoveredPduSession {
                session_id: session_id.clone(),
                ue_context_id: context.context_id.clone(),
                pdu_session_id: pdu_id.clone(),
                dnn,
                snssai,
                state: if released.is_some() {
                    "RELEASED"
                } else if established {
                    "ACTIVE"
                } else {
                    "INCOMPLETE"
                }
                .into(),
                establishment_timestamp_ns: related[0].timestamp_ns,
                release_timestamp_ns: released.map(|event| event.timestamp_ns),
                interfaces,
                correlation_status: "UNKNOWN".into(),
                event_ids: related.iter().map(|event| event.event_id.clone()).collect(),
            };
            procedures.extend(discover_procedures(context, Some(&session), &related));
            pdu_sessions.push(session);
        }
    }

    let pfcp_sessions = discover_pfcp_sessions(&events);
    let gtpu_tunnels = discover_gtpu_tunnels(&events, &pfcp_sessions);
    let assigned: HashSet<_> = event_context.keys().cloned().collect();
    let mut background_event_ids = Vec::new();
    let mut unmatched_event_ids = Vec::new();
    for event in events.iter() {
        if assigned.contains(&event.event_id)
            || pfcp_sessions
                .iter()
                .any(|session| session.event_ids.contains(&event.event_id))
            || gtpu_tunnels
                .iter()
                .any(|tunnel| tunnel.event_ids.contains(&event.event_id))
        {
            continue;
        }
        if is_background(event) {
            background_event_ids.push(event.event_id.clone());
        } else {
            unmatched_event_ids.push(event.event_id.clone());
        }
    }
    let session_associated = events.len() - background_event_ids.len() - unmatched_event_ids.len();
    let mut event_accounting = BTreeMap::new();
    event_accounting.insert("source_events".into(), events.len());
    event_accounting.insert("session_events".into(), session_associated);
    event_accounting.insert("background_events".into(), background_event_ids.len());
    event_accounting.insert("unmatched_events".into(), unmatched_event_ids.len());
    event_accounting.insert(
        "duplicate_observations".into(),
        duplicate_observations.len(),
    );

    contexts.sort_by(|a, b| a.context_id.cmp(&b.context_id));
    pdu_sessions.sort_by(|a, b| a.session_id.cmp(&b.session_id));
    procedures.sort_by(|a, b| a.procedure_id.cmp(&b.procedure_id));
    DiscoveryResult {
        ue_contexts: contexts,
        pdu_sessions,
        pfcp_sessions,
        gtpu_tunnels,
        procedures,
        background_event_ids,
        unmatched_event_ids,
        duplicate_observations,
        event_accounting,
    }
}

fn ngap_endpoints(event: &EventRecord) -> (String, String) {
    if event.source_participant == "gNB" {
        (
            event.source_address.clone(),
            event.destination_address.clone(),
        )
    } else if event.destination_participant == "gNB" {
        (
            event.destination_address.clone(),
            event.source_address.clone(),
        )
    } else {
        let mut endpoints = [
            event.source_address.clone(),
            event.destination_address.clone(),
        ];
        endpoints.sort();
        (endpoints[0].clone(), endpoints[1].clone())
    }
}

fn first_identifier_from(events: &[&EventRecord], names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        events
            .iter()
            .find_map(|event| event.first_identifier(name).map(str::to_owned))
    })
}

fn discover_procedures(
    context: &DiscoveredUeContext,
    session: Option<&DiscoveredPduSession>,
    events: &[&EventRecord],
) -> Vec<ProcedureInstance> {
    let mut groups: BTreeMap<&str, Vec<&EventRecord>> = BTreeMap::new();
    let nas_parents = events
        .iter()
        .filter(|event| event.protocol.starts_with("NAS-5G"))
        .filter_map(|event| event.parent_event_id.as_deref())
        .collect::<BTreeSet<_>>();
    for event in events {
        if event.protocol == "NGAP"
            && nas_parents.contains(event.event_id.as_str())
            && (event.message_name.contains("NAS") || event.message_name.contains("InitialUE"))
        {
            continue;
        }
        let kind = if event.protocol.starts_with("NAS-5G") {
            event
                .source_json
                .get("procedure")
                .and_then(Value::as_str)
                .unwrap_or("OTHER_NAS")
        } else if event.message_name.contains("PDU") {
            "PDU_SESSION"
        } else if event.message_name.contains("Context") {
            "UE_CONTEXT"
        } else if event.message_name.contains("NAS") || event.message_name.contains("InitialUE") {
            "REGISTRATION"
        } else {
            "OTHER_SIGNALING"
        };
        groups.entry(kind).or_default().push(event);
    }
    let mut procedures = Vec::new();
    for (kind, ordered) in groups {
        let mut current = Vec::new();
        for event in ordered {
            if is_explicit_start(kind, &event.message_name) && !current.is_empty() {
                procedures.push(build_procedure(context, session, kind, &current));
                current.clear();
            }
            current.push(event);
            if is_explicit_terminal(kind, &event.message_name) {
                procedures.push(build_procedure(context, session, kind, &current));
                current.clear();
            }
        }
        if !current.is_empty() {
            procedures.push(build_procedure(context, session, kind, &current));
        }
    }
    procedures
}

fn build_procedure(
    context: &DiscoveredUeContext,
    session: Option<&DiscoveredPduSession>,
    kind: &str,
    events: &[&EventRecord],
) -> ProcedureInstance {
    let end = events.last().copied().unwrap_or(events[0]);
    let has_failure = end.message_name.contains("Reject") || end.message_name.contains("Failure");
    let has_success = is_explicit_success(kind, &end.message_name);
    let result = if has_failure {
        "FAILURE"
    } else if has_success {
        "SUCCESS"
    } else {
        "INCOMPLETE"
    };
    let failure_cause = events.iter().find_map(|event| {
        event
            .first_identifier("5gmm_cause")
            .or_else(|| event.first_identifier("5gsm_cause"))
            .map(str::to_owned)
    });
    let start = events[0];
    let key = format!(
        "{}|{}|{}|{}",
        context.context_id,
        session
            .map(|value| value.session_id.as_str())
            .unwrap_or("none"),
        kind,
        start.timestamp_ns
    );
    ProcedureInstance {
        procedure_id: stable_id("procedure", &key),
        procedure_type: kind.into(),
        ue_context_id: context.context_id.clone(),
        pdu_session_id: session.map(|value| value.session_id.clone()),
        start_timestamp_ns: start.timestamp_ns,
        end_timestamp_ns: end.timestamp_ns,
        event_ids: events.iter().map(|event| event.event_id.clone()).collect(),
        result: result.into(),
        start_event_id: start.event_id.clone(),
        end_event_id: (result != "INCOMPLETE").then(|| end.event_id.clone()),
        duration_ns: end.timestamp_ns - start.timestamp_ns,
        failure_cause,
        missing_evidence: if result == "INCOMPLETE" {
            vec![format!(
                "no explicit completion or failure observed for {kind}"
            )]
        } else {
            Vec::new()
        },
        evidence: if result == "INCOMPLETE" {
            "POSSIBLE"
        } else {
            "EXACT"
        }
        .into(),
    }
}

fn is_explicit_start(kind: &str, message: &str) -> bool {
    match kind {
        "REGISTRATION" => message == "Registration Request",
        "AUTHENTICATION" => message == "Authentication Request",
        "SECURITY_MODE" => message == "Security Mode Command",
        "PDU_SESSION_ESTABLISHMENT" => message == "PDU Session Establishment Request",
        "PDU_SESSION_MODIFICATION" => {
            message.contains("Modification Request") || message.contains("Modification Command")
        }
        "PDU_SESSION_RELEASE" => {
            message.contains("Release Request") || message.contains("Release Command")
        }
        "DEREGISTRATION" => message == "Deregistration Request",
        _ => false,
    }
}

fn is_explicit_terminal(kind: &str, message: &str) -> bool {
    message.contains("Reject") || message.contains("Failure") || is_explicit_success(kind, message)
}

fn is_explicit_success(kind: &str, message: &str) -> bool {
    match kind {
        "REGISTRATION" => message == "Registration Complete",
        "AUTHENTICATION" => message == "Authentication Response",
        "SECURITY_MODE" => message == "Security Mode Complete",
        "PDU_SESSION_ESTABLISHMENT" | "PDU_SESSION" => {
            message.contains("Establishment Accept") || message.contains("ResourceSetupResponse")
        }
        "PDU_SESSION_MODIFICATION" => message == "PDU Session Modification Complete",
        "PDU_SESSION_RELEASE" => message == "PDU Session Release Complete",
        "DEREGISTRATION" => message == "Deregistration Accept",
        _ => {
            message.contains("Response")
                || message.contains("Complete")
                || message.contains("Accept")
        }
    }
}

fn discover_pfcp_sessions(events: &[EventRecord]) -> Vec<DiscoveredPfcpSession> {
    #[derive(Default)]
    struct Pending<'a> {
        scope: String,
        transaction: String,
        events: Vec<&'a EventRecord>,
        seids: BTreeSet<String>,
    }

    let mut ordered = events
        .iter()
        .filter(|event| event.protocol == "PFCP" && event.message_name.contains("Session"))
        .collect::<Vec<_>>();
    ordered.sort_by_key(|event| event.timestamp_ns);
    let mut sessions: Vec<Pending<'_>> = Vec::new();
    for event in ordered {
        let scope = endpoint_scope(event);
        let transaction = event
            .first_identifier("pfcp_sequence")
            .unwrap_or("unknown")
            .to_owned();
        let event_seids = identifier_set(&[event], &["seid", "f_seid"])
            .into_iter()
            .filter(|value| value != "0x0000000000000000")
            .collect::<BTreeSet<_>>();
        let by_seid = sessions
            .iter()
            .position(|session| session.scope == scope && !session.seids.is_disjoint(&event_seids));
        let by_transaction = sessions
            .iter()
            .position(|session| session.scope == scope && session.transaction == transaction);
        let index = by_seid.or(by_transaction).unwrap_or_else(|| {
            sessions.push(Pending {
                scope: scope.clone(),
                transaction: transaction.clone(),
                events: Vec::new(),
                seids: BTreeSet::new(),
            });
            sessions.len() - 1
        });
        sessions[index].events.push(event);
        sessions[index].seids.extend(event_seids);
    }

    sessions
        .into_iter()
        .map(|session| {
            let mut events = session.events;
            let state = if events
                .iter()
                .any(|event| event.message_name.contains("Deletion Response"))
            {
                "DELETED"
            } else if events
                .iter()
                .any(|event| event.message_name.contains("Establishment Response"))
            {
                "ESTABLISHED"
            } else {
                "INCOMPLETE"
            };
            let key = format!(
                "{}|{}|{}",
                session.scope,
                session.seids.iter().cloned().collect::<Vec<_>>().join(","),
                events[0].timestamp_ns
            );
            let (smf_endpoint, upf_endpoint) = pfcp_endpoints(events[0]);
            DiscoveredPfcpSession {
                pfcp_session_id: stable_id("pfcp", &key),
                smf_endpoint,
                upf_endpoint,
                seids: session.seids.into_iter().collect(),
                pdr_ids: identifier_set(&events, &["pdr_id"]),
                far_ids: identifier_set(&events, &["far_id"]),
                tunnel_ids: collect_pfcp_tunnels(
                    &events
                        .iter()
                        .map(|event| (*event).clone())
                        .collect::<Vec<_>>(),
                )
                .into_iter()
                .map(|(teid, endpoint)| stable_id("pfcp-tunnel", &format!("{teid}|{endpoint:?}")))
                .collect(),
                state: state.into(),
                first_timestamp_ns: events[0].timestamp_ns,
                last_timestamp_ns: events.last().unwrap().timestamp_ns,
                event_ids: events.iter().map(|event| event.event_id.clone()).collect(),
            }
        })
        .collect()
}

fn pfcp_endpoints(event: &EventRecord) -> (String, String) {
    if event.source_participant == "SMF" || event.destination_participant == "UPF" {
        (
            event.source_address.clone(),
            event.destination_address.clone(),
        )
    } else if event.destination_participant == "SMF" || event.source_participant == "UPF" {
        (
            event.destination_address.clone(),
            event.source_address.clone(),
        )
    } else {
        (
            event.source_address.clone(),
            event.destination_address.clone(),
        )
    }
}

fn discover_gtpu_tunnels(
    events: &[EventRecord],
    pfcp_sessions: &[DiscoveredPfcpSession],
) -> Vec<DiscoveredGtpuTunnel> {
    let mut groups: BTreeMap<String, Vec<&EventRecord>> = BTreeMap::new();
    for event in events.iter().filter(|event| event.protocol == "GTP-U") {
        let Some(teid) = event.first_identifier("teid") else {
            continue;
        };
        let key = format!(
            "{}|{}|{}|{}",
            event.source_address, event.destination_address, teid, event.direction
        );
        groups.entry(key).or_default().push(event);
    }
    groups
        .into_iter()
        .map(|(key, mut events)| {
            events.sort_by_key(|event| event.timestamp_ns);
            let teid = events[0].first_identifier("teid").unwrap().to_owned();
            let tunnel_id = stable_id("tunnel", &key);
            let endpoint_candidates = [&events[0].source_address, &events[0].destination_address]
                .into_iter()
                .map(|endpoint| {
                    stable_id(
                        "pfcp-tunnel",
                        &format!("{teid}|{:?}", Some(endpoint.clone())),
                    )
                })
                .collect::<BTreeSet<_>>();
            let related = pfcp_sessions
                .iter()
                .filter(|session| {
                    session
                        .tunnel_ids
                        .iter()
                        .any(|candidate| endpoint_candidates.contains(candidate))
                })
                .collect::<Vec<_>>();
            let related_pfcp_session =
                (related.len() == 1).then(|| related[0].pfcp_session_id.clone());
            DiscoveredGtpuTunnel {
                tunnel_id,
                teid,
                source_endpoint: events[0].source_address.clone(),
                destination_endpoint: events[0].destination_address.clone(),
                direction: events[0].direction.clone(),
                related_pfcp_session,
                first_timestamp_ns: events[0].timestamp_ns,
                last_timestamp_ns: events.last().unwrap().timestamp_ns,
                packet_count: events.len(),
                byte_count: events
                    .iter()
                    .flat_map(|event| &event.packet_references)
                    .map(|packet| u64::from(packet.captured_length))
                    .sum(),
                event_ids: events.iter().map(|event| event.event_id.clone()).collect(),
            }
        })
        .collect()
}

fn identifier_set(events: &[&EventRecord], names: &[&str]) -> Vec<String> {
    events
        .iter()
        .flat_map(|event| names.iter().flat_map(|name| event.identifier_values(name)))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn endpoint_scope(event: &EventRecord) -> String {
    let mut endpoints = [
        event.source_address.as_str(),
        event.destination_address.as_str(),
    ];
    endpoints.sort();
    format!("{}|{}", endpoints[0], endpoints[1])
}

fn is_background(event: &EventRecord) -> bool {
    event.message_name.contains("Heartbeat")
        || event.message_name.contains("Association Setup")
        || event.message_name.contains("NG Setup")
}

fn observation_key(event: &EventRecord) -> String {
    let packets = event
        .packet_references
        .iter()
        .map(|packet| format!("{}:{}", packet.source_file, packet.packet_number))
        .collect::<Vec<_>>()
        .join("|");
    format!("{}|{}|{packets}", event.capture_id, event.event_id)
}

fn duplicate_observation_keys(events: &[EventRecord]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut duplicates = BTreeSet::new();
    for event in events {
        let key = observation_key(event);
        if !seen.insert(key.clone()) {
            duplicates.insert(key);
        }
    }
    duplicates.into_iter().collect()
}

fn stable_id(prefix: &str, value: &str) -> String {
    format!("{prefix}-{:016x}", stable_hash(value.as_bytes()))
}

fn collect_pfcp_tunnels(events: &[EventRecord]) -> Vec<(String, Option<String>)> {
    let mut result = BTreeSet::new();
    for e in events.iter().filter(|e| e.protocol == "PFCP") {
        if let Some(items) = e.information_elements.as_array() {
            for item in items {
                let Some(value) = item.get("value").and_then(Value::as_str) else {
                    continue;
                };
                let teid = component(value, "teid");
                if let Some(teid) = teid {
                    result.insert((teid, component(value, "ipv4")));
                }
            }
        }
    }
    result.into_iter().collect()
}

pub fn component(value: &str, key: &str) -> Option<String> {
    value.split(',').find_map(|part| {
        let (k, v) = part.split_once('=')?;
        (k.trim() == key).then(|| v.trim().to_owned())
    })
}

fn duplicate_ids(events: &[EventRecord]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut dup = BTreeSet::new();
    for e in events {
        if !seen.insert(&e.event_id) {
            dup.insert(e.event_id.clone());
        }
    }
    dup.into_iter().collect()
}

fn stable_hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325u64, |mut h, b| {
        h ^= u64::from(*b);
        h.wrapping_mul(0x100000001b3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(
        id: &str,
        protocol: &str,
        name: &str,
        ids: &[(&str, &str)],
        packet: u64,
    ) -> EventRecord {
        let source = format!(
            r#"{{"event_id":"{id}","capture_id":"cap","capture_point_id":"{protocol}","timestamp":{{"seconds":1,"nanoseconds":{packet},"raw_ticks":{packet},"display":"1.00000000{packet}Z"}},"interface":"{protocol}","protocol":"{protocol}","message_name":"{name}","source_endpoint":{{"address":"a","network_function":"gNB"}},"destination_endpoint":{{"address":"b","network_function":"AMF"}},"direction":"UNKNOWN","session_identifiers":[],"information_elements":[],"decoding_status":"DECODED","decoder_name":"d","decoder_version":"1","raw_payload_reference":"sha256:x","packet_references":[{{"source_file":"x","packet_number":{packet},"byte_offset":0,"interface_id":0,"captured_length":1,"original_length":1}}],"errors":[]}}"#
        );
        let mut e = parse_event(serde_json::from_str(&source).unwrap()).unwrap();
        e.identifiers = ids
            .iter()
            .map(|(a, b)| ((*a).into(), (*b).into()))
            .collect();
        e
    }

    #[test]
    fn reconstructs_ue_and_pdu_context() {
        let mut events = vec![event(
            "n",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            &[
                ("ran_ue_ngap_id", "4"),
                ("amf_ue_ngap_id", "4"),
                ("pdu_session_id", "1"),
            ],
            1,
        )];
        let r = reconstruct(
            events,
            ReconstructionHints {
                ue_pseudonym: Some("UE-A".into()),
                ..Default::default()
            },
        );
        assert_eq!(r.ue.ran_ue_ngap_id.as_deref(), Some("4"));
        assert_eq!(r.ue.pdu_session_id.as_deref(), Some("1"));
    }

    #[test]
    fn reconstructs_pfcp_session() {
        let mut events = vec![event(
            "p",
            "PFCP",
            "PFCP Session Establishment Response",
            &[("pfcp_sequence", "2"), ("f_seid", "0x2"), ("pdr_id", "1")],
            1,
        )];
        let r = reconstruct(events, Default::default());
        assert_eq!(r.pfcp.state, "ESTABLISHED");
        assert_eq!(r.pfcp.pdr_ids, vec!["1"]);
    }

    #[test]
    fn missing_messages_remain_incomplete() {
        let r = reconstruct(Vec::new(), Default::default());
        assert_eq!(r.ue.state, "INCOMPLETE");
        assert_eq!(r.pfcp.state, "INCOMPLETE");
    }

    #[test]
    fn duplicate_event_ids_are_reported_not_dropped() {
        let e = event("same", "NGAP", "x", &[], 1);
        let r = reconstruct(vec![e.clone(), e], Default::default());
        assert_eq!(r.events.len(), 2);
        assert_eq!(r.duplicate_event_ids, vec!["same"]);
    }

    #[test]
    fn ordering_is_deterministic() {
        let mut events = vec![
            event("b", "NGAP", "x", &[], 2),
            event("a", "NGAP", "x", &[], 1),
        ];
        deterministic_sort(&mut events);
        assert_eq!(events[0].event_id, "a");
    }

    #[test]
    fn provenance_is_required_and_preserved() {
        let e = event("a", "NGAP", "x", &[], 1);
        assert!(e.has_provenance());
        let r = reconstruct(vec![e], Default::default());
        assert!(r.events[0].has_provenance());
    }

    #[test]
    fn nas_child_inherits_exact_parent_context_without_time_correlation() {
        let parent = event(
            "parent-a",
            "NGAP",
            "InitialUEMessage",
            &[("ran_ue_ngap_id", "10"), ("amf_ue_ngap_id", "100")],
            1,
        );
        let mut child = event(
            "nas-a",
            "NAS-5GSM",
            "PDU Session Establishment Request",
            &[("pdu_session_id", "1"), ("pti", "7")],
            99,
        );
        child.parent_event_id = Some(parent.event_id.clone());
        child.source_json["procedure"] = Value::String("PDU_SESSION_ESTABLISHMENT".into());
        let unrelated = event(
            "parent-b",
            "NGAP",
            "InitialUEMessage",
            &[("ran_ue_ngap_id", "11"), ("amf_ue_ngap_id", "101")],
            98,
        );
        let result = discover_sessions(&mut vec![parent, unrelated, child]);
        assert_eq!(result.ue_contexts.len(), 2);
        assert_eq!(result.pdu_sessions.len(), 1);
        let session = &result.pdu_sessions[0];
        let context = result
            .ue_contexts
            .iter()
            .find(|c| c.context_id == session.ue_context_id)
            .unwrap();
        assert_eq!(context.ran_ue_ngap_id.as_deref(), Some("10"));
        assert!(session.event_ids.iter().any(|id| id == "nas-a"));
    }

    #[test]
    fn discovers_multiple_ues_and_multiple_pdu_sessions() {
        let mut events = vec![
            event(
                "ue-a-1",
                "NGAP",
                "InitialUEMessage",
                &[("ran_ue_ngap_id", "10"), ("amf_ue_ngap_id", "100")],
                1,
            ),
            event(
                "ue-a-pdu-1",
                "NGAP",
                "PDUSessionResourceSetupResponse",
                &[
                    ("ran_ue_ngap_id", "10"),
                    ("amf_ue_ngap_id", "100"),
                    ("pdu_session_id", "1"),
                ],
                2,
            ),
            event(
                "ue-a-pdu-2",
                "NGAP",
                "PDUSessionResourceSetupRequest",
                &[
                    ("ran_ue_ngap_id", "10"),
                    ("amf_ue_ngap_id", "100"),
                    ("pdu_session_id", "2"),
                ],
                3,
            ),
            event(
                "ue-b-pdu-1",
                "NGAP",
                "PDUSessionResourceSetupResponse",
                &[
                    ("ran_ue_ngap_id", "11"),
                    ("amf_ue_ngap_id", "101"),
                    ("pdu_session_id", "1"),
                ],
                4,
            ),
        ];
        let result = discover_sessions(&mut events);
        assert_eq!(result.ue_contexts.len(), 2);
        assert_eq!(result.pdu_sessions.len(), 3);
        assert_eq!(
            result
                .pdu_sessions
                .iter()
                .filter(|session| session.pdu_session_id == "1")
                .count(),
            2
        );
        assert_ne!(
            result.pdu_sessions[0].session_id,
            result.pdu_sessions[1].session_id
        );
        assert!(result
            .pdu_sessions
            .iter()
            .any(|session| session.state == "INCOMPLETE"));
    }

    #[test]
    fn identifier_reuse_after_release_creates_new_lifecycle() {
        let mut events = vec![
            event(
                "first",
                "NGAP",
                "InitialUEMessage",
                &[("ran_ue_ngap_id", "7"), ("amf_ue_ngap_id", "9")],
                1,
            ),
            event(
                "released",
                "NGAP",
                "UEContextReleaseComplete",
                &[("ran_ue_ngap_id", "7"), ("amf_ue_ngap_id", "9")],
                2,
            ),
            event(
                "reused",
                "NGAP",
                "InitialUEMessage",
                &[("ran_ue_ngap_id", "7"), ("amf_ue_ngap_id", "9")],
                3,
            ),
        ];
        let result = discover_sessions(&mut events);
        assert_eq!(result.ue_contexts.len(), 2);
        assert_eq!(
            result
                .ue_contexts
                .iter()
                .map(|context| context.lifecycle_generation)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([1, 2])
        );
    }

    #[test]
    fn repeated_import_is_deduplicated_and_deterministic() {
        let original = event(
            "same",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            &[
                ("ran_ue_ngap_id", "4"),
                ("amf_ue_ngap_id", "4"),
                ("pdu_session_id", "1"),
            ],
            1,
        );
        let first = discover_sessions(&mut vec![original.clone(), original.clone()]);
        let second = discover_sessions(&mut vec![original]);
        assert_eq!(first.duplicate_observations.len(), 1);
        assert_eq!(first.pdu_sessions.len(), 1);
        assert_eq!(
            first.pdu_sessions[0].session_id,
            second.pdu_sessions[0].session_id
        );
        assert_eq!(first.event_accounting["source_events"], 1);
    }

    #[test]
    fn out_of_order_input_produces_stable_sessions() {
        let first = event(
            "first",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            &[
                ("ran_ue_ngap_id", "8"),
                ("amf_ue_ngap_id", "18"),
                ("pdu_session_id", "3"),
            ],
            1,
        );
        let second = event(
            "second",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            &[
                ("ran_ue_ngap_id", "8"),
                ("amf_ue_ngap_id", "18"),
                ("pdu_session_id", "3"),
            ],
            2,
        );
        let a = discover_sessions(&mut vec![second.clone(), first.clone()]);
        let b = discover_sessions(&mut vec![first, second]);
        assert_eq!(a.pdu_sessions[0].session_id, b.pdu_sessions[0].session_id);
        assert_eq!(a.pdu_sessions[0].event_ids, b.pdu_sessions[0].event_ids);
    }

    #[test]
    fn five_ue_fixture_supports_concurrency_multiple_pdus_and_incomplete_state() {
        let mut events = Vec::new();
        for ue in 1..=5u64 {
            events.push(event(
                &format!("ue-{ue}-initial"),
                "NGAP",
                "InitialUEMessage",
                &[
                    ("ran_ue_ngap_id", &ue.to_string()),
                    ("amf_ue_ngap_id", &(100 + ue).to_string()),
                ],
                ue,
            ));
            events.push(event(
                &format!("ue-{ue}-pdu-1"),
                "NGAP",
                if ue == 5 {
                    "PDUSessionResourceSetupRequest"
                } else {
                    "PDUSessionResourceSetupResponse"
                },
                &[
                    ("ran_ue_ngap_id", &ue.to_string()),
                    ("amf_ue_ngap_id", &(100 + ue).to_string()),
                    ("pdu_session_id", "1"),
                ],
                10 + ue,
            ));
        }
        events.push(event(
            "ue-1-pdu-2",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            &[
                ("ran_ue_ngap_id", "1"),
                ("amf_ue_ngap_id", "101"),
                ("pdu_session_id", "2"),
            ],
            20,
        ));
        let result = discover_sessions(&mut events);
        assert_eq!(result.ue_contexts.len(), 5);
        assert_eq!(result.pdu_sessions.len(), 6);
        assert_eq!(
            result
                .pdu_sessions
                .iter()
                .filter(|session| session.state == "INCOMPLETE")
                .count(),
            1
        );
        let ue_with_two = result
            .pdu_sessions
            .iter()
            .filter(|session| session.pdu_session_id == "2")
            .map(|session| session.ue_context_id.clone())
            .next()
            .unwrap();
        assert_eq!(
            result
                .pdu_sessions
                .iter()
                .filter(|session| session.ue_context_id == ue_with_two)
                .count(),
            2
        );
    }

    #[test]
    fn v2_3_corpus_discovers_three_isolated_end_to_end_sessions() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/oiran-v2.3-multi-session/corpus.json"
        ))
        .unwrap();
        assert_eq!(
            fixture["fixture_label"],
            "TEST DATA — NOT CAPTURED NETWORK EVIDENCE"
        );
        let mut events = Vec::new();
        for (offset, ue) in fixture["ues"].as_array().unwrap().iter().enumerate() {
            let ordinal = u64::try_from(offset + 1).unwrap();
            let ran = ue["ran_ue_ngap_id"].as_str().unwrap();
            let amf = ue["amf_ue_ngap_id"].as_str().unwrap();
            let pdu = ue["pdu_session_id"].as_str().unwrap();
            let sequence = ue["pfcp_sequence"].as_str().unwrap();
            let seid = ue["seid"].as_str().unwrap();
            let teid = ue["teid"].as_str().unwrap();
            let gnb_n3 = ue["gnb_n3"].as_str().unwrap();

            events.push(event(
                &format!("test-ue-{ordinal}-initial"),
                "NGAP",
                "InitialUEMessage",
                &[("ran_ue_ngap_id", ran), ("amf_ue_ngap_id", amf)],
                ordinal * 10,
            ));
            events.push(event(
                &format!("test-ue-{ordinal}-pdu"),
                "NGAP",
                "PDUSessionResourceSetupResponse",
                &[
                    ("ran_ue_ngap_id", ran),
                    ("amf_ue_ngap_id", amf),
                    ("pdu_session_id", pdu),
                    ("dnn", "internet"),
                    ("snssai", "sst=1,sd=010203"),
                ],
                ordinal * 10 + 1,
            ));
            let mut pfcp = event(
                &format!("test-ue-{ordinal}-pfcp"),
                "PFCP",
                "Session Establishment Response",
                &[
                    ("pfcp_sequence", sequence),
                    ("seid", seid),
                    ("f_seid", seid),
                    ("pdr_id", &ordinal.to_string()),
                    ("far_id", &ordinal.to_string()),
                ],
                ordinal * 10 + 2,
            );
            pfcp.source_address = "10.10.0.3".into();
            pfcp.destination_address = "10.10.0.4".into();
            pfcp.source_participant = "SMF".into();
            pfcp.destination_participant = "UPF".into();
            pfcp.information_elements = serde_json::json!([
                {"name":"F-TEID","value":format!("teid={teid},ipv4={gnb_n3}")}
            ]);
            events.push(pfcp);

            let mut gtpu = event(
                &format!("test-ue-{ordinal}-gtpu"),
                "GTP-U",
                "G-PDU",
                &[("teid", teid)],
                ordinal * 10 + 3,
            );
            gtpu.source_address = gnb_n3.into();
            gtpu.destination_address = "10.30.0.1".into();
            gtpu.source_participant = "gNB".into();
            gtpu.destination_participant = "UPF".into();
            gtpu.direction = "UPLINK".into();
            events.push(gtpu);
        }

        let result = discover_sessions(&mut events);
        assert_eq!(result.ue_contexts.len(), 3);
        assert_eq!(result.pdu_sessions.len(), 3);
        assert_eq!(result.pfcp_sessions.len(), 3);
        assert_eq!(result.gtpu_tunnels.len(), 3);
        assert_eq!(
            result
                .pdu_sessions
                .iter()
                .map(|session| session.session_id.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            3
        );
        assert!(result.ue_contexts.iter().all(|context| result
            .pdu_sessions
            .iter()
            .filter(|session| session.ue_context_id == context.context_id)
            .count()
            == 1));
        assert!(result
            .gtpu_tunnels
            .iter()
            .all(|tunnel| tunnel.related_pfcp_session.is_some()));
        assert_eq!(result.unmatched_event_ids.len(), 0);
    }

    #[test]
    fn certified_dataset_accounting_remains_stable() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1/oiran_events.jsonl");
        let result = discover_sessions(&mut load_path(&path).unwrap());
        assert_eq!(result.event_accounting["source_events"], 54);
        assert_eq!(result.ue_contexts.len(), 2);
        assert_eq!(result.pdu_sessions.len(), 1);
        assert_eq!(result.pfcp_sessions.len(), 2);
        assert_eq!(result.gtpu_tunnels.len(), 2);
        assert!(result
            .gtpu_tunnels
            .iter()
            .all(|tunnel| tunnel.related_pfcp_session.is_some()));
    }

    #[test]
    fn prepares_lte_session_and_s1u_counters_without_timing_identity_join() {
        let mut s1ap = event(
            "s1ap",
            "S1AP",
            "InitialContextSetupResponse",
            &[("enb_ue_s1ap_id", "41"), ("mme_ue_s1ap_id", "7")],
            1,
        );
        s1ap.interface = "S1-MME".into();
        let mut nas = event(
            "nas",
            "NAS-EPS-MM",
            "Attach Complete",
            &[("imsi_pseudonym", "subscriber-opaque-a")],
            2,
        );
        nas.interface = "S1-MME".into();
        let mut s11 = event(
            "s11",
            "GTPv2-C",
            "CreateSessionResponse",
            &[("bearer_ebi", "5"), ("bearer_f_teid", "0x01020304")],
            3,
        );
        s11.interface = "S11".into();
        let mut uplink = event(
            "s1u-ul",
            "GTP-U",
            "G-PDU",
            &[("teid", "0x01020304")],
            4,
        );
        uplink.interface = "S1-U".into();
        uplink.direction = "UPLINK".into();
        uplink.packet_references[0].captured_length = 128;
        let mut downlink = uplink.clone();
        downlink.event_id = "s1u-dl".into();
        downlink.direction = "DOWNLINK".into();
        downlink.timestamp_ns = 5;
        downlink.packet_references[0].packet_number = 5;
        downlink.packet_references[0].captured_length = 256;

        let sessions = discover_lte_sessions(&[s1ap, nas, s11, uplink, downlink]);
        assert_eq!(sessions.len(), 1);
        let session = &sessions[0];
        assert_eq!(session.technology, "LTE");
        assert_eq!(session.ue_pseudonym, "subscriber-opaque-a");
        assert_eq!(session.state, "ACTIVE_WITH_USER_PLANE");
        assert_eq!(session.eps_bearer_ids, vec!["5"]);
        assert_eq!(session.s11_f_teids, vec!["0x01020304"]);
        assert_eq!(session.tunnels[0].uplink_packets, 1);
        assert_eq!(session.tunnels[0].downlink_packets, 1);
        assert_eq!(session.tunnels[0].bytes, 384);
    }
}
