//! Deterministic reconstruction of UE, PDU, PFCP and GTP-U state from normalized events.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const LTE_CROSS_PLANE_WINDOW_NS: i128 = 300_000_000_000;

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
    /// 2.21.95 (défaut recette #10 7039298457, ordre #9 7039438165) —
    /// clé de corrélation live↔publi propagée depuis le JSONL d'events
    /// (`NormalizedEvent::stable_event_key`, event-schema 1.6.0). Vide
    /// → l'event provient d'un JSONL antérieur à 1.6.0. `serde(default)`
    /// tolère les anciens formats (iso-comportement 2.21.93 pour les
    /// datasets pré-2.21.91).
    #[serde(default)]
    pub stable_event_key: String,
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
    /// 2.20.0 — modèle multi-sonde PRO 400G. Les 4 champs ci-dessous
    /// sont OPTIONNELS : absent du JSONL → `None`, emission JSONL
    /// skip quand `None` (`skip_serializing_if`). La sortie reste
    /// bit-identique aux events 2.19.x qui ne portent pas ces
    /// champs. Design : `OIRAN/docs/architecture/PHASE1-2.md` §3.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub physical_link: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_source: Option<String>,
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

/// Breakdown used by the publication RSS harness. Every value is a retained
/// byte lower bound derived from `size_of` for inline/vector storage plus the
/// owned capacities reachable from the named field. Allocator metadata is not
/// guessed. `source_json_sbi` is an informational subset of `source_json`.
pub fn publication_projection_field_bytes(events: &[EventRecord]) -> BTreeMap<&'static str, usize> {
    fn add(map: &mut BTreeMap<&'static str, usize>, key: &'static str, value: usize) {
        let current = map.entry(key).or_default();
        *current = current.saturating_add(value);
    }
    fn value_bytes(value: &Value) -> usize {
        match value {
            Value::Null | Value::Bool(_) | Value::Number(_) => 0,
            Value::String(value) => value.capacity(),
            Value::Array(values) => {
                values.capacity() * std::mem::size_of::<Value>()
                    + values.iter().map(value_bytes).sum::<usize>()
            }
            Value::Object(values) => {
                values.len() * std::mem::size_of::<(String, Value)>()
                    + values
                        .iter()
                        .map(|(key, value)| key.capacity() + value_bytes(value))
                        .sum::<usize>()
            }
        }
    }
    let mut bytes = BTreeMap::new();
    add(
        &mut bytes,
        "event_record_inline",
        events.len() * std::mem::size_of::<EventRecord>(),
    );
    for event in events {
        for (key, value) in [
            ("event_id", &event.event_id),
            // 2.21.95 — RSS accounting pour le champ ajouté. Taille ≈
            // 4× celle de `event_id` (basename|iid|pkt|off|proto|ord)
            // mais capacity peut être 0 pour les datasets pré-2.21.91.
            ("stable_event_key", &event.stable_event_key),
            ("capture_id", &event.capture_id),
            ("capture_point_id", &event.capture_point_id),
            ("timestamp", &event.timestamp),
            ("interface", &event.interface),
            ("protocol", &event.protocol),
            ("message_name", &event.message_name),
            ("source_address", &event.source_address),
            ("destination_address", &event.destination_address),
            ("source_participant", &event.source_participant),
            ("destination_participant", &event.destination_participant),
            ("direction", &event.direction),
            ("decoding_status", &event.decoding_status),
            ("decoder_name", &event.decoder_name),
            ("decoder_version", &event.decoder_version),
            ("raw_payload_reference", &event.raw_payload_reference),
        ] {
            add(&mut bytes, key, value.capacity());
        }
        if let Some(value) = &event.parent_event_id {
            add(&mut bytes, "parent_event_id", value.capacity());
        }
        add(
            &mut bytes,
            "identifiers_vec",
            event.identifiers.capacity() * std::mem::size_of::<(String, String)>(),
        );
        for (name, value) in &event.identifiers {
            add(&mut bytes, "identifier_names", name.capacity());
            add(&mut bytes, "identifier_values", value.capacity());
        }
        add(
            &mut bytes,
            "information_elements",
            value_bytes(&event.information_elements),
        );
        add(
            &mut bytes,
            "packet_references_vec",
            event.packet_references.capacity() * std::mem::size_of::<PacketRef>(),
        );
        for packet in &event.packet_references {
            add(&mut bytes, "packet_reference_paths", packet.source_file.capacity());
        }
        add(
            &mut bytes,
            "errors",
            event.errors.capacity() * std::mem::size_of::<String>()
                + event.errors.iter().map(String::capacity).sum::<usize>(),
        );
        add(&mut bytes, "source_json", value_bytes(&event.source_json));
        if let Some(sbi) = event.source_json.get("sbi") {
            add(&mut bytes, "source_json_sbi", value_bytes(sbi));
        }
        for (key, value) in [
            ("probe_id", event.probe_id.as_ref()),
            ("probe_type", event.probe_type.as_ref()),
            ("physical_link", event.physical_link.as_ref()),
            ("timestamp_source", event.timestamp_source.as_ref()),
        ] {
            if let Some(value) = value {
                add(&mut bytes, key, value.capacity());
            }
        }
    }
    bytes
}

fn lte_subscriber_pseudonym(event: &EventRecord) -> Option<&str> {
    event
        .first_identifier("subscriber_pseudonym")
        .or_else(|| event.first_identifier("imsi_pseudonym"))
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
    /// 2.21.49 — events SBI rattachés à cette session par FENÊTRE DE
    /// TEMPS (dernier recours, voir `attach_sbi_to_sessions`), distincts
    /// des rattachements par clé exacte. L'UI les marque comme tels.
    #[serde(default)]
    pub sbi_time_window_event_ids: Vec<String>,
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
    pub start_timestamp_ns: i128,
    pub end_timestamp_ns: i128,
    pub duration_ns: i128,
    pub event_ids: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug)]
struct LteContext<'a> {
    capture_id: String,
    enb: Option<String>,
    mme: Option<String>,
    s1_events: Vec<&'a EventRecord>,
    pseudonym: Option<String>,
    erab_teids: BTreeSet<String>,
    s11_events: Vec<&'a EventRecord>,
    s1u_events: Vec<&'a EventRecord>,
    s5c_events: Vec<&'a EventRecord>,
    s5u_events: Vec<&'a EventRecord>,
    sxab_events: Vec<&'a EventRecord>,
    s6a_events: Vec<&'a EventRecord>,
}

fn normalized_lte_teid(value: &str) -> Option<String> {
    let raw = value
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches('0');
    let raw = if raw.is_empty() { "0" } else { raw };
    u32::from_str_radix(raw, 16)
        .ok()
        .map(|value| format!("0x{value:x}"))
}

/// 2.7.13: cross-plane S1-MME/S11/S1-U join no longer gates on a
/// timestamp window — that would compare ts across captures, which is
/// forbidden. The join relies entirely on structural keys
/// (MME/eNB-UE-S1AP-ID, E-RAB TEIDs, F-TEID, pseudonym when present).
/// The predicate kept its shape for API compatibility and now accepts
/// any non-empty related set so a context with no S1 anchor is still
/// rejected downstream by the TEID intersection check.
fn within_lte_window(_event: &EventRecord, related: &[&EventRecord]) -> bool {
    !related.is_empty()
}

fn protocol_is(event: &EventRecord, expected: &str) -> bool {
    event.protocol.eq_ignore_ascii_case(expected)
}

fn protocol_is_any(event: &EventRecord, expected: &[&str]) -> bool {
    expected.iter().any(|value| protocol_is(event, value))
}

fn protocol_starts_with(event: &EventRecord, prefix: &str) -> bool {
    event.protocol.get(..prefix.len())
        .is_some_and(|value| value.eq_ignore_ascii_case(prefix))
}

fn same_gtpv2c_transaction(left: &EventRecord, right: &EventRecord) -> bool {
    if !protocol_is(left, "GTPv2-C")
        || !protocol_is(right, "GTPv2-C")
        || left.capture_id != right.capture_id
        || left.first_identifier("gtpv2c_sequence")
            != right.first_identifier("gtpv2c_sequence")
    {
        return false;
    }
    let left_procedure = left
        .message_name
        .trim_end_matches("Request")
        .trim_end_matches("Response");
    let right_procedure = right
        .message_name
        .trim_end_matches("Request")
        .trim_end_matches("Response");
    let same_endpoints = (left.source_address == right.source_address
        && left.destination_address == right.destination_address)
        || (left.source_address == right.destination_address
            && left.destination_address == right.source_address);
    left.first_identifier("gtpv2c_sequence").is_some()
        && left_procedure == right_procedure
        && same_endpoints
}

/// Builds a deterministic LTE preparation view from normalized S1AP/EPS NAS,
/// S11 and S1-U events. It deliberately does not infer UE identity from timing
/// and does not claim an S1AP/S11 bridge until an explicit bearer identifier is
/// emitted by both decoders.
pub fn discover_lte_sessions(events: &[EventRecord]) -> Vec<LteSession> {
    let mut lte = events
        .iter()
        .filter(|event| {
            matches!(
                event.interface.as_str(),
                "S1-MME" | "S11" | "S1-U" | "S5-C" | "S5-U" | "Sxab" | "S6a"
            )
                && protocol_is_any(event, &[
                    "S1AP", "NAS-EPS-MM", "NAS-EPS-SM", "GTPv2-C",
                    "GTP-U", "PFCP", "DIAMETER",
                ])
        })
        .collect::<Vec<_>>();
    // 2.7.13: canonical (capture_id, seq, event_id). ts never influences
    // a session-discovery decision.
    lte.sort_by(|a, b| canonical_sort_key(a).cmp(&canonical_sort_key(b)));
    // 2.7.15: consolidate S1AP contexts by the structural eNB UE S1AP
    // identity. The pre-2.7.15 code (session-engine/src/lib.rs:313-319)
    // inserted every observed `(capture_id, enb, mme)` triple, so an
    // `InitialUEMessage` event (which carries `enb_ue_s1ap_id` but no
    // `mme_ue_s1ap_id` — the MME has not yet allocated one) created a
    // distinct context from the rest of the exchange. ANR3 observed
    // this on a real P4 import (issue #10 comment 6636015016): a single
    // Attach→Detach flow produced one 24-event session (matching the
    // `(enb, None)` context) and a second 22-event session missing both
    // `InitialUEMessage` and the NAS `Attach Request` child, matching
    // `(enb, Some(mme))`. The consolidation groups S1AP events by
    // `(capture_id, enb)`, resolves the canonical set of `mme` values
    // observed on that enb, and emits one context per `(enb, mme)` only
    // when the mme is actually assigned. A context with `mme=None` is
    // retained only when NO S1AP event on that enb ever carried a mme
    // identifier (fully anonymous exchange). Two distinct UEs — with
    // distinct `enb_ue_s1ap_id` values — still yield two contexts.
    let mut mme_by_enb: BTreeMap<(String, Option<String>), BTreeSet<String>> = BTreeMap::new();
    for event in lte.iter().filter(|event| protocol_is(event, "S1AP")) {
        let enb = event.first_identifier("enb_ue_s1ap_id").map(str::to_owned);
        let mme = event.first_identifier("mme_ue_s1ap_id").map(str::to_owned);
        if enb.is_none() && mme.is_none() {
            continue;
        }
        let entry = mme_by_enb
            .entry((event.capture_id.clone(), enb))
            .or_default();
        if let Some(value) = mme {
            entry.insert(value);
        }
    }
    let mut contexts: BTreeSet<(String, Option<String>, Option<String>)> = BTreeSet::new();
    for ((capture_id, enb), mme_values) in mme_by_enb {
        if mme_values.is_empty() {
            contexts.insert((capture_id, enb, None));
        } else {
            for mme in mme_values {
                contexts.insert((capture_id.clone(), enb.clone(), Some(mme)));
            }
        }
    }
    let mut lte_contexts = contexts
        .into_iter()
        .map(|(capture_id, enb, mme)| {
            // 2.7.15: structural match. The enb check is strict. The mme
            // check accepts an event with no `mme_ue_s1ap_id` (e.g. the
            // InitialUEMessage and the NAS Attach Request child it
            // envelopes, which the MME has not yet assigned a mme id to)
            // as long as the enb matches; otherwise the mme values must
            // be equal. If the enclosing context was built with mme=None
            // (no mme was ever observed for that enb), any event sharing
            // the enb is admitted.
            let matches_context = |event: &&EventRecord| {
                if event.capture_id != capture_id || event.interface != "S1-MME" {
                    return false;
                }
                let enb_ok = match (enb.as_deref(), event.first_identifier("enb_ue_s1ap_id")) {
                    (Some(ctx_enb), Some(evt_enb)) => ctx_enb == evt_enb,
                    (None, _) => true,
                    (Some(_), None) => false,
                };
                if !enb_ok {
                    return false;
                }
                match (mme.as_deref(), event.first_identifier("mme_ue_s1ap_id")) {
                    (Some(ctx_mme), Some(evt_mme)) => ctx_mme == evt_mme,
                    (Some(_), None) => true,
                    (None, _) => true,
                }
            };
            let s1_events = lte
                .iter()
                .copied()
                .filter(matches_context)
                .collect::<Vec<_>>();
            let pseudonym = s1_events
                .iter()
                .find_map(|event| lte_subscriber_pseudonym(event))
                .map(str::to_owned);
            let erab_teids = s1_events
                .iter()
                .flat_map(|event| event.identifier_values("erab_teid"))
                .filter_map(normalized_lte_teid)
                .collect();
            LteContext {
                capture_id,
                enb,
                mme,
                s1_events,
                pseudonym,
                erab_teids,
                s11_events: Vec::new(),
                s1u_events: Vec::new(),
                s5c_events: Vec::new(),
                s5u_events: Vec::new(),
                sxab_events: Vec::new(),
                s6a_events: Vec::new(),
            }
        })
        .collect::<Vec<_>>();

    // An S11 event crosses capture provenance when its bearer TEID set
    // uniquely matches one S1 context's E-RAB TEIDs inside the cross-plane
    // window. The opaque subscriber pseudonym, when present on both sides,
    // must agree; when either side has no subscriber identifier the TEID
    // match alone is the bridge (2.7.6: imports can run without any IMSI
    // anywhere in the trace, so correlation MUST fall back to structural
    // keys — see `s1_s11_s1u_correlate_by_teid_without_any_subscriber_identifier`).
    for event in lte.iter().copied().filter(|event| event.interface == "S11") {
        let event_teids = ["f_teid", "bearer_f_teid"]
            .into_iter()
            .flat_map(|name| event.identifier_values(name))
            .filter_map(normalized_lte_teid)
            .collect::<BTreeSet<_>>();
        if event_teids.is_empty() {
            continue;
        }
        let event_pseudonym = lte_subscriber_pseudonym(event);
        let owners = lte_contexts
            .iter()
            .enumerate()
            .filter(|(_, context)| {
                let exact_pseudonym = matches!(
                    (context.pseudonym.as_deref(), event_pseudonym),
                    (Some(context_pseudonym), Some(event_pseudonym))
                        if context_pseudonym == event_pseudonym
                );
                let exact_bearer = !context.erab_teids.is_disjoint(&event_teids);
                // A subscriber can legitimately have several historical S1
                // contexts in an append-only dataset. When bearer evidence
                // is present it is the session key; the subscriber proof is
                // only a fallback when neither side exposes an E-RAB/F-TEID.
                let context_has_bearer = !context.erab_teids.is_empty();
                (if context_has_bearer && !event_teids.is_empty() {
                    exact_bearer
                } else {
                    exact_pseudonym
                })
                    && within_lte_window(event, &context.s1_events)
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if let [owner] = owners.as_slice() {
            lte_contexts[*owner].s11_events.push(event);
        }
    }

    // A user-plane TEID is admitted only when the already established
    // S1/S11 chain assigns it to one context. Reused TEIDs stay unmatched.
    for event in lte
        .iter()
        .copied()
        .filter(|event| event.interface == "S1-U")
    {
        let Some(teid) = event.first_identifier("teid").and_then(normalized_lte_teid) else {
            continue;
        };
        let owners = lte_contexts
            .iter()
            .enumerate()
            .filter(|(_, context)| {
                context.s11_events.iter().any(|control| {
                    ["f_teid", "bearer_f_teid"]
                        .into_iter()
                        .flat_map(|name| control.identifier_values(name))
                        .filter_map(normalized_lte_teid)
                        .any(|candidate| candidate == teid)
                }) && within_lte_window(event, &context.s11_events)
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if let [owner] = owners.as_slice() {
            lte_contexts[*owner].s1u_events.push(event);
        }
    }

    // S5-C is owned by the unique S11 context sharing a normalized F-TEID.
    for event in lte.iter().copied().filter(|event| event.interface == "S5-C") {
        let event_teids = ["f_teid", "bearer_f_teid"]
            .into_iter()
            .flat_map(|name| event.identifier_values(name))
            .filter_map(normalized_lte_teid)
            .collect::<BTreeSet<_>>();
        let owners = lte_contexts
            .iter()
            .enumerate()
            .filter(|(_, context)| {
                context.s11_events.iter().any(|control| {
                    ["f_teid", "bearer_f_teid"]
                        .into_iter()
                        .flat_map(|name| control.identifier_values(name))
                        .filter_map(normalized_lte_teid)
                        .any(|teid| event_teids.contains(&teid))
                })
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if let [owner] = owners.as_slice() {
            lte_contexts[*owner].s5c_events.push(event);
        }
    }

    // A Create Session request and response do not necessarily repeat every
    // U-plane F-TEID. Once one half is uniquely owned through S11, admit its
    // companion only by the exact GTPv2-C transaction key: capture,
    // sequence, procedure and unordered endpoint pair. This is structural;
    // timestamps never participate.
    for event in lte.iter().copied().filter(|event| event.interface == "S5-C") {
        if lte_contexts
            .iter()
            .any(|context| context.s5c_events.iter().any(|owned| owned.event_id == event.event_id))
        {
            continue;
        }
        let owners = lte_contexts
            .iter()
            .enumerate()
            .filter(|(_, context)| {
                context
                    .s5c_events
                    .iter()
                    .any(|owned| same_gtpv2c_transaction(event, owned))
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if let [owner] = owners.as_slice() {
            lte_contexts[*owner].s5c_events.push(event);
        }
    }

    // S5-U is owned by the unique S5-C bearer F-TEID.
    for event in lte.iter().copied().filter(|event| event.interface == "S5-U") {
        let Some(teid) = event.first_identifier("teid").and_then(normalized_lte_teid) else {
            continue;
        };
        let owners = lte_contexts
            .iter()
            .enumerate()
            .filter(|(_, context)| {
                context.s5c_events.iter().any(|control| {
                    ["f_teid", "bearer_f_teid"]
                        .into_iter()
                        .flat_map(|name| control.identifier_values(name))
                        .filter_map(normalized_lte_teid)
                        .any(|candidate| candidate == teid)
                })
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if let [owner] = owners.as_slice() {
            lte_contexts[*owner].s5u_events.push(event);
        }
    }

    // Sxab PFCP is admitted only when one LTE context owns a matching S5-U TEID.
    for event in lte.iter().copied().filter(|event| event.interface == "Sxab") {
        let event_teids = ["teid", "f_teid"]
            .into_iter()
            .flat_map(|name| event.identifier_values(name))
            .filter_map(normalized_lte_teid)
            .collect::<BTreeSet<_>>();
        let owners = lte_contexts
            .iter()
            .enumerate()
            .filter(|(_, context)| {
                context.s5u_events.iter().any(|user| {
                    user.first_identifier("teid")
                        .and_then(normalized_lte_teid)
                        .is_some_and(|teid| event_teids.contains(&teid))
                })
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if let [owner] = owners.as_slice() {
            lte_contexts[*owner].sxab_events.push(event);
        }
    }

    // S6a carries no bearer key. Its only admissible bridge is the exact,
    // common-domain subscriber pseudonym. The EPS identity can first appear
    // on GTPv2-C/S11, so compare both the S1 context and its owned S11
    // events. Raw identity is never surfaced.
    for event in lte.iter().copied().filter(|event| event.interface == "S6a") {
        let Some(pseudonym) = lte_subscriber_pseudonym(event) else { continue };
        let has_owned_s11_match = lte_contexts.iter().any(|context| {
            context
                .s11_events
                .iter()
                .filter_map(|control| lte_subscriber_pseudonym(control))
                .any(|control_pseudonym| control_pseudonym == pseudonym)
        });
        let owners = lte_contexts
            .iter()
            .enumerate()
            .filter(|(_, context)| {
                let via_owned_s11 = context
                        .s11_events
                        .iter()
                        .filter_map(|control| lte_subscriber_pseudonym(control))
                        .any(|control_pseudonym| control_pseudonym == pseudonym);
                if has_owned_s11_match {
                    via_owned_s11
                } else {
                    context.pseudonym.as_deref() == Some(pseudonym)
                }
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if let [owner] = owners.as_slice() {
            lte_contexts[*owner].s6a_events.push(event);
        }
    }

    let mut sessions = Vec::new();
    for context in lte_contexts {
        let LteContext {
            capture_id,
            enb,
            mme,
            s1_events,
            pseudonym,
            s11_events: s11,
            s1u_events: s1u,
            s5c_events: s5c,
            s5u_events: s5u,
            sxab_events: sxab,
            s6a_events: s6a,
            ..
        } = context;
        let mut associated = s1_events;
        let ue_pseudonym = pseudonym
            .unwrap_or_else(|| stable_id("LTE-UE", &format!("{capture_id}|{:?}|{:?}", enb, mme)));
        associated.extend(s11.iter().copied());
        let collect_ids = |source: &[&EventRecord], names: &[&str]| {
            source
                .iter()
                .flat_map(|event| {
                    event
                        .identifiers
                        .iter()
                        .filter(|(name, _)| names.contains(&name.as_str()))
                        .map(|(_, value)| value.clone())
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        };
        let eps_bearer_ids =
            collect_ids(&associated, &["eps_bearer_identity", "ebi", "bearer_ebi"]);
        let s11_f_teids = collect_ids(&s11, &["f_teid", "bearer_f_teid"]);
        associated.extend(s1u.iter().copied());
        associated.extend(s5c.iter().copied());
        associated.extend(s5u.iter().copied());
        associated.extend(sxab.iter().copied());
        associated.extend(s6a.iter().copied());
        // 2.7.13: canonical (capture_id, seq, event_id) — associated bundle
        // mixes events from S1-MME, S11 and S1-U captures.
        associated.sort_by(|a, b| canonical_sort_key(a).cmp(&canonical_sort_key(b)));
        associated.dedup_by(|left, right| left.event_id == right.event_id);
        let mut tunnel_map: BTreeMap<String, LteTunnelCounters> = BTreeMap::new();
        for event in &s1u {
            let teid = event.first_identifier("teid").unwrap();
            let counters = tunnel_map
                .entry(teid.to_owned())
                .or_insert(LteTunnelCounters {
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
        let procedures = associated
            .iter()
            .map(|event| event.message_name.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let interfaces = associated
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
        let start_timestamp_ns = associated
            .first()
            .map(|event| event.timestamp_ns)
            .unwrap_or(0);
        let end_timestamp_ns = associated
            .last()
            .map(|event| event.timestamp_ns)
            .unwrap_or(0);
        sessions.push(LteSession {
            session_id: stable_id(
                "lte-session",
                &format!("{capture_id}|{ue_pseudonym}|{:?}|{:?}", enb, mme),
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
            start_timestamp_ns,
            end_timestamp_ns,
            duration_ns: end_timestamp_ns.saturating_sub(start_timestamp_ns),
            event_ids: associated
                .iter()
                .map(|event| event.event_id.clone())
                .collect(),
            limitations: vec![
                "Offline synthetic certification only; real LTE evidence requires ANR1".into(),
                "S11 association requires a unique S1 context sharing an opaque pseudonym and E-RAB/F-TEID; S1-U requires a uniquely owned S11 F-TEID".into(),
                "Cross-plane evidence is bounded to 300 seconds and preserves each source capture_id".into(),
                "No timestamp-only S1AP/S11/S1-U identity association is performed".into(),
            ],
        });
    }
    sessions.sort_by(|left, right| left.session_id.cmp(&right.session_id));
    sessions
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
    // 2.21.102 (ordre #9 7045732954) — backfill `stable_event_key` à
    // la LECTURE pour les events stockés qui ne la portent pas (dataset
    // pré-2.21.91 ou JSONL émis avant event-schema 1.6.0). Même formule
    // que `derive_stable_event_key`. Dérivation en ORDRE DE FICHIER
    // (= ordre d'émission du décodeur live), avant `deterministic_sort`
    // pour que les ordinaux coïncident avec ceux de la republication
    // live.
    backfill_stable_event_keys(&mut events);
    deterministic_sort(&mut events);
    Ok(events)
}

/// 2.21.102 (défaut ANR1 #9 7044712668, ordre #9 7045732954) —
/// renseigne `stable_event_key` pour chaque event dont le champ est
/// vide, en conservant intacts ceux qui le portent déjà. Appelé par
/// les lecteurs de JSONL stockés (`load_jsonl`, `load_jsonl_slim`,
/// `load_path_streaming_index`) et par `apps/api::callflow` /
/// `live-probe::callflow_page` pour patcher les callflows persistés
/// AVANT 2.21.91 **sans réécriture disque**.
///
/// La formule et les champs sont identiques à
/// [`event_schema::derive_stable_event_key`] :
/// `{basename}|{iid}|{pkt}|{off}|{protocol}|{ordinal}`. L'ordinal est
/// le rang 0-based dans l'ordre d'émission (= ordre des events dans
/// `oiran_events.jsonl`, qui est l'ordre où le décodeur les a produits).
/// Événement sans `packet_references` : clé laissée vide (écart
/// déclaré OUVERT au caller).
pub fn backfill_stable_event_keys(events: &mut [EventRecord]) {
    // 0.5.27 (POLARIS 2.21.133) — l'ordinal n'est plus le rang de LECTURE.
    // Un stockage trié (fichier trié par `event_id`, callflow dans l'ordre
    // du ladder) mettait un enfant avant son parent une fois sur deux, et
    // la clé dérivée n'égalait alors pas celle du décodeur (55 events sur
    // 522 sur une capture réelle). Les events d'un même paquet sont
    // numérotés dans l'ordre d'émission reconstitué : chaque parent, suivi
    // de ses enfants ; à défaut de parenté, l'ordre de lecture.
    let mut by_packet: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, event) in events.iter().enumerate() {
        if let Some(packet) = event.packet_references.first() {
            by_packet
                .entry(event_schema::packet_lookup_key(
                    &packet.source_file,
                    packet.interface_id,
                    packet.packet_number,
                    packet.byte_offset,
                ))
                .or_default()
                .push(index);
        }
    }
    for members in by_packet.values() {
        let order = event_schema::emission_order(members.len(), |position| {
            let event = &events[members[position]];
            (event.event_id.as_str(), event.parent_event_id.as_deref())
        });
        for (ordinal, position) in order.into_iter().enumerate() {
            let event = &mut events[members[position]];
            if !event.stable_event_key.is_empty() {
                continue;
            }
            let Some(packet) = event.packet_references.first() else {
                continue;
            };
            event.stable_event_key = event_schema::derive_stable_event_key(
                &packet.source_file,
                packet.interface_id,
                packet.packet_number,
                packet.byte_offset,
                &event.protocol,
                ordinal as u32,
            );
        }
    }
}

pub fn load_path(path: &std::path::Path) -> Result<Vec<EventRecord>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    load_jsonl(io::BufReader::new(file))
}

/// Bounded publication-time index. The complete event bodies remain in the
/// JSONL file; RAM contains only the set of event ids plus the latest compact
/// state-changing/correlation observation for each semantic key.
pub struct StreamingEventIndex {
    pub events: Vec<EventRecord>,
    pub event_ids: BTreeSet<String>,
    pub source_event_count: usize,
}

/// Streams a published JSONL without ever materialising the dataset as a
/// `Vec<EventRecord>`. This is the input used by continuous publication for
/// session discovery. Repeated observations with the same protocol state,
/// endpoints and stable identifiers replace one another, leaving one compact
/// representative; full records are reloaded from disk by event id when the
/// corresponding session call flow is written.
pub fn load_path_streaming_index(path: &std::path::Path) -> Result<StreamingEventIndex, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let reader = io::BufReader::new(file);
    let mut event_ids = BTreeSet::new();
    let mut representatives = BTreeMap::<String, EventRecord>::new();
    let mut source_event_count = 0usize;
    for (line_no, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("line {}: {e}", line_no + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(&line)
            .map_err(|e| format!("line {}: invalid JSON: {e}", line_no + 1))?;
        let mut event = parse_event(value).map_err(|e| format!("line {}: {e}", line_no + 1))?;
        source_event_count = source_event_count.saturating_add(1);
        if !event_ids.insert(event.event_id.clone()) {
            continue;
        }
        compact_publication_event(&mut event);
        let key = publication_semantic_key(&event);
        representatives.insert(key, event);
    }
    let mut events = representatives.into_values().collect::<Vec<_>>();
    deterministic_sort(&mut events);
    Ok(StreamingEventIndex {
        events,
        event_ids,
        source_event_count,
    })
}

/// 2.9.18-fu3 (devmat, ANR2 #9 comment 6750859966) : variante
/// `BTreeSet<String>`-less pour le pipeline de publication continu.
/// ANR2 a prouvé que `event_ids` à 2 M entrées (≈ 200 MiB) sous
/// `MemoryMax=256 MiB` conduisait à l'OOM. Le caller construit
/// désormais un `SpillingEventIdSet` disk-backed en parallèle de
/// cette fonction.
///
/// Garanties mémoire : identique à `load_path_streaming_index`
/// moins le set d'event_ids ; les représentants compacts
/// (`BTreeMap<key, EventRecord>`) sont les seuls états scalant
/// avec le nombre d'événements sémantiquement uniques.
pub struct StreamingRepresentativesIndex {
    pub events: Vec<EventRecord>,
    pub source_event_count: usize,
}

#[derive(Debug, Deserialize, Serialize)]
struct SpilledRepresentative {
    key: String,
    ordinal: u64,
    event: EventRecord,
}

static REPRESENTATIVE_RUN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn flush_representative_run(
    staging_dir: &Path,
    run_index: usize,
    records: &mut Vec<SpilledRepresentative>,
) -> Result<PathBuf, String> {
    records.sort_by(|left, right| {
        left.key
            .cmp(&right.key)
            .then_with(|| left.ordinal.cmp(&right.ordinal))
    });
    let path = staging_dir.join(format!("run-{run_index:06}.jsonl"));
    let file = fs::File::create(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut writer = BufWriter::new(file);
    let mut offset = 0usize;
    while offset < records.len() {
        let key = records[offset].key.clone();
        let mut last = offset;
        while last + 1 < records.len() && records[last + 1].key == key {
            last += 1;
        }
        serde_json::to_writer(&mut writer, &records[last]).map_err(|error| error.to_string())?;
        writer.write_all(b"\n").map_err(|error| error.to_string())?;
        offset = last + 1;
    }
    writer.flush().map_err(|error| error.to_string())?;
    records.clear();
    Ok(path)
}

struct RepresentativeRunReader {
    path: PathBuf,
    lines: io::Lines<BufReader<fs::File>>,
    current: Option<SpilledRepresentative>,
}

impl RepresentativeRunReader {
    fn open(path: PathBuf) -> Result<Self, String> {
        let file = fs::File::open(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        let mut reader = Self {
            path,
            lines: BufReader::new(file).lines(),
            current: None,
        };
        reader.advance()?;
        Ok(reader)
    }

    fn advance(&mut self) -> Result<(), String> {
        self.current = match self.lines.next() {
            Some(Ok(line)) => Some(
                serde_json::from_str(&line)
                    .map_err(|error| format!("{}: {error}", self.path.display()))?,
            ),
            Some(Err(error)) => return Err(format!("{}: {error}", self.path.display())),
            None => None,
        };
        Ok(())
    }
}

/// Disk-backed equivalent of `load_paths_streaming_representatives_with_progress`.
///
/// Input order is recorded as a monotonic ordinal. Each sorted run retains the
/// greatest ordinal for a semantic key; the external merge applies the same
/// rule across runs. This is exactly the legacy BTreeMap `insert` contract:
/// the last observation in manifest/shard order wins. Only `memory_cap_bytes`
/// of serialized run records are accumulated before spilling.
pub fn load_paths_spilling_representatives_with_progress<F>(
    paths: &[PathBuf],
    staging_root: &Path,
    memory_cap_bytes: usize,
    mut progress: F,
) -> Result<StreamingRepresentativesIndex, String>
where
    F: FnMut(usize, usize),
{
    if memory_cap_bytes == 0 {
        return Err("representative run memory cap must be greater than zero".into());
    }
    let sequence = REPRESENTATIVE_RUN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let staging_dir = staging_root.join(format!(
        "representatives-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&staging_dir)
        .map_err(|error| format!("{}: {error}", staging_dir.display()))?;

    let mut records = Vec::<SpilledRepresentative>::new();
    let mut retained_bytes = 0usize;
    let mut run_paths = Vec::<PathBuf>::new();
    let mut source_event_count = 0usize;
    let mut ordinal = 0u64;
    for path in paths {
        let file = fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
        let mut reader = BufReader::new(&file);
        let mut line = String::new();
        let mut line_no = 0usize;
        let mut consumed_bytes = 0u64;
        let mut advised_bytes = 0u64;
        loop {
            line.clear();
            let read = reader
                .read_line(&mut line)
                .map_err(|error| format!("{} line {}: {error}", path.display(), line_no + 1))?;
            if read == 0 {
                break;
            }
            line_no = line_no.saturating_add(1);
            consumed_bytes = consumed_bytes.saturating_add(read as u64);
            if line.trim().is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(&line).map_err(|error| {
                format!("{} line {}: invalid JSON: {error}", path.display(), line_no)
            })?;
            let mut event = parse_event(value)
                .map_err(|error| format!("{} line {}: {error}", path.display(), line_no))?;
            source_event_count = source_event_count.saturating_add(1);
            ordinal = ordinal.saturating_add(1);
            compact_publication_event(&mut event);
            let record = SpilledRepresentative {
                key: publication_semantic_key(&event),
                ordinal,
                event,
            };
            retained_bytes = retained_bytes.saturating_add(
                serde_json::to_vec(&record)
                    .map_err(|error| error.to_string())?
                    .len(),
            );
            records.push(record);
            if retained_bytes >= memory_cap_bytes {
                let path = flush_representative_run(&staging_dir, run_paths.len(), &mut records)?;
                run_paths.push(path);
                retained_bytes = 0;
            }
            if source_event_count % 100_000 == 0 {
                progress(source_event_count, 0);
            }
            if consumed_bytes.saturating_sub(advised_bytes) >= 16 * 1024 * 1024 {
                advise_file_range_no_longer_needed(
                    &file,
                    advised_bytes,
                    consumed_bytes.saturating_sub(advised_bytes),
                );
                advised_bytes = consumed_bytes;
            }
        }
        advise_file_range_no_longer_needed(
            &file,
            advised_bytes,
            consumed_bytes.saturating_sub(advised_bytes),
        );
    }
    if !records.is_empty() {
        let path = flush_representative_run(&staging_dir, run_paths.len(), &mut records)?;
        run_paths.push(path);
    }

    let mut readers = run_paths
        .iter()
        .cloned()
        .map(RepresentativeRunReader::open)
        .collect::<Result<Vec<_>, _>>()?;
    let mut events = Vec::<EventRecord>::new();
    loop {
        let Some(next_key) = readers
            .iter()
            .filter_map(|reader| reader.current.as_ref().map(|record| record.key.as_str()))
            .min()
            .map(str::to_owned)
        else {
            break;
        };
        let mut winner: Option<SpilledRepresentative> = None;
        for reader in &mut readers {
            if reader.current.as_ref().is_some_and(|record| record.key == next_key) {
                let candidate = reader.current.take().expect("checked above");
                if winner
                    .as_ref()
                    .is_none_or(|current| candidate.ordinal > current.ordinal)
                {
                    winner = Some(candidate);
                }
                reader.advance()?;
            }
        }
        events.push(winner.expect("at least one run owns the minimum key").event);
    }
    deterministic_sort(&mut events);
    progress(source_event_count, events.len());

    for path in run_paths {
        fs::remove_file(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    }
    fs::remove_dir(&staging_dir)
        .map_err(|error| format!("{}: {error}", staging_dir.display()))?;
    Ok(StreamingRepresentativesIndex {
        events,
        source_event_count,
    })
}

/// 2.21.63 / session-engine 0.5.24 — une publication physique parcourt des
/// centaines de shards immuables. Rendre chaque fichier propre au noyau dès
/// sa dernière ligne évite que leur page cache s'accumule jusqu'à EOF et
/// chevauche les structures de reconstruction.
#[cfg(target_family = "unix")]
fn advise_file_range_no_longer_needed(file: &fs::File, offset: u64, len: u64) {
    use std::os::fd::AsRawFd;

    let _ = unsafe {
        libc::posix_fadvise(
            file.as_raw_fd(),
            offset.min(i64::MAX as u64) as libc::off_t,
            len.min(i64::MAX as u64) as libc::off_t,
            libc::POSIX_FADV_DONTNEED,
        )
    };
}

#[cfg(not(target_family = "unix"))]
fn advise_file_range_no_longer_needed(_file: &fs::File, _offset: u64, _len: u64) {}

pub fn load_path_streaming_representatives(
    path: &std::path::Path,
) -> Result<StreamingRepresentativesIndex, String> {
    load_path_streaming_representatives_with_progress(path, |_, _| {})
}

/// Charge les représentants de publication et rend la passe observable sans
/// conserver un second index en mémoire. Le callback reçoit
/// `(événements_lus, représentants_retenus)` tous les 100 000 événements puis
/// une dernière fois à EOF. Il est volontairement synchrone : le caller peut
/// publier une trace RSS/progression sans modifier l'ordre canonique.
pub fn load_path_streaming_representatives_with_progress<F>(
    path: &std::path::Path,
    progress: F,
) -> Result<StreamingRepresentativesIndex, String>
where
    F: FnMut(usize, usize),
{
    load_paths_streaming_representatives_with_progress(&[path.to_path_buf()], progress)
}

/// Stream an immutable-shard dataset without materialising or concatenating
/// its JSONL files. Shards are visited in manifest order; representatives are
/// finally sorted by the canonical event key, never by timestamp.
pub fn load_paths_streaming_representatives_with_progress<F>(
    paths: &[std::path::PathBuf],
    mut progress: F,
) -> Result<StreamingRepresentativesIndex, String>
where
    F: FnMut(usize, usize),
{
    let mut representatives = BTreeMap::<String, EventRecord>::new();
    let mut source_event_count = 0usize;
    for path in paths {
        let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let reader = io::BufReader::new(file);
        for (line_no, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| format!("{} line {}: {e}", path.display(), line_no + 1))?;
            if line.trim().is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(&line).map_err(|e| {
                format!("{} line {}: invalid JSON: {e}", path.display(), line_no + 1)
            })?;
            let mut event = parse_event(value)
                .map_err(|e| format!("{} line {}: {e}", path.display(), line_no + 1))?;
            source_event_count = source_event_count.saturating_add(1);
            compact_publication_event(&mut event);
            let key = publication_semantic_key(&event);
            // A shard list is the logical concatenation of its immutable
            // files. Match the monolithic reader's last-observation-wins
            // contract exactly: retaining the first observation made a
            // historical shard shadow later LTE/5G evidence.
            representatives.insert(key, event);
            if source_event_count % 100_000 == 0 {
                progress(source_event_count, representatives.len());
            }
        }
    }
    progress(source_event_count, representatives.len());
    let mut events = representatives.into_values().collect::<Vec<_>>();
    deterministic_sort(&mut events);
    Ok(StreamingRepresentativesIndex {
        events,
        source_event_count,
    })
}

fn compact_publication_event(event: &mut EventRecord) {
    const STABLE_IDENTIFIERS: &[&str] = &[
        "enb_ue_s1ap_id",
        "mme_ue_s1ap_id",
        "erab_teid",
        "f_teid",
        "bearer_f_teid",
        "f_teid_iface",
        "bearer_f_teid_iface",
        "ebi",
        "bearer_ebi",
        "gtpv2c_sequence",
        "pfcp_sequence",
        "ran_ue_ngap_id",
        "amf_ue_ngap_id",
        "pdu_session_id",
        "dnn",
        "network_instance",
        "snssai",
        "s_nssai",
        "seid",
        "f_seid",
        "pdr_id",
        "far_id",
        "qer_id",
        "teid",
        // 2.21.51 (ANR2 #10 6983842360) — le lookup SBI par tunnel lit
        // `gtp_teid` (n2SmInfo décodé) : la compaction le jetait, donc
        // 0 rattachement par clé exacte sur les représentants publiés.
        "gtp_teid",
        "tunnel_endpoint_ip",
        "tunnel_direction",
        "transport_layer_address",
        "ue_ip",
        "inner_source_ip",
        "inner_destination_ip",
        "qfi",
        "sm_context_reference",
        "subscriber_pseudonym",
        "imsi_pseudonym",
        "tmsi_pseudonym",
    ];
    event
        .identifiers
        .retain(|(name, _)| STABLE_IDENTIFIERS.contains(&name.as_str()));
    event.identifiers.sort();
    if protocol_is_any(event, &["PFCP", "NGAP"]) {
        if let Some(items) = event.information_elements.as_array_mut() {
            items.retain(|item| {
                let name = item
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let value = item
                    .get("value")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_ascii_lowercase();
                [
                    "teid",
                    "ipv4",
                    "seid",
                    "pdr",
                    "far",
                    "qer",
                    "network_instance",
                    "dnn",
                    "snssai",
                    "s_nssai",
                ]
                .iter()
                .any(|needle| name.contains(needle) || value.contains(needle))
            });
        }
    } else {
        event.information_elements = Value::Array(Vec::new());
    }
    if event.packet_references.len() > 2 {
        let last = event.packet_references.last().cloned();
        event.packet_references.truncate(1);
        if let Some(last) = last {
            if event
                .packet_references
                .first()
                .map_or(true, |first| first.packet_number != last.packet_number)
            {
                event.packet_references.push(last);
            }
        }
    }
    event.timestamp.clear();
    event.decoding_status.clear();
    event.decoder_name.clear();
    event.decoder_version.clear();
    event.raw_payload_reference.clear();
    event.errors.clear();
    // Schema compatibility is checked while the full JSONL is decoded. None
    // of the publication discovery/correlation passes reads it afterwards,
    // whereas retaining one copy per representative keeps a JSON object node,
    // key and value alive for the whole publication. Procedure and SBI stay:
    // both are consumed by downstream discovery/correlation.
    if let Some(source) = event.source_json.as_object_mut() {
        source.remove("schema_version");
    }
}

fn publication_semantic_key(event: &EventRecord) -> String {
    // 2.11.12: la représentation garde tous les identifiants stables ci-dessus,
    // mais la *clé* ne doit contenir que l'état durable d'une session/tunnel.
    // Les numéros de transaction GTPv2/PFCP et les identifiants PDR/FAR/QER
    // changent à chaque message. Les inclure ici empêchait la compaction et
    // retenait pratiquement tout le JSONL de production sous forme d'objets Rust
    // + String (4,2 GiB anonymes observés avant la phase 01). Ils restent bien
    // présents dans EventRecord pour la découverte/corrélation.
    const SEMANTIC_KEY_IDENTIFIERS: &[&str] = &[
        "enb_ue_s1ap_id",
        "mme_ue_s1ap_id",
        "erab_teid",
        "f_teid",
        "bearer_f_teid",
        "f_teid_iface",
        "bearer_f_teid_iface",
        "ebi",
        "bearer_ebi",
        "ran_ue_ngap_id",
        "amf_ue_ngap_id",
        "pdu_session_id",
        "dnn",
        "network_instance",
        "snssai",
        "s_nssai",
        "seid",
        "f_seid",
        "teid",
        "tunnel_endpoint_ip",
        "tunnel_direction",
        "transport_layer_address",
        "ue_ip",
        "inner_source_ip",
        "inner_destination_ip",
        "qfi",
        "sm_context_reference",
        "subscriber_pseudonym",
        "imsi_pseudonym",
    ];
    let identifiers = event
        .identifiers
        .iter()
        .filter(|(name, _)| SEMANTIC_KEY_IDENTIFIERS.contains(&name.as_str()))
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("|");
    let tunnel_material = event
        .information_elements
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("value").and_then(Value::as_str))
        .flat_map(|value| value.split(','))
        .filter_map(|part| {
            let (name, value) = part.split_once('=')?;
            let name = name.trim().to_ascii_lowercase();
            [
                "teid",
                "ipv4",
                "seid",
                "network_instance",
                "dnn",
                "snssai",
                "s_nssai",
            ]
            .contains(&name.as_str())
            .then(|| format!("{name}={}", value.trim()))
        })
        .collect::<Vec<String>>()
        .join("|");
    // Setup/establishment messages are procedure occurrences, not periodic
    // state samples. Two packets with the same tunnel/session material are
    // both legitimate (for example a second PDU resource setup in one UE
    // context). Preserve their canonical packet occurrence while keeping
    // high-volume PFCP modifications and GTP-U data compacted.
    //
    // 2.18.3 (ANR1 #10 6898944250) — SBI-HTTP2 ajouté : la clé
    // semantic pré-2.18.3 ne distinguait pas deux opérations SBI
    // consécutives sur la même PDU session (même pseudonyme, même
    // pdu_session_id, même message_name « CreateSMContext » → même
    // clé → `representatives.insert` ne gardait que le dernier).
    // Résultat prod : pour la session `5g-session-99e8a9a6f5a0d5af`,
    // les events SBI étaient PERDUS avant `discover_sessions` →
    // `attach_sbi_to_sessions` avait 0 event SBI à rattacher →
    // callflow `9 N2 / 2 N3 / 8 N4 / 0 SBI` observé par Sadok.
    // Les events SBI sont des procédures (pas des échantillons
    // périodiques comme GTP-U) ; on les préserve tous par
    // `(capture_id, packet_number)`.
    let procedure = event
        .message_name
        .to_ascii_lowercase()
        .replace(' ', "")
        .replace('-', "");
    // 2.21.36 — tout NGAP / NAS est une procédure de signalisation (faible
    // volume) : chaque occurrence est préservée. Avant, deux essais du même
    // UE (mêmes identifiants, mêmes adresses) partageaient une clé et le
    // second écrasait les events N2 du premier (« last observation wins »).
    let preserve_occurrence = protocol_is(event, "NGAP")
        || protocol_is_any(event, &["NAS-5GMM", "NAS-5GSM"])
        || (protocol_is(event, "S1AP")
            && (procedure.contains("initialcontextsetup")
                || procedure.contains("erabsetup")))
        || (protocol_is(event, "GTPv2-C") && procedure.contains("createsession"))
        || (protocol_is(event, "PFCP") && procedure.contains("sessionestablishment"))
        || protocol_is(event, "SBI-HTTP2");
    let distinct_procedure_occurrence = preserve_occurrence
        .then(|| {
            event.packet_references.first().map_or_else(
                || event.event_id.clone(),
                |packet| format!("{}:{}", event.capture_id, packet.packet_number),
            )
        })
        .unwrap_or_default();
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        event.capture_point_id,
        event.interface,
        event.protocol,
        event.message_name,
        event.source_address,
        event.destination_address,
        event.direction,
        event.parent_event_id.as_deref().unwrap_or(""),
        identifiers,
        tunnel_material,
        distinct_procedure_occurrence,
    )
}

/// 2.7.24: like `load_path` but drops `information_elements` for every
/// event whose `protocol` is NOT in the IE-reading set
/// (`PFCP`, `NGAP`). Those two protocols are the only ones whose IEs
/// drive session discovery (`collect_pfcp_tunnels`) and
/// cross-interface correlation (`tunnel_key`/`tunnel_keys` in
/// `correlation-engine`); for everything else the IE tree is a pure
/// render-time payload. Dropping it for N3/GTP-U, SBI, S1AP, GTPv2-C,
/// NAS, etc., halves to triples per-event memory on real datasets
/// where these protocols dominate — the key memory win for 2.7.24.
///
/// The per-session `reconstruct` + `build_callflow` path still needs
/// full IEs; that is done later via `load_events_by_ids` which uses
/// the heavy `load_path` and holds only a few hundred events in RAM
/// at a time.
pub fn load_path_slim(path: &std::path::Path) -> Result<Vec<EventRecord>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    load_jsonl_slim(io::BufReader::new(file))
}

pub fn load_jsonl_slim<R: BufRead>(reader: R) -> Result<Vec<EventRecord>, String> {
    let mut events = Vec::new();
    for (line_no, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("line {}: {e}", line_no + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(&line)
            .map_err(|e| format!("line {}: invalid JSON: {e}", line_no + 1))?;
        let mut event =
            parse_event(value).map_err(|e| format!("line {}: {e}", line_no + 1))?;
        if !protocol_is_any(&event, &["PFCP", "NGAP"]) {
            event.information_elements = Value::Array(Vec::new());
        }
        events.push(event);
    }
    // 2.21.102 — même backfill que load_jsonl sur le chemin slim.
    backfill_stable_event_keys(&mut events);
    deterministic_sort(&mut events);
    Ok(events)
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
    for key in ["schema_version", "procedure"] {
        if let Some(value) = v.get(key) {
            compact_source.insert(key.to_string(), value.clone());
        }
    }
    // Publication only reads these three SBI attributes when proving an SCP
    // forwarded request (correlation-engine::correlate_sbi_routing). Keeping
    // the other eight metadata fields in every SBI representative retained
    // most of the real-lab RSS even though none participates in discovery,
    // correlation or callflow construction.
    if let Some(sbi) = v.get("sbi").and_then(Value::as_object) {
        let mut compact_sbi = serde_json::Map::new();
        for key in ["request_uri", "http_method", "operation"] {
            if let Some(value) = sbi.get(key) {
                compact_sbi.insert(key.to_string(), value.clone());
            }
        }
        if !compact_sbi.is_empty() {
            compact_source.insert("sbi".to_string(), Value::Object(compact_sbi));
        }
    }
    // 2.20.0 — lit les champs multi-sonde optionnels s'ils sont
    // présents dans le JSONL. Absent → None (iso-comportement
    // 2.19.x : rien n'est émis en retour).
    let opt_string = |path: &[&str]| -> Option<String> {
        let mut p = &v;
        for key in path {
            p = p.get(*key)?;
        }
        p.as_str().map(ToOwned::to_owned)
    };
    Ok(EventRecord {
        event_id: string(&["event_id"])?,
        // 2.21.95 — lit `stable_event_key` émis par event-schema 1.6.0.
        // Absent (JSONL pré-2.21.91) → chaîne vide, préservée telle
        // quelle dans la sortie (`skip_serializing_if = "String::is_empty"`
        // côté CallFlowEvent).
        stable_event_key: v
            .get("stable_event_key")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
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
        probe_id: opt_string(&["probe_id"]),
        probe_type: opt_string(&["probe_type"]),
        physical_link: opt_string(&["physical_link"]),
        timestamp_source: opt_string(&["timestamp_source"]),
    })
}

/// 2.7.13: the canonical processing order inside OIRAN is
/// `(capture_id, packet_number, event_id)`. The timestamp is NEVER used
/// for a processing decision, and no two events from different captures
/// are compared by `timestamp_ns`. Call flow ladder rendering may, as a
/// presentation step, order events by `timestamp_ns` — see
/// `callflow-schema::build_ladder_records_for_display` for the only
/// place that is allowed to do so, and the explicit comment at that
/// call site.
///
/// 0.5.27 (POLARIS 2.21.133) — ordre DANS un même paquet. Jusqu'ici
/// l'`event_id` départageait seul deux events d'un même paquet. C'est un
/// hachage : entre un message NGAP / S1AP et le NAS qu'il porte, l'ordre
/// était arbitraire (sur une capture réelle à cinq abonnés, 26 enfants
/// sur 58 passaient avant leur parent). Désormais, dans un même paquet :
///   1. parent avant enfant, par structure (`parent_event_id`) ;
///   2. puis l'ordinal d'émission lu en fin de `stable_event_key`
///      (`…|protocole|ordinal`) quand la clé est présente ;
///   3. puis l'`event_id`, comme avant.
/// La clé reste une comparaison de valeurs portées par chaque event :
/// l'ordre est total et ne dépend pas des autres events présents.
pub fn canonical_sort_key<'a>(event: &'a EventRecord) -> (&'a str, u64, InPacketOrder<'a>) {
    (event.capture_id.as_str(), event.packet_number(), in_packet_order(event))
}

/// 0.5.27 — rang d'un event parmi ceux de son paquet : `(enfant ?,
/// ordinal d'émission, event_id)`. Utilisé par `canonical_sort_key` et
/// par l'ordre d'affichage du ladder (`callflow-schema`).
pub type InPacketOrder<'a> = (bool, u32, &'a str);

pub fn in_packet_order<'a>(event: &'a EventRecord) -> InPacketOrder<'a> {
    (
        event.parent_event_id.is_some(),
        emission_ordinal(&event.stable_event_key),
        event.event_id.as_str(),
    )
}

/// 0.5.27 — ordinal d'émission porté par une `stable_event_key`
/// (`{fichier}|{iid}|{paquet}|{offset}|{protocole}|{ordinal}`).
/// `u32::MAX` si la clé est absente ou mal formée : l'event se range
/// alors après ceux qui en portent une, puis par `event_id`.
pub fn emission_ordinal(stable_event_key: &str) -> u32 {
    stable_event_key
        .rsplit('|')
        .next()
        .and_then(|last| last.parse::<u32>().ok())
        .unwrap_or(u32::MAX)
}

pub fn deterministic_sort(events: &mut [EventRecord]) {
    events.sort_by(|a, b| canonical_sort_key(a).cmp(&canonical_sort_key(b)));
}

/// 2.15.0 (ANR1 #10 6883006379) — étend un ensemble d'`event_id`
/// sélectionnés avec les PFCP siblings observés dans la même
/// slice d'events : tout event PFCP qui partage un `pfcp_sequence`
/// ou un `seid`/`f_seid` non nul avec un event déjà dans la
/// sélection est tiré dans la sélection.
///
/// Corrige le défaut mesuré en prod : le `shard JSONL contenait
/// un `PFCP Session Establishment Request` (type 50,
/// `pfcp_sequence=2209`) qui n'était **pas** dans
/// `session.event_ids` (parce que la découverte 5G de la session
/// s'ancre sur N2 et ne connaît pas les SEIDs avant d'avoir vu
/// la Response/Modification), alors que la `Response` et la
/// `Modification` **étaient** dans la sélection. Résultat : la
/// Request disparaissait du callflow côté UI alors que le shard
/// la contenait.
///
/// Les callers doivent passer **tous** les events disponibles
/// au niveau de l'agrégation (la slice non filtrée) et
/// l'ensemble initial `selection`. Le résultat est un nouveau
/// `BTreeSet` qui inclut `selection` + les PFCP siblings. Ordre
/// canonique `(capture_id, packet_number, event_id)` garanti par
/// `canonical_sort_key` / `deterministic_sort` à l'étape
/// `reconstruct` qui suit — aucune décision n'est prise ici en
/// fonction de `timestamp_ns`.
pub fn expand_pfcp_session_members(
    events: &[EventRecord],
    selection: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut known_seqs: BTreeSet<String> = BTreeSet::new();
    let mut known_seids: BTreeSet<String> = BTreeSet::new();
    for event in events {
        if !selection.contains(&event.event_id) {
            continue;
        }
        if !protocol_is(event, "PFCP") {
            continue;
        }
        if let Some(seq) = event.first_identifier("pfcp_sequence") {
            known_seqs.insert(seq.to_owned());
        }
        for name in ["seid", "f_seid"] {
            for v in event.identifier_values(name) {
                if v != "0x0000000000000000" {
                    known_seids.insert(v.to_owned());
                }
            }
        }
    }
    let mut expanded = selection.clone();
    if known_seqs.is_empty() && known_seids.is_empty() {
        return expanded;
    }
    for event in events {
        if expanded.contains(&event.event_id) {
            continue;
        }
        if !protocol_is(event, "PFCP") {
            continue;
        }
        let seq_match = event
            .first_identifier("pfcp_sequence")
            .map(|seq| known_seqs.contains(seq))
            .unwrap_or(false);
        let seid_match = ["seid", "f_seid"].iter().any(|name| {
            event
                .identifier_values(name)
                .into_iter()
                .any(|v| v != "0x0000000000000000" && known_seids.contains(v))
        });
        if seq_match || seid_match {
            expanded.insert(event.event_id.clone());
        }
    }
    expanded
}

pub fn reconstruct(mut events: Vec<EventRecord>, hints: ReconstructionHints) -> Reconstruction {
    deterministic_sort(&mut events);
    let duplicate_event_ids = duplicate_ids(&events);
    let pdu_anchor = events
        .iter()
        .find(|e| protocol_is(e, "NGAP") && e.message_name.contains("PDUSessionResourceSetup"));
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
        if protocol_is(e, "PFCP")
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
        let value = if protocol_is(e, "NGAP") {
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
            } else if protocol_is(e, "PFCP") {
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
            } else if protocol_is(e, "GTP-U") {
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
            } else {
                Association::Unmatched
        };
        association.insert(e.event_id.clone(), value);
    }

    let mut tunnels = Vec::new();
    for (teid, endpoint) in teid_records {
        let matching: Vec<_> = events
            .iter()
            .filter(|e| protocol_is(e, "GTP-U") && e.first_identifier("teid") == Some(&teid))
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

    for event in events.iter().filter(|event| protocol_is(event, "NGAP")) {
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
        // 2.21.36 — InitialUEMessage et InitialContextSetupRequest ouvrent
        // une NOUVELLE connexion logique UE (TS 38.413 §8.3.1 / §8.6.1) :
        // ils ne prolongent jamais un contexte déjà établi. Sinon deux essais
        // successifs du même UE, avec identifiants NGAP réutilisés et sans
        // release observée, étaient fusionnés dans la session du premier.
        let opens_new_connection = event.message_name.contains("InitialUEMessage");
        let restarts_context_setup = event.message_name.contains("InitialContextSetupRequest");
        // Le contexte le plus RÉCENT gagne (`rposition`) : après ouverture
        // d'une nouvelle connexion, les messages suivants la prolongent, pas
        // l'ancienne restée non libérée.
        let matching = contexts.iter().rposition(|context| {
            !opens_new_connection
                && !(restarts_context_setup && context.state == "ACTIVE")
                && context.state != "RELEASED"
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
        .filter(|event| protocol_is_any(event, &["NAS-5GMM", "NAS-5GSM"]))
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
            // 2.7.13: canonical (capture_id, seq, event_id) — ts never
            // drives a PDU session lifecycle decision.
            related.sort_by(|a, b| canonical_sort_key(a).cmp(&canonical_sort_key(b)));
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
                sbi_time_window_event_ids: Vec::new(),
            };
            procedures.extend(discover_procedures(context, Some(&session), &related));
            pdu_sessions.push(session);
        }
    }

    let pfcp_sessions = discover_pfcp_sessions(&events);
    let gtpu_tunnels = discover_gtpu_tunnels(&events, &pfcp_sessions);

    // 2.9.9 (#9 comment 6725858177) : attachment SBI à la session.
    // ANR2 a prouvé que les 25 événements SBI de la fenêtre callflow
    // de `5g-session-5e3fc8ce83936ea0` n'étaient rattachés à aucune
    // session. La règle : clé exacte, jamais par `ts`.
    //
    // Clés acceptées, dans l'ordre :
    //   1. `(subscriber_pseudonym, pdu_session_id)` — SBI JSON body
    //      publie SUPI/PEI pseudonymisé + pduSessionId ; la session
    //      5G le porte via ses événements NGAP+NAS.
    //   2. `(tunnel_endpoint_ip, gtp_teid)` normalisés — SBI
    //      `n2SmInfo` carry la UL NG-U TNL Information ; la session
    //      N2 publie le même couple sur son
    //      `PDUSessionResourceSetupRequest`.
    //
    // La règle est fail-closed : un SBI qui n'a ni (pseudonyme,
    // pduSessionId) ni (TEID, IP) reste non rattaché et compte en
    // `unmatched`. Aucun critère temporel n'est utilisé.
    let sbi_counters = attach_sbi_to_sessions(&events, &mut pdu_sessions, &mut event_context);

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
    event_accounting.insert("sbi_attached_exact_key".into(), sbi_counters.by_exact_key);
    event_accounting.insert("sbi_attached_time_window".into(), sbi_counters.by_time_window);
    event_accounting.insert(
        "sbi_unattached_ambiguous".into(),
        sbi_counters.unattached_ambiguous,
    );
    event_accounting.insert("sbi_unattached_no_key".into(), sbi_counters.unattached_no_key);
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

/// 2.9.9 (#9 comment 6725858177) : règle de rattachement SBI →
/// session par clé exacte. Jamais par timestamp.
///
/// Pour chaque session PDU, on prépare deux index :
///   * `pseudo_pdu`   → (`subscriber_pseudonym`, `pdu_session_id`).
///     Scan des events de la session (NGAP + NAS) ; si l'un porte
///     un `subscriber_pseudonym`, il devient une clé de rattachement
///     pour un SBI qui publie le même pseudo + le même pduSessionId.
///   * `tunnel`       → (`tunnel_endpoint_ip`, `gtp_teid`)
///     normalisés via `event_schema`. SBI `CreateSMContext` /
///     `UpdateSMContext` / `N1N2MessageTransfer` carry la UL NG-U
///     TNL Information extraite du `n2SmInfo` ; la session N2
///     publie le même couple sur son `PDUSessionResourceSetupRequest`.
///
/// Un SBI qui match par l'une des deux clés est ajouté à
/// `session.event_ids` + inscrit dans `event_context` sous le
/// `ue_context_id` de la session. Les deux index étant construits
/// sur des IE strictement présentes (pseudonyme OU tuple tunnel),
/// l'attache est **exacte** — un timing n'intervient à aucun moment.
/// 2.21.55 (ANR2 #10 6988143045, B1) — les SBI stockés avant le
/// catalogue courant (`UnsupportedSbiOperation`, ex. PUT
/// `nudm-uecm/.../smf-registrations/<PDU>`) n'exportent pas
/// `subscriber_pseudonym`, alors que l'URI sanitisée par le décodeur le
/// porte déjà : `subscriber-psn-<32 hex>` (`decoder-sbi::sanitize_uri`,
/// même domaine que l'identifiant). Lecture stricte, fail-closed : un
/// seul segment `subscriber-psn-` de 32 hex minuscules, sinon `None`.
/// Aucune identité en clair n'est lue (l'URI stockée est déjà
/// pseudonymisée). Appliqué à la publication : couvre le stock existant.
fn sbi_uri_subscriber_pseudonym(event: &EventRecord) -> Option<String> {
    let uri = event
        .source_json
        .get("sbi")
        .and_then(|sbi| sbi.get("request_uri"))
        .and_then(Value::as_str)?;
    let path = uri.split('?').next().unwrap_or(uri);
    let mut found: Option<&str> = None;
    for segment in path.split('/') {
        let Some(pseudo) = segment.strip_prefix("subscriber-") else {
            continue;
        };
        let hex = pseudo.strip_prefix("psn-")?;
        if hex.len() != 32 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return None;
        }
        if found.is_some_and(|previous| previous != pseudo) {
            return None;
        }
        found = Some(pseudo);
    }
    found.map(str::to_owned)
}

/// 2.21.49 — résultat comptable du rattachement SBI (exposé dans
/// `DiscoveryResult.event_accounting`).
#[derive(Default)]
struct SbiAttachCounters {
    by_exact_key: usize,
    by_time_window: usize,
    unattached_ambiguous: usize,
    /// 2.21.57 — SBI sans aucune clé (ni pseudonyme, ni PDU, ni tunnel) :
    /// jamais rattachables, désormais comptés pour que la somme des quatre
    /// compteurs égale le nombre total de SBI (comparaison entre versions).
    unattached_no_key: usize,
}

/// 2.21.49 — marge autour de la vie d'une session pour le rattachement
/// par fenêtre de temps (SBI d'enregistrement émis juste avant le N2 de
/// la session, SBI de libération juste après).
const SBI_TIME_WINDOW_MARGIN_NS: i128 = 2_000_000_000;

fn attach_sbi_to_sessions(
    events: &[EventRecord],
    pdu_sessions: &mut Vec<DiscoveredPduSession>,
    event_context: &mut BTreeMap<String, String>,
) -> SbiAttachCounters {
    let mut counters = SbiAttachCounters::default();
    if pdu_sessions.is_empty() {
        return counters;
    }
    // Snapshot de lookup event_id → &EventRecord.
    let event_by_id: BTreeMap<_, _> = events
        .iter()
        .map(|event| (event.event_id.clone(), event))
        .collect();

    // Index (pseudo, pdu_session_id) → session_index.
    // 2.21.49 — ensembles : une clé n'est EXACTE que si elle désigne une
    // seule session (au lab, `(pseudonyme, PDU 1)` et les TEID se répètent
    // d'un essai à l'autre — ANR2 #10 6972508696 : TEID 0xf124 dans 30
    // sessions, `(pseudonyme, 1)` dans 136).
    let mut pseudo_pdu: BTreeMap<(String, String), BTreeSet<usize>> = BTreeMap::new();
    // Index (tunnel_endpoint_ip_norm, gtp_teid_norm) → sessions.
    let mut tunnel_idx: BTreeMap<(String, String), BTreeSet<usize>> = BTreeMap::new();
    // 2.18.7 (ANR1 #10 6901968948) — Index pseudo → ensemble de
    // sessions. Fallback pour les events SBI qui portent le
    // `subscriber_pseudonym` mais PAS de `pdu_session_id` (ex.
    // Nudm_SDM `am-data`, Nudm_UECM `registrations`, Npcf
    // `am-policy-data`) ni de tunnel `(ip, teid)` (pas de
    // n2SmInfo). Avant 2.18.7 : ces events n'étaient attachés à
    // AUCUNE session malgré un match abonné prouvé par la trace
    // Live. On relie désormais ces events à TOUTES les sessions
    // du même pseudonyme — l'abonné est le seul lien légitime
    // disponible, et attacher à plusieurs sessions concurrentes
    // reste correct (c'est bien l'abonné qui porte l'opération).
    let mut pseudo_only: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    // 2.18.11 (ANR2 #10 — 0 SBI rattaché alors que 4 SBI portent le
    // pseudonyme exact de la session) : les events d'une PDU session
    // (N2 PDUSessionResourceSetup, N4, N3) ne portent PAS le SUPI ;
    // le `subscriber_pseudonym` vit sur le NAS de Registration du MÊME
    // UE context (SUCI null-scheme). `pseudo_only` restait donc vide.
    // On indexe aussi les pseudonymes portés par n'importe quel event
    // du UE context exact de la session (lien `event_context`, jamais
    // de proximité temporelle).
    let mut context_pseudos: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for event in events {
        if let (Some(context_id), Some(pseudo)) = (
            event_context.get(&event.event_id),
            event.first_identifier("subscriber_pseudonym"),
        ) {
            context_pseudos
                .entry(context_id.as_str())
                .or_default()
                .insert(pseudo);
        }
    }
    for (idx, session) in pdu_sessions.iter().enumerate() {
        if let Some(pseudos) = context_pseudos.get(session.ue_context_id.as_str()) {
            for pseudo in pseudos {
                let entry = pseudo_only.entry((*pseudo).to_owned()).or_default();
                if !entry.contains(&idx) {
                    entry.push(idx);
                }
                // 2.21.51 (ANR2 #10 6983842360 : `pseudo_pdu_keys=0`) —
                // les events N2/N4/N3 d'une PDU session ne portent pas le
                // SUPI ; le pseudonyme vit sur le NAS du MÊME contexte UE
                // (lien `event_context` exact). Sans cette entrée, la clé
                // `(pseudonyme, PDU)` n'existait jamais.
                pseudo_pdu
                    .entry(((*pseudo).to_owned(), session.pdu_session_id.clone()))
                    .or_default()
                    .insert(idx);
            }
        }
    }
    for (idx, session) in pdu_sessions.iter().enumerate() {
        let pdu_id = session.pdu_session_id.clone();
        for event_id in &session.event_ids {
            let Some(event) = event_by_id.get(event_id).copied() else {
                continue;
            };
            if let Some(pseudo) = event.first_identifier("subscriber_pseudonym") {
                let entry = pseudo_only.entry(pseudo.to_owned()).or_default();
                if !entry.contains(&idx) {
                    entry.push(idx);
                }
                pseudo_pdu
                    .entry((pseudo.to_owned(), pdu_id.clone()))
                    .or_default()
                    .insert(idx);
            }
            // 2.9.15 (#9 comment 6728928219) : ANR2 a prouvé que le
            // N2 `PDUSessionResourceSetupRequest` publie son tuple
            // sous des noms `item_0_tunnel_ip_ul` +
            // `item_0_gtp_teid_ul` (préfixe `item_0_`, suffixe
            // directional `_ul` / `_dl`), pas sous
            // `tunnel_endpoint_ip` / `gtp_teid` plats. La lecture
            // pré-2.9.15 ne trouvait rien côté N2 → `tunnel_idx`
            // vide → SBI jamais rattaché par tunnel. Correctif :
            // scanner TOUS les identifiers du N2 pour les paires
            // `*tunnel_(ip|endpoint_ip)_(ul|dl)?` ↔
            // `*gtp_teid_(ul|dl)?` avec le MÊME préfixe.
            //
            // Règle : pour chaque identifier dont le nom se
            // termine par `tunnel_endpoint_ip`, `tunnel_ip_ul`,
            // `tunnel_ip_dl` ou `tunnel_ip`, chercher un pair
            // teid avec le MÊME préfixe + suffixe teid (adapté
            // depuis `correlation-engine::directional_tunnel_components`
            // pour la cohérence inter-modules).
            //
            // `event.identifiers` est un `Vec<(String, String)>` ;
            // on construit une BTreeMap `name → value` locale
            // (peu d'entrées par événement) pour chercher les
            // paires.
            use std::collections::BTreeMap;
            let named: BTreeMap<&str, &str> = event
                .identifiers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            index_tunnel_names(&named, idx, &mut tunnel_idx);

            // 2.9.17 (#9 comment 6738246907) : ANR2 a prouvé que
            // sur le run `5g-session-936f7625b33cbfd1` la 2.9.16
            // laissait toujours SBI OUVERT. Cause : decoder-ngap
            // n'exporte PAS `item_0_tunnel_ip_ul` /
            // `item_0_gtp_teid_ul` dans `session_identifiers` —
            // l'enum de bare-keys au `decoder-ngap:834-847`
            // n'inclut que `tunnel_ip_ul`, `gtp_teid_ul` bruts et
            // `item_0_*` ne matche pas (deux clés différentes).
            // Les valeurs vivent alors uniquement dans la chaîne
            // composite d'une InformationElement (ex. « UL NG-U
            // UP TNL Information ») :
            //   `item_0_tunnel_ip_ul=10.77.22.13,item_0_gtp_teid_ul=0x25fb,...`
            //
            // Correctif : parser chaque `information_elements[*]
            // .value` du N2/NAS, extraire les mêmes paires
            // directional (préfixe commun + suffix
            // tunnel_ip_ul/gtp_teid_ul), et indexer.
            if let Some(ies) = event.information_elements.as_array() {
                for ie in ies {
                    let Some(value) = ie.get("value").and_then(serde_json::Value::as_str) else {
                        continue;
                    };
                    let parsed: BTreeMap<&str, &str> = value
                        .split(',')
                        .filter_map(|pair| pair.split_once('='))
                        .map(|(k, v)| (k.trim(), v.trim()))
                        .collect();
                    index_tunnel_names(&parsed, idx, &mut tunnel_idx);
                }
            }

            // 2.17.1 (ANR1 #10 E2E-5G) — fix SBI continuous perdu.
            // Les sessions découvertes depuis le plan utilisateur
            // seul (GTP-U N3 sans N2 associé — cas prod
            // `5g-session-99e8a9a6f5a0d5af`) n'ont AUCUN event N2
            // qui publierait `tunnel_endpoint_ip`/`gtp_teid` →
            // `tunnel_idx` reste vide pour cette session → les
            // events SBI qui portent pourtant le même tuple
            // `(tunnel_endpoint_ip, gtp_teid)` ne sont jamais
            // rattachés. decoder-gtpu émet `teid` (sans préfixe
            // `gtp_`) + `tunnel_endpoint_ip` dans ses
            // `session_identifiers` (voir decoder-gtpu/src/lib.rs:
            // 158-171). On les indexe ici avec le MÊME alias
            // `gtp_teid` que celui qu'attendent les SBI (lookup
            // ligne 1980-1982 ci-dessous).
            if event.protocol.eq_ignore_ascii_case("GTP-U") {
                if let (Some(ip_raw), Some(teid_raw)) = (
                    event.first_identifier("tunnel_endpoint_ip"),
                    event.first_identifier("teid"),
                ) {
                    let normalized_ip = event_schema::normalize_ip(ip_raw);
                    let normalized_teid = event_schema::normalize_teid_hex(teid_raw);
                    if let Some(teid) = normalized_teid {
                        tunnel_idx
                            .entry((normalized_ip, teid))
                            .or_default()
                            .insert(idx);
                    }
                }
            }
        }
    }

    // 2.21.49 — fenêtre de vie de chaque session, calculée sur ses events
    // NON-SBI (N2/N3/N4) avant tout rattachement SBI.
    let windows: Vec<Option<(i128, i128)>> = pdu_sessions
        .iter()
        .map(|session| {
            let stamps = session
                .event_ids
                .iter()
                .filter_map(|id| event_by_id.get(id))
                .filter(|event| !protocol_is(event, "SBI-HTTP2"))
                .map(|event| event.timestamp_ns)
                .collect::<Vec<_>>();
            let first = stamps.iter().min().copied()?;
            let last = stamps.iter().max().copied()?;
            Some((first - SBI_TIME_WINDOW_MARGIN_NS, last + SBI_TIME_WINDOW_MARGIN_NS))
        })
        .collect();

    let mut sbi_events = events
        .iter()
        .filter(|event| protocol_is(event, "SBI-HTTP2"))
        .collect::<Vec<_>>();
    sbi_events.sort_by(|left, right| canonical_sort_key(left).cmp(&canonical_sort_key(right)));
    for event in sbi_events {
        if event_context.contains_key(&event.event_id) {
            continue;
        }
        let pdu_id = event.first_identifier("pdu_session_id").map(str::to_owned);
        let pseudo = event
            .first_identifier("subscriber_pseudonym")
            .map(str::to_owned)
            .or_else(|| sbi_uri_subscriber_pseudonym(event));
        // Règle des sondes pro : 1) clé exacte UNIQUE ; 2) sinon, en dernier
        // recours, la fenêtre de vie de la session (même horloge de l'hôte
        // de capture), parmi les seules sessions candidates par clé ; une
        // seule session dans la fenêtre, sinon non rattaché (fail-closed).
        let mut key_candidates: Option<BTreeSet<usize>> = None;
        let mut had_tunnel_key = false;
        if let (Some(pseudo), Some(pdu_id)) = (&pseudo, &pdu_id) {
            if let Some(indices) = pseudo_pdu.get(&(pseudo.clone(), pdu_id.clone())) {
                key_candidates = Some(indices.clone());
            }
        }
        if key_candidates.as_ref().is_none_or(|set| set.len() != 1) {
            let ip = event
                .first_identifier("tunnel_endpoint_ip")
                .map(event_schema::normalize_ip);
            let teid = event
                .first_identifier("gtp_teid")
                .and_then(event_schema::normalize_teid_hex);
            if let (Some(ip), Some(teid)) = (ip, teid) {
                had_tunnel_key = true;
                if let Some(indices) = tunnel_idx.get(&(ip, teid)) {
                    key_candidates = Some(match key_candidates {
                        Some(previous) if indices.len() != 1 => {
                            let both = previous
                                .intersection(indices)
                                .copied()
                                .collect::<BTreeSet<_>>();
                            if both.is_empty() {
                                previous
                            } else {
                                both
                            }
                        }
                        _ => indices.clone(),
                    });
                }
            }
        }
        let mut method_time_window = false;
        let targets: Vec<usize> = match key_candidates {
            Some(set) if set.len() == 1 => set.into_iter().collect(),
            other => {
                let pool: Vec<usize> = match other {
                    Some(set) => set.into_iter().collect(),
                    None => pseudo
                        .as_deref()
                        .and_then(|value| pseudo_only.get(value))
                        .cloned()
                        .unwrap_or_default(),
                };
                let inside = pool
                    .into_iter()
                    .filter(|idx| {
                        pdu_id
                            .as_ref()
                            .is_none_or(|pdu| &pdu_sessions[*idx].pdu_session_id == pdu)
                    })
                    .filter(|idx| {
                        windows[*idx].is_some_and(|(start, end)| {
                            event.timestamp_ns >= start && event.timestamp_ns <= end
                        })
                    })
                    .collect::<BTreeSet<_>>();
                // Plusieurs sessions dans la fenêtre : acceptable seulement si
                // elles appartiennent au MÊME contexte UE (sessions PDU
                // concurrentes d'un même enregistrement : l'opération abonné
                // les concerne toutes). Contextes différents → ambigu.
                let contexts = inside
                    .iter()
                    .map(|idx| pdu_sessions[*idx].ue_context_id.as_str())
                    .collect::<BTreeSet<_>>();
                if !inside.is_empty() && contexts.len() == 1 {
                    method_time_window = true;
                    inside.into_iter().collect()
                } else {
                    if pseudo.is_some() || pdu_id.is_some() || had_tunnel_key {
                        counters.unattached_ambiguous += 1;
                    } else {
                        counters.unattached_no_key += 1;
                    }
                    Vec::new()
                }
            }
        };
        if targets.is_empty() {
            continue;
        }
        if method_time_window {
            counters.by_time_window += 1;
        } else {
            counters.by_exact_key += 1;
        }
        for idx in targets {
            let session = &mut pdu_sessions[idx];
            session.event_ids.push(event.event_id.clone());
            if method_time_window {
                session.sbi_time_window_event_ids.push(event.event_id.clone());
            }
            if !session.interfaces.iter().any(|iface| iface == &event.interface) {
                session.interfaces.push(event.interface.clone());
                session.interfaces.sort();
            }
            event_context
                .entry(event.event_id.clone())
                .or_insert_with(|| session.ue_context_id.clone());
        }
    }
    counters
}

/// 2.18.0 (ANR1 #10 E2E-5G — SBI identities) — agrégat compact des
/// identités abonné/équipement observées pour UNE session, dérivé des
/// events SBI rattachés par `attach_sbi_to_sessions`. Shape prévue
/// pour être consommée par `lib.rs::identity_summary_for_session`
/// (ou son équivalent) **sans modifier** la pipeline tshark → vault
/// existante. Chaque champ documente la source SBI (service +
/// opération + event_id) pour que l'UI puisse afficher la preuve.
///
/// Invariant « jamais d'hypothèse » : un champ est `None` tant
/// qu'aucun event SBI rattaché à la session ne publie l'identifiant
/// correspondant. Un seul event → un seul `source_event_id` ;
/// plusieurs events → la 1re observation canonique
/// `(capture_id, packet_number, event_id)` est retenue.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SbiIdentitySummary {
    pub msisdn_pseudonym: Option<SbiIdentityValue>,
    pub imei_pseudonym: Option<SbiIdentityValue>,
    pub imeisv_pseudonym: Option<SbiIdentityValue>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SbiIdentityValue {
    pub value: String,
    /// Chaîne lisible `"SBI:<service>:<operation>"` ou simplement
    /// `"SBI"` si l'event ne porte pas les deux. Permet à l'UI de
    /// montrer la source sans dévoiler le payload.
    pub source: String,
    pub source_event_id: String,
    pub capture_id: String,
    pub packet_number: u64,
}

/// 2.18.0 — Collecte les identités SBI observées dans la fenêtre
/// d'une session PDU. Rattachement par subscriber_pseudonym : seuls
/// les events SBI appartenant déjà à `session.event_ids` sont
/// scannés, ce qui garantit que le match SUPI est déjà prouvé par
/// `attach_sbi_to_sessions`.
///
/// La fonction est pure (aucun side-effect) et testable isolément
/// sans `lib.rs`. Elle sera appelée côté lib.rs au moment de
/// construire `/api/v1/sessions/:id.identities` — voir rapport #10
/// pour la ligne exacte à toucher.
pub fn collect_sbi_identities_for_session(
    session: &DiscoveredPduSession,
    events: &[EventRecord],
) -> SbiIdentitySummary {
    let event_by_id: BTreeMap<_, _> = events
        .iter()
        .map(|event| (event.event_id.as_str(), event))
        .collect();
    let mut summary = SbiIdentitySummary::default();
    for event_id in &session.event_ids {
        let Some(event) = event_by_id.get(event_id.as_str()).copied() else {
            continue;
        };
        if !protocol_is(event, "SBI-HTTP2") {
            continue;
        }
        let source = sbi_identity_source(event);
        let capture_id = event.capture_id.clone();
        let packet_number = event.packet_number();
        if summary.msisdn_pseudonym.is_none() {
            if let Some(value) = event.first_identifier("msisdn_pseudonym") {
                summary.msisdn_pseudonym = Some(SbiIdentityValue {
                    value: value.to_owned(),
                    source: source.clone(),
                    source_event_id: event.event_id.clone(),
                    capture_id: capture_id.clone(),
                    packet_number,
                });
            }
        }
        if summary.imei_pseudonym.is_none() {
            if let Some(value) = event.first_identifier("imei_pseudonym") {
                summary.imei_pseudonym = Some(SbiIdentityValue {
                    value: value.to_owned(),
                    source: source.clone(),
                    source_event_id: event.event_id.clone(),
                    capture_id: capture_id.clone(),
                    packet_number,
                });
            }
        }
        if summary.imeisv_pseudonym.is_none() {
            if let Some(value) = event.first_identifier("imeisv_pseudonym") {
                summary.imeisv_pseudonym = Some(SbiIdentityValue {
                    value: value.to_owned(),
                    source: source.clone(),
                    source_event_id: event.event_id.clone(),
                    capture_id,
                    packet_number,
                });
            }
        }
    }
    summary
}

fn sbi_identity_source(event: &EventRecord) -> String {
    let service = event
        .first_identifier("sbi_service")
        .map(str::to_owned);
    let operation = event
        .first_identifier("sbi_operation")
        .map(str::to_owned);
    match (service.as_deref(), operation.as_deref()) {
        (Some(service), Some(op)) if !service.is_empty() && !op.is_empty() => {
            format!("SBI:{service}:{op}")
        }
        (Some(service), _) if !service.is_empty() => format!("SBI:{service}"),
        _ => event
            .message_name
            .is_empty()
            .then(|| "SBI".to_owned())
            .unwrap_or_else(|| format!("SBI:{}", event.message_name)),
    }
}

/// 2.9.17 (#9 comment 6738246907) : scanne une map name→value
/// pour les paires directional
/// `*tunnel_(endpoint_ip|ip_ul|ip_dl|ip)` ↔
/// `*gtp_teid(_ul|_dl)?` avec le MÊME préfixe. Mutualisé entre
/// `session_identifiers` (bare keys) et le parse des IE
/// composites (`decoder-ngap` emits `item_0_tunnel_ip_ul=…,
/// item_0_gtp_teid_ul=…` dans une seule chaîne value).
fn index_tunnel_names(
    named: &std::collections::BTreeMap<&str, &str>,
    session_idx: usize,
    tunnel_idx: &mut std::collections::BTreeMap<(String, String), std::collections::BTreeSet<usize>>,
) {
    for (name, value) in named.iter() {
        let (prefix, ip_norm) = if let Some(prefix) = name.strip_suffix("tunnel_endpoint_ip") {
            (prefix, event_schema::normalize_ip(value))
        } else if let Some(prefix) = name.strip_suffix("tunnel_ip_ul") {
            (prefix, event_schema::normalize_ip(value))
        } else if let Some(prefix) = name.strip_suffix("tunnel_ip_dl") {
            (prefix, event_schema::normalize_ip(value))
        } else if let Some(prefix) = name.strip_suffix("tunnel_ip") {
            (prefix, event_schema::normalize_ip(value))
        } else {
            continue;
        };
        let teid_candidates: [String; 4] = [
            format!("{prefix}gtp_teid"),
            format!("{prefix}gtp_teid_ul"),
            format!("{prefix}gtp_teid_dl"),
            format!("{prefix}teid"),
        ];
        for teid_name in &teid_candidates {
            if let Some(teid_raw) = named.get(teid_name.as_str()) {
                if let Some(teid_norm) = event_schema::normalize_teid_hex(teid_raw) {
                    tunnel_idx
                        .entry((ip_norm.clone(), teid_norm))
                        .or_default()
                        .insert(session_idx);
                }
            }
        }
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
        .filter(|event| protocol_starts_with(event, "NAS-5G"))
        .filter_map(|event| event.parent_event_id.as_deref())
        .collect::<BTreeSet<_>>();
    for event in events {
        if protocol_is(event, "NGAP")
            && nas_parents.contains(event.event_id.as_str())
            && (event.message_name.contains("NAS") || event.message_name.contains("InitialUE"))
        {
            continue;
        }
        let kind = if protocol_starts_with(event, "NAS-5G") {
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
        .filter(|event| protocol_is(event, "PFCP") && event.message_name.contains("Session"))
        .collect::<Vec<_>>();
    // 2.7.13: canonical (capture_id, seq, event_id) — PFCP session
    // reconstruction stays deterministic without a cross-capture ts
    // comparison.
    ordered.sort_by(|a, b| canonical_sort_key(a).cmp(&canonical_sort_key(b)));
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
    for event in events.iter().filter(|event| protocol_is(event, "GTP-U")) {
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
            // 2.7.13: canonical (capture_id, seq, event_id) — GTP-U
            // tunnel aggregation uses structural order.
            events.sort_by(|a, b| canonical_sort_key(a).cmp(&canonical_sort_key(b)));
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
    for e in events.iter().filter(|e| protocol_is(e, "PFCP")) {
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

    #[test]
    fn compact_projection_drops_only_unread_schema_metadata() {
        let mut record = event("schema-audit", "NAS-5GS", "RegistrationRequest", &[], 1);
        record.source_json = serde_json::json!({
            "schema_version": "1.5.0",
            "procedure": "REGISTRATION",
            "sbi": {"operation": "CreateSMContext"}
        });

        compact_publication_event(&mut record);

        assert!(record.source_json.get("schema_version").is_none());
        assert_eq!(record.source_json["procedure"], "REGISTRATION");
        assert_eq!(record.source_json["sbi"]["operation"], "CreateSMContext");
    }

    #[test]
    fn sbi_publication_projection_is_equivalent_for_consumed_fields() {
        let base = serde_json::json!({
            "event_id": "evt-sbi-equivalence",
            "capture_id": "cap-sbi",
            "capture_point_id": "SBI",
            "timestamp": {"seconds": 1, "nanoseconds": 2, "raw_ticks": 3, "display": "1.000000002Z"},
            "interface": "SBI",
            "protocol": "SBI-HTTP2",
            "message_name": "CreateSMContext",
            "source_endpoint": {"address": "10.0.0.1", "network_function": "SCP"},
            "destination_endpoint": {"address": "10.0.0.2", "network_function": "SMF"},
            "direction": "CORE_TO_CORE",
            "session_identifiers": [],
            "information_elements": [],
            "decoding_status": "DECODED",
            "decoder_name": "decoder-sbi",
            "decoder_version": "1",
            "raw_payload_reference": "sha256:test",
            "packet_references": [{"source_file": "SBI.pcapng", "packet_number": 1, "byte_offset": 0, "interface_id": 0, "captured_length": 64, "original_length": 64}],
            "errors": [],
            "sbi": {
                "request_uri": "/nsmf-pdusession/v1/sm-contexts/1",
                "http_method": "POST",
                "operation": "CreateSMContext",
                "tcp_connection_id": "discarded",
                "http2_stream_id": 17,
                "consumer_nf": "SCP",
                "producer_nf": "SMF",
                "service": "nsmf-pdusession",
                "http_status": 201,
                "scp_transit": true,
                "transaction_duration_ns": 42
            }
        });
        let full = parse_event(base.clone()).expect("full SBI event parses");
        let mut already_compact = base;
        already_compact["sbi"] = serde_json::json!({
            "request_uri": "/nsmf-pdusession/v1/sm-contexts/1",
            "http_method": "POST",
            "operation": "CreateSMContext"
        });
        let compact = parse_event(already_compact).expect("compact SBI event parses");

        assert_eq!(full.source_json, compact.source_json);
        assert_eq!(full.source_json["sbi"].as_object().unwrap().len(), 3);
        assert!(full.source_json["sbi"].get("tcp_connection_id").is_none());
    }

    #[test]
    fn streaming_index_preserves_distinct_setup_occurrences() {
        use std::io::Write;

        let path = std::env::temp_dir().join(format!(
            "oiran-streaming-index-{}-{}.jsonl",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let mut writer = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
        for packet in 1..=2 {
            let record = serde_json::json!({
                "event_id": format!("event-{packet}"),
                "capture_id": "cap",
                "capture_point_id": "N2",
                "timestamp": {"seconds":1,"nanoseconds":packet,"raw_ticks":packet,"display":"1Z"},
                "interface": "N2",
                "protocol": "NGAP",
                "message_name": "PDUSessionResourceSetupResponse",
                "source_endpoint": {"address":"a","network_function":"gNB"},
                "destination_endpoint": {"address":"b","network_function":"AMF"},
                "direction": "RAN_TO_CORE",
                "session_identifiers": [
                    {"name":"ran_ue_ngap_id","value":"41","pseudonymized":false},
                    {"name":"amf_ue_ngap_id","value":"73","pseudonymized":false},
                    {"name":"pdu_session_id","value":"1","pseudonymized":false},
                    {"name":"enb_ue_s1ap_id","value":"9","pseudonymized":false},
                    {"name":"mme_ue_s1ap_id","value":"10","pseudonymized":false},
                    {"name":"erab_teid","value":"0x7804","pseudonymized":false},
                    {"name":"bearer_f_teid","value":"0x7f6f","pseudonymized":false}
                ],
                "information_elements": [
                    {"name":"TEID","value":"0x01020304"},
                    {"name":"large-render-only-payload","value":"x".repeat(16_384)}
                ],
                "decoding_status": "DECODED",
                "decoder_name": "test",
                "decoder_version": "1",
                "raw_payload_reference": "sha256:test",
                "packet_references": [{"source_file":"x","packet_number":packet,"byte_offset":0,"interface_id":0,"captured_length":1,"original_length":1}],
                "errors": []
            });
            writeln!(writer, "{record}").unwrap();
        }
        writer.flush().unwrap();

        let index = load_path_streaming_index(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(index.source_event_count, 2);
        assert_eq!(index.event_ids.len(), 2);
        assert!(index.event_ids.contains("event-1"));
        assert!(index.event_ids.contains("event-2"));
        assert_eq!(index.events.len(), 2, "both setup packets are legitimate events");
        let representative = &index.events[1];
        assert_eq!(representative.event_id, "event-2");
        assert!(representative.timestamp.is_empty());
        assert!(representative.raw_payload_reference.is_empty());
        assert!(representative
            .information_elements
            .as_array()
            .unwrap()
            .iter()
            .all(|value| value["name"] != "large-render-only-payload"));
        for name in ["enb_ue_s1ap_id", "mme_ue_s1ap_id", "erab_teid", "bearer_f_teid"] {
            assert!(representative.first_identifier(name).is_some(), "{name} compacted away");
        }
    }

    #[test]
    fn publication_key_ignores_transaction_ids_but_representative_keeps_them() {
        use std::io::Write;

        let path = std::env::temp_dir().join(format!(
            "oiran-publication-key-{}-{}.jsonl",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let mut writer = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
        for (packet, sequence, pdr) in [(1, "100", "1"), (2, "101", "2")] {
            let record = serde_json::json!({
                "event_id": format!("event-{packet}"),
                "capture_id": "cap",
                "capture_point_id": "N4",
                "timestamp": {"seconds":1,"nanoseconds":packet,"raw_ticks":packet,"display":"1Z"},
                "interface": "N4",
                "protocol": "PFCP",
                "message_name": "SessionModificationRequest",
                "source_endpoint": {"address":"a","network_function":"SMF"},
                "destination_endpoint": {"address":"b","network_function":"UPF"},
                "direction": "CORE_TO_CORE",
                "session_identifiers": [
                    {"name":"seid","value":"42","pseudonymized":false},
                    {"name":"teid","value":"0x01020304","pseudonymized":false},
                    {"name":"pfcp_sequence","value":sequence,"pseudonymized":false},
                    {"name":"pdr_id","value":pdr,"pseudonymized":false}
                ],
                "information_elements": [
                    {"name":"Create PDR","value":format!("pdr_id={pdr},far_id={pdr},teid=0x01020304,ipv4=10.0.0.2")}
                ],
                "decoding_status": "DECODED",
                "decoder_name": "test",
                "decoder_version": "1",
                "raw_payload_reference": "sha256:test",
                "packet_references": [{"source_file":"x","packet_number":packet,"byte_offset":0,"interface_id":0,"captured_length":1,"original_length":1}],
                "errors": []
            });
            writeln!(writer, "{record}").unwrap();
        }
        writer.flush().unwrap();

        let mut progress = Vec::new();
        let index = load_path_streaming_representatives_with_progress(&path, |read, retained| {
            progress.push((read, retained));
        })
        .unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(index.source_event_count, 2);
        assert_eq!(index.events.len(), 1, "transaction ids must not defeat compaction");
        assert_eq!(progress.last(), Some(&(2, 1)));
        let representative = &index.events[0];
        assert!(representative.first_identifier("pfcp_sequence").is_some());
        assert!(representative.first_identifier("pdr_id").is_some());
    }

    /// Gate mémoire 2.11.12. Exécution volontairement explicite :
    /// `cargo test -p session-engine --release publication_scale_1_5m -- --ignored --nocapture`
    ///
    /// Le profil reproduit le facteur aggravant de production : gros IE de
    /// rendu, 1,5 M observations, séquence/identifiant de règle variant à
    /// chaque message, mais seulement 4 096 états de session/tunnel durables.
    #[test]
    #[ignore = "scale gate: writes about 3.9 GB and parses 1.5 M events"]
    fn publication_scale_1_5m_stays_below_two_gib() {
        use std::io::Write;

        const EVENT_COUNT: usize = 1_500_000;
        const STATE_COUNT: usize = 4_096;
        const TWO_GIB_KB: u64 = 2 * 1024 * 1024;
        let path = std::env::temp_dir().join(format!(
            "oiran-publication-scale-{}-{}.jsonl",
            std::process::id(),
            std::thread::current().name().unwrap_or("scale")
        ));
        let mut writer = std::io::BufWriter::with_capacity(
            1024 * 1024,
            std::fs::File::create(&path).unwrap(),
        );
        let render_payload = "x".repeat(1_500);
        for packet in 0..EVENT_COUNT {
            let state = packet % STATE_COUNT;
            let record = serde_json::json!({
                "event_id": format!("synthetic-{packet:08x}"),
                "capture_id": "synthetic-production-profile",
                "capture_point_id": "N4",
                "timestamp": {"seconds":1,"nanoseconds":packet % 1_000_000_000,"raw_ticks":packet,"display":"synthetic"},
                "interface": "N4",
                "protocol": "PFCP",
                "message_name": "SessionModificationRequest",
                "source_endpoint": {"address":"10.0.0.1","network_function":"SMF"},
                "destination_endpoint": {"address":"10.0.0.2","network_function":"UPF"},
                "direction": "CORE_TO_CORE",
                "session_identifiers": [
                    {"name":"seid","value":format!("{state}"),"pseudonymized":false},
                    {"name":"teid","value":format!("0x{state:08x}"),"pseudonymized":false},
                    {"name":"pfcp_sequence","value":format!("{packet}"),"pseudonymized":false},
                    {"name":"pdr_id","value":format!("{packet}"),"pseudonymized":false}
                ],
                "information_elements": [
                    {"name":"F-TEID","value":format!("teid=0x{state:08x},ipv4=10.0.0.2")},
                    {"name":"render_payload","value":render_payload}
                ],
                "decoding_status": "DECODED",
                "decoder_name": "synthetic",
                "decoder_version": "1",
                "raw_payload_reference": "sha256:synthetic",
                "packet_references": [{"source_file":"synthetic","packet_number":packet,"byte_offset":0,"interface_id":0,"captured_length":1,"original_length":1}],
                "errors": []
            });
            writeln!(writer, "{record}").unwrap();
        }
        writer.flush().unwrap();
        drop(writer);
        let input_bytes = std::fs::metadata(&path).unwrap().len();

        let index = load_path_streaming_representatives_with_progress(&path, |read, retained| {
            if read % 100_000 == 0 {
                eprintln!(
                    "PUBLICATION_SCALE_PROGRESS scanned_events={read} retained_events={retained}"
                );
            }
        })
        .unwrap();
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let vmhwm_kb = status
            .lines()
            .find_map(|line| line.strip_prefix("VmHWM:"))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap();
        std::fs::remove_file(&path).unwrap();

        eprintln!(
            "PUBLICATION_SCALE_RESULT source_events={} representatives={} input_bytes={} vmhwm_kb={vmhwm_kb}",
            index.source_event_count,
            index.events.len(),
            input_bytes,
        );
        assert_eq!(index.source_event_count, EVENT_COUNT);
        assert_eq!(index.events.len(), STATE_COUNT);
        assert!(
            vmhwm_kb < TWO_GIB_KB,
            "VmHWM {vmhwm_kb} KiB must remain below 2 GiB"
        );
    }

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

    /// 2.9.9 (#9 comment 6725858177) — `attach_sbi_to_sessions`
    /// rattache un SBI à sa PDU session par clé exacte. ANR2 a
    /// publié sur le run `5g-session-5e3fc8ce83936ea0` :
    ///   * NGAP `PDUSessionResourceSetupRequest` : PDU 1,
    ///     `subscriber_pseudonym=psn-aaa…` (ex. valeur ANR2 pour
    ///     N2), tunnel UL `0xd4a6` / `10.77.22.13`.
    ///   * NGAP `PDUSessionResourceSetupResponse` : PDU 1.
    ///   * SBI `CreateSMContext` : PDU 1,
    ///     `subscriber_pseudonym` SBI body — doit MATCHER le N2
    ///     via `(pseudo, pdu_session_id)`.
    ///   * SBI `N1N2MessageTransfer` : PDU 1 + tunnel `0xd4a6` /
    ///     `10.77.22.13` — doit MATCHER par TEID/IP même si le
    ///     `subscriber_pseudonym` SBI diffère (cas réel ANR2).
    ///
    /// Négatif : SBI avec TEID ≠ `0xd4a7` + pseudo différent → non
    /// rattaché, reste dans `unmatched`.
    /// 2.9.15 (#9 comment 6728928219) — ANR2 a prouvé que
    /// `attach_sbi_to_sessions` 2.9.9 ne rattachait toujours pas
    /// le SBI à la session sur le run réel
    /// `tpl-small-traffic-276467540950` /
    /// `5g-session-5f3245de7580dee3`. La clé est présente et
    /// identique dans les trois événements (TEID 0x25fb, IP
    /// 10.77.22.13), mais le N2 publie son tuple sous
    /// `item_0_tunnel_ip_ul` + `item_0_gtp_teid_ul` (préfixe +
    /// suffixe directionnel) et non pas comme `tunnel_endpoint_ip`
    /// plat. La lecture pré-2.9.15 ne trouvait rien côté session
    /// → `tunnel_idx` vide → SBI jamais rattaché.
    ///
    /// 2.9.15 : `attach_sbi_to_sessions` scanne désormais TOUS
    /// les identifiers N2/NAS pour les paires
    /// `*tunnel_(endpoint_ip|ip_ul|ip_dl|ip)` ↔ `*gtp_teid(_ul|_dl)?`
    /// avec le MÊME préfixe. Les shapes `item_0_…` produites par
    /// l'ANR2 déclenchent désormais l'indexation.
    #[test]
    fn sbi_attach_matches_item_0_directional_tunnel_names_anr2_6728928219() {
        // N2 PDUSessionResourceSetupRequest avec les noms
        // RÉELS publiés par ANR2 sur le run du 2026-11-08 :
        //   item_0_tunnel_ip_ul = 10.77.22.13
        //   item_0_gtp_teid_ul  = 0x25fb
        let n2 = event(
            "evt-1e27eff0f6589f86",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            &[
                ("ran_ue_ngap_id", "4"),
                ("amf_ue_ngap_id", "73"),
                ("pdu_session_id", "1"),
                ("item_0_tunnel_ip_ul", "10.77.22.13"),
                ("item_0_gtp_teid_ul", "0x25fb"),
            ],
            1,
        );
        let n2_resp = event(
            "evt-n2-resp",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            &[
                ("ran_ue_ngap_id", "4"),
                ("amf_ue_ngap_id", "73"),
                ("pdu_session_id", "1"),
            ],
            2,
        );
        // SBI N1N2MessageTransfer publie le tuple sous les noms
        // PLATS `tunnel_endpoint_ip` / `gtp_teid`.
        let sbi = event(
            "evt-45eedbe889db2938",
            "SBI-HTTP2",
            "N1N2MessageTransfer",
            &[
                ("pdu_session_id", "1"),
                ("tunnel_endpoint_ip", "10.77.22.13"),
                ("gtp_teid", "0x25fb"),
            ],
            3,
        );
        let events = vec![n2, n2_resp, sbi];
        let discovery = discover_sessions(&mut events.clone());
        assert_eq!(discovery.pdu_sessions.len(), 1);
        let session = &discovery.pdu_sessions[0];
        assert!(
            session.event_ids.iter().any(|id| id == "evt-45eedbe889db2938"),
            "SBI evt-45eedbe889db2938 doit être rattaché par (item_0_tunnel_ip_ul, item_0_gtp_teid_ul) normalisés ; event_ids={:?}",
            session.event_ids
        );
        assert!(
            session.interfaces.iter().any(|i| i == "SBI-HTTP2"),
            "SBI-HTTP2 doit apparaître dans session.interfaces"
        );
    }

    /// 2.9.17 (#9 comment 6738246907) — Rejoue le run réel
    /// `5g-session-936f7625b33cbfd1`. ANR2 a prouvé que 2.9.16
    /// laissait toujours SBI OUVERT parce que
    /// `decoder-ngap:834-847` n'ajoute dans `session_identifiers`
    /// que les bare keys (`tunnel_ip_ul`, `gtp_teid_ul`), pas les
    /// préfixées `item_0_tunnel_ip_ul` qu'il produit dans la chaîne
    /// composite d'une IE (ex. « UL NG-U UP TNL Information »).
    ///
    /// 2.9.17 étend `attach_sbi_to_sessions` pour parser aussi les
    /// IE composites. Le test insère les event_id réels d'ANR2 et
    /// place le tuple TEID/IP dans un IE value, PAS dans
    /// session_identifiers — la forme exacte produite par
    /// `decoder-ngap::append_sureq_item_summary`.
    #[test]
    fn sbi_attach_reads_tunnel_from_information_elements_anr2_6738246907_2_9_17() {
        // Helper inline : construit un event avec IE composite.
        fn event_with_ie_value(
            id: &str,
            protocol: &str,
            name: &str,
            ids: &[(&str, &str)],
            ie_value: &str,
            packet: u64,
        ) -> EventRecord {
            let mut e = event(id, protocol, name, ids, packet);
            e.information_elements = serde_json::json!([
                {
                    "id": 74,
                    "name": "UL NG-U UP TNL Information",
                    "value": ie_value,
                    "length": ie_value.len() as u64,
                }
            ]);
            e
        }

        // N2 PDUSessionResourceSetupRequest : session_identifiers
        // ne porte QUE pdu_session_id (bare) ; le tuple TEID/IP
        // est dans la chaîne value d'une IE sous forme
        // `item_0_tunnel_ip_ul=…,item_0_gtp_teid_ul=…`.
        let n2_req = event_with_ie_value(
            "evt-n2-936f7625",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            &[
                ("ran_ue_ngap_id", "4"),
                ("amf_ue_ngap_id", "73"),
                ("pdu_session_id", "1"),
            ],
            "item_0_pdu_session_id=1,item_0_sst=1,item_0_tunnel_ip_ul=10.77.22.13,item_0_gtp_teid_ul=0x9ab3,item_0_pdu_session_type=IPv4",
            1,
        );
        let n2_resp = event(
            "evt-n2-resp-936f7625",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            &[
                ("ran_ue_ngap_id", "4"),
                ("amf_ue_ngap_id", "73"),
                ("pdu_session_id", "1"),
            ],
            2,
        );
        // SBI N1N2MessageTransfer : tuple plat dans
        // session_identifiers (décodeur SBI 2.9.9+ fait les deux).
        let sbi = event(
            "evt-sbi-936f7625",
            "SBI-HTTP2",
            "N1N2MessageTransfer",
            &[
                ("pdu_session_id", "1"),
                ("tunnel_endpoint_ip", "10.77.22.13"),
                ("gtp_teid", "0x9ab3"),
            ],
            3,
        );
        let events = vec![n2_req, n2_resp, sbi];
        let discovery = discover_sessions(&mut events.clone());
        assert_eq!(discovery.pdu_sessions.len(), 1, "une PDU session");
        let session = &discovery.pdu_sessions[0];
        assert!(
            session.event_ids.iter().any(|id| id == "evt-sbi-936f7625"),
            "SBI doit être rattaché via le tuple extrait de l'IE composite ; event_ids={:?}",
            session.event_ids
        );
        assert!(
            session.interfaces.iter().any(|i| i == "SBI-HTTP2"),
            "interfaces doit inclure SBI-HTTP2"
        );
    }

    #[test]
    fn sbi_attach_rules_match_anr2_production_shapes_2_9_9() {
        let shared_pseudo = "psn-fakeanr2n2sbi0000000000000000";
        let n2_request = event(
            "evt-n2-req",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            &[
                ("ran_ue_ngap_id", "4"),
                ("amf_ue_ngap_id", "73"),
                ("pdu_session_id", "1"),
                ("subscriber_pseudonym", shared_pseudo),
                ("tunnel_endpoint_ip", "10.77.22.13"),
                ("gtp_teid", "0xd4a6"),
            ],
            1,
        );
        let n2_response = event(
            "evt-n2-resp",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            &[
                ("ran_ue_ngap_id", "4"),
                ("amf_ue_ngap_id", "73"),
                ("pdu_session_id", "1"),
            ],
            2,
        );
        let sbi_create = event(
            "evt-sbi-create",
            "SBI-HTTP2",
            "CreateSMContext",
            &[
                ("pdu_session_id", "1"),
                ("subscriber_pseudonym", shared_pseudo),
            ],
            3,
        );
        // ANR2 réel : URI SBI porte un pseudo DIFFÉRENT du pseudo
        // body (dérivation sur IE différentes), mais le tuple
        // (IP, TEID) extrait du `n2SmInfo` est le même que N2.
        let sbi_n1n2 = event(
            "evt-sbi-n1n2",
            "SBI-HTTP2",
            "N1N2MessageTransfer",
            &[
                ("pdu_session_id", "1"),
                ("subscriber_pseudonym", "psn-sbi-uri-divergent-dddddddddddd"),
                ("tunnel_endpoint_ip", "10.77.22.13"),
                // 2.9.9 : forme non-paddée. La normalisation
                // partagée l'égalise avec le N4 0x0000d4a6.
                ("gtp_teid", "0xd4a6"),
            ],
            4,
        );
        // Négatif : TEID différent + pseudo différent → non rattaché.
        let sbi_outsider = event(
            "evt-sbi-outsider",
            "SBI-HTTP2",
            "CreateSMContext",
            &[
                ("pdu_session_id", "1"),
                ("subscriber_pseudonym", "psn-another-subscriber-00000000"),
                ("tunnel_endpoint_ip", "10.77.22.13"),
                ("gtp_teid", "0xd4a7"),
            ],
            5,
        );

        let events = vec![n2_request, n2_response, sbi_create, sbi_n1n2, sbi_outsider];
        let discovery = discover_sessions(&mut events.clone());
        assert_eq!(discovery.pdu_sessions.len(), 1, "une seule PDU session");
        let session = &discovery.pdu_sessions[0];
        assert_eq!(session.pdu_session_id, "1");
        // Les deux SBI valides sont rattachés via respectivement
        // (pseudo, pduSessionId) et (TEID, IP).
        assert!(
            session.event_ids.iter().any(|id| id == "evt-sbi-create"),
            "SBI CreateSMContext doit être rattaché par (pseudo, pduSessionId)"
        );
        assert!(
            session.event_ids.iter().any(|id| id == "evt-sbi-n1n2"),
            "SBI N1N2MessageTransfer doit être rattaché par (TEID, IP)"
        );
        // Le SBI avec TEID ≠ et pseudo différent reste non rattaché.
        assert!(
            !session.event_ids.iter().any(|id| id == "evt-sbi-outsider"),
            "SBI avec TEID ≠ et pseudo différent ne doit PAS être rattaché"
        );
        assert!(
            discovery.unmatched_event_ids.contains(&"evt-sbi-outsider".to_string())
                || discovery.background_event_ids.contains(&"evt-sbi-outsider".to_string()),
            "SBI outsider doit tomber en unmatched/background"
        );
        // Prouve la règle : aucun critère temporel. Le SBI
        // outsider a le TS le plus élevé, pourtant il n'est PAS
        // rattaché — l'attache n'est jamais faite par ts.
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

    /// 2.15.0 (ANR1 #10 6883006379) — test de régression fidèle
    /// aux payloads ANR1 sur la session `5g-session-c330d205adafa233` :
    /// le shard JSONL contient la `PFCP Session Establishment
    /// Request` (type 50, `pfcp_sequence=2209`) mais la découverte
    /// 5G de session n'a pas inclus son `event_id` dans la
    /// sélection initiale (seuls la Response et la Modification y
    /// étaient). `expand_pfcp_session_members` doit re-rattacher
    /// la Request par match `pfcp_sequence`, puis `reconstruct`
    /// doit la classifier `Association::Session`.
    #[test]
    fn expand_pfcp_session_members_pulls_request_absent_from_initial_selection() {
        // IDs et pfcp_sequence (2209/2210) repris tels quels du
        // commentaire #10 6883006379.
        let request = event(
            "evt-349c72dc0f5510c3",
            "PFCP",
            "PFCP Session Establishment Request",
            &[("pfcp_sequence", "2209")],
            1,
        );
        let response = event(
            "evt-104645ebe2174b02",
            "PFCP",
            "PFCP Session Establishment Response",
            &[("pfcp_sequence", "2209"), ("f_seid", "0x314")],
            2,
        );
        let modif = event(
            "evt-aa1b0ac453b62fd9",
            "PFCP",
            "PFCP Session Modification Request",
            &[("pfcp_sequence", "2210"), ("f_seid", "0x314")],
            3,
        );
        let events = vec![request, response, modif];
        // Sélection initiale : seuls Response et Modification
        // (comme observé en prod, la Request manque).
        let selection: BTreeSet<String> = [
            "evt-104645ebe2174b02".to_string(),
            "evt-aa1b0ac453b62fd9".to_string(),
        ]
        .into_iter()
        .collect();
        let expanded = expand_pfcp_session_members(&events, &selection);
        assert!(
            expanded.contains("evt-349c72dc0f5510c3"),
            "the PFCP Session Establishment Request must be re-included \
             via pfcp_sequence=2209 match, got {expanded:?}"
        );
        assert_eq!(expanded.len(), 3, "selection must contain 3 events");

        // Après expand, reconstruct doit classifier les 3 PFCP
        // events comme Association::Session.
        let selected = events
            .iter()
            .filter(|event| expanded.contains(&event.event_id))
            .cloned()
            .collect::<Vec<_>>();
        let r = reconstruct(selected, Default::default());
        assert_eq!(r.events.len(), 3, "all 3 events must enter reconstruct");
        for event in &r.events {
            assert_eq!(
                r.association.get(&event.event_id),
                Some(&Association::Session),
                "PFCP event {} must be Association::Session",
                event.event_id
            );
        }
    }

    /// 2.15.0 — garde : si la sélection initiale ne contient aucun
    /// event PFCP, l'expansion est un no-op. On ne tire pas des
    /// events PFCP non liés dans la session.
    #[test]
    fn expand_pfcp_session_members_is_noop_without_pfcp_seed() {
        let ngap = event(
            "ngap-01",
            "NGAP",
            "InitialUEMessage",
            &[("ran_ue_ngap_id", "1")],
            1,
        );
        let pfcp = event(
            "pfcp-99",
            "PFCP",
            "PFCP Session Establishment Request",
            &[("pfcp_sequence", "999")],
            2,
        );
        let events = vec![ngap, pfcp];
        let selection: BTreeSet<String> = ["ngap-01".to_string()].into_iter().collect();
        let expanded = expand_pfcp_session_members(&events, &selection);
        assert_eq!(expanded.len(), 1, "no PFCP seed → no PFCP sibling pulled in");
        assert!(expanded.contains("ngap-01"));
        assert!(!expanded.contains("pfcp-99"));
    }

    /// 2.15.0 — garde : un `f_seid` nul (`0x0000000000000000`) ne
    /// doit jamais faire match (plusieurs sessions partagent le
    /// placeholder nul à la création).
    #[test]
    fn expand_pfcp_session_members_ignores_null_seid() {
        let seed = event(
            "pfcp-seed",
            "PFCP",
            "PFCP Session Establishment Response",
            &[("f_seid", "0x0000000000000000"), ("pfcp_sequence", "1")],
            1,
        );
        let other = event(
            "pfcp-other",
            "PFCP",
            "PFCP Session Establishment Request",
            &[("f_seid", "0x0000000000000000"), ("pfcp_sequence", "2")],
            2,
        );
        let events = vec![seed, other];
        let selection: BTreeSet<String> = ["pfcp-seed".to_string()].into_iter().collect();
        let expanded = expand_pfcp_session_members(&events, &selection);
        assert!(!expanded.contains("pfcp-other"), "null f_seid must not create a match");
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
        // 2.7.18: dataset regenerated with oiran-decode 0.6.0 (24 N2 +
        // 30 N4 + 10 N3 = 64 events; the 2.7.15-and-earlier decoder emitted
        // only 14 N2 events for the same pcapng, so the shipped
        // oiran_events.jsonl was 54 lines). pcapng captures are unchanged.
        assert_eq!(result.event_accounting["source_events"], 64);
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
            &[
                ("enb_ue_s1ap_id", "41"),
                ("mme_ue_s1ap_id", "7"),
                ("erab_teid", "0x01020304"),
            ],
            1,
        );
        s1ap.interface = "S1-MME".into();
        let mut nas = event(
            "nas",
            "NAS-EPS-MM",
            "Attach Complete",
            &[
                ("enb_ue_s1ap_id", "41"),
                ("mme_ue_s1ap_id", "7"),
                ("subscriber_pseudonym", "subscriber-opaque-a"),
            ],
            2,
        );
        nas.interface = "S1-MME".into();
        let mut s11 = event(
            "s11",
            "GTPv2-C",
            "CreateSessionResponse",
            &[
                ("subscriber_pseudonym", "subscriber-opaque-a"),
                ("bearer_ebi", "5"),
                ("bearer_f_teid", "0x01020304"),
            ],
            3,
        );
        s11.interface = "S11".into();
        s11.capture_id = "capture-s11".into();
        let mut uplink = event("s1u-ul", "GTP-U", "G-PDU", &[("teid", "0x01020304")], 4);
        uplink.interface = "S1-U".into();
        uplink.capture_id = "capture-s1u".into();
        uplink.direction = "UPLINK".into();
        uplink.packet_references[0].captured_length = 128;
        let mut downlink = uplink.clone();
        downlink.event_id = "s1u-dl".into();
        downlink.direction = "DOWNLINK".into();
        downlink.timestamp_ns = uplink.timestamp_ns + 1;
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
        assert_eq!(session.start_timestamp_ns, 1_000_000_001);
        assert_eq!(session.end_timestamp_ns, 1_000_000_005);
        assert_eq!(session.duration_ns, 4);
    }

    #[test]
    fn s1_s11_s1u_correlate_by_teid_without_any_subscriber_identifier() {
        // 2.7.6: imports can run with no IMSI anywhere in the trace (the
        // decoders may legitimately see sessions that never carried an
        // identity IE). The LTE session discovery must still stitch the
        // planes using the structural keys: MME/eNB-UE-S1AP-ID on S1-MME,
        // the F-TEID on S11, and the matching TEID on S1-U. No
        // `subscriber_pseudonym`, `imsi_pseudonym`, `msisdn_pseudonym` or
        // `mei_pseudonym` is present on ANY event.
        let mut s1ap = event(
            "s1ap",
            "S1AP",
            "InitialContextSetupResponse",
            &[
                ("enb_ue_s1ap_id", "41"),
                ("mme_ue_s1ap_id", "7"),
                ("erab_teid", "0x01020304"),
            ],
            1,
        );
        s1ap.interface = "S1-MME".into();
        let mut s11 = event(
            "s11",
            "GTPv2-C",
            "CreateSessionResponse",
            &[("bearer_ebi", "5"), ("bearer_f_teid", "0x01020304")],
            2,
        );
        s11.interface = "S11".into();
        s11.capture_id = "capture-s11".into();
        let mut uplink = event("s1u-ul", "GTP-U", "G-PDU", &[("teid", "0x01020304")], 3);
        uplink.interface = "S1-U".into();
        uplink.capture_id = "capture-s1u".into();
        uplink.direction = "UPLINK".into();
        uplink.packet_references[0].captured_length = 128;
        let mut downlink = uplink.clone();
        downlink.event_id = "s1u-dl".into();
        downlink.direction = "DOWNLINK".into();
        downlink.timestamp_ns = uplink.timestamp_ns + 1;
        downlink.packet_references[0].packet_number = 4;
        downlink.packet_references[0].captured_length = 256;

        // Precondition: no event carries any subscriber-identity label.
        let all_events = [&s1ap, &s11, &uplink, &downlink];
        for e in &all_events {
            for (name, _) in &e.identifiers {
                assert!(
                    ![
                        "subscriber_pseudonym",
                        "imsi_pseudonym",
                        "msisdn_pseudonym",
                        "mei_pseudonym",
                        "ue_identity_pseudonym",
                        "supi",
                        "imsi",
                        "msisdn",
                        "pei",
                    ]
                    .contains(&name.as_str()),
                    "test precondition broken: subscriber identifier {name} leaked into fixture"
                );
            }
        }

        let sessions = discover_lte_sessions(&[s1ap, s11, uplink, downlink]);
        assert_eq!(sessions.len(), 1);
        let session = &sessions[0];
        assert_eq!(session.technology, "LTE");
        // The S1-MME context carried neither NAS pseudonym nor subscriber id,
        // so the session falls back to a stable synthetic UE identifier
        // derived from (capture_id, enb_ue_s1ap_id, mme_ue_s1ap_id).
        assert!(
            session.ue_pseudonym.starts_with("LTE-UE-"),
            "expected stable LTE-UE identifier, got {}",
            session.ue_pseudonym
        );
        // The three planes must all be tied to the single session.
        assert_eq!(session.state, "ACTIVE_WITH_USER_PLANE");
        assert_eq!(session.eps_bearer_ids, vec!["5"]);
        assert_eq!(session.s11_f_teids, vec!["0x01020304"]);
        assert_eq!(session.tunnels.len(), 1);
        assert_eq!(session.tunnels[0].teid, "0x01020304");
        assert_eq!(session.tunnels[0].uplink_packets, 1);
        assert_eq!(session.tunnels[0].downlink_packets, 1);
        assert_eq!(session.tunnels[0].bytes, 384);
    }

    #[test]
    fn partitions_two_lte_ues_by_explicit_context_pseudonym_and_teid() {
        let mut events = Vec::new();
        for (ordinal, pseudonym, enb, mme, teid) in [
            (1u64, "subscriber-opaque-a", "41", "7", "0x01020304"),
            (2u64, "subscriber-opaque-b", "42", "8", "0x05060708"),
        ] {
            let mut s1ap = event(
                &format!("s1ap-{ordinal}"),
                "S1AP",
                "InitialContextSetupResponse",
                &[
                    ("enb_ue_s1ap_id", enb),
                    ("mme_ue_s1ap_id", mme),
                    ("erab_teid", teid),
                ],
                ordinal * 10,
            );
            s1ap.interface = "S1-MME".into();
            let mut nas = event(
                &format!("nas-{ordinal}"),
                "NAS-EPS-MM",
                "Attach Complete",
                &[
                    ("enb_ue_s1ap_id", enb),
                    ("mme_ue_s1ap_id", mme),
                    ("imsi_pseudonym", pseudonym),
                ],
                ordinal * 10 + 1,
            );
            nas.interface = "S1-MME".into();
            let mut s11 = event(
                &format!("s11-{ordinal}"),
                "GTPv2-C",
                "CreateSessionResponse",
                &[
                    ("imsi_pseudonym", pseudonym),
                    ("bearer_ebi", "5"),
                    ("bearer_f_teid", teid),
                ],
                ordinal * 10 + 2,
            );
            s11.interface = "S11".into();
            s11.capture_id = format!("capture-s11-{ordinal}");
            let mut s1u = event(
                &format!("s1u-{ordinal}"),
                "GTP-U",
                "G-PDU",
                &[("teid", teid)],
                ordinal * 10 + 3,
            );
            s1u.interface = "S1-U".into();
            s1u.capture_id = format!("capture-s1u-{ordinal}");
            s1u.direction = if ordinal == 1 { "UPLINK" } else { "DOWNLINK" }.into();
            events.extend([s1ap, nas, s11, s1u]);
        }
        let sessions = discover_lte_sessions(&events);
        assert_eq!(sessions.len(), 2);
        assert_eq!(
            sessions
                .iter()
                .map(|session| session.ue_pseudonym.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["subscriber-opaque-a", "subscriber-opaque-b"])
        );
        assert!(sessions.iter().all(|session| session.tunnels.len() == 1));
        assert!(sessions.iter().all(|session| session.event_ids.len() == 4));
        assert_ne!(sessions[0].tunnels[0].teid, sessions[1].tunnels[0].teid);
        let manifest: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/lte-offline-certification-synthetic-manifest.json"
        ))
        .unwrap();
        let expected = &manifest["expected"];
        assert_eq!(
            sessions.len() as u64,
            expected["ue_sessions"].as_u64().unwrap()
        );
        assert_eq!(
            sessions
                .iter()
                .map(|session| session.eps_bearer_ids.len())
                .sum::<usize>() as u64,
            expected["eps_bearers"].as_u64().unwrap()
        );
        assert_eq!(
            sessions
                .iter()
                .map(|session| session.tunnels.len())
                .sum::<usize>() as u64,
            expected["distinct_s1u_teids"].as_u64().unwrap()
        );
        assert_eq!(
            sessions
                .iter()
                .flat_map(|session| &session.tunnels)
                .map(|tunnel| tunnel.uplink_packets)
                .sum::<usize>() as u64,
            expected["uplink_packets"].as_u64().unwrap()
        );
        assert_eq!(
            sessions
                .iter()
                .flat_map(|session| &session.tunnels)
                .map(|tunnel| tunnel.downlink_packets)
                .sum::<usize>() as u64,
            expected["downlink_packets"].as_u64().unwrap()
        );
    }

    #[test]
    fn reused_teid_across_two_contexts_keeps_user_plane_unmatched() {
        let mut events = Vec::new();
        for (ordinal, pseudonym, enb, mme) in [
            (1u64, "subscriber-opaque-a", "41", "7"),
            (2u64, "subscriber-opaque-b", "42", "8"),
        ] {
            let mut radio = event(
                &format!("radio-{ordinal}"),
                "S1AP",
                "InitialContextSetupResponse",
                &[
                    ("enb_ue_s1ap_id", enb),
                    ("mme_ue_s1ap_id", mme),
                    ("imsi_pseudonym", pseudonym),
                    ("erab_teid", "0x101"),
                ],
                ordinal * 10,
            );
            radio.interface = "S1-MME".into();
            radio.capture_id = format!("capture-s1-{ordinal}");
            let mut control = event(
                &format!("control-{ordinal}"),
                "GTPv2-C",
                "CreateSessionResponse",
                &[("imsi_pseudonym", pseudonym), ("bearer_f_teid", "0x101")],
                ordinal * 10 + 1,
            );
            control.interface = "S11".into();
            control.capture_id = format!("capture-s11-{ordinal}");
            events.extend([control, radio]);
        }
        let mut user = event("user", "GTP-U", "G-PDU", &[("teid", "0x101")], 15);
        user.interface = "S1-U".into();
        user.capture_id = "capture-s1u".into();
        events.insert(0, user);

        let sessions = discover_lte_sessions(&events);
        assert_eq!(sessions.len(), 2);
        assert!(sessions.iter().all(|session| session.tunnels.is_empty()));
        assert!(sessions
            .iter()
            .all(|session| !session.event_ids.iter().any(|id| id == "user")));
    }

    #[test]
    fn partial_and_out_of_order_cross_plane_events_are_deterministic() {
        let mut radio = event(
            "radio",
            "S1AP",
            "InitialContextSetupResponse",
            &[
                ("enb_ue_s1ap_id", "41"),
                ("mme_ue_s1ap_id", "7"),
                ("imsi_pseudonym", "subscriber-opaque-a"),
                ("erab_teid", "0x101"),
            ],
            30,
        );
        radio.interface = "S1-MME".into();
        radio.capture_id = "capture-s1".into();
        let mut control = event(
            "control",
            "GTPv2-C",
            "CreateSessionResponse",
            &[
                ("imsi_pseudonym", "subscriber-opaque-a"),
                ("bearer_f_teid", "0x101"),
            ],
            20,
        );
        control.interface = "S11".into();
        control.capture_id = "capture-s11".into();
        let first = discover_lte_sessions(&[control.clone(), radio.clone()]);
        let second = discover_lte_sessions(&[radio, control]);
        assert_eq!(first, second);
        assert_eq!(first[0].state, "INCOMPLETE");
        assert_eq!(first[0].interfaces, vec!["S1-MME", "S11"]);
    }

    #[test]
    fn crossed_timestamps_across_captures_do_not_alter_sessions_or_attachments() {
        // 2.7.13 regression: the canonical processing order is
        // (capture_id, seq, event_id). Two separate captures whose
        // event timestamps interleave arbitrarily must produce the
        // same `discover_lte_sessions` result as the (capture_id, seq)
        // order. This proves no session-reconstruction decision
        // depends on `timestamp_ns`.
        fn session_shape(sessions: &[LteSession]) -> Vec<(String, String, Vec<String>, Vec<String>, usize, usize)> {
            sessions
                .iter()
                .map(|s| {
                    let mut teids = s
                        .tunnels
                        .iter()
                        .map(|t| t.teid.clone())
                        .collect::<Vec<_>>();
                    teids.sort();
                    (
                        s.technology.clone(),
                        s.state.clone(),
                        s.eps_bearer_ids.clone(),
                        teids,
                        s.tunnels.iter().map(|t| t.uplink_packets).sum::<usize>(),
                        s.tunnels.iter().map(|t| t.downlink_packets).sum::<usize>(),
                    )
                })
                .collect()
        }
        // S1-MME capture
        let mut s1ap = event(
            "s1ap-ics",
            "S1AP",
            "InitialContextSetupResponse",
            &[
                ("enb_ue_s1ap_id", "77"),
                ("mme_ue_s1ap_id", "11"),
                ("erab_teid", "0x00ab00cd"),
            ],
            1,
        );
        s1ap.interface = "S1-MME".into();
        s1ap.capture_id = "cap-s1mme".into();
        s1ap.timestamp_ns = 1_000_000_900; // intentionally late
        let mut nas = event(
            "nas-attach",
            "NAS-EPS-MM",
            "Attach Complete",
            &[
                ("subscriber_pseudonym", "subscriber-opaque-7"),
                ("enb_ue_s1ap_id", "77"),
                ("mme_ue_s1ap_id", "11"),
            ],
            2,
        );
        nas.interface = "S1-MME".into();
        nas.capture_id = "cap-s1mme".into();
        nas.timestamp_ns = 1_000_000_950;
        // S11 capture — ts BEFORE the S1AP event even though it is
        // logically a response to the latter.
        let mut s11 = event(
            "s11-create-rsp",
            "GTPv2-C",
            "CreateSessionResponse",
            &[
                ("subscriber_pseudonym", "subscriber-opaque-7"),
                ("bearer_ebi", "7"),
                ("bearer_f_teid", "0x00ab00cd"),
            ],
            1,
        );
        s11.interface = "S11".into();
        s11.capture_id = "cap-s11".into();
        s11.timestamp_ns = 500_000_100; // way before S1AP
        // S1-U capture — ts interleaved with S1-MME.
        let mut ul = event("s1u-ul", "GTP-U", "G-PDU", &[("teid", "0x00ab00cd")], 1);
        ul.interface = "S1-U".into();
        ul.capture_id = "cap-s1u".into();
        ul.timestamp_ns = 800_000_200;
        ul.direction = "UPLINK".into();
        ul.packet_references[0].captured_length = 128;
        let mut dl = ul.clone();
        dl.event_id = "s1u-dl".into();
        dl.timestamp_ns = 1_500_000_300; // after everything
        dl.direction = "DOWNLINK".into();
        dl.packet_references[0].packet_number = 2;
        dl.packet_references[0].captured_length = 256;

        // Canonical (capture_id, seq, event_id) order.
        let mut canonical = vec![s1ap.clone(), nas.clone(), s11.clone(), ul.clone(), dl.clone()];
        canonical.sort_by(|a, b| canonical_sort_key(a).cmp(&canonical_sort_key(b)));
        let sessions_canonical = discover_lte_sessions(&canonical);

        // Crossed-ts order (what a naive ts sort would have produced).
        let mut ts_sorted =
            vec![s1ap.clone(), nas.clone(), s11.clone(), ul.clone(), dl.clone()];
        ts_sorted.sort_by_key(|event| event.timestamp_ns);
        let sessions_ts = discover_lte_sessions(&ts_sorted);

        assert_eq!(session_shape(&sessions_canonical), session_shape(&sessions_ts));
        assert_eq!(sessions_canonical.len(), 1);
        assert_eq!(sessions_canonical[0].state, "ACTIVE_WITH_USER_PLANE");
        assert_eq!(sessions_canonical[0].eps_bearer_ids, vec!["7"]);
        assert_eq!(sessions_canonical[0].tunnels.len(), 1);
        assert_eq!(sessions_canonical[0].tunnels[0].teid, "0x00ab00cd");
    }

    #[test]
    fn anr3_attach_to_detach_flow_consolidates_into_a_single_session() {
        // 2.7.15: ANR3 field evidence (issue #10 comment 6636015016)
        // showed a single Attach→Detach exchange producing two sessions,
        // one of which was `RELEASED` with 22 events missing both
        // `InitialUEMessage` and the NAS `Attach Request` child. Root
        // cause (file:line): session-engine/src/lib.rs:313-319 inserted
        // `(capture_id, enb, None)` for the InitialUEMessage AND
        // `(capture_id, enb, Some(mme))` for the rest of the exchange,
        // producing two contexts for the same UE. 2.7.15 consolidates
        // contexts on the structural `(capture_id, enb_ue_s1ap_id)`
        // key.
        let capture = "cap-s1mme";
        let enb_id = "77";
        let mme_id = "11";
        let make = |suffix: &str, name: &str, seq: u64, ids: &[(&str, &str)]| {
            let mut e = event(suffix, "S1AP", name, ids, seq);
            e.interface = "S1-MME".into();
            e.capture_id = capture.into();
            e
        };
        // Seven S1AP envelopes: InitialUEMessage (enb only), then six
        // messages that all carry `mme_ue_s1ap_id`.
        let initial = make(
            "ue-init",
            "InitialUEMessage",
            1,
            &[("enb_ue_s1ap_id", enb_id)],
        );
        let auth = make(
            "dl-auth",
            "DownlinkNASTransport",
            2,
            &[("enb_ue_s1ap_id", enb_id), ("mme_ue_s1ap_id", mme_id)],
        );
        let smc = make(
            "dl-smc",
            "DownlinkNASTransport",
            3,
            &[("enb_ue_s1ap_id", enb_id), ("mme_ue_s1ap_id", mme_id)],
        );
        let ics_req = make(
            "ics-req",
            "InitialContextSetupRequest",
            4,
            &[
                ("enb_ue_s1ap_id", enb_id),
                ("mme_ue_s1ap_id", mme_id),
                ("erab_teid", "0x01020304"),
            ],
        );
        let ics_rsp = make(
            "ics-rsp",
            "InitialContextSetupResponse",
            5,
            &[
                ("enb_ue_s1ap_id", enb_id),
                ("mme_ue_s1ap_id", mme_id),
                ("erab_teid", "0x01020304"),
            ],
        );
        let detach = make(
            "detach",
            "DownlinkNASTransport",
            6,
            &[("enb_ue_s1ap_id", enb_id), ("mme_ue_s1ap_id", mme_id)],
        );
        let release = make(
            "release",
            "UEContextReleaseComplete",
            7,
            &[("enb_ue_s1ap_id", enb_id), ("mme_ue_s1ap_id", mme_id)],
        );
        // One NAS child inherits the InitialUEMessage identifiers (enb
        // only, no mme). Pre-2.7.15 this event fell into the
        // `(enb, None)` context only.
        let mut nas_attach = event(
            "nas-attach",
            "NAS-EPS-MM",
            "Attach Request",
            &[("enb_ue_s1ap_id", enb_id)],
            1,
        );
        nas_attach.interface = "S1-MME".into();
        nas_attach.capture_id = capture.into();
        nas_attach.parent_event_id = Some("ue-init".into());

        let mut s11 = event(
            "s11-create-rsp",
            "GTPv2-C",
            "CreateSessionResponse",
            &[("bearer_ebi", "5"), ("bearer_f_teid", "0x01020304")],
            1,
        );
        s11.interface = "S11".into();
        s11.capture_id = "cap-s11".into();

        let mut s1u = event("s1u-ul", "GTP-U", "G-PDU", &[("teid", "0x01020304")], 1);
        s1u.interface = "S1-U".into();
        s1u.capture_id = "cap-s1u".into();
        s1u.direction = "UPLINK".into();
        s1u.packet_references[0].captured_length = 128;

        let events = vec![
            initial, nas_attach, auth, smc, ics_req, ics_rsp, detach, release, s11, s1u,
        ];
        let sessions = discover_lte_sessions(&events);
        assert_eq!(
            sessions.len(),
            1,
            "a single Attach→Detach flow must produce ONE session (got {})",
            sessions.len()
        );
        let session = &sessions[0];
        assert_eq!(session.technology, "LTE");
        // The single consolidated session must include BOTH the
        // InitialUEMessage and its NAS Attach Request child, which were
        // dropped from the `(enb, Some(mme))` context before 2.7.15.
        assert!(session.event_ids.contains(&"ue-init".to_string()));
        assert!(session.event_ids.contains(&"nas-attach".to_string()));
        assert!(session.event_ids.contains(&"release".to_string()));
    }

    #[test]
    fn two_distinct_ues_each_get_their_own_session_after_consolidation() {
        // Mirror guard for 2.7.15: the consolidation must not merge
        // two UEs. Distinct `enb_ue_s1ap_id` values keep distinct
        // contexts even when their `mme_ue_s1ap_id` or TEID values
        // coincide.
        let capture = "cap-s1mme";
        let make = |suffix: &str, enb: &str, mme: &str, teid: &str, seq: u64, name: &str| {
            let mut e = event(
                suffix,
                "S1AP",
                name,
                &[
                    ("enb_ue_s1ap_id", enb),
                    ("mme_ue_s1ap_id", mme),
                    ("erab_teid", teid),
                ],
                seq,
            );
            e.interface = "S1-MME".into();
            e.capture_id = capture.into();
            e
        };
        let ue1_a = make("a1", "77", "11", "0x1111", 1, "InitialContextSetupResponse");
        let ue1_b = make("b1", "77", "11", "0x1111", 2, "UEContextReleaseComplete");
        let ue2_a = make("a2", "88", "22", "0x2222", 3, "InitialContextSetupResponse");
        let ue2_b = make("b2", "88", "22", "0x2222", 4, "UEContextReleaseComplete");
        let mut s11_1 = event(
            "s11-1",
            "GTPv2-C",
            "CreateSessionResponse",
            &[("bearer_ebi", "5"), ("bearer_f_teid", "0x1111")],
            1,
        );
        s11_1.interface = "S11".into();
        s11_1.capture_id = "cap-s11".into();
        let mut s11_2 = event(
            "s11-2",
            "GTPv2-C",
            "CreateSessionResponse",
            &[("bearer_ebi", "6"), ("bearer_f_teid", "0x2222")],
            2,
        );
        s11_2.interface = "S11".into();
        s11_2.capture_id = "cap-s11".into();
        let sessions = discover_lte_sessions(&[ue1_a, ue1_b, ue2_a, ue2_b, s11_1, s11_2]);
        assert_eq!(
            sessions.len(),
            2,
            "two distinct UEs must still yield two sessions after consolidation"
        );
        let teids: std::collections::BTreeSet<String> = sessions
            .iter()
            .flat_map(|s| s.s11_f_teids.iter().cloned())
            .collect();
        assert!(
            teids.contains("0x1111"),
            "session TEIDs should contain the UE1 bearer, got {teids:?}"
        );
        assert!(
            teids.contains("0x2222"),
            "session TEIDs should contain the UE2 bearer, got {teids:?}"
        );
    }

    /// 2.18.11 (ANR2 #10) — la PDU session ne porte pas le SUPI ; le
    /// pseudonyme abonné est sur le NAS Registration du MÊME UE
    /// context. Un SBI am-data (pseudonyme seul) doit s'y rattacher ;
    /// un SBI d'un autre abonné non.
    #[test]
    fn sbi_attaches_via_the_pseudonym_of_the_session_ue_context() {
        let registration = event(
            "evt-nas-reg",
            "NAS-5GMM",
            "Registration Request",
            &[("subscriber_pseudonym", "psn-ue201")],
            1,
        );
        let n2_setup = event(
            "evt-n2-pdu",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            &[("pdu_session_id", "1"), ("ran_ue_ngap_id", "5")],
            2,
        );
        let sbi_same = event(
            "evt-sbi-am-data",
            "SBI-HTTP2",
            "GET am-data",
            &[("subscriber_pseudonym", "psn-ue201")],
            3,
        );
        let sbi_other = event(
            "evt-sbi-other",
            "SBI-HTTP2",
            "GET am-data",
            &[("subscriber_pseudonym", "psn-ue05")],
            4,
        );
        let events = vec![registration, n2_setup, sbi_same, sbi_other];
        let mut pdu_sessions = vec![DiscoveredPduSession {
            session_id: "5g-session-ue201".into(),
            ue_context_id: "ue-ctx-201".into(),
            pdu_session_id: "1".into(),
            dnn: None,
            snssai: None,
            state: "ACTIVE".into(),
            establishment_timestamp_ns: 0,
            release_timestamp_ns: None,
            interfaces: vec!["N2".into()],
            correlation_status: "OPEN".into(),
            event_ids: vec!["evt-n2-pdu".into()],
            sbi_time_window_event_ids: Vec::new(),
        }];
        let mut event_context: BTreeMap<String, String> = BTreeMap::new();
        event_context.insert("evt-nas-reg".into(), "ue-ctx-201".into());
        event_context.insert("evt-n2-pdu".into(), "ue-ctx-201".into());
        attach_sbi_to_sessions(&events, &mut pdu_sessions, &mut event_context);
        let ids = &pdu_sessions[0].event_ids;
        assert!(ids.contains(&"evt-sbi-am-data".to_string()), "got {ids:?}");
        assert!(!ids.contains(&"evt-sbi-other".to_string()), "contamination : {ids:?}");
    }

    /// 2.17.1 (ANR1 #10 E2E-5G, fix a — SBI continuous perdu).
    /// Reproduit le cas `5g-session-99e8a9a6f5a0d5af` : une session
    /// 5G découverte uniquement depuis GTP-U N3 (sans N2 associé
    /// dans le callflow). Le SBI publie `(tunnel_endpoint_ip,
    /// gtp_teid)` qui MATCHE exactement les events N3 GTP-U, mais
    /// avant 2.17.1 `attach_sbi_to_sessions` n'indexait les tunnels
    /// qu'à partir des events N2 → tunnel_idx vide → SBI jamais
    /// rattaché → `/sessions/.../events?protocol=HTTP2` = 0.
    /// Le fix 2.17.1 indexe aussi les events N3 GTP-U (ils émettent
    /// `teid` + `tunnel_endpoint_ip` depuis decoder-gtpu, voir
    /// `decoder-gtpu/src/lib.rs:158-171`) sous l'alias `gtp_teid`
    /// attendu par les SBI.
    #[test]
    fn sbi_attach_rescues_orphan_session_via_n3_gtpu_tunnel_anr1_e2e_5g() {
        // Pas d'event N2 : la session « orpheline » est découverte
        // par l'autre voie (GTP-U N3 + UE context release). On
        // simule en construisant un `DiscoveredPduSession` à la
        // main ET en passant un event N3 GTP-U qui porte la clé.
        //
        // Les tests existants passent par `discover_sessions` pour
        // construire les PDU sessions. Ici on teste la sous-fn
        // `attach_sbi_to_sessions` directement pour prouver
        // l'indexation GTP-U.
        let mut n3 = event(
            "evt-n3-gtpu-ul",
            "GTP-U",
            "GTP-U",
            &[
                ("teid", "0x7a1c"),
                ("tunnel_endpoint_ip", "10.77.23.13"),
                ("tunnel_direction", "UPLINK"),
            ],
            1,
        );
        n3.interface = "N3".into();
        let sbi = event(
            "evt-sbi-orphan",
            "SBI-HTTP2",
            "N1N2MessageTransfer",
            &[
                ("pdu_session_id", "1"),
                ("tunnel_endpoint_ip", "10.77.23.13"),
                ("gtp_teid", "0x7a1c"),
            ],
            2,
        );
        let events = vec![n3.clone(), sbi.clone()];
        // Session orpheline : event_ids = [n3] (découverte GTP-U).
        let mut pdu_sessions = vec![DiscoveredPduSession {
            session_id: "5g-session-orphan".into(),
            ue_context_id: "ue-ctx-orphan".into(),
            pdu_session_id: "1".into(),
            dnn: None,
            snssai: None,
            state: "ACTIVE".into(),
            establishment_timestamp_ns: 0,
            release_timestamp_ns: None,
            interfaces: vec!["N3".into()],
            correlation_status: "OPEN".into(),
            event_ids: vec!["evt-n3-gtpu-ul".into()],
            sbi_time_window_event_ids: Vec::new(),
        }];
        let mut event_context: BTreeMap<String, String> = BTreeMap::new();
        event_context.insert("evt-n3-gtpu-ul".into(), "ue-ctx-orphan".into());

        attach_sbi_to_sessions(&events, &mut pdu_sessions, &mut event_context);

        assert_eq!(
            pdu_sessions[0].event_ids.len(),
            2,
            "SBI doit être rattaché à la session orpheline découverte via GTP-U ; got {:?}",
            pdu_sessions[0].event_ids
        );
        assert!(
            pdu_sessions[0].event_ids.contains(&"evt-sbi-orphan".into()),
            "event_ids doit contenir evt-sbi-orphan ; got {:?}",
            pdu_sessions[0].event_ids
        );
        assert!(
            pdu_sessions[0].interfaces.iter().any(|i| i == "SBI-HTTP2"),
            "SBI-HTTP2 doit apparaître dans session.interfaces ; got {:?}",
            pdu_sessions[0].interfaces
        );
        assert_eq!(
            event_context.get("evt-sbi-orphan").map(String::as_str),
            Some("ue-ctx-orphan"),
            "event_context doit cartographier le SBI à la session orpheline"
        );
    }

    /// 2.18.0 (ANR1 #10 E2E-5G — SBI identities) —
    /// `collect_sbi_identities_for_session` remonte les 3 kinds
    /// (`msisdn`, `imei`, `imeisv`) depuis les events SBI de la
    /// session, et laisse `None` quand aucun event SBI ne porte
    /// l'identifiant correspondant (invariant anti-hypothèse).
    /// Les events d'autres sessions (SUPI différent, donc pas dans
    /// `session.event_ids`) ne doivent JAMAIS fuiter leurs
    /// identités dans la summary de la session courante.
    #[test]
    fn collect_sbi_identities_for_session_reads_only_attached_events() {
        let sbi_full = event(
            "evt-sbi-a-sm-ctx",
            "SBI-HTTP2",
            "N1N2MessageTransfer",
            &[
                ("pdu_session_id", "1"),
                ("subscriber_pseudonym", "psn-supi-a"),
                ("msisdn_pseudonym", "hash-msisdn-a"),
                ("imei_pseudonym", "hash-imei-a"),
                ("sbi_service", "nsmf-pdusession"),
                ("sbi_operation", "CreateSMContext"),
            ],
            1,
        );
        // Un event SBI d'une AUTRE session (SUPI différent) — il
        // ne doit JAMAIS fuiter ses identités dans la summary de
        // la session A.
        let sbi_other = event(
            "evt-sbi-b-sm-ctx",
            "SBI-HTTP2",
            "CreateSMContext",
            &[
                ("pdu_session_id", "2"),
                ("subscriber_pseudonym", "psn-supi-b"),
                ("msisdn_pseudonym", "hash-msisdn-b"),
                ("imeisv_pseudonym", "hash-imeisv-b"),
            ],
            2,
        );
        let session = DiscoveredPduSession {
            session_id: "5g-session-a".into(),
            ue_context_id: "ue-ctx-a".into(),
            pdu_session_id: "1".into(),
            dnn: None,
            snssai: None,
            state: "ACTIVE".into(),
            establishment_timestamp_ns: 0,
            release_timestamp_ns: None,
            interfaces: vec!["SBI-HTTP2".into()],
            correlation_status: "OPEN".into(),
            // SEULE la session A pointe sur evt-sbi-a-sm-ctx ;
            // sbi_other n'est PAS dans event_ids.
            event_ids: vec!["evt-sbi-a-sm-ctx".into()],
            sbi_time_window_event_ids: Vec::new(),
        };
        let events = vec![sbi_full.clone(), sbi_other.clone()];
        let summary = collect_sbi_identities_for_session(&session, &events);

        // MSISDN + IMEI pour la session A.
        let msisdn = summary.msisdn_pseudonym.as_ref().expect("msisdn attendu");
        assert_eq!(msisdn.value, "hash-msisdn-a");
        assert_eq!(msisdn.source_event_id, "evt-sbi-a-sm-ctx");
        assert_eq!(msisdn.source, "SBI:nsmf-pdusession:CreateSMContext");
        let imei = summary.imei_pseudonym.as_ref().expect("imei attendu");
        assert_eq!(imei.value, "hash-imei-a");

        // IMEISV absent → None (invariant anti-hypothèse).
        assert!(summary.imeisv_pseudonym.is_none());
    }

    /// 2.18.0 — Une session qui n'a AUCUN event SBI rattaché
    /// retourne une summary entièrement None (pas de fuite depuis
    /// des events d'autres sessions).
    #[test]
    fn collect_sbi_identities_for_session_returns_empty_when_no_sbi_event() {
        let n2 = event(
            "evt-n2-only",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            &[("pdu_session_id", "1")],
            1,
        );
        let session = DiscoveredPduSession {
            session_id: "5g-session-only-n2".into(),
            ue_context_id: "ue-ctx-only".into(),
            pdu_session_id: "1".into(),
            dnn: None,
            snssai: None,
            state: "ACTIVE".into(),
            establishment_timestamp_ns: 0,
            release_timestamp_ns: None,
            interfaces: vec!["N2".into()],
            correlation_status: "OPEN".into(),
            event_ids: vec!["evt-n2-only".into()],
            sbi_time_window_event_ids: Vec::new(),
        };
        let summary = collect_sbi_identities_for_session(&session, &[n2]);
        assert!(summary.msisdn_pseudonym.is_none());
        assert!(summary.imei_pseudonym.is_none());
        assert!(summary.imeisv_pseudonym.is_none());
    }

    /// 2.18.3 (ANR1 #10 6898944250) — reproduit le FAIL prod sur
    /// `5g-session-99e8a9a6f5a0d5af` : plusieurs events SBI du même
    /// pseudonyme + PDU session + message_name collisionnaient sur
    /// une `publication_semantic_key` identique → `load_paths_
    /// streaming_representatives` ne retenait qu'un seul event SBI
    /// (le dernier) → `attach_sbi_to_sessions` avait 0 SBI à
    /// rattacher. Le fix 2.18.3 ajoute SBI-HTTP2 à
    /// `preserve_occurrence`, chaque event SBI est distingué par
    /// `(capture_id, packet_number)` et tous sont retenus.
    #[test]
    fn publication_semantic_key_preserves_each_sbi_operation_occurrence_anr1_6898944250() {
        let make = |event_id: &str, packet: u64, name: &str| {
            let mut e = event(
                event_id,
                "SBI-HTTP2",
                name,
                &[
                    ("subscriber_pseudonym", "psn-supi-abc"),
                    ("pdu_session_id", "1"),
                ],
                packet,
            );
            // Toutes les opérations SBI sur le même capture + même
            // couple source/dest/direction → clé 100 % identique
            // en-dehors du packet_number.
            e.capture_id = "sha256:continuous".into();
            e.packet_references[0].packet_number = packet;
            e
        };
        let sbi1 = make("evt-sbi-1", 10, "CreateSMContext");
        let sbi2 = make("evt-sbi-2", 20, "CreateSMContext");
        let sbi3 = make("evt-sbi-3", 30, "N1N2MessageTransfer");
        let key1 = publication_semantic_key(&sbi1);
        let key2 = publication_semantic_key(&sbi2);
        let key3 = publication_semantic_key(&sbi3);
        assert_ne!(
            key1, key2,
            "deux CreateSMContext consécutifs doivent avoir des clés distinctes (packet_number)"
        );
        assert_ne!(key1, key3, "message_name différent → clé différente");
        assert_ne!(key2, key3);
    }

    /// 2.18.3 — l'event GTP-U data-plane reste compacté : deux
    /// paquets GTP-U successifs avec le même tunnel partagent la
    /// clé (pour éviter l'explosion mémoire 4 GiB déjà rencontrée
    /// en 2.11.12).
    #[test]
    fn publication_semantic_key_still_compacts_gtpu_data_plane() {
        let make = |event_id: &str, packet: u64| {
            let mut e = event(
                event_id,
                "GTP-U",
                "G-PDU",
                &[
                    ("teid", "0x1234"),
                    ("tunnel_endpoint_ip", "10.77.23.13"),
                ],
                packet,
            );
            e.capture_id = "sha256:continuous".into();
            e.packet_references[0].packet_number = packet;
            e
        };
        let g1 = make("evt-gtpu-1", 100);
        let g2 = make("evt-gtpu-2", 101);
        let key1 = publication_semantic_key(&g1);
        let key2 = publication_semantic_key(&g2);
        assert_eq!(
            key1, key2,
            "deux GTP-U data-plane doivent partager la clé (compactage vital)"
        );
    }

    /// 2.18.3 — vérifie la chaîne `publication_semantic_key →
    /// representatives dedup` : 3 events SBI du même pseudonyme +
    /// même PDU session + même message_name survivent tous au
    /// dédoublonnage (avant 2.18.3 : collision → 2 perdus). C'est
    /// l'étape où la cause prod a été observée (FAIL #10 6898944250).
    /// Le rattachement final par `attach_sbi_to_sessions` dépend
    /// aussi du pipeline PDU complet (Response + context release) ;
    /// ici on isole UNIQUEMENT la correction du dedup — la suite
    /// est couverte par `sbi_attach_rules_match_anr2_production_shapes_2_9_9`
    /// et consorts.
    #[test]
    fn sbi_events_survive_representatives_dedup_anr1_6898944250() {
        use std::io::Write;
        let tmp = std::env::temp_dir().join(format!(
            "oiran-sbi-dedup-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        {
            let mut file = std::fs::File::create(&tmp).unwrap();
            for (ev, packet) in [("evt-sbi-1", 10u64), ("evt-sbi-2", 20), ("evt-sbi-3", 30)] {
                writeln!(file, r#"{{"event_id":"{ev}","parent_event_id":null,"capture_id":"sha256:continuous","capture_point_id":"SBI","timestamp":{{"seconds":1,"nanoseconds":{packet},"raw_ticks":{packet},"resolution_base":10,"resolution_exponent":9,"display":"1.000000{packet:03}Z"}},"interface":"SBI","protocol":"SBI-HTTP2","message_name":"CreateSMContext","source_endpoint":{{"address":"10.77.3.1","network_function":"AMF"}},"destination_endpoint":{{"address":"10.77.3.2","network_function":"SMF"}},"direction":"CORE_TO_CORE","session_identifiers":[{{"name":"subscriber_pseudonym","value":"psn-supi-abc","pseudonymized":true}},{{"name":"pdu_session_id","value":"1","pseudonymized":false}}],"information_elements":[],"decoding_status":"DECODED","decoder_name":"decoder-sbi","decoder_version":"0","raw_payload_reference":"sha256:x","packet_references":[{{"source_file":"x","packet_number":{packet},"byte_offset":0,"interface_id":0,"captured_length":1,"original_length":1}}],"errors":[]}}"#).unwrap();
            }
        }
        let index = load_paths_streaming_representatives_with_progress(
            std::slice::from_ref(&tmp),
            |_, _| {},
        )
        .unwrap();
        let sbi_events: Vec<_> = index
            .events
            .iter()
            .filter(|e| protocol_is(e, "SBI-HTTP2"))
            .collect();
        assert_eq!(
            sbi_events.len(),
            3,
            "les 3 events SBI (même pseudo+pdu, même message_name) doivent survivre au dedup avec 2.18.3 ; got {}",
            sbi_events.len()
        );
        std::fs::remove_file(&tmp).ok();
    }

    /// 2.18.7 (ANR1 #10 6901968948) — reproduit le FAIL prod.
    /// Sessions `5g-session-92e82900a18969c3` + `5g-session-
    /// eab5cc6d8c2b9131` (même abonné) : Live UE-201 reçoit 59 SBI
    /// alors que `/sessions/:id/callflow` montre 0 SBI rattaché.
    ///
    /// Cause : les events SBI N8/N10/N12 (`Nudm_SDM am-data`,
    /// `Nudm_UECM registrations`, `Npcf am-policy-data`) portent
    /// `subscriber_pseudonym` mais PAS de `pdu_session_id` ni de
    /// tunnel `(ip, teid)` (pas de n2SmInfo). Les 2 clés dual de
    /// `attach_sbi_to_sessions` pré-2.18.7 échouaient toutes les
    /// deux → 0 rattachement malgré le match abonné prouvé par la
    /// trace Live.
    ///
    /// Fix 2.18.7 : fallback pseudo-seul après échec des 2 dual.
    /// L'event SBI est rattaché à TOUTES les sessions du même
    /// pseudonyme (l'abonné est le seul lien légitime disponible,
    /// et plusieurs PDU sessions concurrentes du même UE partagent
    /// toutes la même opération AM data / registration).
    #[test]
    fn sbi_without_pdu_or_tunnel_attaches_by_subscriber_pseudonym_alone_anr1_6901968948() {
        // Session 5G avec son N2 setup (seule clé disponible côté
        // session : subscriber_pseudonym via N2).
        let n2 = event(
            "evt-n2-setup",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            &[
                ("subscriber_pseudonym", "psn-supi-xyz"),
                ("pdu_session_id", "1"),
                ("ran_ue_ngap_id", "5"),
                ("amf_ue_ngap_id", "11"),
                ("item_0_tunnel_ip_ul", "10.77.22.13"),
                ("item_0_gtp_teid_ul", "0x1234"),
            ],
            1,
        );
        let n2_resp = event(
            "evt-n2-resp",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            &[
                ("subscriber_pseudonym", "psn-supi-xyz"),
                ("pdu_session_id", "1"),
            ],
            2,
        );
        // Event SBI Nudm_SDM am-data : porte le pseudo (hashé
        // depuis le SUPI de l'URI/body) mais PAS de PDU session
        // ID (opération par abonné, pas par PDU). Shape prod.
        let sbi_am_data = event(
            "evt-sbi-am-data",
            "SBI-HTTP2",
            "GET am-data",
            &[("subscriber_pseudonym", "psn-supi-xyz")],
            3,
        );
        // Event SBI Nudm_UECM registration : idem.
        let sbi_reg = event(
            "evt-sbi-registration",
            "SBI-HTTP2",
            "PUT registrations/amf-3gpp-access",
            &[("subscriber_pseudonym", "psn-supi-xyz")],
            4,
        );
        let events = vec![n2, n2_resp, sbi_am_data, sbi_reg];
        let discovery = discover_sessions(&mut events.clone());
        assert_eq!(discovery.pdu_sessions.len(), 1);
        let session = &discovery.pdu_sessions[0];
        assert!(
            session
                .event_ids
                .iter()
                .any(|id| id == "evt-sbi-am-data"),
            "SBI am-data (sans pdu_session_id, sans tunnel) doit être rattaché par pseudo-seul ; got {:?}",
            session.event_ids
        );
        assert!(
            session
                .event_ids
                .iter()
                .any(|id| id == "evt-sbi-registration"),
            "SBI registration doit aussi être rattaché par pseudo-seul ; got {:?}",
            session.event_ids
        );
        assert!(
            session.interfaces.iter().any(|i| i == "SBI-HTTP2"),
            "SBI-HTTP2 doit apparaître dans session.interfaces ; got {:?}",
            session.interfaces
        );
    }

    /// 2.21.49 — règle des sondes pro. Deux essais du même abonné, avec
    /// les MÊMES `(pseudonyme, PDU 1)` et le MÊME tunnel (cas du lab :
    /// identifiants réutilisés), séparés dans le temps. Le SBI de l'essai 2
    /// va à l'essai 2 par fenêtre de temps, marqué comme tel ; un SBI hors
    /// de toute fenêtre reste non rattaché ; une clé unique prime sur le
    /// temps.
    fn timed(mut e: EventRecord, seconds: i128) -> EventRecord {
        e.timestamp_ns = seconds * 1_000_000_000;
        e
    }

    fn two_runs_same_ids() -> Vec<EventRecord> {
        let run = |n: &str, ran: &str, at: i128, packet: u64| {
            vec![
                timed(
                    event(
                        &format!("evt-n2-setup-{n}"),
                        "NGAP",
                        "PDUSessionResourceSetupRequest",
                        &[
                            ("subscriber_pseudonym", "psn-repeat"),
                            ("pdu_session_id", "1"),
                            ("ran_ue_ngap_id", ran),
                            ("amf_ue_ngap_id", ran),
                            ("item_0_tunnel_ip_ul", "10.77.22.13"),
                            ("item_0_gtp_teid_ul", "0xf124"),
                        ],
                        packet,
                    ),
                    at,
                ),
                timed(
                    event(
                        &format!("evt-n2-resp-{n}"),
                        "NGAP",
                        "PDUSessionResourceSetupResponse",
                        &[("pdu_session_id", "1"), ("ran_ue_ngap_id", ran), ("amf_ue_ngap_id", ran)],
                        packet + 1,
                    ),
                    at + 30,
                ),
            ]
        };
        let mut events = run("a", "1", 1_000, 1);
        events.extend(run("b", "2", 2_000, 10));
        events
    }

    #[test]
    fn sbi_ambiguous_keys_attach_by_time_window_to_the_right_run_and_are_marked() {
        let mut events = two_runs_same_ids();
        let sbi = |id: &str, op: &str, ids: &[(&str, &str)], at: i128, packet: u64| {
            let mut e = timed(event(id, "SBI-HTTP2", op, ids, packet), at);
            e.capture_id = "capture-vtap".into();
            e
        };
        events.push(sbi(
            "evt-sbi-create",
            "CreateSMContext",
            &[("subscriber_pseudonym", "psn-repeat"), ("pdu_session_id", "1")],
            2_001,
            20,
        ));
        events.push(sbi(
            "evt-sbi-n1n2",
            "N1N2MessageTransfer",
            &[("tunnel_endpoint_ip", "10.77.22.13"), ("gtp_teid", "0xf124"), ("pdu_session_id", "1")],
            2_002,
            21,
        ));
        events.push(sbi(
            "evt-sbi-am-data",
            "GetAmData",
            &[("subscriber_pseudonym", "psn-repeat")],
            2_010,
            22,
        ));
        events.push(sbi(
            "evt-sbi-orphan",
            "GetAmData",
            &[("subscriber_pseudonym", "psn-repeat")],
            5_000,
            23,
        ));
        events.push(sbi("evt-sbi-nokey", "NFHeartbeat", &[], 2_003, 24));
        let discovery = discover_sessions(&mut events.clone());
        assert_eq!(discovery.pdu_sessions.len(), 2);
        let session_of = |needle: &str| {
            discovery
                .pdu_sessions
                .iter()
                .filter(|s| s.event_ids.iter().any(|id| id == needle))
                .map(|s| s.session_id.clone())
                .collect::<Vec<_>>()
        };
        let run_b = session_of("evt-n2-setup-b");
        assert_eq!(run_b.len(), 1);
        for id in ["evt-sbi-create", "evt-sbi-n1n2", "evt-sbi-am-data"] {
            assert_eq!(session_of(id), run_b, "{id} doit aller à l'essai 2, et à lui seul");
        }
        assert!(session_of("evt-sbi-orphan").is_empty(), "hors fenêtre : non rattaché");
        let b = discovery
            .pdu_sessions
            .iter()
            .find(|s| s.session_id == run_b[0])
            .unwrap();
        assert_eq!(b.sbi_time_window_event_ids.len(), 3, "rattachement marqué fenêtre");
        assert_eq!(discovery.event_accounting["sbi_attached_time_window"], 3);
        assert_eq!(discovery.event_accounting["sbi_unattached_ambiguous"], 1);
        assert_eq!(discovery.event_accounting["sbi_unattached_no_key"], 1);
        assert!(session_of("evt-sbi-nokey").is_empty());
        // Somme des quatre compteurs = nombre de SBI.
        let total: usize = [
            "sbi_attached_exact_key",
            "sbi_attached_time_window",
            "sbi_unattached_ambiguous",
            "sbi_unattached_no_key",
        ]
        .iter()
        .map(|k| discovery.event_accounting[*k])
        .sum();
        assert_eq!(total, events.iter().filter(|e| protocol_is(e, "SBI-HTTP2")).count());
    }

    /// 2.21.51 — `(pseudonyme, PDU)` doit être une clé exacte même quand
    /// le pseudonyme n'est porté que par le NAS du contexte UE (cas réel :
    /// les N2 PDUSessionResource* ne portent pas le SUPI).
    #[test]
    fn sbi_pseudo_pdu_key_comes_from_the_ue_context_nas() {
        let ids = |extra: &[(&'static str, &'static str)]| {
            let mut v = vec![("ran_ue_ngap_id", "7"), ("amf_ue_ngap_id", "70")];
            v.extend_from_slice(extra);
            v
        };
        let nas = timed(
            event("evt-nas-reg", "NGAP", "InitialUEMessage",
                &[("subscriber_pseudonym", "psn-ctx"), ("ran_ue_ngap_id", "7")], 1),
            100,
        );
        let ics = timed(event("evt-ics", "NGAP", "InitialContextSetupRequest", &ids(&[]), 2), 101);
        let setup = timed(
            event("evt-pdu-setup", "NGAP", "PDUSessionResourceSetupRequest",
                &ids(&[("pdu_session_id", "5")]), 3),
            102,
        );
        let resp = timed(
            event("evt-pdu-resp", "NGAP", "PDUSessionResourceSetupResponse",
                &ids(&[("pdu_session_id", "5")]), 4),
            103,
        );
        // Hors de toute fenêtre : seule la clé exacte peut le rattacher.
        let mut sbi = timed(
            event("evt-sbi-ctx", "SBI-HTTP2", "UpdateSMContext",
                &[("subscriber_pseudonym", "psn-ctx"), ("pdu_session_id", "5")], 5),
            9_000,
        );
        sbi.capture_id = "capture-vtap".into();
        let events = vec![nas, ics, setup, resp, sbi];
        let discovery = discover_sessions(&mut events.clone());
        let session = discovery
            .pdu_sessions
            .iter()
            .find(|s| s.event_ids.iter().any(|id| id == "evt-pdu-setup"))
            .expect("session PDU 5");
        assert!(
            session.event_ids.iter().any(|id| id == "evt-sbi-ctx"),
            "SBI (pseudonyme du NAS, PDU 5) rattaché par clé exacte ; got {:?}",
            session.event_ids
        );
        assert!(session.sbi_time_window_event_ids.is_empty());
        assert_eq!(discovery.event_accounting["sbi_attached_exact_key"], 1);
    }

    /// 2.21.51 — la compaction de publication doit garder `gtp_teid`, lu
    /// par le lookup SBI par tunnel.
    #[test]
    fn sbi_tunnel_key_survives_publication_compaction() {
        let mut events = two_runs_same_ids();
        events[0].identifiers.retain(|(name, _)| name != "item_0_gtp_teid_ul");
        events[0].identifiers.push(("item_0_gtp_teid_ul".into(), "0x0a01".into()));
        // La clé tunnel du N2 vit aussi dans un IE (cas réel 2.9.17) : la
        // compaction garde les IE NGAP porteurs de tunnel.
        let mut sbi = timed(
            event("evt-sbi-tunnel", "SBI-HTTP2", "N1N2MessageTransfer",
                &[("tunnel_endpoint_ip", "10.77.22.13"), ("gtp_teid", "0x0a01")], 30),
            9_000,
        );
        sbi.capture_id = "capture-vtap".into();
        events.push(sbi);
        for event in events.iter_mut().filter(|e| protocol_is(e, "SBI-HTTP2")) {
            compact_publication_event(event);
        }
        let discovery = discover_sessions(&mut events.clone());
        let a = discovery
            .pdu_sessions
            .iter()
            .find(|s| s.event_ids.iter().any(|id| id == "evt-n2-setup-a"))
            .unwrap();
        assert!(
            a.event_ids.iter().any(|id| id == "evt-sbi-tunnel"),
            "tunnel unique après compaction du SBI ; got {:?}",
            a.event_ids
        );
        assert_eq!(discovery.event_accounting["sbi_attached_exact_key"], 1);
    }

    /// 2.21.55 — SBI historique sans identifiant pseudonyme : le
    /// pseudonyme est relu dans l'URI sanitisée et la clé exacte
    /// `(pseudonyme, PDU)` rattache.
    #[test]
    fn sbi_pseudonym_is_read_from_sanitized_uri_when_identifier_missing() {
        let psn = "psn-0123456789abcdef0123456789abcdef";
        let nas = timed(
            event("evt-nas-reg", "NGAP", "InitialUEMessage",
                &[("subscriber_pseudonym", psn), ("ran_ue_ngap_id", "7")], 1),
            100,
        );
        let ids = |extra: &[(&'static str, &'static str)]| {
            let mut v = vec![("ran_ue_ngap_id", "7"), ("amf_ue_ngap_id", "70")];
            v.extend_from_slice(extra);
            v
        };
        let ics = timed(event("evt-ics", "NGAP", "InitialContextSetupRequest", &ids(&[]), 2), 101);
        let setup = timed(
            event("evt-pdu-setup", "NGAP", "PDUSessionResourceSetupRequest",
                &ids(&[("pdu_session_id", "1")]), 3),
            102,
        );
        let resp = timed(
            event("evt-pdu-resp", "NGAP", "PDUSessionResourceSetupResponse",
                &ids(&[("pdu_session_id", "1")]), 4),
            103,
        );
        let mut sbi = timed(
            event("evt-sbi-uecm", "SBI-HTTP2", "UnsupportedSbiOperation",
                &[("pdu_session_id", "1")], 5),
            9_000,
        );
        sbi.capture_id = "capture-vtap".into();
        sbi.source_json = serde_json::json!({"sbi": {
            "request_uri": format!("/nudm-uecm/v1/subscriber-{psn}/registrations/smf-registrations/1"),
            "http_method": "PUT"
        }});
        let mut bad = sbi.clone();
        bad.event_id = "evt-sbi-bad".into();
        bad.source_json = serde_json::json!({"sbi": {
            "request_uri": "/nudm-uecm/v1/subscriber-psn-XYZ/registrations/smf-registrations/1"
        }});
        let events = vec![nas, ics, setup, resp, sbi, bad];
        let discovery = discover_sessions(&mut events.clone());
        let session = discovery
            .pdu_sessions
            .iter()
            .find(|s| s.event_ids.iter().any(|id| id == "evt-pdu-setup"))
            .expect("session PDU 1");
        assert!(
            session.event_ids.iter().any(|id| id == "evt-sbi-uecm"),
            "pseudonyme lu dans l'URI → clé exacte ; got {:?}",
            session.event_ids
        );
        assert!(!session.event_ids.iter().any(|id| id == "evt-sbi-bad"), "URI non conforme : fail-closed");
        assert_eq!(discovery.event_accounting["sbi_attached_exact_key"], 1);
    }

    #[test]
    fn sbi_overlapping_windows_of_two_contexts_stay_unattached() {
        let mut events = two_runs_same_ids();
        // L'essai 2 démarre pendant l'essai 1 : fenêtres chevauchantes.
        for e in events.iter_mut().skip(2) {
            e.timestamp_ns -= 990 * 1_000_000_000;
        }
        let mut sbi = timed(
            event(
                "evt-sbi-overlap",
                "SBI-HTTP2",
                "CreateSMContext",
                &[("subscriber_pseudonym", "psn-repeat"), ("pdu_session_id", "1")],
                20,
            ),
            1_015,
        );
        sbi.capture_id = "capture-vtap".into();
        events.push(sbi);
        let discovery = discover_sessions(&mut events.clone());
        assert_eq!(discovery.pdu_sessions.len(), 2);
        assert!(discovery
            .pdu_sessions
            .iter()
            .all(|s| !s.event_ids.iter().any(|id| id == "evt-sbi-overlap")));
        assert_eq!(discovery.event_accounting["sbi_unattached_ambiguous"], 1);
        assert_eq!(discovery.event_accounting["sbi_attached_time_window"], 0);
    }

    #[test]
    fn sbi_unique_exact_key_wins_over_time_and_is_not_marked_time_window() {
        let mut events = two_runs_same_ids();
        // `pdu_session_id=2` n'existe que dans... aucune session : on prend
        // un SM context unique à la place : (pseudonyme, PDU 1) est ambigu,
        // mais un tunnel propre à l'essai 1 tranche, même hors fenêtre.
        events[0]
            .identifiers
            .retain(|(name, _)| name != "item_0_gtp_teid_ul");
        events[0]
            .identifiers
            .push(("item_0_gtp_teid_ul".into(), "0x0a01".into()));
        let mut late = timed(
            event(
                "evt-sbi-late-unique",
                "SBI-HTTP2",
                "N1N2MessageTransfer",
                &[("tunnel_endpoint_ip", "10.77.22.13"), ("gtp_teid", "0x0a01")],
                30,
            ),
            9_000,
        );
        late.capture_id = "capture-vtap".into();
        events.push(late);
        let discovery = discover_sessions(&mut events.clone());
        let a = discovery
            .pdu_sessions
            .iter()
            .find(|s| s.event_ids.iter().any(|id| id == "evt-n2-setup-a"))
            .unwrap();
        assert!(a.event_ids.iter().any(|id| id == "evt-sbi-late-unique"));
        assert!(a.sbi_time_window_event_ids.is_empty());
        assert_eq!(discovery.event_accounting["sbi_attached_exact_key"], 1);
    }

    /// 2.18.7 — un abonné avec DEUX sessions actives : un SBI
    /// AM data (sans pdu_session_id) doit être rattaché aux DEUX
    /// sessions (l'opération est par abonné, pas par PDU — toute
    /// les PDU sessions concurrentes partagent la même operation).
    #[test]
    fn sbi_pseudo_only_attaches_to_all_sessions_of_the_same_subscriber() {
        let make_n2 = |event_id: &str, pdu_id: &str, packet: u64| {
            event(
                event_id,
                "NGAP",
                "PDUSessionResourceSetupRequest",
                &[
                    ("subscriber_pseudonym", "psn-supi-xyz"),
                    ("pdu_session_id", pdu_id),
                    ("ran_ue_ngap_id", "5"),
                    ("amf_ue_ngap_id", "11"),
                    ("item_0_tunnel_ip_ul", "10.77.22.13"),
                    ("item_0_gtp_teid_ul", pdu_id),
                ],
                packet,
            )
        };
        let make_resp = |event_id: &str, pdu_id: &str, packet: u64| {
            event(
                event_id,
                "NGAP",
                "PDUSessionResourceSetupResponse",
                &[
                    ("subscriber_pseudonym", "psn-supi-xyz"),
                    ("pdu_session_id", pdu_id),
                ],
                packet,
            )
        };
        let n2_a = make_n2("evt-n2-setup-a", "1", 1);
        let n2_a_resp = make_resp("evt-n2-resp-a", "1", 2);
        let n2_b = make_n2("evt-n2-setup-b", "2", 3);
        let n2_b_resp = make_resp("evt-n2-resp-b", "2", 4);
        let sbi_am_data = event(
            "evt-sbi-am-data",
            "SBI-HTTP2",
            "GET am-data",
            &[("subscriber_pseudonym", "psn-supi-xyz")],
            5,
        );
        let events = vec![n2_a, n2_a_resp, n2_b, n2_b_resp, sbi_am_data];
        let discovery = discover_sessions(&mut events.clone());
        assert_eq!(
            discovery.pdu_sessions.len(),
            2,
            "deux PDU sessions distinctes attendues"
        );
        let both_have_sbi = discovery.pdu_sessions.iter().all(|session| {
            session
                .event_ids
                .iter()
                .any(|id| id == "evt-sbi-am-data")
        });
        assert!(
            both_have_sbi,
            "l'event SBI am-data doit être rattaché aux DEUX sessions du même abonné ; got {:?}",
            discovery
                .pdu_sessions
                .iter()
                .map(|s| (s.pdu_session_id.as_str(), s.event_ids.clone()))
                .collect::<Vec<_>>()
        );
    }

    /// 2.18.7 — non-régression : un SBI qui porte (pseudo, pdu_id)
    /// MATCHANT reste rattaché UNIQUEMENT à la session de ce PDU
    /// (match dual prioritaire). Le fallback pseudo-seul ne doit
    /// PAS inonder les autres sessions du même abonné.
    #[test]
    fn sbi_with_pdu_id_stays_bound_to_its_pdu_session_only() {
        let n2_a = event(
            "evt-n2-a",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            &[
                ("subscriber_pseudonym", "psn-supi-xyz"),
                ("pdu_session_id", "1"),
                ("ran_ue_ngap_id", "5"),
                ("amf_ue_ngap_id", "11"),
            ],
            1,
        );
        let n2_a_resp = event(
            "evt-n2-a-resp",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            &[
                ("subscriber_pseudonym", "psn-supi-xyz"),
                ("pdu_session_id", "1"),
            ],
            2,
        );
        let n2_b = event(
            "evt-n2-b",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            &[
                ("subscriber_pseudonym", "psn-supi-xyz"),
                ("pdu_session_id", "2"),
                ("ran_ue_ngap_id", "5"),
                ("amf_ue_ngap_id", "11"),
            ],
            3,
        );
        let n2_b_resp = event(
            "evt-n2-b-resp",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            &[
                ("subscriber_pseudonym", "psn-supi-xyz"),
                ("pdu_session_id", "2"),
            ],
            4,
        );
        let sbi_pdu1 = event(
            "evt-sbi-pdu1",
            "SBI-HTTP2",
            "CreateSMContext",
            &[
                ("subscriber_pseudonym", "psn-supi-xyz"),
                ("pdu_session_id", "1"),
            ],
            5,
        );
        let events = vec![n2_a, n2_a_resp, n2_b, n2_b_resp, sbi_pdu1];
        let discovery = discover_sessions(&mut events.clone());
        assert_eq!(discovery.pdu_sessions.len(), 2);
        let session_1 = discovery
            .pdu_sessions
            .iter()
            .find(|s| s.pdu_session_id == "1")
            .unwrap();
        let session_2 = discovery
            .pdu_sessions
            .iter()
            .find(|s| s.pdu_session_id == "2")
            .unwrap();
        assert!(
            session_1.event_ids.iter().any(|id| id == "evt-sbi-pdu1"),
            "SBI pdu=1 doit être sur session pdu=1"
        );
        assert!(
            !session_2.event_ids.iter().any(|id| id == "evt-sbi-pdu1"),
            "SBI pdu=1 ne doit PAS être sur session pdu=2 (match dual prioritaire)"
        );
    }

    /// 2.20.0 — un JSONL event SANS les 4 champs multi-sonde se
    /// parse avec `Option::None` : iso-comportement 2.19.x prouvé
    /// au niveau parseur. Aucune ligne existante ne change de
    /// forme.
    #[test]
    fn event_record_parses_without_new_multi_probe_fields_as_none() {
        let line = r#"{
            "event_id":"evt-a",
            "capture_id":"cap-a",
            "capture_point_id":"NGAP",
            "timestamp":{"seconds":1,"nanoseconds":2,"raw_ticks":3,"display":"1.000000002Z"},
            "interface":"N2",
            "protocol":"NGAP",
            "message_name":"InitialUEMessage",
            "source_endpoint":{"address":"a","network_function":"gNB"},
            "destination_endpoint":{"address":"b","network_function":"AMF"},
            "direction":"RAN_TO_CORE",
            "session_identifiers":[],
            "information_elements":[],
            "decoding_status":"DECODED",
            "decoder_name":"d",
            "decoder_version":"1",
            "raw_payload_reference":"sha256:x",
            "packet_references":[{"source_file":"x","packet_number":1,"byte_offset":0,"interface_id":0,"captured_length":1,"original_length":1}],
            "errors":[]
        }"#;
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        let event = parse_event(value).expect("event parses");
        assert!(event.probe_id.is_none(), "probe_id defaults to None");
        assert!(event.probe_type.is_none(), "probe_type defaults to None");
        assert!(event.physical_link.is_none(), "physical_link defaults to None");
        assert!(event.timestamp_source.is_none(), "timestamp_source defaults to None");
    }

    /// 2.20.0 — un JSONL event AVEC les 4 champs les propage
    /// intégralement. Forward-compat pour 2.20.1 (publication
    /// réelle par `CaptureSource`).
    #[test]
    fn event_record_parses_with_multi_probe_fields_propagated() {
        let line = r#"{
            "event_id":"evt-b",
            "capture_id":"cap-a",
            "capture_point_id":"NGAP",
            "timestamp":{"seconds":1,"nanoseconds":2,"raw_ticks":3,"display":"1.000000002Z"},
            "interface":"N2",
            "protocol":"NGAP",
            "message_name":"InitialUEMessage",
            "source_endpoint":{"address":"a","network_function":"gNB"},
            "destination_endpoint":{"address":"b","network_function":"AMF"},
            "direction":"RAN_TO_CORE",
            "session_identifiers":[],
            "information_elements":[],
            "decoding_status":"DECODED",
            "decoder_name":"d",
            "decoder_version":"1",
            "raw_payload_reference":"sha256:x",
            "packet_references":[{"source_file":"x","packet_number":1,"byte_offset":0,"interface_id":0,"captured_length":1,"original_length":1}],
            "errors":[],
            "probe_id":"lab-vprobe",
            "probe_type":"vprobe",
            "physical_link":"enp4s0f1np1",
            "timestamp_source":"hw_ptp"
        }"#;
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        let event = parse_event(value).expect("event parses");
        assert_eq!(event.probe_id.as_deref(), Some("lab-vprobe"));
        assert_eq!(event.probe_type.as_deref(), Some("vprobe"));
        assert_eq!(event.physical_link.as_deref(), Some("enp4s0f1np1"));
        assert_eq!(event.timestamp_source.as_deref(), Some("hw_ptp"));
    }

    #[test]
    fn spilling_representatives_match_legacy_across_multiple_runs() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "oiran-spilling-representatives-{}-{nonce}",
            std::process::id()
        ));
        let staging = root.join("staging");
        fs::create_dir_all(&root).unwrap();
        let first = root.join("events-000001.jsonl");
        let second = root.join("events-000002.jsonl");

        let write_event = |writer: &mut BufWriter<fs::File>, index: usize, generation: usize| {
            let packet = generation * 10_000 + index + 1;
            let value = serde_json::json!({
                "event_id": format!("evt-{generation}-{index:05}"),
                "capture_id": "cap-multi-shard",
                "capture_point_id": "N3",
                "timestamp": {"seconds": 1, "nanoseconds": packet, "raw_ticks": packet, "display": "1Z"},
                "interface": "N3",
                "protocol": "GTP-U",
                "message_name": "G-PDU",
                "source_endpoint": {"address": "10.0.0.1", "network_function": "UPF"},
                "destination_endpoint": {"address": "10.0.0.2", "network_function": "gNB"},
                "direction": "CORE_TO_RAN",
                "session_identifiers": [
                    {"name": "teid", "value": format!("0x{index:08x}"), "pseudonymized": false},
                    {"name": "tunnel_endpoint_ip", "value": "10.0.0.2", "pseudonymized": false}
                ],
                "information_elements": [],
                "decoding_status": "DECODED",
                "decoder_name": "test",
                "decoder_version": "1",
                "raw_payload_reference": "sha256:test",
                "packet_references": [{
                    "source_file": "N3.pcapng", "packet_number": packet,
                    "byte_offset": 0, "interface_id": 0,
                    "captured_length": 64, "original_length": 64
                }],
                "errors": []
            });
            serde_json::to_writer(&mut *writer, &value).unwrap();
            writer.write_all(b"\n").unwrap();
        };
        let write_ngap = |writer: &mut BufWriter<fs::File>, packet: usize| {
            let value = serde_json::json!({
                "event_id": format!("evt-ngap-{packet:05}"),
                "capture_id": "cap-ngap-occurrences",
                "capture_point_id": "N2",
                "timestamp": {"seconds": 2, "nanoseconds": packet, "raw_ticks": packet, "display": "2Z"},
                "interface": "N2",
                "protocol": "NGAP",
                "message_name": "UplinkNASTransport",
                "source_endpoint": {"address": "10.0.0.3", "network_function": "gNB"},
                "destination_endpoint": {"address": "10.0.0.4", "network_function": "AMF"},
                "direction": "RAN_TO_CORE",
                "session_identifiers": [
                    {"name": "ran_ue_ngap_id", "value": "77", "pseudonymized": false},
                    {"name": "amf_ue_ngap_id", "value": "88", "pseudonymized": false}
                ],
                "information_elements": [],
                "decoding_status": "DECODED",
                "decoder_name": "test",
                "decoder_version": "1",
                "raw_payload_reference": "sha256:test",
                "packet_references": [{
                    "source_file": "N2.pcapng", "packet_number": packet,
                    "byte_offset": 0, "interface_id": 0,
                    "captured_length": 64, "original_length": 64
                }],
                "errors": []
            });
            serde_json::to_writer(&mut *writer, &value).unwrap();
            writer.write_all(b"\n").unwrap();
        };
        {
            let mut writer = BufWriter::new(fs::File::create(&first).unwrap());
            for index in 0..2_100 {
                write_event(&mut writer, index, 1);
            }
            write_ngap(&mut writer, 30_001);
            write_ngap(&mut writer, 30_002);
            writer.flush().unwrap();
        }
        {
            let mut writer = BufWriter::new(fs::File::create(&second).unwrap());
            for index in (0..2_100).step_by(7) {
                write_event(&mut writer, index, 2);
            }
            write_ngap(&mut writer, 30_003);
            write_ngap(&mut writer, 30_004);
            writer.flush().unwrap();
        }
        let paths = vec![first.clone(), second.clone()];
        let legacy = load_paths_streaming_representatives_with_progress(&paths, |_, _| {})
            .expect("legacy reference");
        let spilled = load_paths_spilling_representatives_with_progress(
            &paths,
            &staging,
            8 * 1024,
            |_, _| {},
        )
        .expect("disk-backed representatives");

        assert_eq!(spilled.events.len(), 2_104, "at least 2,000 representatives");
        assert_eq!(legacy.source_event_count, spilled.source_event_count);
        assert_eq!(
            serde_json::to_value(&legacy.events).unwrap(),
            serde_json::to_value(&spilled.events).unwrap(),
            "ordered representatives must be byte-for-byte equivalent as JSON",
        );
        let replaced = spilled
            .events
            .iter()
            .find(|event| event.first_identifier("teid") == Some("0x00000000"))
            .unwrap();
        assert_eq!(replaced.event_id, "evt-2-00000", "last observation wins");
        assert_eq!(
            spilled
                .events
                .iter()
                .filter(|event| event.protocol == "NGAP")
                .count(),
            4,
            "73713d0 contract: every NGAP occurrence survives compaction",
        );

        fs::remove_file(first).unwrap();
        fs::remove_file(second).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn spilling_representatives_match_legacy_on_certified_fixture() {
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1/oiran_events.jsonl");
        let staging = std::env::temp_dir().join(format!(
            "oiran-spilling-fixture-{}",
            std::process::id()
        ));
        let paths = vec![source];
        let legacy = load_paths_streaming_representatives_with_progress(&paths, |_, _| {})
            .expect("legacy fixture representatives");
        let spilled = load_paths_spilling_representatives_with_progress(
            &paths,
            &staging,
            4 * 1024,
            |_, _| {},
        )
        .expect("disk-backed fixture representatives");
        assert_eq!(
            serde_json::to_value(&legacy.events).unwrap(),
            serde_json::to_value(&spilled.events).unwrap(),
            "certified fixture representatives differ",
        );

        let mut legacy_events = legacy.events;
        let mut spilled_events = spilled.events;
        let legacy_discovery = discover_sessions(&mut legacy_events);
        let spilled_discovery = discover_sessions(&mut spilled_events);
        assert_eq!(
            serde_json::to_value(legacy_discovery).unwrap(),
            serde_json::to_value(spilled_discovery).unwrap(),
            "certified fixture discovery differs",
        );
    }
}

#[cfg(test)]
mod in_packet_order_tests {
    use super::*;

    /// Event stocké complet (forme des fixtures de ce module), dans le
    /// paquet `packet` du fichier `/ring/n2/n2_00001.pcapng`.
    fn stored(id: &str, parent: Option<&str>, packet: u64, stable_event_key: &str) -> Value {
        let mut value = serde_json::json!({
            "event_id": id,
            "capture_id": "sha256:test",
            "capture_point_id": "N2",
            "timestamp": {"seconds": 1, "nanoseconds": packet, "raw_ticks": packet, "display": "1Z"},
            "interface": "N2",
            "protocol": if parent.is_some() { "NAS-5GMM" } else { "NGAP" },
            "message_name": id,
            "source_endpoint": {"address": "a", "network_function": "gNB"},
            "destination_endpoint": {"address": "b", "network_function": "AMF"},
            "direction": "RAN_TO_CORE",
            "session_identifiers": [],
            "information_elements": [],
            "decoding_status": "DECODED",
            "decoder_name": "test",
            "decoder_version": "1",
            "raw_payload_reference": "sha256:test",
            "packet_references": [{
                "source_file": "/ring/n2/n2_00001.pcapng",
                "packet_number": packet,
                "byte_offset": 0,
                "interface_id": 0,
                "captured_length": 1,
                "original_length": 1
            }],
            "errors": []
        });
        let object = value.as_object_mut().unwrap();
        if let Some(parent) = parent {
            object.insert("parent_event_id".into(), Value::String(parent.into()));
        }
        if !stable_event_key.is_empty() {
            object.insert("stable_event_key".into(), Value::String(stable_event_key.into()));
        }
        value
    }

    fn load(values: &[Value]) -> Vec<EventRecord> {
        let jsonl = values.iter().map(Value::to_string).collect::<Vec<_>>().join("\n");
        load_jsonl(std::io::Cursor::new(jsonl.into_bytes())).unwrap()
    }

    /// 0.5.27 (POLARIS 2.21.133) — dans un même paquet, l'ordre canonique
    /// met le parent avant son enfant même quand l'`event_id` de l'enfant
    /// est le plus petit, puis l'ordinal d'émission, puis l'`event_id`.
    /// D'un paquet à l'autre, rien ne change.
    #[test]
    fn canonical_order_puts_the_parent_first_within_a_packet_2_21_133() {
        let mut events = load(&[
            stored("evt-0001", Some("evt-ffff"), 7, "n2_00001.pcapng|0|7|0|NAS-5GMM|1"),
            stored("evt-ffff", None, 7, "n2_00001.pcapng|0|7|0|NGAP|0"),
            stored("evt-9999", None, 6, "n2_00001.pcapng|0|6|0|NGAP|0"),
        ]);
        deterministic_sort(&mut events);
        let ids: Vec<&str> = events.iter().map(|e| e.event_id.as_str()).collect();
        assert_eq!(ids, vec!["evt-9999", "evt-ffff", "evt-0001"]);
        // Frères sans parenté : l'ordinal d'émission avant l'`event_id`.
        let mut siblings = load(&[
            stored("evt-aaaa", None, 8, "n2_00001.pcapng|0|8|0|NGAP|1"),
            stored("evt-zzzz", None, 8, "n2_00001.pcapng|0|8|0|NGAP|0"),
        ]);
        deterministic_sort(&mut siblings);
        assert_eq!(siblings[0].event_id, "evt-zzzz");
        assert_eq!(emission_ordinal(""), u32::MAX);
        assert_eq!(emission_ordinal("f|0|8|0|NGAP|12"), 12);
        assert_eq!(emission_ordinal("f|0|8|0|NGAP|x"), u32::MAX);
    }

    /// 0.5.27 — un fichier stocké sans clé, enfant avant parent : la clé
    /// dérivée à la lecture numérote le parent 0 et l'enfant 1, comme le
    /// décodeur. Avant : l'enfant prenait 0.
    #[test]
    fn read_time_key_numbers_the_parent_first_2_21_133() {
        let events = load(&[
            stored("evt-0001", Some("evt-ffff"), 7, ""),
            stored("evt-ffff", None, 7, ""),
        ]);
        let key = |id: &str| events.iter().find(|e| e.event_id == id).unwrap().stable_event_key.clone();
        assert_eq!(key("evt-ffff"), "n2_00001.pcapng|0|7|0|NGAP|0");
        assert_eq!(key("evt-0001"), "n2_00001.pcapng|0|7|0|NAS-5GMM|1");
        assert_eq!(events[0].event_id, "evt-ffff", "parent d'abord dans l'ordre canonique");
    }
}
