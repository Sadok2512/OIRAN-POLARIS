//! Deterministic reconstruction of UE, PDU, PFCP and GTP-U state from normalized events.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{self, BufRead};

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
                (exact_pseudonym || exact_bearer)
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
        let owners = lte_contexts
            .iter()
            .enumerate()
            .filter(|(_, context)| {
                context.pseudonym.as_deref() == Some(pseudonym)
                    || context
                        .s11_events
                        .iter()
                        .filter_map(|control| lte_subscriber_pseudonym(control))
                        .any(|control_pseudonym| control_pseudonym == pseudonym)
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
    deterministic_sort(&mut events);
    Ok(events)
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
            representatives.entry(key).or_insert(event);
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
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
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

/// 2.7.13: the canonical processing order inside OIRAN is
/// `(capture_id, packet_number, event_id)`. The timestamp is NEVER used
/// for a processing decision, and no two events from different captures
/// are compared by `timestamp_ns`. Call flow ladder rendering may, as a
/// presentation step, order events by `timestamp_ns` — see
/// `callflow-schema::build_ladder_records_for_display` for the only
/// place that is allowed to do so, and the explicit comment at that
/// call site.
pub fn canonical_sort_key<'a>(event: &'a EventRecord) -> (&'a str, u64, &'a str) {
    (event.capture_id.as_str(), event.packet_number(), event.event_id.as_str())
}

pub fn deterministic_sort(events: &mut [EventRecord]) {
    events.sort_by(|a, b| canonical_sort_key(a).cmp(&canonical_sort_key(b)));
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
    attach_sbi_to_sessions(&events, &mut pdu_sessions, &mut event_context);

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
fn attach_sbi_to_sessions(
    events: &[EventRecord],
    pdu_sessions: &mut Vec<DiscoveredPduSession>,
    event_context: &mut BTreeMap<String, String>,
) {
    if pdu_sessions.is_empty() {
        return;
    }
    // Snapshot de lookup event_id → &EventRecord.
    let event_by_id: BTreeMap<_, _> = events
        .iter()
        .map(|event| (event.event_id.clone(), event))
        .collect();

    // Index (pseudo, pdu_session_id) → session_index.
    let mut pseudo_pdu: BTreeMap<(String, String), usize> = BTreeMap::new();
    // Index (tunnel_endpoint_ip_norm, gtp_teid_norm) → session_index.
    let mut tunnel_idx: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (idx, session) in pdu_sessions.iter().enumerate() {
        let pdu_id = session.pdu_session_id.clone();
        for event_id in &session.event_ids {
            let Some(event) = event_by_id.get(event_id).copied() else {
                continue;
            };
            if let Some(pseudo) = event.first_identifier("subscriber_pseudonym") {
                pseudo_pdu
                    .entry((pseudo.to_owned(), pdu_id.clone()))
                    .or_insert(idx);
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
        }
    }

    for event in events.iter().filter(|event| protocol_is(event, "SBI-HTTP2")) {
        if event_context.contains_key(&event.event_id) {
            continue;
        }
        let pdu_id = event.first_identifier("pdu_session_id").map(str::to_owned);
        let pseudo = event
            .first_identifier("subscriber_pseudonym")
            .map(str::to_owned);
        let mut target_idx: Option<usize> = None;
        if let (Some(pseudo), Some(pdu_id)) = (&pseudo, &pdu_id) {
            if let Some(&idx) = pseudo_pdu.get(&(pseudo.clone(), pdu_id.clone())) {
                target_idx = Some(idx);
            }
        }
        if target_idx.is_none() {
            let ip = event
                .first_identifier("tunnel_endpoint_ip")
                .map(event_schema::normalize_ip);
            let teid = event
                .first_identifier("gtp_teid")
                .and_then(event_schema::normalize_teid_hex);
            if let (Some(ip), Some(teid)) = (ip, teid) {
                if let Some(&idx) = tunnel_idx.get(&(ip, teid)) {
                    target_idx = Some(idx);
                }
            }
        }
        if let Some(idx) = target_idx {
            let session = &mut pdu_sessions[idx];
            session.event_ids.push(event.event_id.clone());
            if !session.interfaces.iter().any(|iface| iface == &event.interface) {
                session.interfaces.push(event.interface.clone());
                session.interfaces.sort();
            }
            event_context.insert(event.event_id.clone(), session.ue_context_id.clone());
        }
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
    tunnel_idx: &mut std::collections::BTreeMap<(String, String), usize>,
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
                        .or_insert(session_idx);
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
    fn streaming_index_retains_only_ids_and_compact_semantic_representatives() {
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
        assert_eq!(index.events.len(), 1, "one semantic state is retained");
        let representative = &index.events[0];
        assert_eq!(
            representative.event_id, "event-2",
            "latest observation wins"
        );
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
}
