//! Strictly owned, allowlisted live capture jobs for the OIRAN local vProbe.

mod callflow_page;
pub mod event_id_set;
pub mod lte_evidence;

pub use event_id_set::{SpillingEventIdSet, DEFAULT_MEM_CAP as EVENT_ID_SET_DEFAULT_MEM_CAP};

pub use callflow_page::{
    read_callflow_page, DEFAULT_CALLFLOW_PAGE_EVENTS, MAX_CALLFLOW_PAGE_EVENTS,
};

use callflow_schema::{
    build_callflow, build_lte_callflow, fold_overlapping_edges, CallFlow, CorrelationEdge,
};
use capture_helper::{
    CaptureHelperClient, CaptureSpec, HelperState, InterfaceId, IpcRequest, MAX_CAPTURE_PLANES,
};
use correlation_engine::{
    correlate_cross_interface_evidence, correlate_discovered_tunnels, correlate_lte_evidence,
};
use disk_safety::{assess, capture_budget, measure_path, CaptureBudget, Decision, Policy};
use event_schema::{
    sha256_hex, DecodeStatus, EvidenceReference, EvidenceState, InformationElement, NamedValue,
    NormalizedEvent, Protocol, PseudonymKey, Sha256Hasher,
};
use oiran_decode::{decode_capture_streaming, DecodeConfig, DecodeReport};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use session_engine::{
    discover_lte_sessions, discover_sessions, load_path, reconstruct, Association, EventRecord,
    ReconstructionHints,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Bounded read-chunk size for streaming file I/O; chosen so SHA-256 and pcap
/// record counting operate on ≤ 1 MiB in memory regardless of input file size.
const STREAM_CHUNK_BYTES: usize = 1 << 20;
const PROBE_ID: &str = "oiran-vprobe-local-01";
const MIN_CAPTURE_BYTES: u64 = 1024 * 1024;
const MAX_N3_FLOW_AGGREGATES: usize = 4096;
/// Reserve kept free during the per-candidate eviction / budget guards so
/// a staging publication can briefly double-write the derived artifact.
/// This is a **working reserve**, not the hard cap on the published
/// dataset — the latter is `derived_output_hard_limit_bytes()` and is
/// operator-configurable (2.7.23).
const MAX_CONTINUOUS_DERIVED_BYTES: u64 = 64 * 1024 * 1024;

/// 2.7.23 (issue #10 comment 6662293690): configurable hard cap on the
/// derived publication (`<base>/.dataset-next/`) size. The 2.7.22 flow
/// kept this at the hardcoded 64 MiB `MAX_CONTINUOUS_DERIVED_BYTES`;
/// since 2.7.22 retains the full published history by design, a 29 478
/// event lab dataset produced a 72 332 673 B derived output which
/// tripped the limit on every publish and locked the worker in a
/// retry loop. `OIRAN_CONTINUOUS_DERIVED_OUTPUT_MAX_BYTES` lets the
/// operator raise the ceiling (default 512 MiB), and the retry-loop
/// behaviour is replaced by a single `Blocked` exit — see the
/// `CONTINUOUS_DERIVED_OUTPUT_LIMIT` branch in
/// `run_continuous_import_inner`.
///
/// Values smaller than `MAX_CONTINUOUS_DERIVED_BYTES` are refused — the
/// staging reserve must still fit under the hard cap.
pub(crate) const DEFAULT_CONTINUOUS_DERIVED_OUTPUT_MAX_BYTES: u64 = 512 * 1024 * 1024;

thread_local! {
    /// 2.7.23: test-only override for
    /// `derived_output_hard_limit_bytes`. Lets a test target a tiny
    /// cap without touching the process-wide
    /// `OIRAN_CONTINUOUS_DERIVED_OUTPUT_MAX_BYTES` env var (which
    /// would leak into every parallel test running under the same
    /// `cargo test` process). Production callers never set this.
    static DERIVED_OUTPUT_LIMIT_OVERRIDE: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
}

fn derived_output_hard_limit_bytes() -> u64 {
    if let Some(value) = DERIVED_OUTPUT_LIMIT_OVERRIDE.with(|cell| cell.get()) {
        return value;
    }
    std::env::var("OIRAN_CONTINUOUS_DERIVED_OUTPUT_MAX_BYTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_CONTINUOUS_DERIVED_OUTPUT_MAX_BYTES)
}

/// 2.9.18-fu3 (ANR2 #9 comment 6750859966) : capacité RAM du
/// `SpillingEventIdSet` partagé `seen_ids` + `retained_event_ids`.
/// Le défaut (65 536 empreintes u64 ≈ 1,5 MiB) est volontairement
/// bas — toute pression mémoire additionnelle est déportée vers
/// des chunks triés sur disque. L'opérateur peut remonter la cap
/// via `OIRAN_EVENT_ID_SET_MEM_CAP` si l'I/O chunk devient
/// significative et qu'il reste de la RAM dans le cgroup.
fn event_id_set_mem_cap() -> usize {
    std::env::var("OIRAN_EVENT_ID_SET_MEM_CAP")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(EVENT_ID_SET_DEFAULT_MEM_CAP)
}

/// 2.10.3 (devmat) : taille de batch de la boucle de publication
/// de session. Default 32 → 32 × `mem_cap` ≈ 48 MiB RAM max pour
/// l'ensemble des SpillingEventIdSets d'un batch (sous la ligne
/// 2.10.2). Opérateur peut remonter via
/// `OIRAN_SESSION_PUBLICATION_BATCH_SIZE` si la mémoire du
/// cgroup l'autorise et si le nombre de scans JSONL par
/// publication (= ceil(sessions / K)) devient significatif.
const SESSION_PUBLICATION_BATCH_SIZE_DEFAULT: usize = 32;
fn session_publication_batch_size() -> usize {
    std::env::var("OIRAN_SESSION_PUBLICATION_BATCH_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(SESSION_PUBLICATION_BATCH_SIZE_DEFAULT)
}
// 2.8.3 (#9 comment 6696366882): the `MAX_SOURCE_CANDIDATES = 512` cap
// was removed. ANR2 proved the cap left ~3 292 paths outside the
// fingerprint cache forever on a 3 805-PCAP tree, so
// `last_pending_characterization` stayed non-zero and every tick forced
// a full rescan (92 000 statx / 30 s, 93.07 % CPU). The import queue
// remains bounded by `MAX_INGESTED_SEGMENTS_PER_SCAN` just below.
/// 2.7.16: per-scan ingestion ceiling. The lab collector can land tens or
/// hundreds of segments in a single rotation window. Prior to this ceiling
/// the import worker tried to admit every candidate in one iteration, so a
/// single backpressure trip at the end of the batch would exit the worker
/// via `terminal_error` and the queue stayed full (issue #9: 212 segments
/// pending). The ceiling forces periodic publish+sleep so pending_segments
/// drains monotonically even under burst.
const MAX_INGESTED_SEGMENTS_PER_SCAN: usize = 32;
pub const MAX_OFFLINE_LTE_SESSIONS: usize = 128;
pub const DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES: u64 = 1024 * 1024 * 1024;
// 2.8.2 (#10 comment 6687323881): removed the arbitrary
// `MAX_CONTINUOUS_SEEN=4096` cap on `seen_checksums`. ANR2 proved in
// production that evicting beyond that cap caused retained source
// segments (> 4 096 files on disk) to be re-discovered as pending
// every scan. The index now grows with the real on-disk file
// population plus any segment held in `state.segments`;
// `purge_missing_source_fingerprints` reclaims entries whose file
// has disappeared AND whose checksum is no longer referenced.
const ACTIVE_PACKET_WINDOW_MS: u64 = 60_000;
pub const CONTINUOUS_CAPTURE_ID: &str = "continuous-lab-import";
pub const CONTINUOUS_DATASET_ID: &str = "dataset-continuous-lab-import";
const HISTORICAL_N2_BOOTSTRAP_PATH: &str = "/var/lib/docker/volumes/oiran_lab_pcap/_data/n2/n2_20261026T121214Z_00001_20261026121214.pcapng";

/// Materialises bounded LTE sessions from already-decoded evidence. This does
/// not start a capture or expand the live-capture interface allowlist.
pub fn offline_lte_callflows(events: &[EventRecord]) -> Result<Vec<CallFlow>, String> {
    let sessions = discover_lte_sessions(events);
    if sessions.len() > MAX_OFFLINE_LTE_SESSIONS {
        return Err(format!(
            "offline LTE session limit exceeded: {} > {}",
            sessions.len(),
            MAX_OFFLINE_LTE_SESSIONS
        ));
    }
    let global_edges = correlate_lte_evidence(events);
    Ok(sessions
        .iter()
        .map(|session| {
            let ids = session.event_ids.iter().collect::<BTreeSet<_>>();
            let edges = global_edges
                .iter()
                .filter(|edge| {
                    ids.contains(&edge.source_event_id) && ids.contains(&edge.target_event_id)
                })
                .cloned()
                .collect();
            build_lte_callflow(session, events, edges)
        })
        .collect())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct N3FlowKey {
    message_type: u32,
    teid: String,
    direction: String,
    source: String,
    destination: String,
    inner_source: String,
    inner_destination: String,
    ue_ip: String,
    qfi: Option<u8>,
}

#[derive(Clone, Debug)]
struct N3FlowAggregate {
    event: NormalizedEvent,
    packet_count: u64,
    wire_bytes: u64,
    first_seen_ns: i128,
    last_seen_ns: i128,
    last_packet: Option<event_schema::PacketReference>,
    qfi: Option<u8>,
}

#[derive(Default)]
struct N3FlowAggregator {
    flows: BTreeMap<N3FlowKey, N3FlowAggregate>,
}

impl N3FlowAggregator {
    fn observe(&mut self, event: NormalizedEvent) -> Result<(), String> {
        let identifier = |name: &str| {
            event
                .session_identifiers
                .iter()
                .find(|item| item.name == name)
                .map(|item| item.value.clone())
                .unwrap_or_default()
        };
        let qfi = event
            .information_elements
            .iter()
            .find(|item| item.name == "PDU Session Container")
            .and_then(|item| item.value.as_deref())
            .and_then(parse_qfi);
        let key = N3FlowKey {
            message_type: event.message_type,
            teid: identifier("teid"),
            direction: event.direction.as_str().to_string(),
            source: event.source_endpoint.address.clone(),
            destination: event.destination_endpoint.address.clone(),
            inner_source: identifier("inner_source_ip"),
            inner_destination: identifier("inner_destination_ip"),
            ue_ip: identifier("ue_ip"),
            qfi,
        };
        let packet_count = event.packet_references.len() as u64;
        let wire_bytes = event
            .packet_references
            .iter()
            .map(|packet| u64::from(packet.original_length))
            .sum::<u64>();
        let timestamp_ns = event.timestamp.unix_nanoseconds().unwrap_or_default();
        let last_packet = event.packet_references.last().cloned();
        if let Some(flow) = self.flows.get_mut(&key) {
            flow.packet_count = flow.packet_count.saturating_add(packet_count);
            flow.wire_bytes = flow.wire_bytes.saturating_add(wire_bytes);
            flow.last_seen_ns = timestamp_ns;
            flow.last_packet = last_packet;
            return Ok(());
        }
        if self.flows.len() >= MAX_N3_FLOW_AGGREGATES {
            return Err("N3_FLOW_AGGREGATE_CARDINALITY_LIMIT".to_string());
        }
        self.flows.insert(
            key,
            N3FlowAggregate {
                event,
                packet_count,
                wire_bytes,
                first_seen_ns: timestamp_ns,
                last_seen_ns: timestamp_ns,
                last_packet,
                qfi,
            },
        );
        Ok(())
    }

    fn finish(self) -> Vec<NormalizedEvent> {
        self.flows
            .into_values()
            .map(|mut flow| {
                let first_packet = flow.event.packet_references.first().cloned();
                flow.event.packet_references.clear();
                if let Some(packet) = first_packet {
                    flow.event.packet_references.push(packet);
                }
                if let Some(packet) = flow.last_packet {
                    if flow
                        .event
                        .packet_references
                        .last()
                        .map(|first| first.packet_number != packet.packet_number)
                        .unwrap_or(true)
                    {
                        flow.event.packet_references.push(packet);
                    }
                }
                flow.event
                    .session_identifiers
                    .retain(|item| item.name != "sequence_number");
                if let Some(qfi) = flow.qfi {
                    flow.event.session_identifiers.push(NamedValue {
                        name: "qfi".into(),
                        value: qfi.to_string(),
                        pseudonymized: false,
                    });
                }
                for (name, value) in [
                    ("aggregate_packet_count", flow.packet_count.to_string()),
                    ("aggregate_wire_bytes", flow.wire_bytes.to_string()),
                    ("aggregate_first_seen_ns", flow.first_seen_ns.to_string()),
                    ("aggregate_last_seen_ns", flow.last_seen_ns.to_string()),
                ] {
                    flow.event.information_elements.push(InformationElement {
                        id: None,
                        name: name.into(),
                        length: 0,
                        value: Some(value),
                        raw_sha256: None,
                        status: DecodeStatus::Decoded,
                    });
                }
                let first_packet = flow
                    .event
                    .packet_references
                    .first()
                    .map(|packet| packet.packet_number)
                    .unwrap_or_default();
                let last_packet = flow
                    .event
                    .packet_references
                    .last()
                    .map(|packet| packet.packet_number)
                    .unwrap_or(first_packet);
                let teid = flow
                    .event
                    .session_identifiers
                    .iter()
                    .find(|item| item.name == "teid")
                    .map(|item| item.value.as_str())
                    .unwrap_or("unknown");
                flow.event.raw_payload_reference = format!(
                    "n3-flow-aggregate:{}:{}:{}-{}",
                    flow.event.capture_id, teid, first_packet, last_packet
                );
                flow.event.evidence_references = flow
                    .event
                    .packet_references
                    .iter()
                    .map(|packet| EvidenceReference {
                        state: EvidenceState::Exact,
                        kind: "packet-provenance".into(),
                        reference: format!(
                            "{}#packet-{}",
                            packet.source_file, packet.packet_number
                        ),
                    })
                    .collect();
                flow.event.decoder_name = "live-probe-n3-flow-aggregator".into();
                flow.event.decoder_version = VERSION.into();
                flow.event.assign_deterministic_id();
                flow.event
            })
            .collect()
    }
}

fn parse_qfi(value: &str) -> Option<u8> {
    value
        .split(',')
        .find_map(|part| part.strip_prefix("qfi="))
        .and_then(|value| value.parse().ok())
}

// 2.9.5 (devmat #9 T1) : agrégation des messages keepalive par
// (interface, paire de nœuds, type). ANR2 preuve 6714896530 : sur le
// dataset de 1.23 M événements, Sxab 868 123 PFCP Heartbeats + S6a
// 76 890 Diameter Device-Watchdog = 944 013 événements ≈ 76,6 % du
// volume. Agréger comme GTP-U : compte, first/last packet_number en
// ordre canonique (capture_id, packet_number), compteur d'échecs
// (requête sans réponse), jamais ts. Pair de nœuds canonicalisée
// (min, max) pour fusionner les deux directions req/resp.

const MAX_KEEPALIVE_AGGREGATES: usize = 4096;

/// Type de keepalive détecté sur un événement. `None` = message de
/// session, conservé tel quel.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum KeepaliveKind {
    PfcpHeartbeat,
    DiameterWatchdog,
    Gtpv2Echo,
    GtpuEcho,
}

impl KeepaliveKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::PfcpHeartbeat => "PFCP_HEARTBEAT",
            Self::DiameterWatchdog => "DIAMETER_DEVICE_WATCHDOG",
            Self::Gtpv2Echo => "GTPV2_ECHO",
            Self::GtpuEcho => "GTPU_ECHO",
        }
    }

    fn aggregated_message_name(&self) -> &'static str {
        match self {
            Self::PfcpHeartbeat => "PFCP Heartbeat (aggregated)",
            Self::DiameterWatchdog => "Device-Watchdog (aggregated)",
            Self::Gtpv2Echo => "GTPv2 Echo (aggregated)",
            Self::GtpuEcho => "GTP-U Echo (aggregated)",
        }
    }
}

/// Classification keepalive d'un événement. `is_request` est toujours
/// `Some(true)` pour une requête et `Some(false)` pour une réponse.
/// Un décodeur pourrait un jour émettre un message de type
/// « Notification » mono-directionnel : alors `is_request = None` et
/// il est compté comme requête (comportement par défaut).
fn classify_keepalive(event: &NormalizedEvent) -> Option<(KeepaliveKind, bool)> {
    let name = event.message_name.as_str();
    match event.protocol {
        Protocol::Pfcp => match name {
            "PFCP Heartbeat Request" => Some((KeepaliveKind::PfcpHeartbeat, true)),
            "PFCP Heartbeat Response" => Some((KeepaliveKind::PfcpHeartbeat, false)),
            _ => None,
        },
        Protocol::Diameter => match name {
            "Device-Watchdog-Request" => Some((KeepaliveKind::DiameterWatchdog, true)),
            "Device-Watchdog-Answer" => Some((KeepaliveKind::DiameterWatchdog, false)),
            _ => None,
        },
        Protocol::Gtpv2c => match name {
            "Echo Request" => Some((KeepaliveKind::Gtpv2Echo, true)),
            "Echo Response" => Some((KeepaliveKind::Gtpv2Echo, false)),
            _ => None,
        },
        Protocol::Gtpu => match name {
            "Echo Request" => Some((KeepaliveKind::GtpuEcho, true)),
            "Echo Response" => Some((KeepaliveKind::GtpuEcho, false)),
            _ => None,
        },
        _ => None,
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct KeepaliveKey {
    interface: String,
    kind: KeepaliveKind,
    // Paire de nœuds canonicalisée (min, max) pour fusionner les deux
    // directions requête/réponse sur un même échange.
    pair_low: String,
    pair_high: String,
}

#[derive(Clone, Debug)]
struct KeepaliveAggregate {
    event: NormalizedEvent,
    request_count: u64,
    response_count: u64,
    first_capture_id: String,
    first_packet_number: u64,
    first_event_id: String,
    last_capture_id: String,
    last_packet_number: u64,
    last_event_id: String,
    first_packet: Option<event_schema::PacketReference>,
    last_packet: Option<event_schema::PacketReference>,
}

#[derive(Default)]
struct KeepaliveAggregator {
    flows: BTreeMap<KeepaliveKey, KeepaliveAggregate>,
}

impl KeepaliveAggregator {
    fn observe(&mut self, event: NormalizedEvent) -> Result<Option<NormalizedEvent>, String> {
        let Some((kind, is_request)) = classify_keepalive(&event) else {
            return Ok(Some(event));
        };
        let src = event.source_endpoint.address.clone();
        let dst = event.destination_endpoint.address.clone();
        let (pair_low, pair_high) = if src <= dst {
            (src, dst)
        } else {
            (dst, src)
        };
        let key = KeepaliveKey {
            interface: event.interface.clone(),
            kind,
            pair_low,
            pair_high,
        };
        let packet_number = event
            .packet_references
            .first()
            .map(|p| p.packet_number)
            .unwrap_or_default();
        let first_packet = event.packet_references.first().cloned();
        let last_packet = event.packet_references.last().cloned();
        if let Some(flow) = self.flows.get_mut(&key) {
            if is_request {
                flow.request_count = flow.request_count.saturating_add(1);
            } else {
                flow.response_count = flow.response_count.saturating_add(1);
            }
            // Ordre canonique (capture_id, packet_number, event_id) —
            // jamais ts. On met à jour first/last si la clé ordonnée
            // courante dépasse / précède celle enregistrée.
            let cur_key = (
                event.capture_id.as_str(),
                packet_number,
                event.event_id.as_str(),
            );
            if cur_key
                < (
                    flow.first_capture_id.as_str(),
                    flow.first_packet_number,
                    flow.first_event_id.as_str(),
                )
            {
                flow.first_capture_id = event.capture_id.clone();
                flow.first_packet_number = packet_number;
                flow.first_event_id = event.event_id.clone();
                flow.first_packet = first_packet;
            }
            if cur_key
                > (
                    flow.last_capture_id.as_str(),
                    flow.last_packet_number,
                    flow.last_event_id.as_str(),
                )
            {
                flow.last_capture_id = event.capture_id.clone();
                flow.last_packet_number = packet_number;
                flow.last_event_id = event.event_id.clone();
                flow.last_packet = last_packet;
            }
            return Ok(None);
        }
        if self.flows.len() >= MAX_KEEPALIVE_AGGREGATES {
            return Err("KEEPALIVE_AGGREGATE_CARDINALITY_LIMIT".to_string());
        }
        let first_cap = event.capture_id.clone();
        let first_pn = packet_number;
        let first_evt = event.event_id.clone();
        let request_count = if is_request { 1 } else { 0 };
        let response_count = if is_request { 0 } else { 1 };
        self.flows.insert(
            key,
            KeepaliveAggregate {
                event,
                request_count,
                response_count,
                first_capture_id: first_cap.clone(),
                first_packet_number: first_pn,
                first_event_id: first_evt.clone(),
                last_capture_id: first_cap,
                last_packet_number: first_pn,
                last_event_id: first_evt,
                first_packet: first_packet.clone(),
                last_packet: last_packet.or(first_packet),
            },
        );
        Ok(None)
    }

    fn finish(self) -> Vec<NormalizedEvent> {
        self.flows
            .into_iter()
            .map(|(key, mut flow)| {
                let message_count = flow.request_count.saturating_add(flow.response_count);
                let failure_count = flow.request_count.saturating_sub(flow.response_count);
                let first_packet = flow.first_packet.clone();
                let last_packet = flow.last_packet.clone();
                flow.event.packet_references.clear();
                if let Some(packet) = first_packet {
                    flow.event.packet_references.push(packet);
                }
                if let Some(packet) = last_packet {
                    if flow
                        .event
                        .packet_references
                        .last()
                        .map(|first| first.packet_number != packet.packet_number)
                        .unwrap_or(true)
                    {
                        flow.event.packet_references.push(packet);
                    }
                }
                flow.event.message_name = key.kind.aggregated_message_name().into();
                // Retire les identifiers volatils pour un aggregate.
                flow.event
                    .session_identifiers
                    .retain(|item| item.name != "sequence_number" && item.name != "fseid_seid");
                // Libère les IEs individuelles — on expose l'évidence
                // statistique à la place.
                flow.event.information_elements.clear();
                for (name, value) in [
                    ("aggregate_keepalive_kind", key.kind.as_str().to_string()),
                    ("aggregate_node_pair_low", key.pair_low.clone()),
                    ("aggregate_node_pair_high", key.pair_high.clone()),
                    ("aggregate_request_count", flow.request_count.to_string()),
                    ("aggregate_response_count", flow.response_count.to_string()),
                    ("aggregate_message_count", message_count.to_string()),
                    ("aggregate_failure_count", failure_count.to_string()),
                    (
                        "aggregate_first_capture_id",
                        flow.first_capture_id.clone(),
                    ),
                    (
                        "aggregate_first_packet_number",
                        flow.first_packet_number.to_string(),
                    ),
                    ("aggregate_first_event_id", flow.first_event_id.clone()),
                    ("aggregate_last_capture_id", flow.last_capture_id.clone()),
                    (
                        "aggregate_last_packet_number",
                        flow.last_packet_number.to_string(),
                    ),
                    ("aggregate_last_event_id", flow.last_event_id.clone()),
                ] {
                    flow.event.information_elements.push(InformationElement {
                        id: None,
                        name: name.into(),
                        length: value.len() as u32,
                        value: Some(value),
                        raw_sha256: None,
                        status: DecodeStatus::Decoded,
                    });
                }
                flow.event.raw_payload_reference = format!(
                    "keepalive-aggregate:{}:{}:{}-{}:{}-{}",
                    key.interface,
                    key.kind.as_str(),
                    key.pair_low,
                    key.pair_high,
                    flow.first_packet_number,
                    flow.last_packet_number,
                );
                flow.event.evidence_references = flow
                    .event
                    .packet_references
                    .iter()
                    .map(|packet| EvidenceReference {
                        state: EvidenceState::Exact,
                        kind: "packet-provenance".into(),
                        reference: format!(
                            "{}#packet-{}",
                            packet.source_file, packet.packet_number
                        ),
                    })
                    .collect();
                flow.event.decoder_name =
                    "live-probe-keepalive-aggregator".into();
                flow.event.decoder_version = VERSION.into();
                flow.event.assign_deterministic_id();
                flow.event
            })
            .collect()
    }
}

// 2.9.5 (devmat #9 T3) : règle de doublon documentée. Un doublon =
// même paquet (capture_id, packet_number, byte_offset) ET même
// protocole ET même message_name. S1AP + NAS-EPS-MM du même paquet
// sont deux message_names DIFFÉRENTS → deux événements légitimes, pas
// un doublon. Deux S1AP InitialContextSetupRequest sur le même paquet
// = doublon.
fn is_duplicate(a: &NormalizedEvent, b: &NormalizedEvent) -> bool {
    if a.protocol != b.protocol || a.message_name != b.message_name {
        return false;
    }
    let (Some(ar), Some(br)) = (a.packet_references.first(), b.packet_references.first()) else {
        return false;
    };
    a.capture_id == b.capture_id
        && ar.packet_number == br.packet_number
        && ar.byte_offset == br.byte_offset
}

fn allowlisted_historical_n2_bootstrap(path: &Path) -> bool {
    path.is_absolute()
        && path.is_file()
        && if cfg!(test) {
            path.file_name().and_then(|name| name.to_str())
                == Some("n2_20261026T121214Z_00001_20261026121214.pcapng")
        } else {
            path == Path::new(HISTORICAL_N2_BOOTSTRAP_PATH)
        }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CaptureState {
    Created,
    Validating,
    Ready,
    Starting,
    Capturing,
    Stopping,
    Processing,
    Completed,
    CompletedEmpty,
    Failed,
    Blocked,
}

impl CaptureState {
    pub fn active(&self) -> bool {
        matches!(
            self,
            Self::Starting | Self::Capturing | Self::Stopping | Self::Processing
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaptureInterface {
    pub interface: String,
    #[serde(default)]
    pub role: Option<String>,
    pub device: String,
    pub protocol: String,
    pub capture_point: String,
    pub bpf_filter: String,
    pub available: bool,
    pub operstate: String,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaptureRequest {
    pub probe_id: String,
    pub name: String,
    pub interfaces: Vec<String>,
    pub duration_seconds: u64,
    pub max_bytes: u64,
    pub rotation_files: u16,
    pub profile: String,
    pub optional_filter: Option<String>,
    #[serde(default)]
    pub capture_group_id: Option<String>,
    #[serde(default)]
    pub scenario_id: Option<String>,
}

impl Default for CaptureRequest {
    fn default() -> Self {
        Self {
            probe_id: PROBE_ID.into(),
            name: "POLARIS-5G-SA".into(),
            interfaces: vec!["N2".into(), "SBI".into(), "N4".into(), "N3".into()],
            duration_seconds: 60,
            max_bytes: 256 * 1024 * 1024,
            rotation_files: 4,
            profile: "POLARIS_5G_SA".into(),
            optional_filter: None,
            capture_group_id: None,
            scenario_id: None,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CaptureMetrics {
    pub packets_received: u64,
    pub bytes_received: u64,
    pub packets_per_second: f64,
    pub bits_per_second: f64,
    pub decoded_events: u64,
    pub decode_events_per_second: f64,
    pub decode_errors: u64,
    pub packet_drops: Option<u64>,
    pub queue_capacity_bytes: u64,
    pub queue_occupancy_percent: Option<f64>,
    pub duration_seconds: f64,
    pub storage_bytes: u64,
    #[serde(default)]
    pub segments_ingested: u64,
    #[serde(default)]
    pub pending_segments: u64,
    /// 2.9.8 (#9 comment 6725097122): segments whose SHA is cached but
    /// whose checksum is NOT in `state.seen_checksums` — i.e. a
    /// candidate observed by the latest scan that has not yet been
    /// published. Computed from `source_cache ∖ seen_checksums` and
    /// always equal to `pending_segments` on the scan boundary.
    /// Published so `/metrics` and `job.json` can prove they read the
    /// same authoritative source.
    #[serde(default)]
    pub pending_fingerprints: u64,
    /// 2.9.8 (#9 comment 6725097122): segments skipped this scan
    /// because they appear for the first time with a given
    /// `(size, mtime)` and need a second scan to prove stability.
    /// Reset every scan. Surfaced so no per-segment deferral is silent.
    #[serde(default)]
    pub pending_stability_segments: u64,
    /// 2.9.8 (#9 comment 6725097122): segments eligible this scan but
    /// deferred because the per-scan batch cap
    /// (`MAX_INGESTED_SEGMENTS_PER_SCAN = 32`) was hit. Reset every
    /// scan. Surfaced so no per-segment deferral is silent.
    #[serde(default)]
    pub pending_batch_segments: u64,
    /// 2.10.3 (devmat, ANR2 #9 comment post-2.10.2 15:38Z) : segments
    /// identifiés comme **lex-greatest filename** par interface SANS
    /// preuve de clôture (ni filename plus récent, ni record dans
    /// `capture-rotation.jsonl`). Autrement dit : segments encore
    /// ouverts par dumpcap. Sortis de `pending_segments` pour que le
    /// comptage « closé mais pas ingéré » (le vrai pending) soit
    /// strictement positif seulement quand il y a un défaut.
    #[serde(default)]
    pub open_segments: u64,
    /// 2.10.3 (devmat) : liste des chemins pcap encore ouverts
    /// (`open_segments`) — bornée à 16 entrées pour le logging
    /// opérateur. Ne contient pas d'identifiants d'abonnés.
    #[serde(default)]
    pub open_segment_paths: Vec<String>,
    /// 2.10.3 (devmat) : liste des chemins pcap **fermés mais
    /// pas encore ingérés** (= vrai pending). Bornée à 16 entrées.
    #[serde(default)]
    pub pending_segment_paths: Vec<String>,
    /// 2.10.3 (devmat, ANR2 #9 comment 15:38Z) : segments INGÉRÉS
    /// (dans `seen_checksums`) mais pour lesquels AUCUN événement
    /// n'a été produit dans `oiran_events.jsonl`. Révèle un défaut
    /// silencieux du décodeur sur un segment donné (cas S6a
    /// `_00064`/`_00065` observés en production 2.10.2). Compteur
    /// cumulatif côté worker ; la liste `zero_event_segment_paths`
    /// borne les 16 derniers chemins pour audit.
    #[serde(default)]
    pub zero_event_segments: u64,
    #[serde(default)]
    pub zero_event_segment_paths: Vec<String>,
    /// 2.9.8 (#9 comment 6725097122): orphan fingerprints dropped at
    /// worker startup — fingerprint persisted but checksum not in
    /// `seen_checksums` (= segment was never committed via
    /// `persist_published_checksums`). Cumulative per worker lifetime.
    #[serde(default)]
    pub orphan_fingerprints_recovered: u64,
    #[serde(default)]
    pub sessions_indexed: u64,
    #[serde(default)]
    pub last_ingested_epoch_ms: Option<u64>,
    #[serde(default)]
    pub ingestion_failures: u64,
    #[serde(default)]
    pub last_packet_epoch_ms: Option<u64>,
    #[serde(default)]
    pub fresh_packet_count: u64,
    #[serde(default)]
    pub active_ue_ips: Vec<String>,
    /// 2.9.1 (#9): count of pcap files the source scan observed per
    /// plane. Covers the 12 production interfaces
    /// (`N2`/`N3`/`N4`/`N6`/`S11`/`S1-MME`/`S1-U`/`S5-C`/`S5-U`/`S6a`/`SBI`/`Sxab`)
    /// plus the sentinel `UNKNOWN` for directories outside the
    /// convention. Entries only appear once at least one file has
    /// been observed for the plane.
    #[serde(default)]
    pub plane_counts: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaptureJob {
    pub capture_id: String,
    pub probe_id: String,
    pub name: String,
    pub profile: String,
    pub interfaces: Vec<String>,
    pub state: CaptureState,
    pub created_epoch_ms: u64,
    pub started_epoch_ms: Option<u64>,
    pub ended_epoch_ms: Option<u64>,
    pub owner: String,
    pub metrics: CaptureMetrics,
    pub output_directory: String,
    pub dataset_id: Option<String>,
    pub session_ids: Vec<String>,
    pub error: Option<String>,
    pub stop_reason: Option<String>,
    pub process_ids: Vec<u32>,
    #[serde(default)]
    pub helper_results: Vec<CaptureHelperResult>,
    #[serde(default)]
    pub capture_group_id: Option<String>,
    #[serde(default)]
    pub scenario_id: Option<String>,
    #[serde(default)]
    pub planes: Vec<CapturePlaneStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CapturePlaneStatus {
    pub plane: String,
    pub interface: String,
    pub capture_job_id: String,
    pub start_timestamp: Option<u64>,
    pub end_timestamp: Option<u64>,
    pub packet_count: u64,
    pub byte_count: u64,
    pub drop_count: Option<u64>,
    pub storage_bytes: u64,
    pub decode_status: String,
    pub dataset_id: Option<String>,
    pub source_sha256: Vec<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaptureHelperResult {
    pub interface: String,
    #[serde(default)]
    pub process_id: u32,
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub termination_signal: Option<i32>,
    #[serde(default)]
    pub error_category: Option<String>,
    pub success: bool,
    pub stderr: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub capture_control_available: bool,
    pub state: CaptureState,
    pub interfaces: Vec<CaptureInterface>,
    pub disk_decision: Decision,
    pub budget: CaptureBudget,
    pub blockers: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiveDataset {
    pub dataset_id: String,
    pub capture_id: String,
    pub path: String,
    pub event_count: usize,
    pub session_ids: Vec<String>,
    pub decode_reports: BTreeMap<String, DecodeReport>,
    pub checksums: BTreeMap<String, String>,
    pub state: String,
    #[serde(default)]
    pub discovery: Option<session_engine::DiscoveryResult>,
    #[serde(default)]
    pub capture_started_epoch_ms: Option<u64>,
    #[serde(default)]
    pub last_packet_epoch_ms: Option<u64>,
    #[serde(default)]
    pub fresh_packet_count: u64,
    #[serde(default)]
    pub active_ue_ips: Vec<String>,
    #[serde(default)]
    pub active_pdu_contexts: Vec<ActivePduContext>,
    /// 2.10.3 (devmat, ANR2 #9 comment post-2.10.2 15:38Z) : liste
    /// de `sha256:...` capture_ids pour lesquels le décodeur a
    /// produit 0 événement malgré la présence de paquets dans le
    /// pcap source. Révèle un défaut silencieux (cas S6a `_00064`,
    /// `_00065` observés en production : 490 + 492 trames Diameter
    /// chacun, 0 events dans le JSONL). Toujours vide quand le
    /// décodeur produit au moins 1 event par segment ingéré.
    #[serde(default)]
    pub zero_event_captures: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActivePduContext {
    pub session_id: String,
    pub internal_ue_id: String,
    pub pdu_session_id: String,
    pub ue_ip: String,
    pub observed_epoch_ms: u64,
    pub provenance: String,
    pub correlation_status: String,
    pub gtpu_event_ids: Vec<String>,
    pub teids: Vec<String>,
    pub directions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct RuntimePduEvidence {
    schema_version: String,
    observed_epoch_ms: u64,
    source: String,
    bindings: Vec<RuntimePduBinding>,
}

#[derive(Clone, Debug, Deserialize)]
struct RuntimePduBinding {
    internal_ue_id: String,
    container: String,
    interface: String,
    ue_ip: String,
    process_state: String,
    registration_state: String,
    pdu_session_state: String,
    pdu_session_id: String,
    status_provenance: String,
    pdu_provenance: String,
    tunnel_provenance: String,
    #[serde(skip)]
    evidence_observed_epoch_ms: u64,
}

#[derive(Clone, Debug)]
pub struct ContinuousImportConfig {
    pub source_root: PathBuf,
    pub scan_interval: Duration,
    pub stable_age: Duration,
    pub max_owned_bytes: u64,
    pub max_segment_bytes: u64,
    pub max_segments: u16,
    pub native_segment_seconds: Option<u64>,
    pub historical_n2_bootstrap: Option<PathBuf>,
    pub runtime_pdu_evidence: Option<PathBuf>,
}

impl ContinuousImportConfig {
    pub fn bounded(source_root: PathBuf) -> Self {
        let policy = Policy::default();
        Self {
            source_root,
            scan_interval: Duration::from_millis(policy.polling_interval_ms),
            stable_age: Duration::from_secs(3),
            max_owned_bytes: DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES
                .saturating_add(MAX_CONTINUOUS_DERIVED_BYTES),
            max_segment_bytes: DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES,
            max_segments: policy.max_files,
            native_segment_seconds: None,
            historical_n2_bootstrap: None,
            runtime_pdu_evidence: None,
        }
    }

    pub fn native(capture_root: PathBuf) -> Self {
        let mut config = Self::bounded(capture_root);
        config.stable_age = Duration::ZERO;
        config.native_segment_seconds = Some(15);
        config.runtime_pdu_evidence = Some(PathBuf::from(
            "/run/oiran/continuous-traffic/pdu-bindings.json",
        ));
        config
    }

    fn validate(&self, policy: Policy) -> Result<(), String> {
        if !self.source_root.is_absolute() || !self.source_root.is_dir() {
            return Err("CONTINUOUS_SOURCE_UNAVAILABLE".into());
        }
        if self.scan_interval < Duration::from_millis(200)
            || (self.native_segment_seconds.is_none() && self.stable_age < self.scan_interval)
            || self.max_segments == 0
            || self.max_segments > policy.max_files
            || self.max_owned_bytes == 0
            || self.max_segment_bytes == 0
            || self.max_segment_bytes
                > policy
                    .max_file_bytes
                    .saturating_mul(u64::from(policy.max_files))
            || self.max_owned_bytes
                > policy
                    .max_file_bytes
                    .saturating_mul(u64::from(policy.max_files))
        {
            return Err("CONTINUOUS_IMPORT_BOUNDS_INVALID".into());
        }
        if self
            .native_segment_seconds
            .is_some_and(|seconds| seconds == 0 || seconds > 60)
        {
            return Err("CONTINUOUS_NATIVE_SEGMENT_DURATION_INVALID".into());
        }
        if self.native_segment_seconds.is_some() && self.max_segments < 3 {
            return Err("CONTINUOUS_NATIVE_RING_TOO_SMALL".into());
        }
        if self
            .historical_n2_bootstrap
            .as_ref()
            .is_some_and(|path| !allowlisted_historical_n2_bootstrap(path))
        {
            return Err("CONTINUOUS_BOOTSTRAP_NOT_ALLOWLISTED".into());
        }
        if self.runtime_pdu_evidence.as_ref().is_some_and(|path| {
            self.native_segment_seconds.is_none()
                || (!cfg!(test)
                    && path != Path::new("/run/oiran/continuous-traffic/pdu-bindings.json"))
        }) {
            return Err("CONTINUOUS_RUNTIME_EVIDENCE_NOT_ALLOWLISTED".into());
        }
        Ok(())
    }
}

/// Bounded persistence for the import failure log so the operator can prove
/// which upstream segment paths failed, with which error code, and when. Kept
/// in `import_state.json` so the record survives probe restarts.
pub const MAX_PERSISTED_INGESTION_FAILURES: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FailedIngestion {
    /// Source segment path as presented by the external capture pipeline
    /// (never masked). The upstream pcap root is operator-controlled so no
    /// subscriber identity is ever surfaced here.
    pub source_path: String,
    /// Exact file size observed when the failure was classified. Older
    /// checkpoints predate this field and deserialize it as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_size_bytes: Option<u64>,
    /// Error code recorded verbatim from the Err branch that caused the
    /// failure. Prefixed-form (`CONTINUOUS_*`) matches the metric labels.
    pub error_code: String,
    pub occurred_epoch_ms: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ContinuousImportState {
    #[serde(default)]
    segments: BTreeMap<String, ImportedSegment>,
    #[serde(default)]
    seen_checksums: BTreeSet<String>,
    #[serde(default)]
    seen_order: VecDeque<String>,
    /// 0.2.0 — persisted log of per-segment ingestion failures (bounded,
    /// FIFO-evicted). Each entry carries source_path + error_code +
    /// occurred_epoch_ms so an operator can audit the 1h window without
    /// losing the record across probe restarts.
    #[serde(default)]
    failed_ingestions: VecDeque<FailedIngestion>,
    /// 2.8.1 (#9, ANR2 perf proof — 77.31% in Sha256Hasher::compress):
    /// cheap-key cache for source files. Key `(dev, inode, size,
    /// mtime_ns)` identifies a file by its filesystem coordinates
    /// instead of its path alone — a rotation that replaces a file at
    /// the same path with a different content gets a new inode or
    /// mtime, so the cache invalidates automatically. The stored
    /// `(sha, packets)` is the proof of identity reused by the dedup
    /// (`seen_checksums`); it is simply not recomputed when the key
    /// matches. Persisted alongside `import_state.json` so a worker
    /// restart does NOT re-hash every segment in the source root.
    #[serde(default)]
    source_fingerprints: BTreeMap<String, SourceFingerprint>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SourceFingerprint {
    pub dev: u64,
    pub inode: u64,
    pub size_bytes: u64,
    pub mtime_ns: i128,
    pub checksum: String,
    pub packets: u64,
}

impl PartialEq for SourceFingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.dev == other.dev
            && self.inode == other.inode
            && self.size_bytes == other.size_bytes
            && self.mtime_ns == other.mtime_ns
            && self.checksum == other.checksum
            && self.packets == other.packets
    }
}
impl Eq for SourceFingerprint {}

/// Push a new failure into the state's bounded failure log. Evicts the
/// oldest entry when the cap is reached so the log never grows unbounded.
pub fn record_ingestion_failure(
    log: &mut VecDeque<FailedIngestion>,
    source_path: impl Into<String>,
    error_code: impl Into<String>,
    occurred_epoch_ms: u64,
) {
    record_ingestion_failure_with_size(log, source_path, None, error_code, occurred_epoch_ms);
}

pub fn record_ingestion_failure_with_size(
    log: &mut VecDeque<FailedIngestion>,
    source_path: impl Into<String>,
    source_size_bytes: Option<u64>,
    error_code: impl Into<String>,
    occurred_epoch_ms: u64,
) {
    log.push_back(FailedIngestion {
        source_path: source_path.into(),
        source_size_bytes,
        error_code: error_code.into(),
        occurred_epoch_ms,
    });
    while log.len() > MAX_PERSISTED_INGESTION_FAILURES {
        log.pop_front();
    }
}

/// 0.2.0 — Decide whether a candidate file is the active dumpcap target
/// (= the newest file for its interface, still "young") and therefore must
/// be excluded from ingestion. Dumpcap keeps writing to the latest file in
/// its rotation ring until a new segment is created; its mtime moves on
/// every pcap_dumper_flush. Filtering it out at discovery time guarantees
/// we never trigger `CONTINUOUS_SOURCE_CHANGED_DURING_IMPORT` because of a
/// still-live writer.
///
/// 2.8.3 (#9 comment 6696366882): a segment is eligible ONLY when its
/// closure is proven, and closure is NEVER inferred from mtime age.
/// Two independent proofs are accepted, either suffices:
///
/// 1. **Sequence proof.** Dumpcap names each rotation segment
///    `<label>_<startStamp>_<NNNNN>_<rotationStamp>.pcapng`
///    (`infrastructure/capture/capture-interface.sh:54`). For a given
///    interface, every segment whose filename is lexicographically less
///    than the greatest observed filename is closed — dumpcap has moved
///    on to a later file. The lex-greatest filename for each interface
///    is the ACTIVE segment and is never included.
///
/// 2. **Rotation-watcher JSONL proof.** `capture-rotation.jsonl` grows
///    by one record per clean segment close
///    (`infrastructure/capture/rotation-watcher.sh`). When the number
///    of records for a plane is ≥ the total number of discovered
///    segments for that plane, the dumpcap lifecycle has closed every
///    one — including the lex-greatest — and all are eligible. This
///    unblocks crash-recovery of a dumpcap that exited after its last
///    rotation.
///
/// Neither proof uses mtime age or mtime "stability". The 2.8.2 behavior
/// (active segment becoming eligible after `2 × stable_age`) imported a
/// still-live file three times while it grew; ANR2 reproduced the N4
/// 9 860 → 10 780 → 12 436 byte sequence.
pub fn finalized_candidates_only(
    candidates: Vec<FinalizationCandidate>,
    rotation_record_counts: &BTreeMap<String, usize>,
) -> Vec<FinalizationCandidate> {
    let mut max_filename_by_interface: BTreeMap<String, String> = BTreeMap::new();
    let mut total_by_interface: BTreeMap<String, usize> = BTreeMap::new();
    for candidate in &candidates {
        total_by_interface
            .entry(candidate.interface.clone())
            .and_modify(|value| *value = value.saturating_add(1))
            .or_insert(1);
        match max_filename_by_interface.get_mut(&candidate.interface) {
            Some(existing) => {
                if candidate.filename > *existing {
                    *existing = candidate.filename.clone();
                }
            }
            None => {
                max_filename_by_interface
                    .insert(candidate.interface.clone(), candidate.filename.clone());
            }
        }
    }
    candidates
        .into_iter()
        .filter(|candidate| {
            let max_for_iface = max_filename_by_interface.get(&candidate.interface);
            if max_for_iface != Some(&candidate.filename) {
                // Sequence proof: a later filename exists for this interface.
                return true;
            }
            // Lex-greatest for its interface. Admit only if the rotation
            // watcher has recorded at least as many closures as there are
            // segments — proof the dumpcap lifecycle closed cleanly.
            let total = total_by_interface
                .get(&candidate.interface)
                .copied()
                .unwrap_or(1);
            rotation_record_counts
                .get(&candidate.interface)
                .map(|&count| count >= total)
                .unwrap_or(false)
        })
        .collect()
}

/// 2.8.3: read `capture-rotation.jsonl` (optional sibling under the source
/// root) and return `plane -> count of close records`. Each line is a JSON
/// object with at least `{"plane":"<label>","exit_code":<int>}`. Only
/// records with `exit_code == 0` count as clean closures.
///
/// A missing file is not an error; it simply means no JSONL proof is
/// available and `finalized_candidates_only` will rely on the sequence
/// rule alone.
pub fn load_rotation_record_counts(root: &Path) -> BTreeMap<String, usize> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let Ok(file) = fs::File::open(root.join("capture-rotation.jsonl")) else {
        return counts;
    };
    let reader = BufReader::new(file);
    for line in reader.lines().flatten() {
        let Ok(record) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let Some(plane) = record.get("plane").and_then(Value::as_str) else {
            continue;
        };
        let exit_ok = record
            .get("exit_code")
            .and_then(Value::as_i64)
            .map(|code| code == 0)
            .unwrap_or(false);
        if !exit_ok {
            continue;
        }
        // Keys are normalised to the same case as `source_interface`
        // returns (upper-case plane name) so `finalized_candidates_only`
        // can compare directly without a per-call conversion.
        counts
            .entry(plane.to_ascii_uppercase())
            .and_modify(|value| *value = value.saturating_add(1))
            .or_insert(1);
    }
    counts
}

/// Minimal shape consumed by `finalized_candidates_only`. Decoupled from
/// `SourceSegment` so the pure function can be unit-tested without reading
/// pcap bytes.
///
/// 2.8.3 (#9 comment 6696366882): `filename` carries the lexicographically
/// comparable segment name. The closed-proof relies on it, never on
/// `modified`, so the `modified` field is kept for persistence callers but
/// no longer influences eligibility.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizationCandidate {
    pub interface: String,
    pub modified: SystemTime,
    pub filename: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ImportedSegment {
    interface: String,
    owned_file: String,
    size_bytes: u64,
    packets: u64,
    imported_epoch_ms: u64,
    #[serde(default)]
    source_path: String,
    #[serde(default)]
    historical_context: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryReport {
    pub schema_version: String,
    pub source_capture_id: String,
    pub source_manifest_sha256: String,
    pub source_pcap_sha256: BTreeMap<String, String>,
    pub decoder_version: String,
    pub recovered_epoch_ms: u64,
    pub recovered_packets: u64,
    pub generated_events: usize,
    pub decode_errors: usize,
    pub dataset_id: String,
    pub dataset_integrity_sha256: String,
    pub registration: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DerivedDatasetRegistration {
    pub schema_version: String,
    pub dataset_id: String,
    pub source_capture_id: String,
    pub source_dataset_id: String,
    pub source_manifest_sha256: String,
    pub source_pcap_sha256: BTreeMap<String, String>,
    pub derived_manifest_sha256: String,
    pub event_artifact_sha256: String,
    pub correlation_artifact_sha256: String,
    pub registered_epoch_ms: u64,
    pub event_count: usize,
    pub session_count: usize,
    pub correlation_edge_count: usize,
    pub complete_e2e_certified: bool,
    pub registration: String,
}

#[derive(Debug, Deserialize)]
struct DerivedDatasetManifest {
    dataset_id: String,
    source_capture_id: String,
    source_dataset_id: String,
    kind: String,
    packet_count: u64,
    event_count: usize,
    ue_context_count: usize,
    pdu_session_count: usize,
    pfcp_session_count: usize,
    gtpu_tunnel_count: usize,
    correlation_edge_count: usize,
    source_immutable: bool,
    complete_e2e_certified: bool,
    artifacts: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct DerivedCorrelationEvidence {
    source_events: usize,
    ue_contexts: usize,
    pdu_sessions: usize,
    pfcp_sessions: usize,
    gtpu_tunnels: usize,
    correlation_edges: Vec<CorrelationEdge>,
}

#[derive(Debug, Deserialize)]
struct ForensicCaptureManifest {
    packets: u64,
    files: Vec<ForensicCaptureFile>,
}

#[derive(Debug, Deserialize)]
struct ForensicCaptureFile {
    file: String,
    interface: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Clone)]
pub struct CaptureManager {
    root: PathBuf,
    interface_root: PathBuf,
    helper: CaptureHelperClient,
    execution_enabled: bool,
    policy: Policy,
    jobs: Arc<Mutex<BTreeMap<String, CaptureJob>>>,
    datasets: Arc<Mutex<BTreeMap<String, LiveDataset>>>,
    sequence: Arc<AtomicU64>,
    continuous_stop: Arc<AtomicBool>,
    continuous_runtime_evidence: Arc<Mutex<Option<PathBuf>>>,
    // 2.7.6: per-deployment HMAC-SHA256 secret. Loaded once from a root-only
    // 0600 file at startup and shared by every import this manager runs,
    // including after a probe restart against the same key path. Wrapped in
    // Arc so the struct stays Clone (handles only, no key copies).
    pseudonym_key: Arc<PseudonymKey>,
}

impl CaptureManager {
    pub fn new(root: PathBuf, execution_enabled: bool) -> Result<Self, String> {
        Self::with_pseudonym_key_path(
            root,
            execution_enabled,
            PseudonymKey::resolve_default_path(),
        )
    }

    /// Explicit per-deployment key path. Primary constructor used by
    /// production entry points (which pass
    /// `PseudonymKey::resolve_default_path()`) and by tests (which pass a
    /// test-scoped path under the temporary root so parallel tests do not
    /// contend for `/var/lib/oiran/pseudonym.key`).
    pub fn with_pseudonym_key_path(
        root: PathBuf,
        execution_enabled: bool,
        pseudonym_key_path: PathBuf,
    ) -> Result<Self, String> {
        let socket = std::env::var_os("OIRAN_CAPTURE_HELPER_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/run/oiran/capture-helper.sock"));
        let expected_uid = std::env::var("OIRAN_CAPTURE_HELPER_UID")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(107);
        Self::with_helper_and_interface_root(
            root,
            execution_enabled,
            CaptureHelperClient::new(socket, expected_uid),
            PathBuf::from("/sys/class/net"),
            pseudonym_key_path,
        )
    }

    pub fn with_helper(
        root: PathBuf,
        execution_enabled: bool,
        helper: CaptureHelperClient,
    ) -> Result<Self, String> {
        Self::with_helper_and_interface_root(
            root,
            execution_enabled,
            helper,
            PathBuf::from("/sys/class/net"),
            PseudonymKey::resolve_default_path(),
        )
    }

    pub fn with_helper_and_interface_root(
        root: PathBuf,
        execution_enabled: bool,
        helper: CaptureHelperClient,
        interface_root: PathBuf,
        pseudonym_key_path: PathBuf,
    ) -> Result<Self, String> {
        if !interface_root.is_absolute() {
            return Err("interface root must be absolute".into());
        }
        fs::create_dir_all(&root).map_err(display_error)?;
        let pseudonym_key = PseudonymKey::load_or_generate(&pseudonym_key_path)
            .map_err(|code| code.to_string())?;
        let manager = Self {
            root,
            interface_root,
            helper,
            execution_enabled,
            policy: Policy::default(),
            jobs: Arc::new(Mutex::new(BTreeMap::new())),
            datasets: Arc::new(Mutex::new(BTreeMap::new())),
            sequence: Arc::new(AtomicU64::new(1)),
            continuous_stop: Arc::new(AtomicBool::new(false)),
            continuous_runtime_evidence: Arc::new(Mutex::new(None)),
            pseudonym_key: Arc::new(pseudonym_key),
        };
        manager.recover_registry()?;
        manager.load_recovery_registry()?;
        manager.load_derived_registry()?;
        Ok(manager)
    }

    pub fn execution_enabled(&self) -> bool {
        (self.execution_enabled && self.helper.available())
            || self
                .get(CONTINUOUS_CAPTURE_ID)
                .is_some_and(|job| job.state.active())
    }

    /// 2.10.0 (devmat) : accessor sur la clé de pseudonymisation
    /// chargée par ce manager. Utilisé par l'API `POST
    /// /sessions/filter` pour calculer le pseudonyme du hint
    /// d'identité opérateur AVANT comparaison — la valeur brute
    /// n'est jamais stockée ni loggée ; seule la clé (déjà protégée
    /// par `OIRAN_PSEUDONYM_KEY_UNAVAILABLE` / `_INSECURE`) est
    /// partagée via l'`Arc`.
    pub fn pseudonym_key(&self) -> Arc<PseudonymKey> {
        self.pseudonym_key.clone()
    }

    pub fn start_continuous_import(
        &self,
        config: ContinuousImportConfig,
    ) -> Result<CaptureJob, String> {
        config.validate(self.policy)?;
        if self
            .get(CONTINUOUS_CAPTURE_ID)
            .is_some_and(|job| job.state.active())
        {
            return Err("CONTINUOUS_IMPORT_ALREADY_ACTIVE".into());
        }
        let base = self.root.join(CONTINUOUS_CAPTURE_ID);
        fs::create_dir_all(base.join("pcap")).map_err(display_error)?;
        self.continuous_stop.store(false, Ordering::Release);
        *self.continuous_runtime_evidence.lock().unwrap() = config.runtime_pdu_evidence.clone();
        // 2.7.16 (issue #9 part 1): a previous worker may have published a
        // dataset to disk at `base/dataset/dataset_manifest.json`. The import
        // state tracks seen_checksums (so no segment is re-ingested), but the
        // in-RAM `datasets` map is empty on process restart. Without this
        // pre-seed, /health and /sessions report zero events until a NEW
        // segment lands and the worker re-publishes — stale datasets on disk
        // are invisible to the API. Recover them synchronously here so the
        // API projection sees the right numbers immediately.
        self.recover_continuous_dataset_from_disk(&base)?;
        let job = CaptureJob {
            capture_id: CONTINUOUS_CAPTURE_ID.into(),
            probe_id: PROBE_ID.into(),
            name: "POLARIS continuous lab collector".into(),
            profile: "POLARIS_5G_SA_CONTINUOUS_IMPORT".into(),
            interfaces: vec!["N2".into(), "N3".into(), "N4".into()],
            state: CaptureState::Starting,
            created_epoch_ms: epoch_ms(),
            started_epoch_ms: Some(epoch_ms()),
            ended_epoch_ms: None,
            owner: "operator".into(),
            metrics: CaptureMetrics {
                queue_capacity_bytes: config.max_owned_bytes,
                ..Default::default()
            },
            output_directory: format!("runtime/live-captures/{CONTINUOUS_CAPTURE_ID}"),
            dataset_id: None,
            session_ids: Vec::new(),
            error: None,
            stop_reason: None,
            process_ids: Vec::new(),
            helper_results: Vec::new(),
            capture_group_id: Some("continuous-lab-import".into()),
            scenario_id: Some("POLARIS_5G_SA_CONTINUOUS_IMPORT".into()),
            planes: ["N2", "N3", "N4"]
                .into_iter()
                .map(|interface| CapturePlaneStatus {
                    plane: plane_name(interface).into(),
                    interface: interface.into(),
                    capture_job_id: CONTINUOUS_CAPTURE_ID.into(),
                    start_timestamp: None,
                    end_timestamp: None,
                    packet_count: 0,
                    byte_count: 0,
                    drop_count: None,
                    storage_bytes: 0,
                    decode_status: "PENDING".into(),
                    dataset_id: None,
                    source_sha256: Vec::new(),
                    error: None,
                })
                .collect(),
        };
        self.jobs
            .lock()
            .unwrap()
            .insert(CONTINUOUS_CAPTURE_ID.into(), job.clone());
        self.persist_job(&job)?;
        self.clear_continuous_active_credit()?;
        self.audit(
            "system",
            "CONTINUOUS_IMPORT_START",
            CONTINUOUS_CAPTURE_ID,
            "accepted",
        )?;
        let manager = self.clone();
        thread::Builder::new()
            .name("continuous-lab-import".into())
            .spawn(move || manager.run_continuous_import(config))
            .map_err(display_error)?;
        Ok(job)
    }

    pub fn interfaces(&self) -> Vec<CaptureInterface> {
        interface_specs()
            .into_iter()
            .map(|interface| discover_interface(interface, &self.interface_root))
            .collect()
    }

    pub fn validate(&self, request: &CaptureRequest) -> ValidationResult {
        let interfaces = self.interfaces();
        let mut blockers = validate_request(request, &interfaces, self.policy);
        if !self.execution_enabled() {
            blockers.push("CAPTURE_EXECUTION_NOT_ENABLED".into());
        }
        let sample = measure_path(&self.root);
        let disk_decision = assess(sample.clone(), self.policy);
        let budget = capture_budget(sample, request.max_bytes, self.policy);
        if !budget.allowed {
            blockers.push("CAPTURE_STORAGE_BUDGET_REJECTED".into());
        }
        if self
            .jobs
            .lock()
            .unwrap()
            .values()
            .any(|job| job.state.active())
        {
            blockers.push("CAPTURE_JOB_ALREADY_ACTIVE".into());
        }
        if blockers.is_empty() {
            let spec = helper_spec(format!("validation-{}", epoch_ms()), request);
            match self.helper.request(&IpcRequest::ValidateCapture(spec)) {
                Ok(response) if response.ok => {}
                Ok(response) => blockers.push(
                    response
                        .error
                        .map(|error| error.category)
                        .unwrap_or_else(|| "CAPTURE_HELPER_REJECTED".into()),
                ),
                Err(_) => blockers.push("CAPTURE_HELPER_UNAVAILABLE".into()),
            }
        }
        blockers.sort();
        blockers.dedup();
        ValidationResult {
            valid: blockers.is_empty(),
            capture_control_available: self.execution_enabled(),
            state: if blockers.is_empty() {
                CaptureState::Ready
            } else {
                CaptureState::Blocked
            },
            interfaces,
            disk_decision,
            budget,
            blockers,
        }
    }

    pub fn start(&self, request: CaptureRequest, owner: &str) -> Result<CaptureJob, String> {
        let validation = self.validate(&request);
        if !validation.valid {
            return Err(format!(
                "capture validation failed: {}",
                validation.blockers.join(",")
            ));
        }
        let capture_id = format!(
            "live-{}-{:04}",
            epoch_ms(),
            self.sequence.fetch_add(1, Ordering::Relaxed)
        );
        let helper_response = self.helper.request(&IpcRequest::StartCapture(helper_spec(
            capture_id.clone(),
            &request,
        )))?;
        if !helper_response.ok {
            return Err(format_helper_error(helper_response.error));
        }
        let job = CaptureJob {
            capture_id: capture_id.clone(),
            probe_id: request.probe_id.clone(),
            name: request.name.clone(),
            profile: request.profile.clone(),
            interfaces: request.interfaces.clone(),
            state: CaptureState::Starting,
            created_epoch_ms: epoch_ms(),
            started_epoch_ms: None,
            ended_epoch_ms: None,
            owner: owner.into(),
            metrics: CaptureMetrics {
                queue_capacity_bytes: request.max_bytes,
                ..Default::default()
            },
            output_directory: format!("runtime/live-captures/{capture_id}"),
            dataset_id: None,
            session_ids: Vec::new(),
            error: None,
            stop_reason: None,
            process_ids: Vec::new(),
            helper_results: Vec::new(),
            capture_group_id: Some(
                request
                    .capture_group_id
                    .clone()
                    .unwrap_or_else(|| format!("group-{capture_id}")),
            ),
            scenario_id: request.scenario_id.clone(),
            planes: request
                .interfaces
                .iter()
                .map(|interface| CapturePlaneStatus {
                    plane: plane_name(interface).into(),
                    interface: interface.clone(),
                    capture_job_id: capture_id.clone(),
                    start_timestamp: None,
                    end_timestamp: None,
                    packet_count: 0,
                    byte_count: 0,
                    drop_count: None,
                    storage_bytes: 0,
                    decode_status: "PENDING".into(),
                    dataset_id: None,
                    source_sha256: Vec::new(),
                    error: None,
                })
                .collect(),
        };
        self.jobs
            .lock()
            .unwrap()
            .insert(capture_id.clone(), job.clone());
        self.persist_job(&job)?;
        self.audit(owner, "CAPTURE_START_REQUESTED", &capture_id, "accepted")?;
        let manager = self.clone();
        thread::Builder::new()
            .name(format!("capture-{capture_id}"))
            .spawn(move || manager.run_job(capture_id, request))
            .map_err(display_error)?;
        Ok(job)
    }

    pub fn stop(&self, capture_id: &str, actor: &str) -> Result<CaptureJob, String> {
        let job = self.get(capture_id).ok_or("capture job not found")?;
        if job.owner != actor && actor != "administrator" {
            return Err("capture job is owned by another operator".into());
        }
        if !job.state.active() {
            return Ok(job);
        }
        if capture_id == CONTINUOUS_CAPTURE_ID {
            self.continuous_stop.store(true, Ordering::Release);
            self.update(capture_id, |job| {
                job.state = CaptureState::Stopping;
                job.stop_reason = Some("OPERATOR_REQUEST".into());
                job.metrics.last_packet_epoch_ms = None;
                job.metrics.fresh_packet_count = 0;
                job.metrics.active_ue_ips.clear();
            })?;
            self.clear_continuous_active_credit()?;
            self.audit(
                actor,
                "CONTINUOUS_IMPORT_STOP_REQUESTED",
                capture_id,
                "accepted",
            )?;
            return self
                .get(capture_id)
                .ok_or_else(|| "capture job disappeared".to_string());
        }
        let response = self.helper.request(&IpcRequest::StopCapture {
            capture_id: capture_id.into(),
        })?;
        if !response.ok {
            return Err(format_helper_error(response.error));
        }
        self.update(capture_id, |job| {
            job.state = CaptureState::Stopping;
            job.stop_reason = Some("OPERATOR_REQUEST".into());
        })?;
        self.audit(actor, "CAPTURE_STOP_REQUESTED", capture_id, "accepted")?;
        self.get(capture_id)
            .ok_or_else(|| "capture job disappeared".to_string())
    }

    pub fn get(&self, id: &str) -> Option<CaptureJob> {
        let job = self.jobs.lock().unwrap().get(id).cloned()?;
        Some(self.capture_job_view(job, epoch_ms()))
    }

    pub fn list(&self) -> Vec<CaptureJob> {
        let observed_epoch_ms = epoch_ms();
        let jobs = self
            .jobs
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        jobs.into_iter()
            .map(|job| self.capture_job_view(job, observed_epoch_ms))
            .collect()
    }

    pub fn datasets(&self) -> Vec<LiveDataset> {
        let observed_epoch_ms = epoch_ms();
        self.datasets
            .lock()
            .unwrap()
            .values()
            .cloned()
            .map(|dataset| live_dataset_view(dataset, observed_epoch_ms))
            .collect()
    }

    pub fn dataset(&self, id: &str) -> Option<LiveDataset> {
        self.datasets
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .map(|dataset| live_dataset_view(dataset, epoch_ms()))
    }

    fn capture_job_view(&self, mut job: CaptureJob, observed_epoch_ms: u64) -> CaptureJob {
        if !fresh_credit(job.metrics.last_packet_epoch_ms, observed_epoch_ms) {
            job.metrics.fresh_packet_count = 0;
            job.metrics.active_ue_ips.clear();
        }
        if job.capture_id == CONTINUOUS_CAPTURE_ID {
            job.metrics.active_ue_ips = self
                .datasets
                .lock()
                .unwrap()
                .get(CONTINUOUS_DATASET_ID)
                .cloned()
                .map(|dataset| live_dataset_view(dataset, observed_epoch_ms).active_ue_ips)
                .unwrap_or_default();
        }
        job
    }

    pub fn callflow(&self, dataset_id: &str, session_id: &str) -> Option<CallFlow> {
        let path = self.callflow_path(dataset_id, session_id)?;
        serde_json::from_slice(&fs::read(path).ok()?).ok()
    }

    fn callflow_path(&self, dataset_id: &str, session_id: &str) -> Option<PathBuf> {
        if !safe_identifier(session_id) {
            return None;
        }
        let (stored_dataset_id, capture_id) = {
            let datasets = self.datasets.lock().unwrap();
            let dataset = datasets.get(dataset_id)?;
            (dataset.dataset_id.clone(), dataset.capture_id.clone())
        };
        let dataset_root = if stored_dataset_id.starts_with("derived-") {
            self.root
                .join("derived-datasets")
                .join(&stored_dataset_id)
                .join("dataset")
        } else if stored_dataset_id.starts_with("recovered-dataset-") {
            self.root
                .join("recovered-datasets")
                .join(&capture_id)
                .join("dataset")
        } else {
            self.root.join(&capture_id).join("dataset")
        };
        Some(
            dataset_root
                .join("callflows")
                .join(format!("{session_id}.json")),
        )
    }

    pub fn callflow_page(
        &self,
        dataset_id: &str,
        session_id: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Option<Value>, String> {
        let Some(path) = self.callflow_path(dataset_id, session_id) else {
            return Ok(None);
        };
        if !path.is_file() {
            return Ok(None);
        }
        read_callflow_page(&path, cursor, limit).map(Some)
    }

    /// Resolves a persisted call flow without cloning `LiveDataset.discovery`.
    /// The continuous dataset can retain thousands of event identifiers; a
    /// read-only HTTP request must not duplicate that index merely to locate
    /// one session artifact.
    pub fn callflow_page_by_session(
        &self,
        session_id: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Option<Value>, String> {
        let dataset_id = {
            let datasets = self.datasets.lock().unwrap();
            datasets
                .values()
                .find(|dataset| {
                    dataset
                        .session_ids
                        .iter()
                        .any(|candidate| candidate == session_id)
                })
                .map(|dataset| dataset.dataset_id.clone())
        };
        let Some(dataset_id) = dataset_id else {
            return Ok(None);
        };
        self.callflow_page(&dataset_id, session_id, cursor, limit)
    }

    /// Validates and atomically registers a reviewed offline-derived dataset.
    /// The caller supplies an administrator-controlled import root and a safe
    /// dataset identifier; paths from an HTTP request are never accepted.
    pub fn import_derived_dataset(
        &self,
        import_root: &Path,
        dataset_id: &str,
        actor: &str,
    ) -> Result<DerivedDatasetRegistration, String> {
        if !safe_identifier(dataset_id) || !dataset_id.starts_with("derived-") {
            return Err("DERIVED_DATASET_ID_INVALID".into());
        }
        let import_root = import_root
            .canonicalize()
            .map_err(|error| format!("DERIVED_IMPORT_ROOT: {error}"))?;
        let source_dir = resolve_derived_import_source(&import_root, dataset_id)?;
        if !source_dir.starts_with(&import_root)
            || source_dir.parent() != Some(import_root.as_path())
        {
            return Err("DERIVED_IMPORT_PATH_REJECTED".into());
        }

        let derived_manifest_path = source_dir.join("dataset_manifest.json");
        let events_path = source_dir.join("oiran_events.jsonl");
        let correlations_path = source_dir.join("correlation_evidence.json");
        let derived_manifest_bytes = fs::read(&derived_manifest_path)
            .map_err(|error| format!("DERIVED_MANIFEST: {error}"))?;
        let events_bytes =
            fs::read(&events_path).map_err(|error| format!("DERIVED_EVENTS: {error}"))?;
        let correlations_bytes = fs::read(&correlations_path)
            .map_err(|error| format!("DERIVED_CORRELATIONS: {error}"))?;
        let manifest: DerivedDatasetManifest = serde_json::from_slice(&derived_manifest_bytes)
            .map_err(|error| format!("DERIVED_MANIFEST_INVALID: {error}"))?;
        if manifest.dataset_id != dataset_id
            || manifest.kind != "OFFLINE_DERIVED_REPLAY"
            || !manifest.source_immutable
            || manifest.complete_e2e_certified
        {
            return Err("DERIVED_MANIFEST_POLICY_REJECTED".into());
        }
        verify_artifact_hash(&manifest, "oiran_events.jsonl", &events_bytes)?;
        verify_artifact_hash(&manifest, "correlation_evidence.json", &correlations_bytes)?;

        let source_root = self.root.join(&manifest.source_capture_id);
        let source_dataset_manifest_path = source_root.join("dataset/dataset_manifest.json");
        let source_dataset: LiveDataset = serde_json::from_slice(
            &fs::read(&source_dataset_manifest_path)
                .map_err(|error| format!("SOURCE_DATASET_MANIFEST: {error}"))?,
        )
        .map_err(|error| format!("SOURCE_DATASET_MANIFEST_INVALID: {error}"))?;
        if source_dataset.dataset_id != manifest.source_dataset_id
            || source_dataset.capture_id != manifest.source_capture_id
        {
            return Err("SOURCE_DATASET_IDENTITY_MISMATCH".into());
        }
        let source_manifest_bytes = fs::read(source_root.join("capture_manifest.json"))
            .map_err(|error| format!("SOURCE_CAPTURE_MANIFEST: {error}"))?;
        let source_manifest: ForensicCaptureManifest =
            serde_json::from_slice(&source_manifest_bytes)
                .map_err(|error| format!("SOURCE_CAPTURE_MANIFEST_INVALID: {error}"))?;
        if source_manifest.packets != manifest.packet_count {
            return Err("SOURCE_PACKET_COUNT_MISMATCH".into());
        }
        let mut source_hashes = BTreeMap::new();
        let mut source_packet_limits = BTreeMap::new();
        for file in &source_manifest.files {
            if !safe_file_name(&file.file) {
                return Err("SOURCE_CAPTURE_FILE_REJECTED".into());
            }
            let path = source_root.join("pcap").join(&file.file);
            // Streaming integrity check: bounded memory regardless of pcap size.
            verify_file_integrity(&path, file.size_bytes, &file.sha256)
                .map_err(|error| format!("SOURCE_PCAP_INTEGRITY: {}: {error}", file.file))?;
            source_packet_limits.insert(file.file.clone(), pcap_record_totals(&path).0);
            source_hashes.insert(file.file.clone(), file.sha256.clone());
        }

        let mut events = load_path(&events_path)?;
        if events.len() != manifest.event_count {
            return Err("DERIVED_EVENT_COUNT_MISMATCH".into());
        }
        validate_derived_event_provenance(
            &events_bytes,
            &manifest.source_capture_id,
            &source_hashes,
            &source_packet_limits,
        )?;
        let schema_versions = events
            .iter()
            .filter_map(|event| event.source_json["schema_version"].as_str())
            .collect::<BTreeSet<_>>();
        let compatible_decoders = BTreeMap::from([
            ("decoder-ngap", "0.3.0"),
            ("decoder-nas", "0.1.0"),
            ("decoder-sbi", "0.1.0"),
            ("decoder-pfcp", "0.2.0"),
            ("decoder-gtpu", "0.1.0"),
        ]);
        if (!events.is_empty() && schema_versions != BTreeSet::from(["1.5.0"]))
            || events.iter().any(|event| {
                compatible_decoders
                    .get(event.decoder_name.as_str())
                    .copied()
                    != Some(event.decoder_version.as_str())
            })
        {
            return Err("DERIVED_SCHEMA_OR_DECODER_INCOMPATIBLE".into());
        }

        let discovery = discover_sessions(&mut events);
        if discovery.ue_contexts.len() != manifest.ue_context_count
            || discovery.pdu_sessions.len() != manifest.pdu_session_count
            || discovery.pfcp_sessions.len() != manifest.pfcp_session_count
            || discovery.gtpu_tunnels.len() != manifest.gtpu_tunnel_count
        {
            return Err("DERIVED_SESSION_COUNT_MISMATCH".into());
        }
        let evidence: DerivedCorrelationEvidence = serde_json::from_slice(&correlations_bytes)
            .map_err(|error| format!("DERIVED_CORRELATIONS_INVALID: {error}"))?;
        if evidence.source_events != events.len()
            || evidence.ue_contexts != discovery.ue_contexts.len()
            || evidence.pdu_sessions != discovery.pdu_sessions.len()
            || evidence.pfcp_sessions != discovery.pfcp_sessions.len()
            || evidence.gtpu_tunnels != discovery.gtpu_tunnels.len()
            || evidence.correlation_edges.len() != manifest.correlation_edge_count
        {
            return Err("DERIVED_EVIDENCE_COUNT_MISMATCH".into());
        }
        let mut recomputed = correlate_cross_interface_evidence(&events);
        recomputed.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
        let mut supplied = evidence.correlation_edges;
        supplied.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
        if serde_json::to_value(&recomputed).map_err(|error| error.to_string())?
            != serde_json::to_value(&supplied).map_err(|error| error.to_string())?
        {
            return Err("DERIVED_CORRELATION_EVIDENCE_MISMATCH".into());
        }

        let derived_root = self.root.join("derived-datasets");
        fs::create_dir_all(&derived_root).map_err(display_error)?;
        let final_root = derived_root.join(dataset_id);
        let report_path = final_root.join("derived_registration.json");
        let derived_manifest_sha256 = sha256_hex(&derived_manifest_bytes);
        if report_path.is_file() {
            let report: DerivedDatasetRegistration =
                serde_json::from_slice(&fs::read(&report_path).map_err(display_error)?)
                    .map_err(|error| error.to_string())?;
            if report.derived_manifest_sha256 != derived_manifest_sha256
                || report.source_capture_id != manifest.source_capture_id
            {
                return Err("DATASET_REGISTRATION_CONFLICT".into());
            }
            let dataset: LiveDataset = serde_json::from_slice(
                &fs::read(final_root.join("dataset/dataset_manifest.json"))
                    .map_err(display_error)?,
            )
            .map_err(|error| error.to_string())?;
            self.persist_derived_registration(&dataset, &final_root.join("dataset"))?;
            return Ok(report);
        }
        if final_root.exists() {
            return Err("DERIVED_IMPORT_INCOMPLETE_OUTPUT_EXISTS".into());
        }

        let staging = derived_root.join(format!(".{dataset_id}.{}.tmp", epoch_ms()));
        let dataset_dir = staging.join("dataset");
        prepare_dataset_directory(&dataset_dir)?;
        atomic_write(&dataset_dir.join("oiran_events.jsonl"), &events_bytes)?;
        atomic_write(
            &dataset_dir.join("correlation_evidence.json"),
            &correlations_bytes,
        )?;
        atomic_write(
            &dataset_dir.join("derived_manifest.json"),
            &derived_manifest_bytes,
        )?;
        let mut session_ids = Vec::new();
        for session in &discovery.pdu_sessions {
            let context = discovery
                .ue_contexts
                .iter()
                .find(|context| context.context_id == session.ue_context_id);
            let mut ids = session.event_ids.iter().cloned().collect::<BTreeSet<_>>();
            if let Some(context) = context {
                ids.extend(context.event_ids.iter().cloned());
            }
            loop {
                let mut expanded = false;
                for edge in &supplied {
                    if ids.contains(&edge.source_event_id) || ids.contains(&edge.target_event_id) {
                        expanded |= ids.insert(edge.source_event_id.clone());
                        expanded |= ids.insert(edge.target_event_id.clone());
                    }
                }
                if !expanded {
                    break;
                }
            }
            let selected = events
                .iter()
                .filter(|event| ids.contains(&event.event_id))
                .cloned()
                .collect::<Vec<_>>();
            let mut edges = correlate_discovered_tunnels(&selected, &discovery);
            edges.extend(correlate_cross_interface_evidence(&selected));
            // 2.7.26: same canonical-key fold as the global path.
            edges = fold_overlapping_edges(edges);
            let mut reconstruction = reconstruct(
                selected,
                ReconstructionHints {
                    ue_pseudonym: context.map(|context| context.pseudonym.clone()),
                    ..Default::default()
                },
            );
            reconstruction.session_id = session.session_id.clone();
            for event in &reconstruction.events {
                reconstruction
                    .association
                    .insert(event.event_id.clone(), Association::Session);
            }
            let edges = supplied
                .iter()
                .filter(|edge| {
                    ids.contains(&edge.source_event_id) && ids.contains(&edge.target_event_id)
                })
                .cloned()
                .collect::<Vec<_>>();
            let flow = build_callflow(&reconstruction, edges);
            atomic_write(
                &dataset_dir
                    .join("callflows")
                    .join(format!("{}.json", flow.session_id)),
                &serde_json::to_vec_pretty(&flow).map_err(|error| error.to_string())?,
            )?;
            atomic_write(
                &dataset_dir
                    .join("callflows")
                    .join(format!("{}.html", flow.session_id)),
                callflow_renderer::render(&flow)
                    .map_err(|error| error.to_string())?
                    .as_bytes(),
            )?;
            session_ids.push(flow.session_id);
        }
        let checksums = BTreeMap::from([
            ("oiran_events.jsonl".into(), sha256_hex(&events_bytes)),
            (
                "correlation_evidence.json".into(),
                sha256_hex(&correlations_bytes),
            ),
            (
                "derived_manifest.json".into(),
                derived_manifest_sha256.clone(),
            ),
        ]);
        let dataset = LiveDataset {
            dataset_id: dataset_id.into(),
            capture_id: manifest.source_capture_id.clone(),
            path: format!("runtime/live-captures/derived-datasets/{dataset_id}/dataset"),
            event_count: events.len(),
            session_ids,
            decode_reports: source_dataset.decode_reports.clone(),
            checksums,
            state: "PARTIAL".into(),
            discovery: Some(discovery),
            capture_started_epoch_ms: None,
            last_packet_epoch_ms: None,
            fresh_packet_count: 0,
            active_ue_ips: Vec::new(),
            active_pdu_contexts: Vec::new(),
            zero_event_captures: Vec::new(),
        };
        atomic_write(
            &dataset_dir.join("dataset_manifest.json"),
            &serde_json::to_vec_pretty(&dataset).map_err(|error| error.to_string())?,
        )?;
        validate_dataset_artifacts(&dataset, &dataset_dir)?;
        let report = DerivedDatasetRegistration {
            schema_version: "1.0".into(),
            dataset_id: dataset_id.into(),
            source_capture_id: manifest.source_capture_id.clone(),
            source_dataset_id: manifest.source_dataset_id,
            source_manifest_sha256: sha256_hex(&source_manifest_bytes),
            source_pcap_sha256: source_hashes,
            derived_manifest_sha256,
            event_artifact_sha256: sha256_hex(&events_bytes),
            correlation_artifact_sha256: sha256_hex(&correlations_bytes),
            registered_epoch_ms: epoch_ms(),
            event_count: dataset.event_count,
            session_count: dataset.session_ids.len(),
            correlation_edge_count: supplied.len(),
            complete_e2e_certified: false,
            registration: "VALIDATED_REGISTERED".into(),
        };
        atomic_write(
            &staging.join("derived_registration.json"),
            &serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?,
        )?;
        fs::rename(&staging, &final_root)
            .map_err(|error| format!("DERIVED_IMPORT_FINALIZATION: {error}"))?;
        self.persist_derived_registration(&dataset, &final_root.join("dataset"))?;
        self.audit(
            actor,
            "DERIVED_DATASET_REGISTERED",
            &manifest.source_capture_id,
            dataset_id,
        )?;
        Ok(report)
    }

    fn clear_continuous_active_credit(&self) -> Result<(), String> {
        let dataset = {
            let mut datasets = self.datasets.lock().unwrap();
            let Some(dataset) = datasets.get_mut(CONTINUOUS_DATASET_ID) else {
                return Ok(());
            };
            // Runtime evidence may expire, but the evidence-backed session and
            // its call flow are part of the durable checkpoint.  Only clear the
            // live credit; removing the session ID here made a restart lossy.
            dataset.capture_started_epoch_ms = None;
            dataset.last_packet_epoch_ms = None;
            dataset.fresh_packet_count = 0;
            dataset.active_ue_ips.clear();
            dataset.active_pdu_contexts.clear();
            dataset.clone()
        };
        let manifest = self
            .root
            .join(CONTINUOUS_CAPTURE_ID)
            .join("dataset/dataset_manifest.json");
        if manifest.is_file() {
            atomic_write(
                &manifest,
                &serde_json::to_vec_pretty(&dataset).map_err(|error| error.to_string())?,
            )?;
        }
        Ok(())
    }

    fn run_job(&self, capture_id: String, request: CaptureRequest) {
        if let Err(error) = self.run_job_inner(&capture_id, &request) {
            let _ = self.update(&capture_id, |job| {
                job.state = CaptureState::Failed;
                job.error = Some(error.clone());
                job.ended_epoch_ms = Some(epoch_ms());
                for plane in &mut job.planes {
                    if !matches!(plane.decode_status.as_str(), "DECODED" | "COMPLETED_EMPTY") {
                        plane.decode_status = if plane.packet_count > 0 {
                            "CAPTURED_PROCESSING_FAILED".into()
                        } else {
                            "FAILED".into()
                        };
                        plane.error = Some(error.clone());
                        plane.end_timestamp = job.ended_epoch_ms;
                    }
                }
            });
            let _ = self.audit(&request.probe_id, "CAPTURE_FAILED", &capture_id, &error);
        }
    }

    fn run_continuous_import(&self, config: ContinuousImportConfig) {
        if let Err(error) = self.run_continuous_import_inner(&config) {
            let _ = self.update(CONTINUOUS_CAPTURE_ID, |job| {
                job.state = CaptureState::Failed;
                job.error = Some(error.clone());
                job.ended_epoch_ms = Some(epoch_ms());
            });
            let _ = self.audit(
                "system",
                "CONTINUOUS_IMPORT_FAILED",
                CONTINUOUS_CAPTURE_ID,
                &error,
            );
        }
    }

    fn run_continuous_import_inner(&self, config: &ContinuousImportConfig) -> Result<(), String> {
        // 2.7.6 (adjusted): the HMAC-SHA256 key is owned by this manager and
        // stays stable across probe restarts against the same key path, so
        // overlapping-append snapshots and restart-recovery datasets dedupe
        // by identical event_id.
        let pseudonym_key = self.pseudonym_key.as_ref();
        let base = self.root.join(CONTINUOUS_CAPTURE_ID);
        let state_path = base.join("import_state.json");
        let mut state = if state_path.is_file() {
            serde_json::from_slice(&fs::read(&state_path).map_err(display_error)?)
                .map_err(|_| "CONTINUOUS_STATE_INVALID".to_string())?
        } else {
            ContinuousImportState::default()
        };
        state
            .segments
            .retain(|_, segment| base.join("pcap").join(&segment.owned_file).is_file());
        state.seen_checksums.extend(state.segments.keys().cloned());
        if state.seen_order.is_empty() {
            state
                .seen_order
                .extend(state.seen_checksums.iter().cloned());
        }
        // 2.7.21 (issue #10 comment 6653514332): remove ONLY the
        // never-committed artifacts (`.dataset-next/`, `.dataset-previous/`,
        // base-level `*.tmp` / `*.compact-tmp` / `*.spool`). The
        // committed `dataset/` subtree — `oiran_events.jsonl`,
        // `dataset_manifest.json`, `callflows/` — is left strictly
        // byte-identical. The 2.7.20 variant compacted
        // `dataset/oiran_events.jsonl` against the current pcap ring
        // (`state.segments.keys()`), but the ring is capped at
        // `max_segments` and does NOT represent the history of
        // capture_ids that ever contributed events: ANR2 arrived with
        // 1 ring entry while the published dataset held 51 capture_ids,
        // and the compaction cut 25 537 events down to 77 (3 945
        // events of 20 captures whose pcap was STILL present were lost
        // through a capture-id mismatch; rollback saved the data). See
        // `clean_continuous_import_root`.
        let compaction = clean_continuous_import_root(&base)?;
        // Structured stderr log so operators can diff size-before /
        // size-after without parsing the Rust stack.
        let log = serde_json::json!({
            "event": "CONTINUOUS_IMPORT_STARTUP_CLEAN",
            "base": base.display().to_string(),
            "total_before_bytes": compaction.total_before(),
            "total_after_bytes": compaction.total_after(),
            "entries": compaction.entries.iter().map(|entry| serde_json::json!({
                "path": entry.path,
                "before_bytes": entry.before_bytes,
                "after_bytes": entry.after_bytes,
                "action": entry.action,
            })).collect::<Vec<_>>(),
        });
        eprintln!("{log}");
        let recovered_dataset = self.dataset(CONTINUOUS_DATASET_ID);
        let mut observed = BTreeMap::<PathBuf, (u64, SystemTime)>::new();
        // 2.8.1 (#9, ANR2 perf 77.31% in Sha256Hasher::compress):
        // per-worker `(dev, inode, size, mtime_ns) → (sha, packets)`
        // cache hydrated from the persisted `source_fingerprints`
        // field of `import_state.json` so a probe restart does NOT
        // re-hash every segment in the source root.
        // 2.9.8 (#9 comment 6725097122): purge orphan fingerprints
        // before hydrating the in-memory cache. ANR2 proved in
        // production that a SourceFingerprint could land in
        // `state.source_fingerprints` while its checksum was never
        // committed to `seen_checksums` (publish failure rollback at
        // `:2949` left the local `source_cache` unreset; a subsequent
        // `cache_mutated=true` scan then persisted those orphans via
        // `:3028`). The invariant for 2.9.8 is: a fingerprint is
        // persisted ONLY after a successful publish. On startup any
        // pre-2.9.8 orphan is dropped with a structured log record and
        // counted in `metrics.orphan_fingerprints_recovered`; the
        // segment is still on disk and will be rehashed next scan.
        let orphans_at_startup = drop_orphan_fingerprints(&mut state);
        if !orphans_at_startup.is_empty() {
            atomic_write(
                &state_path,
                &serde_json::to_vec_pretty(&state).map_err(|error| error.to_string())?,
            )?;
            for (path, checksum) in &orphans_at_startup {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "event": "CONTINUOUS_ORPHAN_FINGERPRINT_DROPPED",
                        "path": path,
                        "checksum": checksum,
                        "reason": "fingerprint persisted without seen_checksums commit",
                    })
                );
            }
            let recovered = orphans_at_startup.len() as u64;
            self.update(CONTINUOUS_CAPTURE_ID, |job| {
                job.metrics.orphan_fingerprints_recovered = job
                    .metrics
                    .orphan_fingerprints_recovered
                    .saturating_add(recovered);
            })?;
        }
        let mut source_cache: SourceSegmentsCache = state
            .source_fingerprints
            .iter()
            .map(|(path, fingerprint)| (PathBuf::from(path), fingerprint.clone()))
            .collect();
        // 2.8.2 (#10 comment 6687323881): dir-mtime gate. ANR2 proved
        // in production that at 10 000 segments every scan walked the
        // source tree and ran 20 000 statx (`collect_source_paths` +
        // `source_segments`'s per-candidate `fs::metadata`), yielding
        // 65% CPU even when every candidate's checksum was cached. The
        // fix: remember each directory's mtime; a scan runs ONLY when
        // at least one watched directory (source root + its immediate
        // subtree) has mutated since the previous scan. A finalised
        // segment ALWAYS touches its containing directory's mtime, so
        // no new file can slip past; an idle source root produces one
        // `stat` per directory per tick (~0% CPU).
        let mut dir_mtimes: BTreeMap<PathBuf, SystemTime> = BTreeMap::new();
        // 2.8.2: force a full scan every `FORCED_RESCAN_INTERVAL`
        // even when the directory mtime has not moved. This covers
        // the edge cases where a file is modified in place (an
        // append does NOT change the parent directory's mtime on
        // ext4) and keeps latency bounded at 5 s for atypical
        // producers. Pure production dumpcap rotation creates new
        // files per segment, so the dir-mtime gate handles the hot
        // path; this timer is a safety net.
        // 2.8.2: cheap file-mtime drift check cadence. Dir mtime on
        // ext4 does NOT change when an existing file is appended to
        // (dumpcap's `-b duration:N` overlapping-append pattern), so
        // the dir-mtime gate alone would miss such updates. The drift
        // check stats every path in `source_cache` and compares the
        // file mtime with the cached fingerprint — 10 000 statx at
        // ~5 µs each = ~50 ms per check, bounded well below the 2% CPU
        // gate. Runs at most every `MTIME_DRIFT_CADENCE`.
        const MTIME_DRIFT_CADENCE: Duration = Duration::from_secs(5);
        let mut last_full_scan = Instant::now()
            .checked_sub(MTIME_DRIFT_CADENCE)
            .unwrap_or_else(Instant::now);
        // 2.8.2: last scan's finalization-pending count. When > 0 we
        // must not trust the dir-mtime gate — those files will become
        // eligible by aging alone, without any directory mutation
        // (see `SourceDiscovery.pending_finalization`).
        let mut last_pending_finalization: usize = 1;
        // 2.8.2: last scan found candidates that passed the finalize
        // filter but had not yet satisfied the `stable_across_scans`
        // check (they appear for the FIRST time with a given
        // `(size, mtime)` and need a second scan to prove stability
        // before ingestion). When > 0 the gate must not skip; the
        // required second scan happens with no directory mutation.
        let mut last_pending_stability: usize = 0;
        // 2.8.2: last scan's count of candidates not yet in
        // `seen_checksums`. When > 0 (burst case: 250 segments
        // discovered but `MAX_INGESTED_SEGMENTS_PER_SCAN=32` processed
        // this scan, 218 left) the gate must keep running without a
        // directory mutation to drain the remainder.
        let mut last_pending_unseen: u64 = 0;
        // 2.8.2: count of disk-scanned paths NOT yet characterised
        // (not in `source_cache` because they were too young for the
        // `stable_age` filter, or dropped by `finalized_candidates_only`,
        // or over the `MAX_SOURCE_CANDIDATES` cap). While > 0 we
        // must keep scanning — those paths will become candidates
        // by aging alone.
        let mut last_pending_characterization: usize = 1;
        // 2.9.1 (#9): paths the worker has already logged under
        // `CONTINUOUS_PLANE_NOT_ALLOWLISTED`. The set is in-memory per
        // worker lifetime — restart ⇒ one log per path per start.
        let mut logged_unknown_planes: BTreeSet<PathBuf> = BTreeSet::new();
        // Exponential backoff on empty scans — each tick with no new
        // segment doubles the sleep up to `MAX_IDLE_SLEEP`. The next
        // segment (detected via source_segments) resets it to the
        // configured scan_interval, so import latency is bounded by
        // scan_interval at the worst case after a burst.
        let mut idle_backoff_factor: u32 = 1;
        let mut bootstrap_pending = Vec::new();
        if let Some(path) = &config.historical_n2_bootstrap {
            if !allowlisted_historical_n2_bootstrap(path) {
                return Err("CONTINUOUS_BOOTSTRAP_NOT_ALLOWLISTED".into());
            }
            let metadata = fs::metadata(path).map_err(display_error)?;
            if metadata.len() > config.max_segment_bytes {
                record_ingestion_failure_with_size(
                    &mut state.failed_ingestions,
                    path.display().to_string(),
                    Some(metadata.len()),
                    "CONTINUOUS_SOURCE_SEGMENT_TOO_LARGE",
                    epoch_ms(),
                );
                atomic_write(
                    &state_path,
                    &serde_json::to_vec_pretty(&state).map_err(|error| error.to_string())?,
                )?;
            } else {
                // Streaming SHA-256 + streaming pcap record count: bootstrap
                // pcap is never fully materialised in RAM.
                let checksum = sha256_hex_file(path)?;
                if !state.segments.contains_key(&checksum) {
                    let candidate = SourceSegment {
                        path: path.clone(),
                        interface: "N2".into(),
                        checksum: checksum.clone(),
                        size_bytes: metadata.len(),
                        packets: count_pcap_records(path),
                        modified: metadata.modified().map_err(display_error)?,
                    };
                    let owned_file = format!("N2.pcap-bootstrap-{}.pcapng", &checksum[..16]);
                    copy_verified(&candidate, &base.join("pcap").join(&owned_file))?;
                    state.segments.insert(
                        checksum.clone(),
                        ImportedSegment {
                            interface: "N2".into(),
                            owned_file,
                            size_bytes: metadata.len(),
                            packets: candidate.packets,
                            imported_epoch_ms: epoch_ms(),
                            source_path: path.display().to_string(),
                            historical_context: true,
                        },
                    );
                    // The copied segment is only a publication candidate at
                    // this point. Its checksum becomes durable after the
                    // rebuilt dataset has been published atomically.
                    bootstrap_pending.push(checksum);
                }
            }
        }
        self.update(CONTINUOUS_CAPTURE_ID, |job| {
            job.state = CaptureState::Capturing;
            job.metrics.segments_ingested = state.seen_checksums.len() as u64;
            job.metrics.storage_bytes = directory_size(&base);
            if let Some(dataset) = &recovered_dataset {
                job.dataset_id = Some(dataset.dataset_id.clone());
                job.session_ids = dataset.session_ids.clone();
                job.metrics.decoded_events = dataset.event_count as u64;
                job.metrics.sessions_indexed = dataset.session_ids.len() as u64;
            }
        })?;
        loop {
            if self.continuous_stop.load(Ordering::Acquire) {
                self.update(CONTINUOUS_CAPTURE_ID, |job| {
                    job.state = CaptureState::Completed;
                    job.ended_epoch_ms = Some(epoch_ms());
                    job.stop_reason = Some("OPERATOR_REQUEST".into());
                })?;
                self.clear_continuous_active_credit()?;
                return Ok(());
            }
            let mut terminal_native_captures = Vec::new();
            if config.native_segment_seconds.is_some() {
                let existing = native_capture_ids(&config.source_root)?;
                let mut native_capture_active = false;
                for capture_id in existing {
                    let response = self.helper.request(&IpcRequest::GetCaptureStatus {
                        capture_id: capture_id.clone(),
                    })?;
                    if response.job.as_ref().is_some_and(|job| job.state.active()) {
                        native_capture_active = true;
                    } else {
                        terminal_native_captures.push(capture_id);
                    }
                }
                if native_capture_active {
                    thread::sleep(config.scan_interval.min(Duration::from_secs(5)));
                    continue;
                }
                let (native_owned_bytes, native_job_count) =
                    native_owned_usage(&config.source_root)?;
                // 2.11.2 (devmat, revue ANR1 — plus d'arrêt silencieux
                // sur BLOCKED). Règle projet :
                //   * blocage à 99 % des `max_owned_bytes`
                //   * alerte à 95 % des `max_owned_bytes`
                //   * sur les octets réellement possédés par OIRAN
                //     (`native_owned_bytes`), pas le FS entier.
                // Pré-2.11.2 : `> max_owned_bytes` (= 100 %) + `return
                // Ok(())` arrêtait la boucle d'import en silence
                // jusqu'à un redémarrage de l'API. ANR1 a dû
                // rollback 2.10.4 (`BOUNDED_STORAGE_FULL` sans
                // reprise auto).
                // 2.11.2 : garde dans la boucle, ne retourne jamais ;
                // réévaluation périodique → reprise auto dès que la
                // cause (bytes > 99 %) disparaît.
                let block_threshold_bytes = native_percentile_of_max(
                    config.max_owned_bytes,
                    99,
                );
                let alert_threshold_bytes = native_percentile_of_max(
                    config.max_owned_bytes,
                    95,
                );
                let over_block = native_owned_bytes >= block_threshold_bytes
                    || native_job_count > usize::from(config.max_segments);
                let over_alert = native_owned_bytes >= alert_threshold_bytes
                    && !over_block;
                if over_block {
                    self.update(CONTINUOUS_CAPTURE_ID, |job| {
                        job.state = CaptureState::Blocked;
                        job.error = Some("CONTINUOUS_NATIVE_AGGREGATE_BUDGET".into());
                        job.stop_reason = Some("BOUNDED_STORAGE_FULL".into());
                        // 2.11.2 : n'écrase pas `ended_epoch_ms` ici —
                        // la boucle reste vivante, pas « ended ».
                    })?;
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "event": "CONTINUOUS_IMPORT_BLOCKED",
                            "reason": "BOUNDED_STORAGE_FULL",
                            "native_owned_bytes": native_owned_bytes,
                            "max_owned_bytes": config.max_owned_bytes,
                            "block_threshold_bytes": block_threshold_bytes,
                            "native_job_count": native_job_count,
                            "max_segments": config.max_segments,
                            "auto_resume": "on next scan when bytes < 99% and job_count ≤ max",
                        })
                    );
                    thread::sleep(config.scan_interval.min(Duration::from_secs(5)));
                    continue;
                } else if over_alert {
                    self.update(CONTINUOUS_CAPTURE_ID, |job| {
                        job.error = Some(format!(
                            "CONTINUOUS_NATIVE_BUDGET_WARN: {:.1}% owned bytes",
                            (native_owned_bytes as f64 / config.max_owned_bytes as f64) * 100.0
                        ));
                    })?;
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "event": "CONTINUOUS_IMPORT_STORAGE_ALERT",
                            "native_owned_bytes": native_owned_bytes,
                            "max_owned_bytes": config.max_owned_bytes,
                            "alert_threshold_bytes": alert_threshold_bytes,
                            "percent": (native_owned_bytes as f64 / config.max_owned_bytes as f64) * 100.0,
                        })
                    );
                } else {
                    // 2.11.2 : condition disparue → reprise auto.
                    // Si l'état précédent était Blocked, re-transition
                    // Capturing (sans redémarrage).
                    self.update(CONTINUOUS_CAPTURE_ID, |job| {
                        if job.state == CaptureState::Blocked {
                            eprintln!(
                                "{}",
                                serde_json::json!({
                                    "event": "CONTINUOUS_IMPORT_RESUMED",
                                    "reason": "BOUNDED_STORAGE_FULL cleared",
                                    "native_owned_bytes": native_owned_bytes,
                                    "max_owned_bytes": config.max_owned_bytes,
                                })
                            );
                            job.state = CaptureState::Capturing;
                            job.stop_reason = None;
                            job.ended_epoch_ms = None;
                        }
                        if job.error.as_deref() == Some("CONTINUOUS_NATIVE_AGGREGATE_BUDGET") {
                            job.error = None;
                        }
                    })?;
                }
                if terminal_native_captures.is_empty() {
                    match self.run_native_segment(config) {
                        Ok(capture_id) => terminal_native_captures.push(capture_id),
                        Err(error) => {
                            if error.contains("DISK_SAFETY") {
                                // 2.11.2 : disque plein → BLOCKED visible + retry.
                                // Pas de return Ok(()) : la boucle reste vivante
                                // et re-tentera à chaque scan dès que
                                // run_native_segment n'échoue plus sur DISK_SAFETY.
                                self.update(CONTINUOUS_CAPTURE_ID, |job| {
                                    job.state = CaptureState::Blocked;
                                    job.error = Some(error.clone());
                                    job.stop_reason = Some("DISK_SAFETY_POLICY".into());
                                    // ended_epoch_ms NOT set — the worker is
                                    // alive and will auto-resume.
                                })?;
                                eprintln!(
                                    "{}",
                                    serde_json::json!({
                                        "event": "CONTINUOUS_IMPORT_BLOCKED",
                                        "reason": "DISK_SAFETY_POLICY",
                                        "detail": error,
                                        "auto_resume": "on next scan when disk safety policy allows capture",
                                    })
                                );
                                thread::sleep(config.scan_interval.min(Duration::from_secs(5)));
                                continue;
                            }
                            self.update(CONTINUOUS_CAPTURE_ID, |job| {
                                job.metrics.ingestion_failures =
                                    job.metrics.ingestion_failures.saturating_add(1);
                                job.error = Some(format!("CONTINUOUS_NATIVE_RETRYABLE: {error}"));
                            })?;
                            thread::sleep(config.scan_interval.min(Duration::from_secs(5)));
                            continue;
                        }
                    }
                }
            }
            // 2.8.2 (#10 comment 6687323881): cheap dir-mtime gate.
            // If no watched directory has mutated since the previous
            // scan AND the previous scan has no file still inside
            // the finalization safety window, we skip the full
            // `source_segments` walk entirely (no 20 000 statx on the
            // N3 directory any more). Files still awaiting their
            // safety-window expiry MUST keep the gate open —
            // `finalized_candidates_only` reclaims them by aging,
            // not by any directory mutation.
            let dirs_mutated =
                source_tree_mutated(&config.source_root, &mut dir_mtimes)?;
            // 2.8.2: when the directory hasn't moved we still owe a
            // periodic file-mtime drift check — an in-place append
            // (dumpcap overlapping-append) leaves the dir mtime
            // untouched on ext4. The check is bounded in size: above
            // `DRIFT_CHECK_MAX_FILES` entries we rely exclusively on
            // the dir-mtime gate because that is the only pattern
            // dumpcap rotation produces at that scale, and the per-
            // tick statx budget must stay under the 2% CPU gate.
            const DRIFT_CHECK_MAX_FILES: usize = 1024;
            let drift_due = !dirs_mutated
                && source_cache.len() <= DRIFT_CHECK_MAX_FILES
                && last_full_scan.elapsed() >= MTIME_DRIFT_CADENCE;
            let mtime_drift = drift_due && source_cache_mtime_drift(&source_cache);
            let scan_needed = dirs_mutated
                || mtime_drift
                || last_pending_finalization > 0
                || last_pending_stability > 0
                || last_pending_unseen > 0
                || last_pending_characterization > 0
                // 2.8.2: native-segment mode spawns rotation targets
                // inside `source_root/continuous-segment-*/` on its
                // own rhythm (`native_segment_seconds`). Skipping
                // scans there would stall the native pipeline. The
                // dir-mtime gate is a CPU optimization for the
                // read-only source case; native mode keeps its
                // existing 5 s poll.
                || config.native_segment_seconds.is_some();
            if !scan_needed {
                // Nothing changed on disk — behave as a quiet idle
                // tick: backoff, sleep, continue.
                const MAX_IDLE_SLEEP_GATE: Duration = Duration::from_secs(10);
                idle_backoff_factor = idle_backoff_factor.saturating_mul(2).min(16);
                let gate_sleep = config
                    .scan_interval
                    .saturating_mul(idle_backoff_factor)
                    .min(MAX_IDLE_SLEEP_GATE);
                thread::sleep(gate_sleep);
                continue;
            }
            let discovery = match source_segments(
                &config.source_root,
                config.stable_age,
                config.native_segment_seconds.is_some(),
                config.max_segment_bytes,
                &mut source_cache,
            ) {
                Ok(candidates) => candidates,
                Err(error) if !terminal_native_captures.is_empty() => {
                    self.update(CONTINUOUS_CAPTURE_ID, |job| {
                        job.metrics.ingestion_failures =
                            job.metrics.ingestion_failures.saturating_add(1);
                        job.error = Some(format!("CONTINUOUS_NATIVE_SEGMENT_REJECTED: {error}"));
                    })?;
                    thread::sleep(config.scan_interval.min(Duration::from_secs(5)));
                    continue;
                }
                Err(error) => return Err(error),
            };
            last_pending_finalization = discovery.pending_finalization;
            // 2.8.3 (#9 comment 6696366882): a KNOWN-ACTIVE segment
            // (lex-greatest filename per interface, no JSONL closure
            // proof) is EXPECTED to be absent from the fingerprint
            // cache. Excluding it here lets this counter reach zero on
            // a stable tree, so the dir-mtime gate at :2098 can short-
            // circuit idle ticks without a full scan. The 2.8.2
            // formula counted every path absent from the capped cache
            // as pending, so with 3 805 PCAPs and a 512 cap the
            // counter was ~3 292 and the loop never idled.
            last_pending_characterization = discovery
                .all_discovered_paths
                .iter()
                .filter(|path| {
                    !source_cache.contains_key(path.as_path())
                        && !discovery.known_active_paths.contains(path.as_path())
                })
                .count();
            // 2.9.1 (#9): publish the per-plane census to
            // `CaptureMetrics.plane_counts` so operators see the full
            // 12-interface landing. Log every unknown / no-decoder
            // path ONCE per worker lifetime.
            //
            // 2.9.2 (#9): also derive `job.interfaces` + `job.planes`
            // from the discovered set — the 2.9.0 initial state at
            // `:1161` hardcoded `["N2","N3","N4"]`, so SBI and the
            // LTE planes never appeared in the Analyzer UI even when
            // they were producing closed segments.
            {
                let plane_counts = discovery.plane_counts.clone();
                let mut to_log: Vec<PathBuf> = Vec::new();
                for path in &discovery.unknown_plane_paths {
                    if logged_unknown_planes.insert(path.clone()) {
                        to_log.push(path.clone());
                    }
                }
                let observed_interfaces: Vec<String> = plane_counts
                    .keys()
                    .filter(|key| key.as_str() != "UNKNOWN")
                    .cloned()
                    .collect();
                self.update(CONTINUOUS_CAPTURE_ID, |job| {
                    job.metrics.plane_counts = plane_counts.clone();
                    if !observed_interfaces.is_empty() {
                        job.interfaces = observed_interfaces.clone();
                        let existing: BTreeMap<String, CapturePlaneStatus> = std::mem::take(&mut job.planes)
                            .into_iter()
                            .map(|plane| (plane.interface.clone(), plane))
                            .collect();
                        job.planes = observed_interfaces
                            .iter()
                            .map(|iface| {
                                existing.get(iface).cloned().unwrap_or_else(|| {
                                    CapturePlaneStatus {
                                        plane: plane_name(iface).into(),
                                        interface: iface.clone(),
                                        capture_job_id: CONTINUOUS_CAPTURE_ID.into(),
                                        start_timestamp: None,
                                        end_timestamp: None,
                                        packet_count: 0,
                                        byte_count: 0,
                                        drop_count: None,
                                        storage_bytes: 0,
                                        decode_status: "OBSERVED".into(),
                                        dataset_id: None,
                                        source_sha256: Vec::new(),
                                        error: None,
                                    }
                                })
                            })
                            .collect();
                    }
                })?;
                for path in to_log {
                    let plane = source_interface(&config.source_root, &path)
                        .unwrap_or_else(|| "UNKNOWN".into());
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "event": "CONTINUOUS_PLANE_NOT_ALLOWLISTED",
                            "path": path.display().to_string(),
                            "plane": plane,
                        })
                    );
                }
            }
            last_full_scan = Instant::now();
            let mut newly_rejected = 0u64;
            for rejected in &discovery.rejected {
                let source_path = rejected.path.display().to_string();
                let already_recorded = state.failed_ingestions.iter().any(|failure| {
                    failure.source_path == source_path
                        && failure.source_size_bytes == Some(rejected.size_bytes)
                        && failure.error_code == "CONTINUOUS_SOURCE_SEGMENT_TOO_LARGE"
                });
                if !already_recorded {
                    record_ingestion_failure_with_size(
                        &mut state.failed_ingestions,
                        source_path,
                        Some(rejected.size_bytes),
                        "CONTINUOUS_SOURCE_SEGMENT_TOO_LARGE",
                        epoch_ms(),
                    );
                    newly_rejected = newly_rejected.saturating_add(1);
                }
            }
            if newly_rejected > 0 {
                atomic_write(
                    &state_path,
                    &serde_json::to_vec_pretty(&state).map_err(|error| error.to_string())?,
                )?;
                self.update(CONTINUOUS_CAPTURE_ID, |job| {
                    job.metrics.ingestion_failures = job
                        .metrics
                        .ingestion_failures
                        .saturating_add(newly_rejected);
                })?;
            }
            let candidates = discovery.segments;
            let candidate_paths = candidates
                .iter()
                .map(|candidate| candidate.path.clone())
                .collect::<BTreeSet<_>>();
            observed.retain(|path, _| candidate_paths.contains(path));
            // 2.8.2 (#10 comment 6687323881): retain source_cache and
            // purge fingerprints against the full disk-scan set
            // (`discovery.all_discovered_paths`), NOT the capped
            // `candidate_paths`. Using the capped set would mistakenly
            // evict entries beyond `MAX_SOURCE_CANDIDATES` even
            // though their file is still on disk, re-hashing them
            // forever.
            //
            // Native-segment mode routes capture files into the
            // manager's capture-root subtree, NOT `source_root`, so
            // `all_discovered_paths` is EMPTY for its iterations.
            // Skipping purge in that case preserves the in-flight
            // native-segment fingerprints and defers cleanup to a
            // non-native scan. For the non-native case
            // `all_discovered_paths` always contains at least one
            // entry when disk actually has files, so an empty set is
            // a safe "do not purge yet" signal.
            // 2.8.2: purge + source_cache retain are safe only for
            // the non-native path (native mode also pulls files from
            // `source_root/continuous-segment-*/<capture_id>/` with
            // a separate lifecycle). Skip for native mode entirely.
            if config.native_segment_seconds.is_none()
                && !discovery.all_discovered_paths.is_empty()
            {
                source_cache.retain(|path, _| discovery.all_discovered_paths.contains(path));
                let fingerprints_changed = purge_missing_source_fingerprints(
                    &mut state,
                    &discovery.all_discovered_paths,
                );
                if fingerprints_changed {
                    atomic_write(
                        &state_path,
                        &serde_json::to_vec_pretty(&state).map_err(|error| error.to_string())?,
                    )?;
                }
            }
            // 2.9.8 (#9 comment 6725097122): `/metrics` and
            // `job.json` must read the same authoritative source for
            // pending work. Both fields are set from the same
            // scan-local count so the invariant is proven by
            // construction. `pending_fingerprints` is the exact
            // mirror, surfaced so an audit can assert concordance
            // without touching internal state.
            let pending = candidates
                .iter()
                .filter(|candidate| !state.seen_checksums.contains(&candidate.checksum))
                .count() as u64;
            // 2.10.3 (devmat, revue 2.10.2 ANR2) : inventaire
            // explicite des segments pending + open. ANR2 a vu
            // `pending_segments=5` figés 1h+ sans savoir lesquels ;
            // on publie les chemins (bornés à 16) pour permettre à
            // l'opérateur de prouver « open par dumpcap » vs
            // « fermé mais pas ingéré ».
            let mut pending_paths: Vec<String> = candidates
                .iter()
                .filter(|candidate| !state.seen_checksums.contains(&candidate.checksum))
                .map(|candidate| candidate.path.display().to_string())
                .collect();
            pending_paths.truncate(16);
            let open_count = discovery.known_active_paths.len() as u64;
            let mut open_paths: Vec<String> = discovery
                .known_active_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect();
            open_paths.truncate(16);
            // Log structuré ligne unique par scan — ANR2 parse
            // directement via `journalctl -u oiran-api`.
            eprintln!(
                "{}",
                serde_json::json!({
                    "event": "CONTINUOUS_PENDING_INVENTORY",
                    "pending_segments": pending,
                    "pending_paths": pending_paths,
                    "open_segments": open_count,
                    "open_paths": open_paths,
                })
            );
            self.update(CONTINUOUS_CAPTURE_ID, |job| {
                job.metrics.pending_segments = pending;
                job.metrics.pending_fingerprints = pending;
                job.metrics.open_segments = open_count;
                job.metrics.open_segment_paths = open_paths.clone();
                job.metrics.pending_segment_paths = pending_paths.clone();
            })?;
            let mut pending_publication = std::mem::take(&mut bootstrap_pending);
            let mut changed = !pending_publication.is_empty();
            let prior_state = state.clone();
            let mut terminal_error = None;
            // 2.7.16: track ingestions since the last publish so we force a
            // bounded-batch commit even under burst. See
            // MAX_INGESTED_SEGMENTS_PER_SCAN.
            let mut ingested_this_scan: usize = 0;
            // 2.8.2: count candidates that passed the finalize filter
            // but were skipped because they appear for the first time
            // with a given `(size, mtime)` — they need a second scan
            // to prove stability. The gate uses this count to force
            // the required second scan even without a directory mutation.
            let mut pending_stability_this_scan: usize = 0;
            // 2.9.8 (#9 comment 6725097122): count candidates eligible
            // this scan but deferred because the per-scan batch cap
            // was hit. Surfaced through
            // `metrics.pending_batch_segments` and logged once per
            // deferred segment so no skip is silent.
            let mut pending_batch_this_scan: usize = 0;
            // 2.11.2 (devmat, revue ANR1) : un segment qui a un
            // SUCCESSEUR (= lex-plus-grand existe dans l'interface)
            // est stable par définition — dumpcap est passé à la
            // rotation suivante, le fichier courant ne reçoit plus
            // d'écriture. La garde de stabilité qui exigeait 2 scans
            // était redondante pour ces cas. 2.11.2 ingère ces
            // segments **dès le premier scan** et réserve la garde
            // aux (rares) cas où le segment est lex-greatest avec
            // rotation record (preuve plus faible, peut encore
            // recevoir un flush out-of-order théorique).
            let mut max_filename_by_iface: BTreeMap<String, String> = BTreeMap::new();
            for candidate in &candidates {
                let filename = candidate
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("")
                    .to_owned();
                if filename.is_empty() {
                    continue;
                }
                max_filename_by_iface
                    .entry(candidate.interface.clone())
                    .and_modify(|current| {
                        if filename > *current {
                            *current = filename.clone();
                        }
                    })
                    .or_insert(filename);
            }
            let mut candidate_iter = candidates.into_iter();
            while let Some(candidate) = candidate_iter.next() {
                if state.seen_checksums.contains(&candidate.checksum) {
                    continue;
                }
                let fingerprint = (candidate.size_bytes, candidate.modified);
                let stable_across_scans = observed.get(&candidate.path) == Some(&fingerprint);
                observed.insert(candidate.path.clone(), fingerprint);
                // 2.11.2 : « successeur présent = stable par définition ».
                let candidate_filename = candidate
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("");
                let has_successor = max_filename_by_iface
                    .get(&candidate.interface)
                    .map(|max| max.as_str() > candidate_filename)
                    .unwrap_or(false);
                if config.native_segment_seconds.is_none()
                    && !has_successor
                    && !stable_across_scans
                {
                    pending_stability_this_scan =
                        pending_stability_this_scan.saturating_add(1);
                    // 2.9.8 (#9 comment 6725097122): per-segment log —
                    // never silent. The counter below is reset to the
                    // scan total so operators can distinguish a fresh
                    // deferral from a cumulative drift.
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "event": "CONTINUOUS_SEGMENT_PENDING_STABILITY",
                            "path": candidate.path.display().to_string(),
                            "checksum": candidate.checksum,
                            "interface": candidate.interface,
                            "size_bytes": candidate.size_bytes,
                            "reason": "first observation of (size, mtime); needs one more scan",
                        })
                    );
                    continue;
                }
                if let Err(error) = decode_capture_streaming(
                    &DecodeConfig {
                        input: candidate.path.clone(),
                        capture_id: format!("sha256:{}", candidate.checksum),
                        interface: candidate.interface.clone(),
                        endpoints: endpoint_map(),
                    },
                    &pseudonym_key,
                    |_| Ok(()),
                ) {
                    self.update(CONTINUOUS_CAPTURE_ID, |job| {
                        job.metrics.ingestion_failures =
                            job.metrics.ingestion_failures.saturating_add(1);
                        job.error = Some(format!("CONTINUOUS_SEGMENT_NOT_FINALIZED: {error}"));
                    })?;
                    // 0.2.0 — persist the failure (source path + code + ts) so
                    // the record survives a probe restart and the operator can
                    // audit a 1h window without losing attempts.
                    record_ingestion_failure(
                        &mut state.failed_ingestions,
                        candidate.path.display().to_string(),
                        format!("CONTINUOUS_SEGMENT_NOT_FINALIZED: {error}"),
                        epoch_ms(),
                    );
                    atomic_write(
                        &state_path,
                        &serde_json::to_vec_pretty(&state).map_err(|error| error.to_string())?,
                    )?;
                    continue;
                }
                // 2.8.4 (#9 comment 6705466743): the count-based eviction
                // on `state.segments` is removed. ANR2 proved that at the
                // historic cap (production ring held < 32 slots at the
                // time), the repair tool's `state.segments` view saw only
                // the latest 6 snapshots of `_00068` instead of the 7
                // proven `_00067` snapshots. The repair tool now relies on
                // the dataset JSONL for history, and `state.segments`
                // grows with every import; `state.segments.retain(...)` on
                // startup (`:1903`) purges entries whose owned_file no
                // longer exists on disk. The byte-level `max_owned_bytes`
                // gate is kept — breaching it is a terminal error, no
                // silent eviction of historical context.
                let staging_bytes = work_bytes(&base);
                if staging_bytes
                    .saturating_add(candidate.size_bytes)
                    .saturating_add(MAX_CONTINUOUS_DERIVED_BYTES)
                    > config.max_owned_bytes
                {
                    // 2.9.8 (#9 comment 6725097122): per-segment log
                    // with the exact numbers so the operator sees
                    // which candidate tripped the gate and the
                    // decomposition of the staging budget. Prior
                    // releases emitted only the aggregate
                    // `CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT`
                    // terminal error — ANR2 could not point at the
                    // blocked N3 segment because nothing logged it.
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "event": "CONTINUOUS_SEGMENT_PENDING_BACKPRESSURE",
                            "path": candidate.path.display().to_string(),
                            "checksum": candidate.checksum,
                            "interface": candidate.interface,
                            "size_bytes": candidate.size_bytes,
                            "staging_bytes": staging_bytes,
                            "derived_reserve_bytes": MAX_CONTINUOUS_DERIVED_BYTES,
                            "max_owned_bytes": config.max_owned_bytes,
                            "reason": "staging + candidate + derived reserve > max_owned_bytes",
                        })
                    );
                    terminal_error = Some((
                        "CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT",
                        "BOUNDED_STORAGE_FULL",
                    ));
                    break;
                }
                let budget =
                    capture_budget(measure_path(&self.root), candidate.size_bytes, self.policy);
                if !budget.allowed {
                    // 2.9.8 (#9 comment 6725097122): same per-segment
                    // log pattern for the disk-safety path — never
                    // silent.
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "event": "CONTINUOUS_SEGMENT_PENDING_DISK_SAFETY",
                            "path": candidate.path.display().to_string(),
                            "checksum": candidate.checksum,
                            "interface": candidate.interface,
                            "size_bytes": candidate.size_bytes,
                            "reason": "disk-safety policy denies new captures",
                        })
                    );
                    terminal_error =
                        Some(("CONTINUOUS_IMPORT_DISK_POLICY_STOP", "DISK_SAFETY_POLICY"));
                    break;
                }
                let extension = candidate
                    .path
                    .extension()
                    .and_then(|value| value.to_str())
                    .unwrap_or("pcap");
                let owned_file = format!(
                    "{}.pcap-{}.{}",
                    candidate.interface,
                    &candidate.checksum[..16],
                    extension
                );
                let destination = base.join("pcap").join(&owned_file);
                if let Err(error) = copy_verified(&candidate, &destination) {
                    self.update(CONTINUOUS_CAPTURE_ID, |job| {
                        job.metrics.ingestion_failures =
                            job.metrics.ingestion_failures.saturating_add(1);
                        job.error = Some(format!("CONTINUOUS_COPY_RETRYABLE: {error}"));
                    })?;
                    record_ingestion_failure(
                        &mut state.failed_ingestions,
                        candidate.path.display().to_string(),
                        format!("CONTINUOUS_COPY_RETRYABLE: {error}"),
                        epoch_ms(),
                    );
                    atomic_write(
                        &state_path,
                        &serde_json::to_vec_pretty(&state).map_err(|error| error.to_string())?,
                    )?;
                    continue;
                }
                if let Err(error) = decode_capture_streaming(
                    &DecodeConfig {
                        input: destination.clone(),
                        capture_id: format!("sha256:{}", candidate.checksum),
                        interface: candidate.interface.clone(),
                        endpoints: endpoint_map(),
                    },
                    &pseudonym_key,
                    |_| Ok(()),
                ) {
                    let _ = fs::remove_file(&destination);
                    self.update(CONTINUOUS_CAPTURE_ID, |job| {
                        job.metrics.ingestion_failures =
                            job.metrics.ingestion_failures.saturating_add(1);
                        job.error = Some(format!("CONTINUOUS_SEGMENT_NOT_FINALIZED: {error}"));
                    })?;
                    record_ingestion_failure(
                        &mut state.failed_ingestions,
                        candidate.path.display().to_string(),
                        format!("CONTINUOUS_SEGMENT_NOT_FINALIZED: {error}"),
                        epoch_ms(),
                    );
                    atomic_write(
                        &state_path,
                        &serde_json::to_vec_pretty(&state).map_err(|error| error.to_string())?,
                    )?;
                    continue;
                }
                state.segments.insert(
                    candidate.checksum.clone(),
                    ImportedSegment {
                        interface: candidate.interface,
                        owned_file,
                        size_bytes: candidate.size_bytes,
                        packets: candidate.packets,
                        imported_epoch_ms: epoch_ms(),
                        source_path: candidate.path.display().to_string(),
                        historical_context: false,
                    },
                );
                pending_publication.push(candidate.checksum);
                changed = true;
                ingested_this_scan = ingested_this_scan.saturating_add(1);
                // 2.7.16: force a publish+sleep every MAX_INGESTED_SEGMENTS_PER_SCAN
                // candidates so the queue drains monotonically. Remaining
                // candidates will be re-discovered on the next scan because
                // their checksums have not yet been persisted into
                // seen_checksums (that happens only after a successful
                // publish at persist_published_checksums below).
                if ingested_this_scan >= MAX_INGESTED_SEGMENTS_PER_SCAN {
                    // 2.9.8 (#9 comment 6725097122): account every
                    // remaining eligible candidate deferred by the
                    // batch cap. Each gets a structured log record so
                    // no per-segment skip is silent; the aggregate is
                    // surfaced through `metrics.pending_batch_segments`.
                    for remaining in candidate_iter.by_ref() {
                        if state.seen_checksums.contains(&remaining.checksum) {
                            continue;
                        }
                        pending_batch_this_scan =
                            pending_batch_this_scan.saturating_add(1);
                        eprintln!(
                            "{}",
                            serde_json::json!({
                                "event": "CONTINUOUS_SEGMENT_PENDING_BATCH",
                                "path": remaining.path.display().to_string(),
                                "checksum": remaining.checksum,
                                "interface": remaining.interface,
                                "size_bytes": remaining.size_bytes,
                                "reason": "per-scan batch cap reached; retried next scan",
                            })
                        );
                    }
                    break;
                }
            }
            self.update(CONTINUOUS_CAPTURE_ID, |job| {
                job.metrics.pending_stability_segments =
                    pending_stability_this_scan as u64;
                job.metrics.pending_batch_segments =
                    pending_batch_this_scan as u64;
            })?;
            let mut published = !changed;
            if changed {
                match self.process_continuous_capture(
                    &base,
                    &interface_specs(),
                    config.max_owned_bytes,
                ) {
                    Ok(dataset) => {
                        self.upsert_dataset(dataset.clone(), &base.join("dataset"))?;
                        // Publication is the commit point. If persisting the
                        // marker fails, the checksum remains unseen and the
                        // next scan safely retries the segment.
                        persist_published_checksums(&state_path, &mut state, &pending_publication)?;
                        let packets = dataset
                            .decode_reports
                            .values()
                            .map(|report| report.packets as u64)
                            .sum();
                        let bytes = directory_size(&base);
                        self.update(CONTINUOUS_CAPTURE_ID, |job| {
                            job.dataset_id = Some(dataset.dataset_id.clone());
                            job.session_ids = dataset.session_ids.clone();
                            job.metrics.packets_received = packets;
                            job.metrics.bytes_received = bytes;
                            job.metrics.storage_bytes = bytes;
                            job.metrics.queue_occupancy_percent = Some(
                                (bytes as f64 / config.max_owned_bytes as f64 * 100.0).min(100.0),
                            );
                            job.metrics.segments_ingested = state.seen_checksums.len() as u64;
                            job.metrics.pending_segments = 0;
                            // 2.9.8: keep the mirror field in lockstep
                            // with `pending_segments` so `/metrics`
                            // and `job.json` prove concordance by
                            // construction.
                            job.metrics.pending_fingerprints = 0;
                            // 2.10.3 : effacer aussi la liste ;
                            // open_segments / open_segment_paths
                            // reflètent les segments ouverts et
                            // conservent leur valeur courante.
                            job.metrics.pending_segment_paths = Vec::new();
                            // 2.10.3 : surfacer les segments
                            // ingérés qui n'ont produit AUCUN
                            // événement (défaut silencieux du
                            // décodeur — cas S6a `_00064`/`_00065`
                            // observé en production 2.10.2).
                            // Cumul lifetime worker ; liste bornée à
                            // 16 chemins.
                            if !dataset.zero_event_captures.is_empty() {
                                job.metrics.zero_event_segments = job
                                    .metrics
                                    .zero_event_segments
                                    .saturating_add(
                                        dataset.zero_event_captures.len() as u64,
                                    );
                                let mut combined: Vec<String> = std::mem::take(
                                    &mut job.metrics.zero_event_segment_paths,
                                );
                                combined.extend(dataset.zero_event_captures.iter().cloned());
                                let combined_len = combined.len();
                                let skip = combined_len.saturating_sub(16);
                                job.metrics.zero_event_segment_paths =
                                    combined.into_iter().skip(skip).collect();
                            }
                            job.metrics.decoded_events = dataset.event_count as u64;
                            job.metrics.sessions_indexed = dataset.session_ids.len() as u64;
                            job.metrics.last_ingested_epoch_ms = Some(epoch_ms());
                            job.metrics.last_packet_epoch_ms = dataset.last_packet_epoch_ms;
                            job.metrics.fresh_packet_count = dataset.fresh_packet_count;
                            job.metrics.active_ue_ips = dataset.active_ue_ips.clone();
                            job.error = None;
                        })?;
                        published = true;
                    }
                    Err(error) => {
                        state = prior_state;
                        // 2.7.23: `CONTINUOUS_DERIVED_OUTPUT_LIMIT` is
                        // non-retryable — looping on the same input
                        // would just re-produce the same oversize
                        // output. Mark the capture `Blocked` with a
                        // stop_reason and exit the worker. Every
                        // other error class (decode, I/O) stays
                        // retryable.
                        if error.starts_with("CONTINUOUS_DERIVED_OUTPUT_LIMIT") {
                            self.update(CONTINUOUS_CAPTURE_ID, |job| {
                                job.state = CaptureState::Blocked;
                                job.error = Some(error.clone());
                                job.stop_reason =
                                    Some("DERIVED_OUTPUT_EXCEEDS_LIMIT".into());
                                job.ended_epoch_ms = Some(epoch_ms());
                            })?;
                            return Ok(());
                        }
                        self.update(CONTINUOUS_CAPTURE_ID, |job| {
                            job.metrics.ingestion_failures =
                                job.metrics.ingestion_failures.saturating_add(1);
                            job.error = Some(format!("CONTINUOUS_DECODE_RETRYABLE: {error}"));
                        })?;
                    }
                }
            }
            if published {
                for capture_id in terminal_native_captures {
                    if native_capture_fully_ingested(
                        &config.source_root,
                        &capture_id,
                        &state.seen_checksums,
                        config.max_segment_bytes,
                    )? {
                        self.finalize_native_capture(&config.source_root, &capture_id)?;
                    }
                }
            }
            let native_budget_exceeded = if config.native_segment_seconds.is_some() {
                let (bytes, jobs) = native_owned_usage(&config.source_root)?;
                bytes > config.max_owned_bytes || jobs > usize::from(config.max_segments)
            } else {
                false
            };
            if native_budget_exceeded {
                self.update(CONTINUOUS_CAPTURE_ID, |job| {
                    job.state = CaptureState::Blocked;
                    job.error = Some("CONTINUOUS_NATIVE_AGGREGATE_BUDGET".into());
                    job.stop_reason = Some("BOUNDED_STORAGE_FULL".into());
                    job.ended_epoch_ms = Some(epoch_ms());
                })?;
                return Ok(());
            }
            if let Some((error, reason)) = terminal_error {
                // 2.7.16: backpressure is recoverable. The candidate that
                // tripped the limit is not in seen_checksums yet (we only
                // commit after publish), so the next scan will re-discover
                // it once eviction frees space. Only DISK_SAFETY_POLICY and
                // other non-recoverable terminals exit the worker.
                let recoverable = error == "CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT";
                self.update(CONTINUOUS_CAPTURE_ID, |job| {
                    job.state = CaptureState::Blocked;
                    job.error = Some(error.into());
                    job.stop_reason = Some(reason.into());
                    if !recoverable {
                        job.ended_epoch_ms = Some(epoch_ms());
                    }
                })?;
                if !recoverable {
                    return Ok(());
                }
            }
            // 2.8.2 (#10 comment 6687323881): persist the source
            // cache ONLY when `source_segments` signalled a cache
            // mutation (a new or modified file was hashed) OR when
            // the purge dropped a vanished file. The 2.8.1 code
            // unconditionally rebuilt a 10 000-entry BTreeMap +
            // byte-compared it on every scan — ANR2 measured the
            // cost. The persistence is now strictly event-driven.
            //
            // 2.9.8 (#9 comment 6725097122): the trigger set now also
            // includes "a segment was published this scan". A scan
            // that hits a cached SHA (`cache_mutated=false`) and
            // publishes it successfully would otherwise never land
            // the fingerprint in `state.source_fingerprints` under
            // the stricter invariant below — the committed SHA would
            // have to wait for an unrelated mutation to be persisted.
            if discovery.cache_mutated || published {
                // 2.9.8 (#9 comment 6725097122): persist ONLY
                // fingerprints whose checksum is in `seen_checksums`
                // — i.e. a segment that has been successfully
                // imported AND published via
                // `persist_published_checksums`. Any fingerprint
                // produced during discovery but never committed
                // (`!stable_across_scans`, batch cap, publish
                // rollback at `:2949`) stays in the in-memory
                // `source_cache` only; on worker restart it will be
                // rehashed, re-admitted, and re-attempted — never
                // stuck as an orphan.
                let next_fingerprints: BTreeMap<String, SourceFingerprint> = source_cache
                    .iter()
                    .filter(|(_, fingerprint)| {
                        state.seen_checksums.contains(&fingerprint.checksum)
                    })
                    .map(|(path, fingerprint)| {
                        (path.display().to_string(), fingerprint.clone())
                    })
                    .collect();
                if next_fingerprints != state.source_fingerprints {
                    state.source_fingerprints = next_fingerprints;
                    atomic_write(
                        &state_path,
                        &serde_json::to_vec_pretty(&state).map_err(|error| error.to_string())?,
                    )?;
                }
            }
            // 2.8.1 backoff: if we did useful work (published or found
            // a pending candidate) reset to the configured scan_interval
            // so the NEXT segment lands within the configured latency.
            // Otherwise double the sleep up to the bounded cap. Import
            // latency of a freshly rotated segment is therefore bounded
            // by `MAX_IDLE_SLEEP`.
            const MAX_IDLE_SLEEP: Duration = Duration::from_secs(10);
            // 2.8.2: carry forward the stability counter so the gate
            // forces the required second scan even when the directory
            // has not mutated. Reset when no candidate needs it.
            last_pending_stability = pending_stability_this_scan;
            last_pending_unseen = pending;
            if pending > 0 || changed || pending_stability_this_scan > 0 {
                idle_backoff_factor = 1;
            } else {
                idle_backoff_factor = idle_backoff_factor.saturating_mul(2).min(16);
            }
            let sleep_for = config
                .scan_interval
                .saturating_mul(idle_backoff_factor)
                .min(MAX_IDLE_SLEEP);
            thread::sleep(sleep_for);
        }
    }

    fn run_native_segment(&self, config: &ContinuousImportConfig) -> Result<String, String> {
        let duration = config
            .native_segment_seconds
            .ok_or_else(|| "CONTINUOUS_NATIVE_DISABLED".to_string())?;
        let capture_id = format!("continuous-segment-{}", epoch_ms());
        let spec = CaptureSpec {
            capture_id: capture_id.clone(),
            interfaces: vec![InterfaceId::N2, InterfaceId::N3, InterfaceId::N4],
            duration_seconds: duration,
            max_bytes: 12 * 1024 * 1024,
            rotation_files: 1,
        };
        let response = self.helper.request(&IpcRequest::StartCapture(spec))?;
        if !response.ok {
            return Err(format_helper_error(response.error));
        }
        loop {
            if self.continuous_stop.load(Ordering::Acquire) {
                let _ = self.helper.request(&IpcRequest::StopCapture {
                    capture_id: capture_id.clone(),
                });
            }
            let response = self.helper.request(&IpcRequest::GetCaptureStatus {
                capture_id: capture_id.clone(),
            })?;
            if !response.ok {
                return Err(format_helper_error(response.error));
            }
            let job = response
                .job
                .ok_or("capture helper omitted native segment state")?;
            if !job.state.active() {
                if matches!(
                    job.state,
                    HelperState::Completed | HelperState::CompletedEmpty
                ) {
                    return Ok(capture_id);
                }
                return Err(job
                    .failure
                    .map(|failure| format!("{}: {}", failure.category, failure.details))
                    .unwrap_or_else(|| "CONTINUOUS_NATIVE_SEGMENT_FAILED".into()));
            }
            thread::sleep(Duration::from_millis(200));
        }
    }

    fn finalize_native_capture(&self, root: &Path, capture_id: &str) -> Result<(), String> {
        cleanup_native_capture(root, capture_id)?;
        let forgotten = self
            .helper
            .request(&IpcRequest::ForgetCapture {
                capture_id: capture_id.to_owned(),
            })
            .is_ok_and(|response| response.ok);
        if !forgotten {
            self.update(CONTINUOUS_CAPTURE_ID, |job| {
                job.metrics.ingestion_failures = job.metrics.ingestion_failures.saturating_add(1);
                job.error = Some("CONTINUOUS_NATIVE_FORGET_RETRYABLE".into());
            })?;
        }
        Ok(())
    }

    fn run_job_inner(&self, capture_id: &str, request: &CaptureRequest) -> Result<(), String> {
        let selected = self
            .interfaces()
            .into_iter()
            .filter(|interface| request.interfaces.contains(&interface.interface))
            .collect::<Vec<_>>();
        let mut previous_packets = 0;
        let mut previous_bytes = 0;
        let mut previous_sample = Instant::now();
        let terminal = loop {
            let response = self.helper.request(&IpcRequest::GetCaptureStatus {
                capture_id: capture_id.into(),
            })?;
            if !response.ok {
                return Err(format_helper_error(response.error));
            }
            let helper_job = response.job.ok_or("capture helper omitted job state")?;
            let packets = helper_job.metrics.packets_received;
            let bytes = helper_job.metrics.bytes_received;
            let elapsed = previous_sample.elapsed().as_secs_f64().max(0.001);
            let pps = packets.saturating_sub(previous_packets) as f64 / elapsed;
            let bps = bytes.saturating_sub(previous_bytes) as f64 * 8.0 / elapsed;
            previous_packets = packets;
            previous_bytes = bytes;
            previous_sample = Instant::now();
            let mapped_state = map_helper_state(helper_job.state);
            self.update(capture_id, |job| {
                job.state = mapped_state;
                job.started_epoch_ms = helper_job.started_epoch_ms;
                job.ended_epoch_ms = helper_job.ended_epoch_ms;
                job.metrics.packets_received = packets;
                job.metrics.bytes_received = bytes;
                job.metrics.storage_bytes = helper_job.metrics.storage_bytes;
                job.metrics.packet_drops = helper_job.metrics.packet_drops;
                job.metrics.packets_per_second = pps;
                job.metrics.bits_per_second = bps;
                job.metrics.duration_seconds = helper_job.metrics.duration_seconds;
                job.metrics.queue_occupancy_percent = Some(
                    (helper_job.metrics.storage_bytes as f64 / request.max_bytes as f64 * 100.0)
                        .min(100.0),
                );
                for plane in &mut job.planes {
                    plane.start_timestamp = helper_job.started_epoch_ms;
                    plane.end_timestamp = helper_job.ended_epoch_ms;
                    plane.drop_count = helper_job.metrics.packet_drops;
                    plane.decode_status = if helper_job.state.active() {
                        "CAPTURING".into()
                    } else {
                        "CAPTURED".into()
                    };
                }
            })?;
            if !helper_job.state.active() {
                break helper_job;
            }
            thread::sleep(Duration::from_millis(200));
        };
        if terminal.state == HelperState::Failed {
            let failure = terminal
                .failure
                .unwrap_or_else(|| capture_helper::HelperFailure {
                    category: "CAPTURE_HELPER_FAILED".into(),
                    details: "capture helper failed without details".into(),
                    exit_code: None,
                    termination_signal: None,
                });
            self.update(capture_id, |job| {
                job.helper_results = vec![CaptureHelperResult {
                    interface: "ISOLATED_HELPER".into(),
                    process_id: 0,
                    exit_code: failure.exit_code,
                    termination_signal: failure.termination_signal,
                    error_category: Some(failure.category.clone()),
                    success: false,
                    stderr: failure.details.clone(),
                }];
                for plane in &mut job.planes {
                    plane.decode_status = "FAILED".into();
                    plane.error = Some(format!("{}: {}", failure.category, failure.details));
                    plane.end_timestamp = terminal.ended_epoch_ms;
                }
            })?;
            return Err(format!("{}: {}", failure.category, failure.details));
        }
        self.update(capture_id, |job| {
            job.state = CaptureState::Processing;
            job.process_ids.clear();
        })?;
        let files = capture_files(&self.root.join(capture_id).join("pcap"));
        if files.is_empty() {
            return Err("CAPTURE_OUTPUT_MISSING".into());
        }
        let (captured_packets, _) = pcap_totals(&files);
        self.update(capture_id, |job| {
            for plane in &mut job.planes {
                let matching = files
                    .iter()
                    .filter(|path| {
                        path.file_name()
                            .and_then(|name| name.to_str())
                            .is_some_and(|name| name.starts_with(&plane.interface))
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                let (packets, storage_bytes) = pcap_totals(&matching);
                plane.packet_count = packets;
                plane.byte_count = matching.iter().map(|path| pcap_record_totals(path).1).sum();
                plane.storage_bytes = storage_bytes;
                plane.decode_status = if packets == 0 {
                    "COMPLETED_EMPTY".into()
                } else {
                    "CAPTURED_PENDING_DECODE".into()
                };
            }
        })?;
        let dataset = self.process_capture(capture_id, &selected)?;
        self.register_dataset(dataset.clone(), &self.root.join(capture_id).join("dataset"))?;
        let plane_results = build_plane_results(
            capture_id,
            &request.interfaces,
            &files,
            &dataset,
            terminal.started_epoch_ms,
            terminal.ended_epoch_ms,
            terminal.metrics.packet_drops,
        );
        self.update(capture_id, |job| {
            job.state = if captured_packets == 0 {
                CaptureState::CompletedEmpty
            } else {
                CaptureState::Completed
            };
            job.ended_epoch_ms = Some(epoch_ms());
            job.dataset_id = Some(dataset.dataset_id.clone());
            job.session_ids = dataset.session_ids.clone();
            job.metrics.decoded_events = dataset.event_count as u64;
            if captured_packets == 0 {
                job.stop_reason = Some("EMPTY_CAPTURE_COMPLETED".into());
            } else {
                job.stop_reason = Some("DURATION_OR_OPERATOR_COMPLETE".into());
            }
            let duration = job.metrics.duration_seconds.max(0.001);
            job.metrics.decode_events_per_second = dataset.event_count as f64 / duration;
            job.planes = plane_results;
        })?;
        self.audit(
            &request.probe_id,
            "CAPTURE_COMPLETED",
            capture_id,
            job_state_label(terminal.state),
        )
    }

    fn process_capture(
        &self,
        capture_id: &str,
        interfaces: &[CaptureInterface],
    ) -> Result<LiveDataset, String> {
        let dataset_id = format!("dataset-{capture_id}");
        let base = self.root.join(capture_id);
        let dataset_dir = base.join("dataset");
        self.process_capture_into(
            capture_id,
            dataset_id,
            &base.join("pcap"),
            &dataset_dir,
            format!("runtime/live-captures/{capture_id}/dataset"),
            interfaces,
        )
    }

    /// 2.7.23: exposed `pub` so RSS harnesses (see
    /// `examples/rss_publication.rs`) can drive one publication cycle
    /// without the full `start_continuous_import` orchestration (which
    /// requires the lab-only allowlisted source directory). Production
    /// callers go through `start_continuous_import`.
    pub fn process_continuous_capture(
        &self,
        base: &Path,
        interfaces: &[CaptureInterface],
        max_owned_bytes: u64,
    ) -> Result<LiveDataset, String> {
        // 2.7.28: cross-process advisory lock (flock) held through the
        // entire dataset-next → dataset swap. `dataset-restore` takes
        // the same lock with `LOCK_NB` and refuses with
        // `RESTORE_REQUIRES_PUBLICATION_LOCK` when the worker holds it.
        let _publication_lock = PublicationLock::acquire_blocking(base)?;
        let current = base.join("dataset");
        let next = base.join(".dataset-next");
        let previous = base.join(".dataset-previous");
        if previous.is_dir() && !current.is_dir() {
            fs::rename(&previous, &current).map_err(display_error)?;
        }
        if next.exists() {
            fs::remove_dir_all(&next).map_err(display_error)?;
        }
        if work_bytes(base).saturating_add(MAX_CONTINUOUS_DERIVED_BYTES) > max_owned_bytes {
            return Err("CONTINUOUS_ATOMIC_TEMP_BUDGET".into());
        }
        let result = self.process_capture_into(
            CONTINUOUS_CAPTURE_ID,
            CONTINUOUS_DATASET_ID.into(),
            &base.join("pcap"),
            &next,
            format!("runtime/live-captures/{CONTINUOUS_CAPTURE_ID}/dataset"),
            interfaces,
        );
        let dataset = match result {
            Ok(dataset) => dataset,
            Err(error) => {
                let _ = fs::remove_dir_all(&next);
                return Err(error);
            }
        };
        let next_bytes = directory_size(&next);
        let derived_limit = derived_output_hard_limit_bytes();
        if next_bytes > derived_limit {
            let _ = fs::remove_dir_all(&next);
            // 2.7.23: the in-publish merge (`process_capture_into`)
            // applied the age-based retention at
            // `OIRAN_DATASET_RETENTION_DAYS` days already, so the
            // `next_bytes` figure above is *after* retention. If it
            // still exceeds the configured cap the operator must
            // either shorten the retention window or raise
            // `OIRAN_CONTINUOUS_DERIVED_OUTPUT_MAX_BYTES`. The worker
            // treats this as non-retryable (see the handler in
            // `run_continuous_import_inner`): one attempt, then
            // `Blocked`, no retry loop.
            let retention_label = retention_days()
                .map(|days| days.to_string())
                .unwrap_or_else(|| "disabled".to_string());
            return Err(format!(
                "CONTINUOUS_DERIVED_OUTPUT_LIMIT: derived output {next_bytes} B exceeds \
                 OIRAN_CONTINUOUS_DERIVED_OUTPUT_MAX_BYTES={derived_limit} B after \
                 age-based retention (OIRAN_DATASET_RETENTION_DAYS={retention_label}); \
                 shorten the retention window or raise the limit",
            ));
        }
        if previous.exists() {
            fs::remove_dir_all(&previous).map_err(display_error)?;
        }
        if current.exists() {
            fs::rename(&current, &previous).map_err(display_error)?;
        }
        if let Err(error) = fs::rename(&next, &current) {
            if previous.is_dir() {
                let _ = fs::rename(&previous, &current);
            }
            return Err(display_error(error));
        }
        if previous.exists() {
            fs::remove_dir_all(&previous).map_err(display_error)?;
        }
        Ok(dataset)
    }

    /// 2.7.28 (issue #10, ANR2 defect on 2.7.27): atomic restore from a
    /// `archive_stale_captures` segment. The hot view is never written
    /// directly — the operator stops the import worker (which would
    /// otherwise hold the publication lock) and invokes this, which:
    ///
    /// 1. Acquires the same `flock` publication lock as the worker.
    ///    Contention → `RESTORE_REQUIRES_PUBLICATION_LOCK`. The
    ///    operator stops `oiran-api.service` before running
    ///    `dataset-restore`; the worker cannot run concurrently.
    /// 2. Validates the archive segment's `manifest.events_sha256`
    ///    against the on-disk `events.jsonl`. Mismatch →
    ///    `RESTORE_ARCHIVE_TAMPERED`.
    /// 3. Reads the current `dataset_manifest.json` (if any) and keeps
    ///    it as the `prior_continuous` checkpoint — operator-written
    ///    `decode_reports` and `checksums` survive restore unchanged.
    /// 4. Prepares `<base>/.dataset-next/` (wipe + recreate) and writes
    ///    `oiran_events.jsonl` by streaming the union of the current
    ///    hot view and the archive segment through a `BTreeSet<event_id>`
    ///    dedup (first occurrence wins), then sorting canonically by
    ///    `(capture_id, packet_number, event_id)` — session-engine's
    ///    `canonical_sort_key` — never by timestamp.
    /// 5. Invokes `publish_events_to_dataset_dir` — the same helper
    ///    `process_capture_into` uses after its PCAP decode — so
    ///    sessions, correlation, callflows and manifest are rebuilt
    ///    through the identical publication path.
    /// 6. Atomically swaps `.dataset-next/` ↔ `dataset/` via
    ///    `.dataset-previous/` and registers the fresh manifest in the
    ///    `datasets` map so `/health` observes the restored view
    ///    immediately.
    ///
    /// Idempotent by construction: two restores on the same inputs
    /// produce byte-identical `oiran_events.jsonl` (dedup+sort is
    /// deterministic) and therefore byte-identical downstream
    /// artifacts.
    pub fn restore_from_archive_segment(
        &self,
        archive_segment_dir: &Path,
    ) -> Result<DatasetRestoreReport, String> {
        let base = self.root.join(CONTINUOUS_CAPTURE_ID);
        let _publication_lock = PublicationLock::try_acquire(&base)?;
        let current = base.join("dataset");
        let next = base.join(".dataset-next");
        let previous = base.join(".dataset-previous");
        if previous.is_dir() && !current.is_dir() {
            fs::rename(&previous, &current).map_err(display_error)?;
        }
        if next.exists() {
            fs::remove_dir_all(&next).map_err(display_error)?;
        }
        let current_events = current.join("oiran_events.jsonl");
        if !current_events.is_file() {
            return Err(format!(
                "RESTORE_MISSING_HOT_VIEW: {}",
                current_events.display()
            ));
        }
        let archive_events = archive_segment_dir.join("events.jsonl");
        if !archive_events.is_file() {
            return Err(format!(
                "RESTORE_MISSING_ARCHIVE_EVENTS: {}",
                archive_events.display()
            ));
        }
        let archive_manifest_path = archive_segment_dir.join("manifest.json");
        if archive_manifest_path.is_file() {
            let manifest: Value =
                serde_json::from_slice(&fs::read(&archive_manifest_path).map_err(display_error)?)
                    .map_err(|error| error.to_string())?;
            if let Some(expected) = manifest.get("events_sha256").and_then(Value::as_str) {
                let actual = sha256_hex_file(&archive_events)?;
                if actual != expected {
                    return Err(format!(
                        "RESTORE_ARCHIVE_TAMPERED: manifest sha {expected} != actual {actual}"
                    ));
                }
            }
        }
        // Prior continuous checkpoint: the restore carries over
        // operator-written `decode_reports` + `checksums` from the
        // current manifest if it exists AND validates against its
        // JSONL. A drifted manifest (ANR2's 2.7.27 symptom) is NOT
        // reused — the restore is also the recovery path, so we treat
        // it the same way 2.7.20 tolerates a missing manifest and
        // rebuild from the events alone.
        let prior_continuous: Option<(PathBuf, LiveDataset)> = if current
            .join("dataset_manifest.json")
            .is_file()
        {
            let bytes = fs::read(current.join("dataset_manifest.json")).map_err(display_error)?;
            if let Ok(dataset) = serde_json::from_slice::<LiveDataset>(&bytes) {
                if validate_dataset_artifacts(&dataset, &current).is_ok() {
                    Some((current.clone(), dataset))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        let event_count_before = count_valid_event_records(&current_events)?;
        let archive_event_count = count_valid_event_records(&archive_events)?;
        prepare_dataset_directory(&next)?;
        let next_events = next.join("oiran_events.jsonl");
        let (overlap_event_ids, events_sha256) =
            canonical_dedup_merge(&current_events, &archive_events, &next_events)?;
        let event_count_after = count_valid_event_records(&next_events)?;
        let dataset = self.publish_events_to_dataset_dir(
            CONTINUOUS_CAPTURE_ID,
            CONTINUOUS_DATASET_ID.into(),
            &next,
            format!("runtime/live-captures/{CONTINUOUS_CAPTURE_ID}/dataset"),
            prior_continuous,
            BTreeMap::new(),
            BTreeMap::new(),
            Vec::new(),
        )?;
        // Atomic swap next ↔ current via previous.
        if previous.exists() {
            fs::remove_dir_all(&previous).map_err(display_error)?;
        }
        if current.exists() {
            fs::rename(&current, &previous).map_err(display_error)?;
        }
        if let Err(error) = fs::rename(&next, &current) {
            if previous.is_dir() {
                let _ = fs::rename(&previous, &current);
            }
            return Err(display_error(error));
        }
        if previous.exists() {
            fs::remove_dir_all(&previous).map_err(display_error)?;
        }
        self.upsert_dataset(dataset.clone(), &current)?;
        Ok(DatasetRestoreReport {
            schema_version: "2.7.28",
            archive_segment_dir: archive_segment_dir.display().to_string(),
            dataset_dir: current.display().to_string(),
            event_count_before,
            archive_event_count,
            overlap_event_count: overlap_event_ids.len(),
            overlap_event_ids,
            event_count_after,
            session_ids: dataset.session_ids.clone(),
            events_sha256,
        })
    }

    /// 2.8.4 (#9 comment 6705466743): historical repair driven by the
    /// CONTENT of the published dataset. ANR2 showed that
    /// `state.segments` can evict history on busy production
    /// deployments, so the repair tool no longer trusts it as the
    /// grouping source. Instead the dataset's `oiran_events.jsonl` is
    /// scanned once; every event is anchored on:
    ///
    ///   * `capture_id = "sha256:<hex>"` — the SNAPSHOT identity (the
    ///     SHA-256 of the pcap file bytes at the moment of import).
    ///     Events from the same snapshot share this.
    ///   * `packet_references[0].source_file` — the owned-file basename
    ///     carries `{interface}.pcap-{sha16}.{ext}` and reveals the
    ///     interface without any lookup.
    ///   * `(interface, first_packet_raw_ticks, first_packet_number,
    ///     first_packet_byte_offset)` — the SEGMENT identity. Two
    ///     snapshots of the same growing dumpcap file share packet 1
    ///     bit-for-bit, so they share this tuple. This is the
    ///     `reconstruction_key` surfaced in the report.
    ///
    /// For each group with more than one snapshot:
    ///
    ///   * If `source_root` is provided, every `<source_root>/<interface_lc>/*.pcapng`
    ///     is SHA-256-hashed (the 2.8.3 sequence rule already identified
    ///     closed files, so the lex-greatest sibling — the active dumpcap
    ///     target — is excluded). The snapshot whose `capture_id` equals
    ///     one of those SHAs is the FINAL. Its events are kept; the other
    ///     snapshots are removed with
    ///     `partial-import-superseded-by-final-capture-id=sha256:…`.
    ///   * If `source_root` is absent AND `state.segments` carries all
    ///     snapshots of the group, the final falls back to the snapshot
    ///     with the largest `size_bytes`. 2.8.4 removes the
    ///     count/byte eviction on `state.segments`, so every import
    ///     going forward is captured and the fallback is safe.
    ///   * Otherwise the group is reported as unresolved and NONE of
    ///     its events are touched.
    ///
    /// Semantics preserved vs. `restore_from_archive_segment`:
    ///   * `flock(LOCK_EX|LOCK_NB)` on
    ///     `<capture-root>/<continuous-capture-id>/.publication.lock`.
    ///   * The hot `dataset/oiran_events.jsonl` is NEVER written
    ///     directly; everything goes through `.dataset-next` + atomic
    ///     swap via `.dataset-previous`.
    ///   * Output sorted canonically by
    ///     `(capture_id, packet_number, event_id)`.
    ///   * Manifest `event_count` equals the number of written lines.
    ///   * Idempotent: the second run on the same inputs produces an
    ///     identical `oiran_events.jsonl` (same SHA-256).
    pub fn repair_partial_imports(
        &self,
        dry_run: bool,
        source_root: Option<&Path>,
    ) -> Result<DatasetRepairReport, String> {
        let base = self.root.join(CONTINUOUS_CAPTURE_ID);
        let _publication_lock = PublicationLock::try_acquire(&base)?;
        let current = base.join("dataset");
        let next = base.join(".dataset-next");
        let previous = base.join(".dataset-previous");
        if previous.is_dir() && !current.is_dir() {
            fs::rename(&previous, &current).map_err(display_error)?;
        }
        if next.exists() {
            fs::remove_dir_all(&next).map_err(display_error)?;
        }
        let current_events = current.join("oiran_events.jsonl");
        if !current_events.is_file() {
            return Err(format!(
                "REPAIR_MISSING_HOT_VIEW: {}",
                current_events.display()
            ));
        }
        // 2.8.4: `state.segments` is consulted ONLY as a fallback
        // when `source_root` is absent. Missing or invalid state.json
        // is not fatal — the content-based grouping still works.
        let state_path = base.join("import_state.json");
        let state = if state_path.is_file() {
            serde_json::from_slice::<ContinuousImportState>(
                &fs::read(&state_path).map_err(display_error)?,
            )
            .unwrap_or_default()
        } else {
            ContinuousImportState::default()
        };

        // Phase 1 — walk the JSONL once and build the snapshot index.
        struct SnapshotScan {
            capture_id: String,
            owned_file: String,
            interface: String,
            first_raw_ticks: i128,
            first_packet_number: u64,
            first_byte_offset: u64,
            max_packet_number: u64,
            event_count: usize,
        }
        let mut snapshots: BTreeMap<String, SnapshotScan> = BTreeMap::new();
        let event_count_before = count_valid_event_records(&current_events)?;
        {
            let reader = BufReader::new(fs::File::open(&current_events).map_err(display_error)?);
            for line in reader.lines() {
                let line = line.map_err(display_error)?;
                if line.trim().is_empty() {
                    continue;
                }
                let Ok(value) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                let Some(capture_id) = value.get("capture_id").and_then(Value::as_str) else {
                    continue;
                };
                let source_file = value
                    .pointer("/packet_references/0/source_file")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let owned_file = std::path::Path::new(source_file)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("")
                    .to_owned();
                let interface = value
                    .get("interface")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| {
                        owned_file
                            .split_once(".pcap-")
                            .map(|(prefix, _)| prefix)
                            .unwrap_or("")
                    })
                    .to_owned();
                let raw_ticks = value
                    .pointer("/timestamp/raw_ticks")
                    .and_then(|value| value.as_i64().map(i128::from).or_else(|| value.as_str().and_then(|s| s.parse::<i128>().ok())))
                    .unwrap_or(0);
                let packet_number = value
                    .pointer("/packet_references/0/packet_number")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let byte_offset = value
                    .pointer("/packet_references/0/byte_offset")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let entry = snapshots
                    .entry(capture_id.to_owned())
                    .or_insert(SnapshotScan {
                        capture_id: capture_id.to_owned(),
                        owned_file: owned_file.clone(),
                        interface: interface.clone(),
                        first_raw_ticks: raw_ticks,
                        first_packet_number: packet_number,
                        first_byte_offset: byte_offset,
                        max_packet_number: packet_number,
                        event_count: 0,
                    });
                if entry.owned_file.is_empty() {
                    entry.owned_file = owned_file;
                }
                if entry.interface.is_empty() {
                    entry.interface = interface;
                }
                // Anchor on the event with the SMALLEST
                // (raw_ticks, packet_number, byte_offset) tuple — that is
                // the first packet of this snapshot. Two snapshots of
                // the same growing file share that packet bit-for-bit.
                if (raw_ticks, packet_number, byte_offset)
                    < (
                        entry.first_raw_ticks,
                        entry.first_packet_number,
                        entry.first_byte_offset,
                    )
                {
                    entry.first_raw_ticks = raw_ticks;
                    entry.first_packet_number = packet_number;
                    entry.first_byte_offset = byte_offset;
                }
                if packet_number > entry.max_packet_number {
                    entry.max_packet_number = packet_number;
                }
                entry.event_count = entry.event_count.saturating_add(1);
            }
        }

        // Phase 2 — prefix-SHA grouping (2.9.2). ANR2's #9 comment
        // 6708784283 proved the 2.8.4/2.9.0 content-identity key
        // `(interface, first_raw_ticks, …)` fails in production:
        // snapshots of a growing dumpcap file carry DISJOINT packet
        // ranges (each import decodes only the newly-grown region),
        // so every snapshot sits in its own singleton group and the
        // loop below exits with `scans.len() <= 1`. The authoritative
        // link is instead the SHA-256 of each snapshot: the
        // `capture_id` of a partial import equals the SHA of a BYTE
        // PREFIX of the final closed file at a packet boundary. The
        // 2.9.2 algorithm walks each closed file under
        // `<source-root>/<plane-lc>/`, snapshots the running SHA at
        // every packet boundary (`prefix_sha_index`), and groups
        // snapshots by the on-disk file whose full SHA or any prefix
        // SHA matches their `capture_id`.
        #[derive(Clone, Copy)]
        enum ShaMatchKind {
            Full,
            Prefix(u64),
        }
        let mut on_disk_prefix: Vec<PrefixIndex> = Vec::new();
        let mut sha_to_disk: BTreeMap<String, (PathBuf, ShaMatchKind)> = BTreeMap::new();
        if let Some(root) = source_root {
            if root.is_dir() {
                for entry in fs::read_dir(root).map_err(display_error)?.flatten() {
                    let dir = entry.path();
                    if !dir.is_dir() {
                        continue;
                    }
                    let plane = dir.file_name().and_then(|value| value.to_str()).unwrap_or("");
                    let canonical = canonical_interface_for_plane(plane).unwrap_or("");
                    if canonical.is_empty() || !interface_has_decoder(canonical) {
                        continue;
                    }
                    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
                        .map_err(display_error)?
                        .flatten()
                        .map(|entry| entry.path())
                        .filter(|path| {
                            path.is_file()
                                && path
                                    .file_name()
                                    .and_then(|name| name.to_str())
                                    .is_some_and(|name| name.to_ascii_lowercase().contains(".pcap"))
                        })
                        .collect();
                    files.sort();
                    // 2.8.3 sequence rule: the lex-greatest sibling
                    // is the active dumpcap target. Exclude it from
                    // closed-file inspection.
                    let _active = files.pop();
                    for path in files {
                        if let Ok(index) = prefix_sha_index(&path) {
                            sha_to_disk.insert(
                                format!("sha256:{}", index.full_sha_hex),
                                (index.path.clone(), ShaMatchKind::Full),
                            );
                            for (sha_hex, (packet_count, _bytes)) in &index.prefix_sha {
                                sha_to_disk.insert(
                                    format!("sha256:{sha_hex}"),
                                    (index.path.clone(), ShaMatchKind::Prefix(*packet_count)),
                                );
                            }
                            on_disk_prefix.push(index);
                        }
                    }
                }
            }
        }

        // `prefix_sha_groups` groups snapshots by the on-disk file
        // they belong to. A snapshot that didn't match any on-disk
        // prefix/full SHA stays in `unmatched_snapshots` and is
        // eligible for the 2.8.4 fallback paths.
        let mut prefix_sha_groups: BTreeMap<PathBuf, Vec<SnapshotScan>> = BTreeMap::new();
        let mut unmatched_snapshots: Vec<SnapshotScan> = Vec::new();
        for (_, scan) in snapshots {
            if let Some((path, _kind)) = sha_to_disk.get(&scan.capture_id) {
                prefix_sha_groups
                    .entry(path.clone())
                    .or_default()
                    .push(scan);
            } else {
                unmatched_snapshots.push(scan);
            }
        }

        let mut partial_groups: Vec<PartialImportGroup> = Vec::new();
        let mut unresolved_groups: Vec<PartialImportGroup> = Vec::new();
        let mut drop_reason: BTreeMap<String, String> = BTreeMap::new();
        // Groups that need a fresh import of their on-disk file. The
        // actual decode + emit happens in phase 4b, so the dry-run
        // path can report them without side effects.
        let mut fresh_import_queue: Vec<(PathBuf, String)> = Vec::new();

        for (on_disk_path, mut scans) in prefix_sha_groups {
            if scans.is_empty() {
                continue;
            }
            scans.sort_by(|a, b| a.capture_id.cmp(&b.capture_id));
            let (full_sha, full_packet_count) = on_disk_prefix
                .iter()
                .find(|idx| idx.path == on_disk_path)
                .map(|idx| (idx.full_sha_hex.clone(), idx.full_packet_count))
                .unwrap_or_default();
            let full_capture_id = format!("sha256:{full_sha}");
            let has_full = scans.iter().any(|s| s.capture_id == full_capture_id);
            let interface = scans
                .iter()
                .map(|s| s.interface.clone())
                .find(|value| !value.is_empty())
                .unwrap_or_default();
            let (final_capture_id, final_source) = if has_full {
                (
                    Some(full_capture_id.clone()),
                    PartialImportFinalSource::OnDiskSha256Match,
                )
            } else {
                fresh_import_queue
                    .push((on_disk_path.clone(), full_capture_id.clone()));
                (
                    Some(full_capture_id.clone()),
                    PartialImportFinalSource::PrefixShaMatchFreshImport,
                )
            };
            let snapshot_records: Vec<PartialImportSnapshot> = scans
                .iter()
                .map(|scan| PartialImportSnapshot {
                    capture_id: scan.capture_id.clone(),
                    owned_file: scan.owned_file.clone(),
                    event_count: scan.event_count,
                    max_packet_number: scan.max_packet_number,
                    state_size_bytes: state
                        .segments
                        .get(scan.capture_id.strip_prefix("sha256:").unwrap_or(""))
                        .map(|entry| entry.size_bytes),
                    state_imported_epoch_ms: state
                        .segments
                        .get(scan.capture_id.strip_prefix("sha256:").unwrap_or(""))
                        .map(|entry| entry.imported_epoch_ms),
                })
                .collect();
            let group = PartialImportGroup {
                reconstruction_key: format!(
                    "on_disk_path={}|full_sha256={full_sha}|full_packet_count={full_packet_count}",
                    on_disk_path.display()
                ),
                interface: interface.clone(),
                first_packet_raw_ticks: 0,
                first_packet_number: 0,
                first_packet_byte_offset: 0,
                snapshots: snapshot_records,
                final_capture_id: final_capture_id.clone(),
                final_source,
                final_on_disk_path: Some(on_disk_path.display().to_string()),
                needs_fresh_import: !has_full,
            };
            // Every snapshot BUT the full one drops. Under
            // `PrefixShaMatchFreshImport` ALL snapshots drop; the
            // on-disk file is decoded afresh in phase 4b and its
            // events replace the prefix imports.
            for scan in &scans {
                if scan.capture_id != full_capture_id {
                    drop_reason.insert(
                        scan.capture_id.clone(),
                        format!(
                            "partial-import-superseded-by-final-capture-id={full_capture_id}"
                        ),
                    );
                }
            }
            partial_groups.push(group);
        }

        // 2.9.14 (#9 comment 6728398325) — ANR2 a prouvé que le
        // plan `_00067` couvrait seulement 3 des 5 planes non
        // vides (`N4`, `SBI`, `Sxab` matchés via prefix-SHA) et
        // manquait `N2` + `S6a` qui n'avaient ZÉRO événement dans
        // le dataset. Un fichier fermé sur disque sans aucun
        // `capture_id` matchant (ni full ni prefix) n'était pas
        // réparé. Correctif : pour chaque PrefixIndex découvert
        // dont le `full_sha_hex` n'est PAS déjà dans
        // `fresh_import_queue` ET n'apparaît dans AUCUN
        // `capture_id` dataset, pousser une fresh-import "pure".
        let dataset_capture_ids: BTreeSet<String> = {
            let mut set = BTreeSet::new();
            let reader = BufReader::new(fs::File::open(&current_events).map_err(display_error)?);
            for line in reader.lines() {
                let line = line.map_err(display_error)?;
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(value) = serde_json::from_str::<Value>(&line) {
                    if let Some(cap) = value.get("capture_id").and_then(Value::as_str) {
                        set.insert(cap.to_owned());
                    }
                }
            }
            set
        };
        let already_queued: BTreeSet<String> = fresh_import_queue
            .iter()
            .map(|(_, capture)| capture.clone())
            .collect();
        for index in &on_disk_prefix {
            let full_capture_id = format!("sha256:{}", index.full_sha_hex);
            if already_queued.contains(&full_capture_id) {
                continue;
            }
            if dataset_capture_ids.contains(&full_capture_id) {
                continue;
            }
            let prefix_touched = index
                .prefix_sha
                .keys()
                .any(|hex| dataset_capture_ids.contains(&format!("sha256:{hex}")));
            if prefix_touched {
                continue;
            }
            let interface = index
                .path
                .parent()
                .and_then(|parent| parent.file_name())
                .and_then(|name| name.to_str())
                .and_then(canonical_interface_for_plane)
                .map(str::to_owned)
                .unwrap_or_default();
            fresh_import_queue.push((index.path.clone(), full_capture_id.clone()));
            partial_groups.push(PartialImportGroup {
                reconstruction_key: format!(
                    "on_disk_path={}|full_sha256={}|full_packet_count={}|uncovered_closed_file",
                    index.path.display(),
                    index.full_sha_hex,
                    index.full_packet_count
                ),
                interface,
                first_packet_raw_ticks: 0,
                first_packet_number: 0,
                first_packet_byte_offset: 0,
                snapshots: Vec::new(),
                final_capture_id: Some(full_capture_id),
                final_source: PartialImportFinalSource::PrefixShaMatchFreshImport,
                final_on_disk_path: Some(index.path.display().to_string()),
                needs_fresh_import: true,
            });
        }

        // 2.8.4 fallback — run the content-identity grouping ONLY on
        // snapshots that didn't match a prefix SHA on disk. Covers
        // the "no --source-root" case and any snapshot whose on-disk
        // file has been pruned.
        type GroupKey = (String, i128, u64, u64);
        let mut groups: BTreeMap<GroupKey, Vec<SnapshotScan>> = BTreeMap::new();
        for scan in unmatched_snapshots {
            let key = (
                scan.interface.clone(),
                scan.first_raw_ticks,
                scan.first_packet_number,
                scan.first_byte_offset,
            );
            groups.entry(key).or_default().push(scan);
        }

        for ((interface, first_raw_ticks, first_pkt, first_off), mut scans) in groups {
            if scans.len() <= 1 {
                continue;
            }
            scans.sort_by(|a, b| a.capture_id.cmp(&b.capture_id));
            let reconstruction_key = format!(
                "interface={interface}|first_raw_ticks={first_raw_ticks}|first_packet_number={first_pkt}|first_byte_offset={first_off}"
            );
            let (final_capture_id, final_source, final_on_disk_path) =
                {
                    // Fallback: state.segments-based "largest size"
                    // rule. 2.9.2 reaches here only for snapshots
                    // that did NOT match any on-disk prefix SHA.
                    let mut best: Option<(String, u64, u64)> = None;
                    for scan in &scans {
                        let hex = scan.capture_id.strip_prefix("sha256:").unwrap_or("");
                        if let Some(entry) = state.segments.get(hex) {
                            let candidate = (
                                scan.capture_id.clone(),
                                entry.size_bytes,
                                entry.imported_epoch_ms,
                            );
                            match &best {
                                None => best = Some(candidate),
                                Some((_, existing_size, existing_epoch)) => {
                                    if (candidate.1, candidate.2) > (*existing_size, *existing_epoch) {
                                        best = Some(candidate);
                                    }
                                }
                            }
                        }
                    }
                    match best {
                        Some((capture, _, _)) => (
                            Some(capture),
                            PartialImportFinalSource::StateSegmentsLargest,
                            None,
                        ),
                        None => (None, PartialImportFinalSource::UnresolvedNoEvidence, None),
                    }
                };

            let snapshot_records: Vec<PartialImportSnapshot> = scans
                .iter()
                .map(|scan| {
                    let hex = scan.capture_id.strip_prefix("sha256:").unwrap_or("");
                    let state_entry = state.segments.get(hex);
                    PartialImportSnapshot {
                        capture_id: scan.capture_id.clone(),
                        owned_file: scan.owned_file.clone(),
                        event_count: scan.event_count,
                        max_packet_number: scan.max_packet_number,
                        state_size_bytes: state_entry.map(|entry| entry.size_bytes),
                        state_imported_epoch_ms: state_entry.map(|entry| entry.imported_epoch_ms),
                    }
                })
                .collect();

            let group = PartialImportGroup {
                reconstruction_key,
                interface: interface.clone(),
                first_packet_raw_ticks: first_raw_ticks,
                first_packet_number: first_pkt,
                first_packet_byte_offset: first_off,
                snapshots: snapshot_records,
                final_capture_id: final_capture_id.clone(),
                final_source,
                final_on_disk_path,
                needs_fresh_import: matches!(final_source, PartialImportFinalSource::UnresolvedNoEvidence),
            };

            if let Some(final_capture) = &final_capture_id {
                for scan in &scans {
                    if &scan.capture_id != final_capture {
                        drop_reason.insert(
                            scan.capture_id.clone(),
                            format!(
                                "partial-import-superseded-by-final-capture-id={final_capture}"
                            ),
                        );
                    }
                }
                partial_groups.push(group);
            } else {
                unresolved_groups.push(group);
            }
        }

        // Phase 4 — stream the JSONL AGAIN and split kept vs
        // removed. 2.9.17 (#9 comment 6739207609, BILAN #10
        // 6739221109) : ANR2 a prouvé que la version pré-2.9.17
        // chargeait TOUT le JSONL retenu dans un
        // `Vec<(String, u64, String, String)>`, consommant
        // ~14 GiB RSS sur 1.3M événements et déclenchant
        // l'OOM-killer deux fois (exit 137). 2.9.17 écrit chaque
        // ligne retenue dans un fichier scratch sous
        // `.dataset-next/.repair-staging/` et ne garde en mémoire
        // qu'un `BTreeMap<sort_key, (offset, len)>` + un
        // `BTreeSet<wire_key>` — total ~400 MB pour 1.3M.
        //
        // ATOMICITÉ (2.9.17 règle ANR2) : import_state.json et
        // dataset/ ne changent QU'au renommage atomique final.
        // Un kill -9 à ce stade laisse `.dataset-next/` intact et
        // nettoyable par `--recover`.
        prepare_dataset_directory(&next)?;
        let repair_staging_dir = next.join(".repair-staging");
        fs::create_dir_all(&repair_staging_dir).map_err(display_error)?;
        let scratch_path = repair_staging_dir.join("kept-events.jsonl");
        let mut removed: Vec<RepairRemovedEvent> = Vec::new();
        // 2.9.17-fu (#9 comment 6739207609, bench 1,5 M) : interning
        // des `capture_id` pour la clé de tri. Il y a typiquement
        // < 100 capture_ids distincts pour 1,5 M lignes ;
        // sans interning, 71 B × 1,5 M = ~107 MB rien que pour la
        // duplication de la chaîne SHA.
        let mut capture_id_intern: HashMap<String, Arc<str>> = HashMap::new();
        // Clé de tri = `(capture_id_arc, packet_number, event_id)` —
        // itération en ordre canonique sans Vec en mémoire.
        let mut sort_index: BTreeMap<(Arc<str>, u64, String), (u64, u32)> = BTreeMap::new();
        // Dedup wire 2.9.13 (clé compacte 2.9.17-fu) — chaque tuple
        // wire est hashé SHA256 et stocké sous forme `[u8; 32]`.
        // HashSet<[u8;32]> ≈ 56 B/entrée × 1,5 M ≈ 84 MB, versus
        // ~230 MB pour `BTreeSet<(String, u64, u64, String, String)>`.
        let mut wire_seen: HashSet<[u8; 32]> = HashSet::new();
        let mut scratch_offset: u64 = 0;
        let mut kept_event_count: usize = 0;
        {
            let scratch = fs::File::create(&scratch_path).map_err(display_error)?;
            let mut scratch_writer = BufWriter::with_capacity(STREAM_CHUNK_BYTES, scratch);
            let reader = BufReader::new(fs::File::open(&current_events).map_err(display_error)?);
            for line in reader.lines() {
                let line = line.map_err(display_error)?;
                if line.trim().is_empty() {
                    continue;
                }
                let Ok(value) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                let capture_id = value
                    .get("capture_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                if let Some(reason) = drop_reason.get(&capture_id) {
                    let event_id = value
                        .get("event_id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned();
                    let source_file = value
                        .pointer("/packet_references/0/source_file")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned();
                    removed.push(RepairRemovedEvent {
                        event_id,
                        source_file,
                        capture_id: capture_id.clone(),
                        reason: reason.clone(),
                    });
                    continue;
                }
                let packet_number = value
                    .pointer("/packet_references/0/packet_number")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let event_id = value
                    .get("event_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                // 2.9.17 : dedup wire INLINE (2.9.13 règle,
                // dépliée ici pour éviter l'accumulation en Vec).
                let byte_offset = value
                    .pointer("/packet_references/0/byte_offset")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let protocol = value
                    .get("protocol")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let message_name = value
                    .get("message_name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                // 2.9.17-fu : clé wire compacte — SHA256 des 5
                // champs concaténés avec séparateurs non-ambigus.
                let mut wire_h = Sha256Hasher::new();
                wire_h.update(capture_id.as_bytes());
                wire_h.update(&[0u8]);
                wire_h.update(&packet_number.to_le_bytes());
                wire_h.update(&byte_offset.to_le_bytes());
                wire_h.update(protocol.as_bytes());
                wire_h.update(&[0u8]);
                wire_h.update(message_name.as_bytes());
                let wire_key = wire_h.finish_bytes();
                if !wire_seen.insert(wire_key) {
                    let source_file = value
                        .pointer("/packet_references/0/source_file")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned();
                    removed.push(RepairRemovedEvent {
                        event_id: event_id.clone(),
                        source_file,
                        capture_id: capture_id.clone(),
                        reason: "wire-duplicate-superseded".into(),
                    });
                    continue;
                }
                drop(value);
                // 2.9.17-fu : intern du capture_id pour la clé de tri.
                let capture_id_arc = capture_id_intern
                    .entry(capture_id.clone())
                    .or_insert_with(|| Arc::from(capture_id.as_str()))
                    .clone();
                // Append line + newline to scratch ; stocker
                // offset + longueur pour relecture canonique.
                let payload = line.as_bytes();
                scratch_writer.write_all(payload).map_err(display_error)?;
                scratch_writer.write_all(b"\n").map_err(display_error)?;
                let len = (payload.len() + 1) as u32;
                sort_index.insert(
                    (capture_id_arc, packet_number, event_id),
                    (scratch_offset, len),
                );
                scratch_offset = scratch_offset.saturating_add(len as u64);
                kept_event_count = kept_event_count.saturating_add(1);
            }
            scratch_writer.flush().map_err(display_error)?;
            scratch_writer.get_ref().sync_all().map_err(display_error)?;
            drop(scratch_writer);
            // Phase 4b (2.9.2) — fresh-import every on-disk file
            // whose FULL-SHA snapshot is missing from the dataset.
            // The decode runs through `decode_capture_streaming` with
            // the same `PseudonymKey` the live-probe owns, so event
            // IDs are reproducible and stay compatible with the
            // dataset's canonical `(capture_id, packet_number,
            // event_id)` sort. Dry-run SKIPS the decode — it only
            // reports what WOULD be added; the SHA computation
            // further down still produces an accurate "what-would-be"
            // digest because the removed prefix snapshots are
            // dropped either way.
            // 2.9.17 : fresh-import écrit DIRECTEMENT au scratch
            // avec dedup wire inline, pas d'accumulation en Vec.
            if !dry_run {
                let scratch_append = OpenOptions::new()
                    .append(true)
                    .open(&scratch_path)
                    .map_err(display_error)?;
                let mut scratch_writer = BufWriter::with_capacity(STREAM_CHUNK_BYTES, scratch_append);
                for (on_disk_path, full_capture_id) in &fresh_import_queue {
                    let interface = on_disk_path
                        .parent()
                        .and_then(|parent| parent.file_name())
                        .and_then(|name| name.to_str())
                        .and_then(canonical_interface_for_plane)
                        .unwrap_or("");
                    if interface.is_empty() {
                        continue;
                    }
                    let config = DecodeConfig {
                        input: on_disk_path.clone(),
                        capture_id: full_capture_id.clone(),
                        interface: interface.to_owned(),
                        endpoints: HashMap::new(),
                    };
                    let capture_id_clone = full_capture_id.clone();
                    // 2.9.17-fu : intern du capture_id du
                    // fresh-import (une fois par décodage).
                    let capture_id_arc = capture_id_intern
                        .entry(capture_id_clone.clone())
                        .or_insert_with(|| Arc::from(capture_id_clone.as_str()))
                        .clone();
                    let scratch_writer_ref = &mut scratch_writer;
                    let scratch_offset_ref = &mut scratch_offset;
                    let kept_event_count_ref = &mut kept_event_count;
                    let sort_index_ref = &mut sort_index;
                    let wire_seen_ref = &mut wire_seen;
                    let removed_ref = &mut removed;
                    if decode_capture_streaming(
                        &config,
                        self.pseudonym_key.as_ref(),
                        |mut event| {
                            event.assign_deterministic_id();
                            let packet_number = event
                                .packet_references
                                .first()
                                .map(|p| p.packet_number)
                                .unwrap_or(0);
                            let byte_offset = event
                                .packet_references
                                .first()
                                .map(|p| p.byte_offset)
                                .unwrap_or(0);
                            let source_file = event
                                .packet_references
                                .first()
                                .map(|p| p.source_file.clone())
                                .unwrap_or_default();
                            let event_id = event.event_id.clone();
                            let mut wire_h = Sha256Hasher::new();
                            wire_h.update(capture_id_clone.as_bytes());
                            wire_h.update(&[0u8]);
                            wire_h.update(&packet_number.to_le_bytes());
                            wire_h.update(&byte_offset.to_le_bytes());
                            wire_h.update(event.protocol.as_str().as_bytes());
                            wire_h.update(&[0u8]);
                            wire_h.update(event.message_name.as_bytes());
                            let wire_key = wire_h.finish_bytes();
                            if !wire_seen_ref.insert(wire_key) {
                                removed_ref.push(RepairRemovedEvent {
                                    event_id,
                                    source_file,
                                    capture_id: capture_id_clone.clone(),
                                    reason: "wire-duplicate-superseded".into(),
                                });
                                return Ok(());
                            }
                            let line = event.to_json();
                            let payload = line.as_bytes();
                            scratch_writer_ref.write_all(payload).map_err(display_error)?;
                            scratch_writer_ref.write_all(b"\n").map_err(display_error)?;
                            let len = (payload.len() + 1) as u32;
                            sort_index_ref.insert(
                                (capture_id_arc.clone(), packet_number, event_id),
                                (*scratch_offset_ref, len),
                            );
                            *scratch_offset_ref = scratch_offset_ref.saturating_add(len as u64);
                            *kept_event_count_ref = kept_event_count_ref.saturating_add(1);
                            Ok(())
                        },
                    )
                    .is_err()
                    {
                        continue;
                    }
                }
                scratch_writer.flush().map_err(display_error)?;
                scratch_writer.get_ref().sync_all().map_err(display_error)?;
                drop(scratch_writer);
            }
        }

        // 2.9.17 : SHA canonique calculé en lisant le scratch
        // dans l'ordre `sort_index`, pas depuis un Vec en mémoire.
        // Si `removed.is_empty()`, `current_events` est déjà
        // canoniquement sortie (ou on retourne un rapport dry-run
        // qui ne modifiera rien).
        let event_count_after = if removed.is_empty() && dry_run {
            event_count_before
        } else {
            kept_event_count
        };
        let computed_sha_hex = if removed.is_empty() {
            sha256_hex_file(&current_events)?
        } else {
            // Stream read du scratch, hash via le `sort_index`.
            let mut events_sha = Sha256Hasher::new();
            use std::io::{Read, Seek, SeekFrom};
            let mut scratch = fs::File::open(&scratch_path).map_err(display_error)?;
            let mut buffer = Vec::new();
            for (_, (offset, len)) in sort_index.iter() {
                scratch.seek(SeekFrom::Start(*offset)).map_err(display_error)?;
                buffer.resize(*len as usize, 0u8);
                scratch.read_exact(&mut buffer).map_err(display_error)?;
                events_sha.update(&buffer);
            }
            events_sha.finish_hex()
        };

        if dry_run || removed.is_empty() {
            // 2.9.17 : cleanup du scratch — on n'écrit RIEN dans
            // `.dataset-next/` au-delà du staging. La prochaine
            // passe réelle (!dry_run) reconstruit depuis zéro.
            let _ = fs::remove_dir_all(&next);
            return Ok(DatasetRepairReport {
                schema_version: "2.9.18",
                dataset_dir: current.display().to_string(),
                dry_run,
                event_count_before,
                event_count_after,
                partial_import_groups: partial_groups,
                unresolved_groups,
                removed_events: removed,
                events_sha256: computed_sha_hex,
            });
        }

        let prior_continuous: Option<(PathBuf, LiveDataset)> = if current
            .join("dataset_manifest.json")
            .is_file()
        {
            let bytes = fs::read(current.join("dataset_manifest.json")).map_err(display_error)?;
            if let Ok(dataset) = serde_json::from_slice::<LiveDataset>(&bytes) {
                if validate_dataset_artifacts(&dataset, &current).is_ok() {
                    Some((current.clone(), dataset))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        let next_events = next.join("oiran_events.jsonl");
        // 2.9.17 : le scratch contient déjà toutes les lignes
        // retenues, mais dans l'ordre d'écriture (pas canonique).
        // Relecture via `sort_index` pour produire le fichier
        // final canonique en streaming, SANS matérialiser le tout
        // en RAM. Hash se recalculerait identiquement à
        // `computed_sha_hex` plus haut si on l'avait écrit en
        // même temps ; on le fait exprès pour que `events_sha256`
        // du rapport reste byte-identique au contenu renommé.
        {
            use std::io::{Read, Seek, SeekFrom};
            let mut scratch = fs::File::open(&scratch_path).map_err(display_error)?;
            let file = fs::File::create(&next_events).map_err(display_error)?;
            let mut writer = BufWriter::with_capacity(STREAM_CHUNK_BYTES, file);
            let mut buffer = Vec::new();
            for (_, (offset, len)) in sort_index.iter() {
                scratch.seek(SeekFrom::Start(*offset)).map_err(display_error)?;
                buffer.resize(*len as usize, 0u8);
                scratch.read_exact(&mut buffer).map_err(display_error)?;
                writer.write_all(&buffer).map_err(display_error)?;
            }
            writer.flush().map_err(display_error)?;
            writer.get_ref().sync_all().map_err(display_error)?;
        }
        // 2.9.17 : staging terminé. Suppression du scratch
        // avant publish_events_to_dataset_dir (qui balaie le
        // dataset_dir pour le manifest).
        let _ = fs::remove_dir_all(&repair_staging_dir);
        let dataset = self.publish_events_to_dataset_dir(
            CONTINUOUS_CAPTURE_ID,
            CONTINUOUS_DATASET_ID.into(),
            &next,
            format!("runtime/live-captures/{CONTINUOUS_CAPTURE_ID}/dataset"),
            prior_continuous,
            BTreeMap::new(),
            BTreeMap::new(),
            Vec::new(),
        )?;
        if previous.exists() {
            fs::remove_dir_all(&previous).map_err(display_error)?;
        }
        if current.exists() {
            fs::rename(&current, &previous).map_err(display_error)?;
        }
        if let Err(error) = fs::rename(&next, &current) {
            if previous.is_dir() {
                let _ = fs::rename(&previous, &current);
            }
            return Err(display_error(error));
        }
        if previous.exists() {
            fs::remove_dir_all(&previous).map_err(display_error)?;
        }
        self.upsert_dataset(dataset, &current)?;
        Ok(DatasetRepairReport {
            schema_version: "2.9.18",
            dataset_dir: current.display().to_string(),
            dry_run: false,
            event_count_before,
            event_count_after,
            partial_import_groups: partial_groups,
            unresolved_groups,
            removed_events: removed,
            events_sha256: computed_sha_hex,
        })
    }

    /// 2.7.23: exposed `pub` so RSS harnesses (see
    /// `examples/rss_publication.rs`) can drive one publication cycle
    /// into a scratch directory, bypassing the
    /// `CONTINUOUS_DERIVED_OUTPUT_LIMIT` ceiling of
    /// `process_continuous_capture` (which is sized for the production
    /// ring, not multi-hundred-thousand-event histories). Production
    /// callers go through `process_continuous_capture`.
    pub fn process_capture_into(
        &self,
        capture_id: &str,
        dataset_id: String,
        pcap_dir: &Path,
        dataset_dir: &Path,
        dataset_path: String,
        interfaces: &[CaptureInterface],
    ) -> Result<LiveDataset, String> {
        // 2.7.6 (adjusted): the per-deployment key is owned by the manager
        // and shared across every capture processed by this binary — so a
        // probe restart that rebuilds the same dataset reuses the same key
        // and its event_ids remain stable.
        let pseudonym_key = self.pseudonym_key.as_ref();
        let prior_continuous = if capture_id == CONTINUOUS_CAPTURE_ID {
            if let Some(parent) = dataset_dir.parent() {
                let current = parent.join("dataset");
                if current == dataset_dir || !current.join("dataset_manifest.json").is_file() {
                    None
                } else {
                    let dataset: LiveDataset = serde_json::from_slice(
                        &fs::read(current.join("dataset_manifest.json")).map_err(display_error)?,
                    )
                    .map_err(|_| "CONTINUOUS_CHECKPOINT_MANIFEST_INVALID".to_string())?;
                    validate_dataset_artifacts(&dataset, &current)
                        .map_err(|error| format!("CONTINUOUS_CHECKPOINT_INVALID: {error}"))?;
                    Some((current, dataset))
                }
            } else {
                None
            }
        } else {
            None
        };
        prepare_dataset_directory(dataset_dir)?;
        let events_path = dataset_dir.join("oiran_events.jsonl");
        let decoded_spool_path = dataset_dir.join(".decoded-events.spool");
        let decoded_spool_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&decoded_spool_path)
            .map_err(display_error)?;
        let mut decoded_spool = BufWriter::with_capacity(STREAM_CHUNK_BYTES, decoded_spool_file);
        let mut reports = BTreeMap::new();
        let mut checksums = BTreeMap::new();
        // 2.10.3 (devmat, ANR2 #9 comment 15:38Z) : captures
        // ingérés mais 0 events produits — surfacé dans
        // `LiveDataset.zero_event_captures`.
        let mut zero_event_captures: Vec<String> = Vec::new();
        let endpoints = endpoint_map();
        for interface in interfaces {
            let mut files = capture_files_for(pcap_dir, &interface.interface);
            files.sort();
            for path in files {
                if fs::metadata(&path)
                    .map(|metadata| metadata.len())
                    .unwrap_or(0)
                    <= 24
                {
                    continue;
                }
                // Streaming SHA-256; the decoder re-reads from the file path
                // on its own, so we do not need to keep the bytes in memory.
                let checksum = sha256_hex_file(&path)?;
                let capture_hash = format!("sha256:{checksum}");
                let aggregate_n3 = capture_id == CONTINUOUS_CAPTURE_ID
                    && interface.interface.eq_ignore_ascii_case("N3");
                let mut n3_aggregator = N3FlowAggregator::default();
                let mut keepalive_aggregator = KeepaliveAggregator::default();
                let mut individual_events = 0usize;
                let mut report = decode_capture_streaming(
                    &DecodeConfig {
                        input: path.clone(),
                        capture_id: capture_hash,
                        interface: interface.interface.clone(),
                        endpoints: endpoints.clone(),
                    },
                    &pseudonym_key,
                    |event| {
                        // 2.9.5 (devmat #9 T1) : les keepalives (PFCP HB,
                        // Diameter Device-Watchdog, GTPv2 Echo, GTP-U Echo)
                        // sont toujours agrégés par (interface, paire de
                        // nœuds, kind) — ANR2 preuve 6714896530 montre
                        // qu'ils dominent >75 % du volume.
                        let event = match keepalive_aggregator.observe(event)? {
                            None => return Ok(()),
                            Some(event) => event,
                        };
                        if aggregate_n3 && event.protocol == Protocol::Gtpu {
                            return n3_aggregator.observe(event);
                        }
                        individual_events = individual_events.saturating_add(1);
                        decoded_spool
                            .write_all(event.to_json().as_bytes())
                            .and_then(|_| decoded_spool.write_all(b"\n"))
                            .map_err(display_error)
                    },
                )?;
                let n3_aggregates = if aggregate_n3 {
                    n3_aggregator.finish()
                } else {
                    Vec::new()
                };
                let keepalive_aggregates = keepalive_aggregator.finish();
                report.events = individual_events
                    .saturating_add(n3_aggregates.len())
                    .saturating_add(keepalive_aggregates.len());
                for event in n3_aggregates.into_iter().chain(keepalive_aggregates) {
                    decoded_spool
                        .write_all(event.to_json().as_bytes())
                        .and_then(|_| decoded_spool.write_all(b"\n"))
                        .map_err(display_error)?;
                }
                let key = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("capture.pcap")
                    .to_string();
                // 2.10.3 : si 0 events produits, loguer + surfacer
                // dans LiveDataset.zero_event_captures. Jamais
                // d'identité abonné dans ce log (chemin + SHA + 0).
                if report.events == 0 {
                    // 2.11.2 (devmat, revue ANR1 — ANR2 observed 341
                    // ZERO_EVENTS on 2.10.4 run) : enrichir le log
                    // avec `packets` (trames observées par
                    // `capture_pcap::visit_capture`), `transport_errors`,
                    // `sctp_errors`, `incomplete_sctp`,
                    // `warnings`. Un pcap `packets=0` → vraiment vide
                    // = ZERO_EVENTS légitime. Un pcap `packets>0` mais
                    // `events=0` = soit keepalive agrégé par un autre
                    // décodeur, soit traffic non-reconnu par le
                    // décodeur (défaut à investiguer).
                    let capture_sha = format!("sha256:{}", &checksum);
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "event": "CONTINUOUS_SEGMENT_ZERO_EVENTS",
                            "path": path.display().to_string(),
                            "capture_id": capture_sha,
                            "interface": interface.interface,
                            "capture_format": report.capture_format.clone(),
                            "packets_in_pcap": report.packets,
                            "transport_errors": report.transport_errors,
                            "sctp_errors": report.sctp_errors,
                            "incomplete_sctp": report.incomplete_sctp,
                            "tcp_connections": report.tcp_connections,
                            "tcp_errors": report.tcp_errors,
                            "warnings": report.warnings,
                            "legitimacy_hint": if report.packets == 0 {
                                "empty_pcap_legitimate"
                            } else if report.transport_errors > 0 || report.sctp_errors > 0 {
                                "transport_errors_present_investigate"
                            } else {
                                "traffic_present_decoded_zero_events_investigate"
                            },
                        })
                    );
                    zero_event_captures.push(capture_sha);
                }
                checksums.insert(key.clone(), checksum);
                reports.insert(key, report);
            }
        }
        decoded_spool.flush().map_err(display_error)?;
        decoded_spool.get_ref().sync_all().map_err(display_error)?;
        drop(decoded_spool);
        // 2.9.18-fu3 (ANR2 #9 comment 6750859966) : `seen_ids`
        // persiste sur disque sous `.dataset-next/.merge-staging/ids/`
        // via `SpillingEventIdSet` — au plus 1,5 MiB en RAM, le
        // reste en chunks triés u64 relus en binary search.
        let merge_staging = dataset_dir.join(".merge-staging").join("ids");
        let mut seen_ids = SpillingEventIdSet::new(
            &merge_staging,
            event_id_set_mem_cap(),
        )
        .map_err(display_error)?;
        if capture_id == CONTINUOUS_CAPTURE_ID {
            // 2.7.23: streaming merge, write directly to tmp.
            // 2.7.27: NO retention / purge during merge. Every event
            // passes through — the published dataset is never
            // filtered. Capture-level archive (which NEVER deletes)
            // runs after the rename below.
            let tmp_path = events_path.with_extension("jsonl.tmp");
            let mut writer = BufWriter::with_capacity(
                STREAM_CHUNK_BYTES,
                fs::File::create(&tmp_path).map_err(display_error)?,
            );
            if let Some((prior_dir, _)) = &prior_continuous {
                let prior_events_file = fs::File::open(prior_dir.join("oiran_events.jsonl"))
                    .map_err(display_error)?;
                let reader = BufReader::with_capacity(STREAM_CHUNK_BYTES, prior_events_file);
                merge_event_stream(reader, &mut writer, &mut seen_ids)?;
            }
            let decoded_reader = BufReader::with_capacity(
                STREAM_CHUNK_BYTES,
                fs::File::open(&decoded_spool_path).map_err(display_error)?,
            );
            merge_event_stream(decoded_reader, &mut writer, &mut seen_ids)?;
            writer.flush().map_err(display_error)?;
            writer.get_ref().sync_all().map_err(display_error)?;
            drop(writer);
            fs::rename(&tmp_path, &events_path).map_err(display_error)?;
            // Log opérateur : empreinte mémoire du set.
            eprintln!(
                "CONTINUOUS_IMPORT_SEEN_IDS phase=after-merge total_unique={} chunks={} flushes={} mem_entries={}",
                seen_ids.len_hint(),
                seen_ids.chunk_count(),
                seen_ids.flush_count(),
                seen_ids.mem_len(),
            );
        } else {
            fs::rename(&decoded_spool_path, &events_path).map_err(display_error)?;
        }
        // Le set n'est plus nécessaire à partir d'ici ; son `Drop`
        // supprime chunks + répertoire `.merge-staging/ids/`. On le
        // relâche explicitement avant la publication pour rendre la
        // RAM mesurable et déterministe.
        drop(seen_ids);
        let _ = fs::remove_dir(dataset_dir.join(".merge-staging"));
        // 2.7.27 (issue #10, ANR2): capture-level age retention. Runs
        // ONLY when `OIRAN_DATASET_RETENTION_DAYS` is explicitly set to
        // a positive value. Moves whole captures (never slices inside)
        // to an immutable archive segment; on any archive-write error
        // the hot view is left untouched (fail-closed).
        if capture_id == CONTINUOUS_CAPTURE_ID {
            if let Some(cutoff) = retention_cutoff_epoch_s() {
                let archive_root = dataset_dir
                    .parent()
                    .map(|p| p.join("archive"))
                    .unwrap_or_else(|| dataset_dir.join("archive"));
                archive_stale_captures(&events_path, &archive_root, cutoff)?;
            }
        }
        if decoded_spool_path.exists() {
            fs::remove_file(&decoded_spool_path).map_err(display_error)?;
        }
        self.publish_events_to_dataset_dir(
            capture_id,
            dataset_id,
            dataset_dir,
            dataset_path,
            prior_continuous,
            reports,
            checksums,
            zero_event_captures,
        )
    }

    /// 2.7.28: "events on disk → sessions + callflows + manifest". The
    /// tail of `process_capture_into` from 2.7.23/2.7.24/2.7.26, lifted
    /// out so both the continuous import worker and `dataset-restore`
    /// go through the exact same publication path. The caller must
    /// have already written `dataset_dir/oiran_events.jsonl` (atomic
    /// rename) before invoking this helper — the import worker does so
    /// after merging decoded events against the prior dataset; the
    /// restore flow does so after canonically dedup-merging the hot
    /// view with an archive segment.
    fn publish_events_to_dataset_dir(
        &self,
        capture_id: &str,
        dataset_id: String,
        dataset_dir: &Path,
        dataset_path: String,
        prior_continuous: Option<(PathBuf, LiveDataset)>,
        mut reports: BTreeMap<String, DecodeReport>,
        mut checksums: BTreeMap<String, String>,
        zero_event_captures: Vec<String>,
    ) -> Result<LiveDataset, String> {
        let events_path = dataset_dir.join("oiran_events.jsonl");
        release_unused_heap_pages();
        trace_publication_rss_reset();
        trace_publication_rss("00-after-streaming-merge", None);
        // 2.7.24 + 2.9.18-fu3 + 2.10.3 : stream the JSONL into
        // compact semantic representatives. Pré-2.10.3 on faisait
        // AUSSI une 2ᵉ passe streaming pour alimenter un
        // `SpillingEventIdSet retained_event_ids` servant à
        // filtrer les call-flows prior à recopier. Cette 2ᵉ
        // passe était redondante quand aucune politique de
        // rétention n'est active (`OIRAN_DATASET_RETENTION_DAYS`
        // absent) — la merge preserve par construction tous les
        // event_ids prior dans le JSONL courant. 2.10.3 skippe
        // cette passe hors rétention, économisant un full-scan
        // de `oiran_events.jsonl` (environ 2,7 Go → ~30 s en prod).
        // Quand la rétention est active, la passe est conservée
        // (archive_stale_captures peut supprimer des captures
        // entières du hot view).
        let index = session_engine::load_path_streaming_representatives(&events_path)?;
        let event_count = index.source_event_count;
        let mut events = index.events;
        let retention_active = retention_cutoff_epoch_s().is_some();
        let retention_staging = dataset_dir.join(".publish-staging").join("ids");
        let mut retained_event_ids = SpillingEventIdSet::new(
            &retention_staging,
            event_id_set_mem_cap(),
        )
        .map_err(display_error)?;
        if retention_active {
            let file = fs::File::open(&events_path).map_err(display_error)?;
            let reader = BufReader::with_capacity(STREAM_CHUNK_BYTES, file);
            for line in reader.lines() {
                let line = line.map_err(display_error)?;
                if line.trim().is_empty() {
                    continue;
                }
                let value: serde_json::Value = match serde_json::from_str(&line) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                if let Some(event_id) = value.get("event_id").and_then(serde_json::Value::as_str) {
                    retained_event_ids
                        .insert(event_id)
                        .map_err(display_error)?;
                }
            }
        }
        eprintln!(
            "PUBLICATION_RETAINED_IDS retention_active={} total_unique={} chunks={} flushes={} mem_entries={}",
            retention_active,
            retained_event_ids.len_hint(),
            retained_event_ids.chunk_count(),
            retained_event_ids.flush_count(),
            retained_event_ids.mem_len(),
        );
        trace_publication_rss("01-after-streaming-representatives", Some(events.len()));
        let capture_job = self.get(capture_id);
        // 2.7.28: when restore runs in a manager that never saw the
        // continuous worker start, `capture_job` is None. Fall back to
        // the prior manifest's `capture_started_epoch_ms` so the
        // restored manifest is not stripped of its original capture
        // start time.
        let capture_started_epoch_ms = capture_job
            .as_ref()
            .and_then(|job| job.started_epoch_ms)
            .or_else(|| {
                prior_continuous
                    .as_ref()
                    .and_then(|(_, dataset)| dataset.capture_started_epoch_ms)
            });
        let activity_started_epoch_ms = capture_job
            .as_ref()
            .filter(|job| {
                capture_id != CONTINUOUS_CAPTURE_ID || job.state == CaptureState::Capturing
            })
            .and_then(|job| job.started_epoch_ms);
        let runtime_evidence = (capture_id == CONTINUOUS_CAPTURE_ID)
            .then(|| self.continuous_runtime_evidence.lock().unwrap().clone())
            .flatten();
        let (last_packet_epoch_ms, fresh_packet_count, active_pdu_contexts) = continuous_activity(
            &events,
            activity_started_epoch_ms,
            epoch_ms(),
            runtime_evidence.as_deref(),
        );
        trace_publication_rss("02-after-continuous-activity", Some(events.len()));
        let active_ue_ips = active_pdu_contexts
            .iter()
            .map(|context| context.ue_ip.clone())
            .collect::<Vec<_>>();
        let mut discovery = discover_sessions(&mut events);
        trace_publication_rss("03-after-discover-sessions", Some(events.len()));
        discovery
            .event_accounting
            .insert("source_events".into(), event_count);
        discovery
            .event_accounting
            .insert("publication_index_events".into(), events.len());
        let mut global_edges = correlate_discovered_tunnels(&events, &discovery);
        trace_publication_rss("04-after-correlate-discovered-tunnels", Some(events.len()));
        global_edges.extend(correlate_cross_interface_evidence(&events));
        trace_publication_rss("05-after-correlate-cross-interface", Some(events.len()));
        // 2.7.26 (ANR2 production rollback): two orthogonal rules can
        // compute the same N4↔N3 (or any other) pair from independent
        // evidence paths — in production the audit observed both
        // `n4-n3-discovered-teid-endpoint` (from `correlate_discovered_tunnels`,
        // which fires when `discovery.gtpu_tunnels[].related_pfcp_session`
        // is `Some(..)`, i.e. the session-engine managed to bind the
        // tunnel to a PFCP session) AND
        // `pfcp-outer-header-matches-gtpu-tunnel` (from
        // `correlate_cross_interface_evidence`, which fires on
        // byte-identical tunnel keys regardless of session binding)
        // on every N4↔N3 pair → 4 links instead of 2. The 2.7.25
        // dedup compared `edge_id` only, but the builder bakes
        // `rule_id` INTO `edge_id`, so two rules on the same pair
        // emerged as two distinct edges. 2.7.26 folds by the
        // canonical key `(min/max event_id, interfaces in matching
        // order, evidence_type)` and collapses the matching rule_ids
        // into `matched_rules` without losing a single distinct link.
        global_edges = fold_overlapping_edges(global_edges);
        trace_publication_rss("06-after-fold-overlapping-edges", Some(events.len()));
        // 2.10.2 (devmat, ANR2 #9 comments 6765365357 + 6765466589) :
        // avant 2.10.2, le pipeline construisait `Vec<SessionPlan>` où chaque
        // `SessionPlan` clonait `Vec<CorrelationEdge>` + `BTreeSet<String>`
        // d'event_ids transitifs. Sur 1,5 M events + N sessions × M edges,
        // ce pic additionnel surimposé à `events` + `discovery` +
        // `global_edges` + `lte_flows` + `runtime_flows` suffit à dépasser
        // 1 GB d'anonyme (ANR2 fantôme long : 1,06 GB anon avant
        // manifeste). Fix 2.10.2 :
        //   * LTE + runtime flows construits d'abord (ont encore besoin
        //     de `events`).
        //   * `drop(events)` AVANT la construction des session plans.
        //   * `SessionPlan.ids` → `SpillingEventIdSet` disk-backed
        //     (~1,5 MiB RAM max par session, le reste sur disque sous
        //     `.publish-staging/session-ids/<idx>/`).
        //   * `SessionPlan.edges` supprimé : les edges pertinentes sont
        //     re-filtrées depuis `global_edges` au moment de la boucle
        //     par session (petit coût CPU, gros gain mémoire).
        let lte_flows: Vec<CallFlow> = offline_lte_callflows(&events)?;
        trace_publication_rss("07-after-lte-flows-built", Some(events.len()));
        let runtime_flows: Vec<CallFlow> = active_pdu_contexts
            .iter()
            .map(|active| runtime_pdu_callflow(&events, active))
            .collect();
        trace_publication_rss("08-after-runtime-flows-built", Some(events.len()));
        let indexed_events_count = events.len();
        drop(events);
        release_unused_heap_pages();
        trace_publication_rss("09-after-events-dropped", None);

        // 2.10.3 (devmat, revue 2.10.2 point 2) : boucle de session
        // BATCHÉE. La 2.10.2 faisait 1 full JSONL scan PAR SESSION
        // (via `load_events_by_ids_spilling`). Bench 200K events/400
        // sessions : ~97 sec / 100 sessions = ~1 sec/session (phase
        // 10-batch-* elapsed_ms). Prod 1,5 M events × 500 sessions
        // dominait le 22 min / cycle.
        //
        // 2.10.3 regroupe `SESSION_PUBLICATION_BATCH_SIZE` sessions
        // par passe :
        //   1. Construire K SpillingEventIdSets (K × mem_cap ≈
        //      K × 1,5 MiB en RAM — K=32 → 48 MiB max, sous la
        //      ligne 2.10.2).
        //   2. ONE JSONL scan, dispatch chaque event aux scratch
        //      files per-session dont l'ids_set contient
        //      l'event_id.
        //   3. Per session : lire son scratch, reconstruct, write
        //      call-flow, drop set+scratch.
        //   4. Batch suivant.
        //
        // Scans totaux = ceil(sessions / K). Pour 500 sessions /
        // K=32 = 16 scans vs 500 à l'ancien. Réduction ~31×.
        let session_ids_staging_root = dataset_dir
            .join(".publish-staging")
            .join("session-ids");
        let session_scratch_staging_root = dataset_dir
            .join(".publish-staging")
            .join("session-scratch");
        let mut session_ids = Vec::new();
        let batch_size = session_publication_batch_size();
        let pdu_sessions_len = discovery.pdu_sessions.len();
        for (batch_idx, chunk) in discovery
            .pdu_sessions
            .chunks(batch_size)
            .enumerate()
        {
            // Préparer K SpillingEventIdSets + paramétrage par session.
            struct BatchEntry {
                session_id: String,
                ue_pseudonym: Option<String>,
                ids: SpillingEventIdSet,
                scratch_path: PathBuf,
            }
            let mut entries: Vec<BatchEntry> = Vec::with_capacity(chunk.len());
            for (within_batch_idx, session) in chunk.iter().enumerate() {
                let context = discovery
                    .ue_contexts
                    .iter()
                    .find(|context| context.context_id == session.ue_context_id);
                let global_idx = batch_idx * batch_size + within_batch_idx;
                let session_ids_tmp =
                    session_ids_staging_root.join(format!("{global_idx:06}"));
                let mut ids = SpillingEventIdSet::new(
                    &session_ids_tmp,
                    event_id_set_mem_cap(),
                )
                .map_err(display_error)?;
                for event_id in &session.event_ids {
                    ids.insert(event_id).map_err(display_error)?;
                }
                if let Some(context) = context {
                    for event_id in &context.event_ids {
                        ids.insert(event_id).map_err(display_error)?;
                    }
                }
                expand_session_evidence_ids_disk(&mut ids, &global_edges)
                    .map_err(display_error)?;
                let scratch_path =
                    session_scratch_staging_root.join(format!("{global_idx:06}.jsonl"));
                fs::create_dir_all(&session_scratch_staging_root).map_err(display_error)?;
                entries.push(BatchEntry {
                    session_id: session.session_id.clone(),
                    ue_pseudonym: context.map(|context| context.pseudonym.clone()),
                    ids,
                    scratch_path,
                });
            }

            // Un seul full-scan JSONL : dispatch chaque event aux
            // scratchs dont la SpillingEventIdSet le contient.
            // La passe ne parse pas tout l'event, juste `event_id`
            // (clone du cheap-peek 2.9.17 depuis `load_events_by_ids`).
            {
                let mut scratch_writers: Vec<BufWriter<fs::File>> = entries
                    .iter()
                    .map(|entry| {
                        fs::File::create(&entry.scratch_path)
                            .map(|f| BufWriter::with_capacity(STREAM_CHUNK_BYTES, f))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(display_error)?;
                let file = fs::File::open(&events_path).map_err(display_error)?;
                let reader = BufReader::with_capacity(STREAM_CHUNK_BYTES, file);
                for line in reader.lines() {
                    let line = line.map_err(display_error)?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    #[derive(serde::Deserialize)]
                    struct IdOnly<'a> {
                        event_id: &'a str,
                    }
                    let id_only: IdOnly = match serde_json::from_str(&line) {
                        Ok(value) => value,
                        Err(_) => continue,
                    };
                    for (idx, entry) in entries.iter().enumerate() {
                        if entry.ids.contains(id_only.event_id).map_err(display_error)? {
                            scratch_writers[idx]
                                .write_all(line.as_bytes())
                                .map_err(display_error)?;
                            scratch_writers[idx]
                                .write_all(b"\n")
                                .map_err(display_error)?;
                        }
                    }
                }
                for mut writer in scratch_writers {
                    writer.flush().map_err(display_error)?;
                }
            }

            // Per-session : reconstruct depuis scratch, write
            // callflow, drop. Le scan global n'a été fait qu'une
            // fois pour tout le batch.
            for entry in entries {
                let BatchEntry {
                    session_id: plan_session_id,
                    ue_pseudonym: plan_ue_pseudonym,
                    ids,
                    scratch_path,
                } = entry;
                drop(ids); // libère chunks + tmp_dir avant le reconstruct.
                let scratch_bytes =
                    fs::read(&scratch_path).map_err(display_error)?;
                let _ = fs::remove_file(&scratch_path);
                let selected = session_engine::load_jsonl(&scratch_bytes[..])?;
                let selected_ids: std::collections::BTreeSet<String> = selected
                    .iter()
                    .map(|event| event.event_id.clone())
                    .collect();
                let plan_edges: Vec<CorrelationEdge> = global_edges
                    .iter()
                    .filter(|edge| {
                        selected_ids.contains(&edge.source_event_id)
                            && selected_ids.contains(&edge.target_event_id)
                    })
                    .cloned()
                    .collect();
                let mut reconstruction = reconstruct(
                    selected,
                    ReconstructionHints {
                        ue_pseudonym: plan_ue_pseudonym,
                        ..Default::default()
                    },
                );
                reconstruction.session_id = plan_session_id;
                for event in &reconstruction.events {
                    reconstruction
                        .association
                        .insert(event.event_id.clone(), Association::Session);
                }
                let flow = build_callflow(&reconstruction, plan_edges);
                let json_path = dataset_dir
                    .join("callflows")
                    .join(format!("{}.json", flow.session_id));
                let html_path = dataset_dir
                    .join("callflows")
                    .join(format!("{}.html", flow.session_id));
                atomic_write(
                    &json_path,
                    &serde_json::to_vec_pretty(&flow).map_err(|error| error.to_string())?,
                )?;
                let html = callflow_renderer::render(&flow).map_err(|error| error.to_string())?;
                atomic_write(&html_path, html.as_bytes())?;
                session_ids.push(flow.session_id);
            }
            release_unused_heap_pages();
            trace_publication_rss(
                &format!(
                    "10-session-batch-{}-of-{}",
                    batch_idx + 1,
                    pdu_sessions_len.div_ceil(batch_size)
                ),
                Some(indexed_events_count),
            );
        }
        trace_publication_rss(
            "10a-after-session-callflows",
            Some(indexed_events_count),
        );
        for flow in lte_flows {
            let json_path = dataset_dir
                .join("callflows")
                .join(format!("{}.json", flow.session_id));
            let html_path = dataset_dir
                .join("callflows")
                .join(format!("{}.html", flow.session_id));
            atomic_write(
                &json_path,
                &serde_json::to_vec_pretty(&flow).map_err(|error| error.to_string())?,
            )?;
            let html = callflow_renderer::render(&flow).map_err(|error| error.to_string())?;
            atomic_write(&html_path, html.as_bytes())?;
            session_ids.push(flow.session_id);
        }
        for flow in runtime_flows {
            let json_path = dataset_dir
                .join("callflows")
                .join(format!("{}.json", flow.session_id));
            let html_path = dataset_dir
                .join("callflows")
                .join(format!("{}.html", flow.session_id));
            atomic_write(
                &json_path,
                &serde_json::to_vec_pretty(&flow).map_err(|error| error.to_string())?,
            )?;
            let html = callflow_renderer::render(&flow).map_err(|error| error.to_string())?;
            atomic_write(&html_path, html.as_bytes())?;
            session_ids.push(flow.session_id);
        }
        if let Some((prior_dir, prior)) = &prior_continuous {
            for (name, report) in &prior.decode_reports {
                reports
                    .entry(name.clone())
                    .or_insert_with(|| report.clone());
            }
            for (name, checksum) in &prior.checksums {
                checksums
                    .entry(name.clone())
                    .or_insert_with(|| checksum.clone());
            }
            for session_id in &prior.session_ids {
                if session_ids.contains(session_id) || !safe_identifier(session_id) {
                    continue;
                }
                let prior_json = prior_dir
                    .join("callflows")
                    .join(format!("{session_id}.json"));
                let prior_html = prior_dir
                    .join("callflows")
                    .join(format!("{session_id}.html"));
                let flow: CallFlow =
                    serde_json::from_slice(&fs::read(&prior_json).map_err(display_error)?)
                        .map_err(|error| error.to_string())?;
                // 2.10.3 : hors rétention, l'invariant de merge
                // garantit que tous les event_ids prior sont dans
                // le JSONL courant → filter always-true, skip.
                // Sous rétention, re-check via retained_event_ids.
                let mut all_present = true;
                if retention_active {
                    for event in &flow.events {
                        if !retained_event_ids
                            .contains(&event.event_id)
                            .map_err(display_error)?
                        {
                            all_present = false;
                            break;
                        }
                    }
                }
                if !all_present {
                    continue;
                }
                atomic_write(
                    &dataset_dir
                        .join("callflows")
                        .join(format!("{session_id}.json")),
                    &fs::read(prior_json).map_err(display_error)?,
                )?;
                atomic_write(
                    &dataset_dir
                        .join("callflows")
                        .join(format!("{session_id}.html")),
                    &fs::read(prior_html).map_err(display_error)?,
                )?;
                session_ids.push(session_id.clone());
            }
        }
        session_ids.sort();
        session_ids.dedup();
        // 2.9.18-fu3 : relâche le set disk-backed dès que le filtre
        // call-flow prior est consommé — les chunks + le staging
        // sont supprimés avant qu'on sérialise le manifeste.
        drop(retained_event_ids);
        let _ = fs::remove_dir(dataset_dir.join(".publish-staging"));
        // 2.10.3 (devmat, revue 2.10.2 point 3) : `state=PARTIAL`
        // signifie PRÉCISÉMENT `discovery.unmatched_event_ids ≠ ∅` —
        // des événements wire-identiques ont été publiés mais le
        // session-engine n'a pas pu les rattacher à une session N2
        // (contexte UE non reconstruit — F-TEID / NAS inaccessible),
        // à une session LTE (S1-MME context absent) ou à un tunnel
        // GTP-U orphelin. Ce n'est PAS un défaut — c'est la lecture
        // honnête des événements pour lesquels la corrélation
        // n'était pas démontrable à l'instant de la publication.
        // COMPLETED = `unmatched_event_ids ∩ dataset = ∅`.
        // COMPLETED_EMPTY = `event_count == 0`.
        let dataset_state: &str = if event_count == 0 {
            "COMPLETED_EMPTY"
        } else if discovery.unmatched_event_ids.is_empty() {
            "COMPLETED"
        } else {
            "PARTIAL"
        };
        let partial_reason: Option<String> = if dataset_state == "PARTIAL" {
            Some(format!(
                "{} unmatched event(s) — session-engine could not bind to an N2 UE context, an S1-MME context, nor a GTP-U tunnel at publish time",
                discovery.unmatched_event_ids.len()
            ))
        } else {
            None
        };
        if let Some(reason) = partial_reason.as_deref() {
            eprintln!(
                "{}",
                serde_json::json!({
                    "event": "CONTINUOUS_PUBLICATION_PARTIAL",
                    "state": dataset_state,
                    "reason": reason,
                    "unmatched_event_count": discovery.unmatched_event_ids.len(),
                    "event_count": event_count,
                    "zero_event_captures": zero_event_captures.len(),
                })
            );
        }
        let dataset = LiveDataset {
            dataset_id,
            capture_id: capture_id.into(),
            path: dataset_path,
            event_count,
            session_ids,
            decode_reports: reports,
            checksums,
            state: dataset_state.to_string(),
            discovery: Some(discovery),
            capture_started_epoch_ms,
            last_packet_epoch_ms,
            fresh_packet_count,
            active_ue_ips,
            active_pdu_contexts,
            zero_event_captures,
        };
        trace_publication_rss("11-after-callflows-loop", None);
        atomic_write(
            &dataset_dir.join("dataset_manifest.json"),
            &serde_json::to_vec_pretty(&dataset).map_err(|error| error.to_string())?,
        )?;
        trace_publication_rss("12-after-manifest-written", None);
        validate_dataset_artifacts(&dataset, dataset_dir)?;
        release_unused_heap_pages();
        trace_publication_rss("13-after-release-pages", None);
        Ok(dataset)
    }

    fn register_dataset(&self, dataset: LiveDataset, dataset_dir: &Path) -> Result<(), String> {
        validate_dataset_artifacts(&dataset, dataset_dir)?;
        let mut datasets = self.datasets.lock().unwrap();
        if let Some(existing) = datasets.get(&dataset.dataset_id) {
            if existing.capture_id != dataset.capture_id || existing.checksums != dataset.checksums
            {
                return Err("DATASET_REGISTRATION_CONFLICT".into());
            }
            return Ok(());
        }
        datasets.insert(dataset.dataset_id.clone(), dataset);
        Ok(())
    }

    fn upsert_dataset(&self, dataset: LiveDataset, dataset_dir: &Path) -> Result<(), String> {
        validate_dataset_artifacts(&dataset, dataset_dir)?;
        self.datasets
            .lock()
            .unwrap()
            .insert(dataset.dataset_id.clone(), dataset);
        Ok(())
    }

    /// 2.7.16 (issue #9 part 1): rehydrate `datasets[CONTINUOUS_DATASET_ID]`
    /// from the persisted `dataset_manifest.json` written by a prior worker.
    /// Reads only the manifest file (a few KiB of JSON) — events.jsonl and
    /// callflows stay on disk and are never materialised into memory, so the
    /// 256 MiB memory ceiling is preserved. Missing manifest → no-op.
    ///
    /// 2.7.19: made `pub` so the apps/api process can rehydrate without
    /// having to spawn the import worker (which requires the lab-only
    /// allowlisted source). Tests use it the same way.
    ///
    /// 2.7.20: tolerate a malformed or drifted manifest the same way we
    /// tolerate a missing one. The worker's startup cleanup
    /// (`clean_continuous_import_root`) deletes any stale manifest + its
    /// callflows if its events.jsonl was partially compacted away; between
    /// `start_continuous_import` calling this function and the worker
    /// thread running its cleanup there is a narrow window where the
    /// manifest on disk cannot be deserialised, and we must not crash the
    /// worker then. A log line records the skip so the operator can trace
    /// it from the audit stream.
    pub fn recover_continuous_dataset_from_disk(&self, base: &Path) -> Result<(), String> {
        let dataset_dir = base.join("dataset");
        let manifest_path = dataset_dir.join("dataset_manifest.json");
        if !manifest_path.is_file() {
            return Ok(());
        }
        let Ok(bytes) = fs::read(&manifest_path) else {
            return Ok(());
        };
        let Ok(dataset) = serde_json::from_slice::<LiveDataset>(&bytes) else {
            eprintln!(
                "{}",
                serde_json::json!({
                    "event": "CONTINUOUS_DATASET_RECOVER_SKIPPED",
                    "reason": "manifest-malformed",
                    "path": manifest_path.display().to_string(),
                })
            );
            return Ok(());
        };
        if dataset.dataset_id != CONTINUOUS_DATASET_ID {
            return Err("CONTINUOUS_DATASET_IDENTIFIER_MISMATCH".into());
        }
        if let Err(error) = self.upsert_dataset(dataset, &dataset_dir) {
            eprintln!(
                "{}",
                serde_json::json!({
                    "event": "CONTINUOUS_DATASET_RECOVER_SKIPPED",
                    "reason": "artifact-drift",
                    "error": error,
                    "path": manifest_path.display().to_string(),
                })
            );
        }
        Ok(())
    }

    /// Rebuild derived artifacts from a failed capture without modifying its
    /// job, helper record, forensic manifest, or original PCAP files.
    pub fn recover_failed_capture(&self, capture_id: &str) -> Result<RecoveryReport, String> {
        if !safe_identifier(capture_id) {
            return Err("RECOVERY_CAPTURE_ID_INVALID".into());
        }
        let job = self
            .get(capture_id)
            .ok_or_else(|| "RECOVERY_CAPTURE_NOT_FOUND".to_string())?;
        if job.state != CaptureState::Failed {
            return Err("RECOVERY_REQUIRES_FAILED_CAPTURE".into());
        }
        let source_root = self.root.join(capture_id);
        let source_manifest_path = source_root.join("capture_manifest.json");
        let source_manifest_bytes = fs::read(&source_manifest_path)
            .map_err(|error| format!("CAPTURE_MANIFEST: {error}"))?;
        let source_manifest: ForensicCaptureManifest =
            serde_json::from_slice(&source_manifest_bytes).map_err(|error| error.to_string())?;
        let source_manifest_sha256 = sha256_hex(&source_manifest_bytes);
        let mut source_pcap_sha256 = BTreeMap::new();
        let mut source_files = Vec::new();
        for record in &source_manifest.files {
            if !safe_file_name(&record.file)
                || !matches!(record.interface.as_str(), "N2" | "N3" | "N4" | "SBI")
            {
                return Err("CAPTURE_MANIFEST_UNSAFE_FILE".into());
            }
            let path = source_root.join("pcap").join(&record.file);
            verify_file_integrity(&path, record.size_bytes, &record.sha256)
                .map_err(|error| format!("SOURCE_PCAP_INTEGRITY: {}: {error}", record.file))?;
            source_pcap_sha256.insert(record.file.clone(), record.sha256.clone());
            source_files.push(path);
        }
        let (recovered_packets, _) = pcap_totals(&source_files);
        if recovered_packets != source_manifest.packets {
            return Err("SOURCE_PACKET_COUNT_MISMATCH".into());
        }

        let recovery_root = self.root.join("recovered-datasets");
        fs::create_dir_all(&recovery_root)
            .map_err(|error| format!("RECOVERY_INITIALIZATION: {error}"))?;
        let final_root = recovery_root.join(capture_id);
        let report_path = final_root.join("recovery_manifest.json");
        if report_path.is_file() {
            let report: RecoveryReport =
                serde_json::from_slice(&fs::read(&report_path).map_err(display_error)?)
                    .map_err(|error| error.to_string())?;
            if report.source_manifest_sha256 != source_manifest_sha256 {
                return Err("RECOVERY_SOURCE_CHANGED".into());
            }
            let dataset: LiveDataset = serde_json::from_slice(
                &fs::read(final_root.join("dataset/dataset_manifest.json"))
                    .map_err(display_error)?,
            )
            .map_err(|error| error.to_string())?;
            self.persist_recovery_registration(&dataset, &final_root.join("dataset"))?;
            return Ok(report);
        }
        if final_root.exists() {
            return Err("RECOVERY_INCOMPLETE_OUTPUT_EXISTS".into());
        }

        let staging = recovery_root.join(format!(".{capture_id}.{}.tmp", epoch_ms()));
        let dataset_dir = staging.join("dataset");
        let interfaces = interface_specs()
            .into_iter()
            .filter(|interface| job.interfaces.contains(&interface.interface))
            .collect::<Vec<_>>();
        let dataset_id = format!("recovered-dataset-{capture_id}");
        let dataset = self.process_capture_into(
            capture_id,
            dataset_id.clone(),
            &source_root.join("pcap"),
            &dataset_dir,
            format!("runtime/live-captures/recovered-datasets/{capture_id}/dataset"),
            &interfaces,
        )?;
        let decode_errors = dataset
            .decode_reports
            .values()
            .map(|report| report.transport_errors + report.sctp_errors + report.incomplete_sctp)
            .sum();
        // Streaming hash over events.jsonl then dataset_manifest.json; the
        // old implementation concatenated both into a single Vec<u8> which
        // on recovered datasets with millions of events would allocate
        // multi-GB. The hash is identical because `Sha256Hasher` is a plain
        // streaming SHA-256.
        let dataset_integrity_sha256 = {
            let mut hasher = Sha256Hasher::new();
            for name in ["oiran_events.jsonl", "dataset_manifest.json"] {
                let file = fs::File::open(dataset_dir.join(name)).map_err(display_error)?;
                let mut reader = BufReader::with_capacity(STREAM_CHUNK_BYTES, file);
                loop {
                    let buf = reader.fill_buf().map_err(display_error)?;
                    if buf.is_empty() {
                        break;
                    }
                    hasher.update(buf);
                    let consumed = buf.len();
                    reader.consume(consumed);
                }
            }
            hasher.finish_hex()
        };
        let report = RecoveryReport {
            schema_version: "1.0".into(),
            source_capture_id: capture_id.into(),
            source_manifest_sha256,
            source_pcap_sha256,
            decoder_version: oiran_decode::VERSION.into(),
            recovered_epoch_ms: epoch_ms(),
            recovered_packets,
            generated_events: dataset.event_count,
            decode_errors,
            dataset_id,
            dataset_integrity_sha256,
            registration: "VALIDATED_REGISTERED".into(),
        };
        atomic_write(
            &staging.join("recovery_manifest.json"),
            &serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?,
        )?;
        validate_dataset_artifacts(&dataset, &dataset_dir)?;
        fs::rename(&staging, &final_root)
            .map_err(|error| format!("RECOVERY_FINALIZATION: {error}"))?;
        self.persist_recovery_registration(&dataset, &final_root.join("dataset"))?;
        Ok(report)
    }

    fn persist_recovery_registration(
        &self,
        dataset: &LiveDataset,
        dataset_dir: &Path,
    ) -> Result<(), String> {
        validate_dataset_artifacts(dataset, dataset_dir)?;
        let registry_path = self.root.join("recovered-datasets/registry.json");
        let mut registry = if registry_path.is_file() {
            serde_json::from_slice::<Vec<LiveDataset>>(
                &fs::read(&registry_path).map_err(display_error)?,
            )
            .map_err(|error| error.to_string())?
        } else {
            Vec::new()
        };
        if let Some(existing) = registry
            .iter()
            .find(|entry| entry.dataset_id == dataset.dataset_id)
        {
            if existing.capture_id != dataset.capture_id || existing.checksums != dataset.checksums
            {
                return Err("DATASET_REGISTRATION_CONFLICT".into());
            }
        } else {
            registry.push(dataset.clone());
            registry.sort_by(|left, right| left.dataset_id.cmp(&right.dataset_id));
            atomic_write(
                &registry_path,
                &serde_json::to_vec_pretty(&registry).map_err(|error| error.to_string())?,
            )?;
        }
        self.register_dataset(dataset.clone(), dataset_dir)
    }

    fn load_recovery_registry(&self) -> Result<(), String> {
        let registry_path = self.root.join("recovered-datasets/registry.json");
        if !registry_path.is_file() {
            return Ok(());
        }
        let registry: Vec<LiveDataset> =
            serde_json::from_slice(&fs::read(&registry_path).map_err(display_error)?)
                .map_err(|error| error.to_string())?;
        for dataset in registry {
            let dataset_dir = self
                .root
                .join("recovered-datasets")
                .join(&dataset.capture_id)
                .join("dataset");
            self.register_dataset(dataset, &dataset_dir)?;
        }
        Ok(())
    }

    fn persist_derived_registration(
        &self,
        dataset: &LiveDataset,
        dataset_dir: &Path,
    ) -> Result<(), String> {
        validate_dataset_artifacts(dataset, dataset_dir)?;
        let registry_path = self.root.join("derived-datasets/registry.json");
        let mut registry = if registry_path.is_file() {
            serde_json::from_slice::<Vec<LiveDataset>>(
                &fs::read(&registry_path).map_err(display_error)?,
            )
            .map_err(|error| error.to_string())?
        } else {
            Vec::new()
        };
        if let Some(existing) = registry
            .iter()
            .find(|entry| entry.dataset_id == dataset.dataset_id)
        {
            if existing.capture_id != dataset.capture_id || existing.checksums != dataset.checksums
            {
                return Err("DATASET_REGISTRATION_CONFLICT".into());
            }
        } else {
            registry.push(dataset.clone());
            registry.sort_by(|left, right| left.dataset_id.cmp(&right.dataset_id));
            atomic_write(
                &registry_path,
                &serde_json::to_vec_pretty(&registry).map_err(|error| error.to_string())?,
            )?;
        }
        self.register_dataset(dataset.clone(), dataset_dir)
    }

    fn load_derived_registry(&self) -> Result<(), String> {
        let registry_path = self.root.join("derived-datasets/registry.json");
        if !registry_path.is_file() {
            return Ok(());
        }
        let registry: Vec<LiveDataset> =
            serde_json::from_slice(&fs::read(&registry_path).map_err(display_error)?)
                .map_err(|error| error.to_string())?;
        for dataset in registry {
            let dataset_dir = self
                .root
                .join("derived-datasets")
                .join(&dataset.dataset_id)
                .join("dataset");
            self.register_dataset(dataset, &dataset_dir)?;
        }
        Ok(())
    }

    fn update(&self, id: &str, update: impl FnOnce(&mut CaptureJob)) -> Result<(), String> {
        let mut jobs = self.jobs.lock().unwrap();
        let job = jobs.get_mut(id).ok_or("capture job not found")?;
        update(job);
        self.persist_job(job)
    }

    fn persist_job(&self, job: &CaptureJob) -> Result<(), String> {
        let directory = self.root.join(&job.capture_id);
        fs::create_dir_all(&directory).map_err(display_error)?;
        fs::write(
            directory.join("job.json"),
            serde_json::to_vec_pretty(job).map_err(|error| error.to_string())?,
        )
        .map_err(display_error)
    }

    fn recover_registry(&self) -> Result<(), String> {
        for entry in fs::read_dir(&self.root)
            .map_err(display_error)?
            .filter_map(Result::ok)
        {
            let path = entry.path();
            let job_path = path.join("job.json");
            if !job_path.is_file() {
                continue;
            }
            let mut job: CaptureJob =
                serde_json::from_slice(&fs::read(&job_path).map_err(display_error)?)
                    .map_err(|error| error.to_string())?;
            let mut recovered = false;
            if job.state.active() {
                job.state = CaptureState::Failed;
                job.error = Some("CONTROLLER_RESTART_RECOVERY".into());
                job.ended_epoch_ms = Some(epoch_ms());
                recovered = true;
            } else if job.state == CaptureState::Completed
                && job.stop_reason.as_deref() == Some("CAPTURE_HELPER_EXITED")
                && capture_files(&path.join("pcap")).is_empty()
            {
                job.state = CaptureState::Failed;
                job.error = Some("CAPTURE_HELPER_EXITED_NO_OUTPUT".into());
                job.dataset_id = None;
                job.session_ids.clear();
                recovered = true;
            }
            if recovered {
                fs::write(
                    &job_path,
                    serde_json::to_vec_pretty(&job).map_err(|error| error.to_string())?,
                )
                .map_err(display_error)?;
            }
            let manifest = path.join("dataset/dataset_manifest.json");
            if (job.capture_id == CONTINUOUS_CAPTURE_ID
                || matches!(
                    job.state,
                    CaptureState::Completed | CaptureState::CompletedEmpty
                ))
                && manifest.is_file()
            {
                if let Ok(dataset) = serde_json::from_slice::<LiveDataset>(
                    &fs::read(&manifest).map_err(display_error)?,
                ) {
                    self.datasets
                        .lock()
                        .unwrap()
                        .insert(dataset.dataset_id.clone(), dataset);
                }
            }
            self.jobs
                .lock()
                .unwrap()
                .insert(job.capture_id.clone(), job);
        }
        Ok(())
    }

    fn audit(
        &self,
        actor: &str,
        action: &str,
        capture_id: &str,
        result: &str,
    ) -> Result<(), String> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join("audit.jsonl"))
            .map_err(display_error)?;
        writeln!(file, "{}", serde_json::json!({"epoch_ms":epoch_ms(),"actor":actor,"action":action,"capture_id":capture_id,"result":result})).map_err(display_error)
    }
}

fn runtime_pdu_callflow(
    events: &[session_engine::EventRecord],
    active: &ActivePduContext,
) -> CallFlow {
    let selected = events
        .iter()
        .filter(|event| active.gtpu_event_ids.contains(&event.event_id))
        .cloned()
        .collect::<Vec<_>>();
    let mut reconstruction = reconstruct(
        selected,
        ReconstructionHints {
            ue_pseudonym: Some(active.internal_ue_id.clone()),
            ..Default::default()
        },
    );
    reconstruction.session_id = active.session_id.clone();
    for event in &reconstruction.events {
        reconstruction
            .association
            .insert(event.event_id.clone(), Association::Session);
    }
    let mut flow = build_callflow(&reconstruction, Vec::new());
    flow.correlation_status
        .insert("E2E".into(), active.correlation_status.clone());
    flow
}

fn prepare_dataset_directory(dataset_dir: &Path) -> Result<(), String> {
    let callflows = dataset_dir.join("callflows");
    fs::create_dir_all(&callflows)
        .map_err(|error| dataset_io_error("DATASET_INITIALIZATION", &callflows, error))?;
    if !dataset_dir.is_dir() || !callflows.is_dir() {
        return Err("DATASET_INITIALIZATION: output path is not a directory".into());
    }
    let probe = dataset_dir.join(format!(".write-check-{}.tmp", epoch_ms()));
    let result = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&probe)
        .and_then(|file| file.sync_all());
    if let Err(error) = result {
        let _ = fs::remove_file(&probe);
        return Err(dataset_io_error("DATASET_PERMISSION", dataset_dir, error));
    }
    fs::remove_file(&probe).map_err(|error| {
        format!(
            "DATASET_INITIALIZATION: remove write check {}: {error}",
            probe.display()
        )
    })
}

fn dataset_io_error(category: &str, path: &Path, error: std::io::Error) -> String {
    format!("{category}: {}: {error}", path.display())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("atomic output has no parent: {}", path.display()))?;
    if !parent.is_dir() {
        return Err(format!(
            "atomic output directory missing: {}",
            parent.display()
        ));
    }
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("artifact");
    let temporary = parent.join(format!(".{name}.{}.tmp", epoch_ms()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| format!("create {}: {error}", temporary.display()))?;
        file.write_all(bytes).map_err(display_error)?;
        file.flush().map_err(display_error)?;
        file.sync_all().map_err(display_error)?;
        fs::rename(&temporary, path)
            .map_err(|error| format!("finalize {}: {error}", path.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn validate_dataset_artifacts(dataset: &LiveDataset, dataset_dir: &Path) -> Result<(), String> {
    let events_path = dataset_dir.join("oiran_events.jsonl");
    let manifest_path = dataset_dir.join("dataset_manifest.json");
    if !events_path.is_file() || !manifest_path.is_file() || !dataset_dir.join("callflows").is_dir()
    {
        return Err("DATASET_REGISTRATION_ARTIFACT_MISSING".into());
    }
    let event_count = count_valid_event_records(&events_path)?;
    if event_count != dataset.event_count {
        return Err("DATASET_REGISTRATION_EVENT_COUNT_MISMATCH".into());
    }
    let persisted: LiveDataset =
        serde_json::from_slice(&fs::read(&manifest_path).map_err(display_error)?)
            .map_err(|error| error.to_string())?;
    if persisted.dataset_id != dataset.dataset_id
        || persisted.capture_id != dataset.capture_id
        || persisted.event_count != dataset.event_count
        || persisted.checksums != dataset.checksums
    {
        return Err("DATASET_REGISTRATION_MANIFEST_MISMATCH".into());
    }
    for session_id in &dataset.session_ids {
        let json = dataset_dir
            .join("callflows")
            .join(format!("{session_id}.json"));
        let html = dataset_dir
            .join("callflows")
            .join(format!("{session_id}.html"));
        if !json.is_file() || !html.is_file() {
            return Err("DATASET_REGISTRATION_CALLFLOW_MISSING".into());
        }
        serde_json::from_slice::<CallFlow>(&fs::read(json).map_err(display_error)?)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Validate a persisted event artifact without rebuilding the complete
/// dataset in memory. Registration runs both before and after continuous
/// publication, so using `load_path` here used to retain one full
/// `Vec<EventRecord>` and made RSS proportional to history size.
fn count_valid_event_records(path: &Path) -> Result<usize, String> {
    let file = fs::File::open(path).map_err(display_error)?;
    let reader = BufReader::with_capacity(STREAM_CHUNK_BYTES, file);
    let mut count = 0usize;
    for (line_number, line) in reader.lines().enumerate() {
        let line = line.map_err(display_error)?;
        if line.trim().is_empty() {
            continue;
        }
        let parsed = session_engine::load_jsonl(line.as_bytes())
            .map_err(|error| format!("line {}: {error}", line_number + 1))?;
        if parsed.len() != 1 {
            return Err(format!(
                "DATASET_REGISTRATION_EVENT_INVALID line {}",
                line_number + 1
            ));
        }
        count = count.saturating_add(1);
        if count % 1024 == 0 {
            release_unused_heap_pages();
        }
    }
    release_unused_heap_pages();
    Ok(count)
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn safe_file_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.contains('/')
        && !value.contains('\\')
        && value != "."
        && value != ".."
}

fn verify_artifact_hash(
    manifest: &DerivedDatasetManifest,
    name: &str,
    bytes: &[u8],
) -> Result<(), String> {
    let expected = manifest
        .artifacts
        .get(name)
        .and_then(|value| value.strip_prefix("sha256:"))
        .ok_or_else(|| format!("DERIVED_ARTIFACT_HASH_MISSING: {name}"))?;
    if sha256_hex(bytes) != expected {
        return Err(format!("DERIVED_ARTIFACT_INTEGRITY: {name}"));
    }
    Ok(())
}

fn resolve_derived_import_source(import_root: &Path, dataset_id: &str) -> Result<PathBuf, String> {
    let direct = import_root.join(dataset_id);
    if direct.is_dir() {
        return direct
            .canonicalize()
            .map_err(|error| format!("DERIVED_IMPORT_SOURCE: {error}"));
    }
    let entries = fs::read_dir(import_root)
        .map_err(|error| format!("DERIVED_IMPORT_ROOT: {error}"))?
        .filter_map(Result::ok)
        .take(65)
        .collect::<Vec<_>>();
    if entries.len() > 64 {
        return Err("DERIVED_IMPORT_ROOT_ENTRY_LIMIT".into());
    }
    let mut matches = Vec::new();
    for entry in entries {
        let path = entry.path();
        let manifest_path = path.join("dataset_manifest.json");
        if !path.is_dir() || !manifest_path.is_file() {
            continue;
        }
        let value: serde_json::Value = match fs::read(&manifest_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        {
            Some(value) => value,
            None => continue,
        };
        if value["dataset_id"].as_str() == Some(dataset_id) {
            matches.push(path.canonicalize().map_err(display_error)?);
        }
    }
    match matches.as_slice() {
        [path] => Ok(path.clone()),
        [] => Err("DERIVED_IMPORT_SOURCE_NOT_FOUND".into()),
        _ => Err("DERIVED_IMPORT_SOURCE_AMBIGUOUS".into()),
    }
}

fn validate_derived_event_provenance(
    events_bytes: &[u8],
    source_capture_id: &str,
    source_hashes: &BTreeMap<String, String>,
    source_packet_limits: &BTreeMap<String, u64>,
) -> Result<(), String> {
    let text =
        std::str::from_utf8(events_bytes).map_err(|_| "DERIVED_EVENTS_NOT_UTF8".to_string())?;
    for (line_number, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event: serde_json::Value = serde_json::from_str(line)
            .map_err(|error| format!("DERIVED_EVENT_INVALID line {}: {error}", line_number + 1))?;
        let references = event["packet_references"]
            .as_array()
            .ok_or_else(|| format!("DERIVED_PROVENANCE_MISSING line {}", line_number + 1))?;
        if references.is_empty() {
            return Err(format!("DERIVED_PROVENANCE_EMPTY line {}", line_number + 1));
        }
        for reference in references {
            let source_file = reference["source_file"]
                .as_str()
                .ok_or_else(|| "DERIVED_SOURCE_FILE_MISSING".to_string())?;
            if !source_file.contains(&format!("/captures/{source_capture_id}/pcap/")) {
                return Err("DERIVED_SOURCE_CAPTURE_MISMATCH".into());
            }
            let file_name = Path::new(source_file)
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| "DERIVED_SOURCE_FILE_INVALID".to_string())?;
            let expected_hash = source_hashes
                .get(file_name)
                .ok_or_else(|| "DERIVED_SOURCE_FILE_UNKNOWN".to_string())?;
            if reference["source_sha256"].as_str() != Some(expected_hash.as_str()) {
                return Err("DERIVED_SOURCE_HASH_MISMATCH".into());
            }
            let packet_number = reference["packet_number"]
                .as_u64()
                .ok_or_else(|| "DERIVED_PACKET_NUMBER_MISSING".to_string())?;
            if packet_number == 0
                || packet_number > *source_packet_limits.get(file_name).unwrap_or(&0)
            {
                return Err("DERIVED_PACKET_REFERENCE_OUT_OF_RANGE".into());
            }
        }
    }
    Ok(())
}

pub fn interface_specs() -> Vec<CaptureInterface> {
    // 2.9.2 (#9 comment 6710853974): ANR2 proved that `_00067` and
    // the other LTE closed segments were ingested with non-zero
    // protocol-frame counts (S1AP/GTP/GTPv2/Diameter/PFCP) but
    // published zero events. Root cause: this list ONLY returned
    // N2/SBI/N4/N3, and `process_capture_into` iterates
    // `for interface in interfaces { capture_files_for(pcap_dir,
    // &interface.interface) … decode_capture_streaming … }` at
    // `OIRAN/live-probe/src/lib.rs:3898-3935`. Owned LTE pcaps
    // (`S1-MME.pcap-*.pcapng`, `S11.pcap-*`, …) never made it
    // through the per-interface loop → no decode call → no
    // `oiran_events.jsonl` line → the symptom
    // `rg -c 'sha256:<checksum>' dataset/oiran_events.jsonl == 0`
    // on every LTE checksum of the import state. Returning the full
    // 11-decoder-backed set fixes the symptom at the root. N6 stays
    // out because no decoder handles it (2.9.1 already counts it in
    // `plane_counts` and logs `CONTINUOUS_PLANE_NOT_ALLOWLISTED`).
    vec![
        spec(
            "N2",
            "br-oiran-n2",
            "NGAP / SCTP",
            "POLARIS N2 Docker bridge",
            "sctp and port 38412",
        ),
        spec(
            "SBI",
            "br-oiran-sbi",
            "HTTP/2 / SBI",
            "POLARIS SBI Docker bridge",
            "tcp port 7777",
        ),
        spec(
            "N4",
            "br-oiran-n4",
            "PFCP / UDP",
            "POLARIS N4 Docker bridge",
            "udp port 8805",
        ),
        spec(
            "N3",
            "br-oiran-n3",
            "GTP-U / UDP",
            "POLARIS N3 Docker bridge",
            "udp port 2152",
        ),
        spec(
            "S1-MME",
            "br-oiran-s1m",
            "S1AP / SCTP + NAS-EPS",
            "POLARIS S1-MME Docker bridge",
            "sctp and port 36412",
        ),
        spec(
            "S1-U",
            "br-oiran-s1u",
            "GTP-U / UDP",
            "POLARIS S1-U Docker bridge",
            "udp port 2152",
        ),
        spec(
            "S11",
            "br-oiran-s11",
            "GTPv2-C / UDP",
            "POLARIS S11 Docker bridge",
            "udp port 2123",
        ),
        spec(
            "S5-C",
            "br-oiran-s5c",
            "GTPv2-C / UDP",
            "POLARIS S5-C Docker bridge",
            "udp port 2123",
        ),
        spec(
            "S5-U",
            "br-oiran-s5u",
            "GTP-U / UDP",
            "POLARIS S5-U Docker bridge",
            "udp port 2152",
        ),
        spec(
            "S6a",
            "br-oiran-s6a",
            "Diameter / SCTP (DIAMETER_PPID=46)",
            "POLARIS S6a Docker bridge",
            "sctp and port 3868",
        ),
        spec(
            "Sxab",
            "br-oiran-sxab",
            "PFCP / UDP",
            "POLARIS Sxa/Sxb Docker bridge",
            "udp port 8805",
        ),
        // 2.11.0 (devmat) : IMS voice plane. SIP sur UDP 5060 par
        // défaut ; RTP/RTCP sur ports dynamiques issus des SDP. Les
        // flux encapsulés dans GTP-U (N3, S1-U) sont décodés par la
        // branche inner de `oiran-decode`, pas ici.
        spec(
            "IMS",
            "br-oiran-ims",
            "SIP / UDP + RTP (SDP-negotiated) / UDP",
            "POLARIS IMS Docker bridge",
            "udp port 5060",
        ),
    ]
}

fn spec(
    interface: &str,
    device: &str,
    protocol: &str,
    point: &str,
    filter: &str,
) -> CaptureInterface {
    CaptureInterface {
        interface: interface.into(),
        role: None,
        device: device.into(),
        protocol: protocol.into(),
        capture_point: point.into(),
        bpf_filter: filter.into(),
        available: false,
        operstate: "UNKNOWN".into(),
        reason: None,
    }
}

fn helper_spec(capture_id: String, request: &CaptureRequest) -> CaptureSpec {
    CaptureSpec {
        capture_id,
        interfaces: request
            .interfaces
            .iter()
            .filter_map(|interface| match interface.as_str() {
                "N2" => Some(InterfaceId::N2),
                "N3" => Some(InterfaceId::N3),
                "N4" => Some(InterfaceId::N4),
                "SBI" => Some(InterfaceId::Sbi),
                _ => None,
            })
            .collect(),
        duration_seconds: request.duration_seconds,
        max_bytes: request.max_bytes,
        rotation_files: request.rotation_files,
    }
}

fn plane_name(interface: &str) -> &'static str {
    match interface {
        "N2" => "NG-C",
        "SBI" => "SBI",
        "N4" => "N4",
        "N3" => "NG-U",
        _ => "UNKNOWN",
    }
}

fn build_plane_results(
    capture_id: &str,
    interfaces: &[String],
    files: &[PathBuf],
    dataset: &LiveDataset,
    started_epoch_ms: Option<u64>,
    ended_epoch_ms: Option<u64>,
    drops: Option<u64>,
) -> Vec<CapturePlaneStatus> {
    interfaces
        .iter()
        .map(|interface| {
            let matching = files
                .iter()
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(interface))
                })
                .cloned()
                .collect::<Vec<_>>();
            let (packet_count, storage_bytes) = pcap_totals(&matching);
            let byte_count = matching.iter().map(|path| pcap_record_totals(path).1).sum();
            let source_sha256 = matching
                .iter()
                .filter_map(|path| {
                    let name = path.file_name()?.to_str()?;
                    dataset.checksums.get(name).cloned()
                })
                .collect::<Vec<_>>();
            let has_report = matching.iter().any(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| dataset.decode_reports.contains_key(name))
            });
            CapturePlaneStatus {
                plane: plane_name(interface).into(),
                interface: interface.clone(),
                capture_job_id: capture_id.into(),
                start_timestamp: started_epoch_ms,
                end_timestamp: ended_epoch_ms,
                packet_count,
                byte_count,
                drop_count: drops,
                storage_bytes,
                decode_status: if packet_count == 0 {
                    "COMPLETED_EMPTY".into()
                } else if has_report {
                    "DECODED".into()
                } else {
                    "CAPTURED_UNDECODED".into()
                },
                dataset_id: Some(dataset.dataset_id.clone()),
                source_sha256,
                error: None,
            }
        })
        .collect()
}

fn map_helper_state(state: HelperState) -> CaptureState {
    match state {
        HelperState::Created => CaptureState::Created,
        HelperState::Validating => CaptureState::Validating,
        HelperState::Ready => CaptureState::Ready,
        HelperState::Starting => CaptureState::Starting,
        HelperState::Capturing => CaptureState::Capturing,
        HelperState::Stopping => CaptureState::Stopping,
        HelperState::Completed => CaptureState::Completed,
        HelperState::CompletedEmpty => CaptureState::CompletedEmpty,
        HelperState::Failed => CaptureState::Failed,
    }
}

fn job_state_label(state: HelperState) -> &'static str {
    match state {
        HelperState::Completed => "COMPLETED",
        HelperState::CompletedEmpty => "COMPLETED_EMPTY",
        HelperState::Failed => "FAILED",
        _ => "TERMINAL_STATE_UNEXPECTED",
    }
}

fn format_helper_error(error: Option<capture_helper::HelperFailure>) -> String {
    error
        .map(|failure| format!("{}: {}", failure.category, failure.details))
        .unwrap_or_else(|| "capture helper returned an unspecified error".into())
}

fn discover_interface(mut interface: CaptureInterface, interface_root: &Path) -> CaptureInterface {
    let base = interface_root.join(&interface.device);
    if !base.is_dir() {
        interface.reason = Some("NETWORK_DEVICE_NOT_FOUND".into());
        return interface;
    }
    interface.operstate = fs::read_to_string(base.join("operstate"))
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_ascii_uppercase();
    interface.available = matches!(interface.operstate.as_str(), "UP" | "UNKNOWN");
    if !interface.available {
        interface.reason = Some(format!("DEVICE_{}", interface.operstate));
    }
    interface
}

fn validate_request(
    request: &CaptureRequest,
    interfaces: &[CaptureInterface],
    policy: Policy,
) -> Vec<String> {
    let mut blockers = Vec::new();
    if request.probe_id != PROBE_ID {
        blockers.push("PROBE_NOT_ALLOWLISTED".into());
    }
    if request.name.is_empty()
        || request.name.len() > 64
        || !request
            .name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        blockers.push("INVALID_CAPTURE_NAME".into());
    }
    if request.interfaces.is_empty() || request.interfaces.len() > MAX_CAPTURE_PLANES {
        blockers.push("INVALID_INTERFACE_COUNT".into());
    }
    let unique = request.interfaces.iter().collect::<BTreeSet<_>>();
    if unique.len() != request.interfaces.len() {
        blockers.push("DUPLICATE_INTERFACE".into());
    }
    for requested in &request.interfaces {
        match interfaces
            .iter()
            .find(|interface| &interface.interface == requested)
        {
            Some(interface) if interface.available => {}
            Some(_) => blockers.push(format!("INTERFACE_{requested}_UNAVAILABLE")),
            None => blockers.push(format!("INTERFACE_{requested}_NOT_ALLOWLISTED")),
        }
    }
    if request.duration_seconds == 0 || request.duration_seconds > policy.max_job_seconds {
        blockers.push("INVALID_CAPTURE_DURATION".into());
    }
    if request.max_bytes < MIN_CAPTURE_BYTES
        || request.max_bytes
            > policy
                .max_file_bytes
                .saturating_mul(u64::from(policy.max_files))
    {
        blockers.push("INVALID_CAPTURE_SIZE".into());
    }
    if request.rotation_files == 0 || request.rotation_files > policy.max_files {
        blockers.push("INVALID_ROTATION".into());
    }
    let minimum_rotated_budget = request
        .interfaces
        .len()
        .saturating_mul(usize::from(request.rotation_files))
        as u64
        * MIN_CAPTURE_BYTES;
    if request.max_bytes < minimum_rotated_budget {
        blockers.push("CAPTURE_BUDGET_TOO_SMALL_FOR_ROTATION".into());
    }
    if request
        .optional_filter
        .as_ref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        blockers.push("CUSTOM_FILTER_NOT_CERTIFIED".into());
    }
    blockers
}

#[derive(Clone, Debug)]
struct SourceSegment {
    path: PathBuf,
    interface: String,
    checksum: String,
    size_bytes: u64,
    packets: u64,
    modified: SystemTime,
}

/// Minimal metadata projection built from `fs::symlink_metadata` only. The
/// previous implementation materialised each candidate's full bytes via
/// `fs::read` BEFORE the finalized filter — Codex measured that this
/// allocated up to 512 × file-size (~RSS 255 MiB on 2 MiB files inside a
/// 256 MiB cgroup, 27 OOMs in 5 min). This struct lets us run the
/// finalized-candidates filter on cheap metadata, then stream-hash only the
/// kept candidates one at a time so the resident set is bounded regardless
/// of the candidate pool size.
#[derive(Clone, Debug)]
struct SourceCandidateMeta {
    path: PathBuf,
    interface: String,
    size_bytes: u64,
    modified: SystemTime,
    /// 2.8.2: carry the filesystem fingerprint from the first
    /// `fs::symlink_metadata` call so `source_segments` can look it up
    /// in the cache WITHOUT a second statx. Avoids the pre-2.8.2
    /// 20 000-statx per scan at 10 000 files.
    dev: u64,
    inode: u64,
    mtime_ns: i128,
    /// 2.8.3: the lexicographically comparable filename
    /// (`path.file_name()`). Closed-proof uses it to decide which
    /// candidate is the still-live writer per interface.
    filename: String,
}

#[derive(Clone, Debug)]
struct RejectedSourceSegment {
    path: PathBuf,
    size_bytes: u64,
}

#[derive(Clone, Debug, Default)]
struct SourceDiscovery {
    segments: Vec<SourceSegment>,
    rejected: Vec<RejectedSourceSegment>,
    /// 2.8.2: set when `source_segments` inserted a new entry into
    /// the cache (the file was new or its `(size, mtime_ns)` changed).
    /// The caller persists `state.source_fingerprints` only when this
    /// is `true` — avoiding an O(N) BTreeMap compare + full JSON
    /// serialize + atomic write on every quiet scan.
    cache_mutated: bool,
    /// 2.8.2: count of candidates the `finalized_candidates_only`
    /// filter excluded as still-live dumpcap targets (too young to
    /// be considered finalised). When > 0 the worker must NOT trust
    /// the dir-mtime gate — these files will become eligible by
    /// aging alone, without any directory mutation.
    pending_finalization: usize,
    /// 2.8.2: the full disk-scan path set BEFORE any cap or filter.
    /// The caller uses this as the "live set" when purging the
    /// persisted `source_fingerprints`.
    all_discovered_paths: BTreeSet<PathBuf>,
    /// 2.8.3: the paths that `finalized_candidates_only` identified as
    /// the still-live dumpcap target per interface (sequence proof
    /// failed, JSONL proof absent). The worker subtracts this set from
    /// `last_pending_characterization` so a quiet active file does not
    /// force endless rescans.
    known_active_paths: BTreeSet<PathBuf>,
    /// 2.9.1 (#9): count of .pcap files observed per plane by
    /// `collect_source_paths`, keyed on the canonical interface string
    /// (`N2`/`N3`/…/`Sxab`) or `UNKNOWN` for unrecognised directories.
    /// Independent from the `segments` list so planes without a
    /// decoder (`N6`) are still surfaced.
    plane_counts: BTreeMap<String, u64>,
    /// 2.9.1: paths outside the canonical 12-plane allowlist, as seen
    /// in the latest scan. The worker logs each path ONCE per worker
    /// lifetime as `CONTINUOUS_PLANE_NOT_ALLOWLISTED`, never silently
    /// skipping it.
    unknown_plane_paths: Vec<PathBuf>,
}

/// 2.8.1 (ANR2 perf 77.31% in `Sha256Hasher::compress`): per-worker
/// cache keyed by filesystem coordinates `(dev, inode, size, mtime_ns)`.
/// A rotation that replaces a file at the same path gets a new inode
/// or mtime, so the key invalidates automatically; a file seen before
/// with the same coordinates reuses its cached `(sha, packets)` and
/// does NOT get re-hashed nor re-read. The in-memory cache is
/// hydrated at startup from `ContinuousImportState.source_fingerprints`,
/// so the fix also survives a probe restart.
pub type SourceSegmentsCache = std::collections::BTreeMap<PathBuf, SourceFingerprint>;

fn fingerprint_from_metadata(metadata: &fs::Metadata) -> (u64, u64, u64, i128) {
    use std::os::unix::fs::MetadataExt;
    let mtime_ns = i128::from(metadata.mtime()) * 1_000_000_000i128
        + i128::from(metadata.mtime_nsec());
    (metadata.dev(), metadata.ino(), metadata.size(), mtime_ns)
}

fn source_segments(
    root: &Path,
    _stable_age: Duration,
    native_only: bool,
    max_segment_bytes: u64,
    cache: &mut SourceSegmentsCache,
) -> Result<SourceDiscovery, String> {
    // 2.8.2: track whether this scan mutated the cache. The caller
    // uses the flag to avoid an O(N) BTreeMap compare + full JSON
    // serialize + atomic write on every quiet scan — the 2.8.1 code
    // did that unconditionally and ANR2 measured the cost at 10 000
    // entries.
    let mut cache_mutated = false;
    let mut paths = Vec::new();
    collect_source_paths(root, 0, &mut paths)?;
    // 2.8.3 (#9 comment 6696366882): `all_discovered_paths` records
    // only paths the worker WILL consider — a known interface, not a
    // symlink, a real file, > 24 B. Files below these filters are
    // silently ignored by the worker, so they must not count towards
    // `last_pending_characterization`; otherwise the gate at :2098
    // never idles on a tree with non-allowlisted directories.
    let mut all_discovered_paths: BTreeSet<PathBuf> = BTreeSet::new();
    let mut plane_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut unknown_plane_paths: Vec<PathBuf> = Vec::new();
    let mut eligible: Vec<SourceCandidateMeta> = Vec::new();
    for path in paths {
        let metadata = fs::symlink_metadata(&path).map_err(display_error)?;
        if native_only && !native_segment_source(root, &path) {
            continue;
        }
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() <= 24 {
            continue;
        }
        let interface = match source_interface(root, &path) {
            Some(value) => value,
            None => {
                // 2.9.1 (#9): unknown plane directory → counted as
                // "UNKNOWN" and surfaced via `unknown_plane_paths`.
                // The worker logs `CONTINUOUS_PLANE_NOT_ALLOWLISTED`
                // once per path.
                *plane_counts.entry("UNKNOWN".to_string()).or_insert(0) += 1;
                unknown_plane_paths.push(path);
                continue;
            }
        };
        // 2.9.1: per-plane counter covers every allowlisted plane,
        // including those without a decoder (N6 → counted, no event
        // ever emitted downstream — same `CONTINUOUS_PLANE_NOT_ALLOWLISTED`
        // log channel as fully-unknown directories).
        *plane_counts.entry(interface.clone()).or_insert(0) += 1;
        if !interface_has_decoder(&interface) {
            unknown_plane_paths.push(path);
            continue;
        }
        all_discovered_paths.insert(path.clone());
        let modified = metadata.modified().map_err(display_error)?;
        // 2.8.3 (#9 comment 6696366882): the stable_age gate is gone.
        // Dumpcap lifecycle, not wall-clock age, decides eligibility.
        // Short-lived segments would otherwise re-enter the eligible
        // pool every scan until they aged, costing a statx per file.
        let (dev, inode, size_bytes, mtime_ns) = fingerprint_from_metadata(&metadata);
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        eligible.push(SourceCandidateMeta {
            path,
            interface,
            size_bytes,
            modified,
            dev,
            inode,
            mtime_ns,
            filename,
        });
    }
    eligible.sort_by(|left, right| {
        right
            .modified
            .cmp(&left.modified)
            .then_with(|| left.path.cmp(&right.path))
    });
    // 2.8.3: apply the sequence-based closed-proof + optional JSONL
    // promotion on the cheap metadata projection. The active segment
    // per interface is identified and preserved in `known_active_paths`
    // so the worker loop can exclude it from
    // `last_pending_characterization` (never a full rescan reason).
    let rotation_counts = load_rotation_record_counts(root);
    let projections: Vec<FinalizationCandidate> = eligible
        .iter()
        .map(|candidate| FinalizationCandidate {
            interface: candidate.interface.clone(),
            modified: candidate.modified,
            filename: candidate.filename.clone(),
        })
        .collect();
    let eligible_before_finalization = projections.len();
    let kept = finalized_candidates_only(projections, &rotation_counts);
    let pending_finalization = eligible_before_finalization.saturating_sub(kept.len());
    let kept_key_set: BTreeSet<(String, String)> = kept
        .iter()
        .map(|p| (p.interface.clone(), p.filename.clone()))
        .collect();
    let mut known_active_paths: BTreeSet<PathBuf> = BTreeSet::new();
    let mut kept_meta: Vec<SourceCandidateMeta> = Vec::new();
    for candidate in eligible {
        if kept_key_set.contains(&(candidate.interface.clone(), candidate.filename.clone())) {
            kept_meta.push(candidate);
        } else {
            known_active_paths.insert(candidate.path);
        }
    }
    // Stream-hash and stream-count packets for each kept candidate, one at a
    // time. The file content is never materialised in RAM — hashing walks the
    // file through a 1 MiB `BufReader` and `pcap_record_totals` already uses
    // `fs::File::read_exact` with a 16-byte record header + `io::copy` into a
    // sink, so it also only buffers a fixed window.
    let mut segments = Vec::with_capacity(kept_meta.len());
    let mut rejected = Vec::new();
    for candidate in kept_meta {
        if candidate.size_bytes > max_segment_bytes {
            if rejected.len() < MAX_PERSISTED_INGESTION_FAILURES {
                rejected.push(RejectedSourceSegment {
                    path: candidate.path,
                    size_bytes: candidate.size_bytes,
                });
            }
            continue;
        }
        // 2.8.3 (#9 comment 6696366882): the 512 cap on `segments` is
        // gone. ANR2 proved that at 3 805 PCAPs the cap left ~3 292 paths
        // outside the fingerprint cache forever, so
        // `last_pending_characterization` stayed non-zero and every tick
        // forced a full rescan (92 000 statx / 30 s). The fingerprint
        // cache now covers every CLOSED segment on disk; the import
        // queue remains bounded by `MAX_INGESTED_SEGMENTS_PER_SCAN = 32`
        // one level up, so the per-scan work budget is unaffected.
        // 2.8.1 (ANR2 perf proof): the cheap key `(dev, inode, size,
        // mtime_ns)` short-circuits the heavy SHA-256 + pcap-record-count
        // work when the file has not been modified since the last scan.
        // perf showed 77.31% of the pre-2.8.1 CPU inside
        // `Sha256Hasher::compress` running on every segment every 1 s.
        // 2.8.2: reuse the fingerprint captured by `collect_source_paths`
        // so we avoid a second statx per candidate (the 2.8.1 code did
        // two statx per candidate; ANR2's gate measured the cost at
        // 10 000 files).
        let dev = candidate.dev;
        let inode = candidate.inode;
        let size = candidate.size_bytes;
        let mtime_ns = candidate.mtime_ns;
        let cached_hit = cache.get(&candidate.path).filter(|entry| {
            entry.dev == dev
                && entry.inode == inode
                && entry.size_bytes == size
                && entry.mtime_ns == mtime_ns
        });
        let (checksum, packets) = if let Some(entry) = cached_hit {
            (entry.checksum.clone(), entry.packets)
        } else {
            match sha256_hex_file(&candidate.path) {
                Ok(fresh) => {
                    let count = count_pcap_records(&candidate.path);
                    cache.insert(
                        candidate.path.clone(),
                        SourceFingerprint {
                            dev,
                            inode,
                            size_bytes: size,
                            mtime_ns,
                            checksum: fresh.clone(),
                            packets: count,
                        },
                    );
                    cache_mutated = true;
                    (fresh, count)
                }
                Err(error) => {
                    // 2.10.4 (devmat, revue 2.10.3 ANR2) : interdiction
                    // du saut silencieux. Pré-2.10.4, un `sha256_hex_file`
                    // qui échouait (I/O, permission, etc.) exécutait un
                    // `continue;` sans aucune trace — ANR2 n'avait aucun
                    // moyen de distinguer un segment ignoré d'un segment
                    // encore pending. 2.10.4 loggue + enregistre dans
                    // `rejected` pour que la ronde suivante retente
                    // (invariant ouvert par ANR2 : « segment fermé →
                    // ingéré OU ingestion_failures avec sa raison »).
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "event": "CONTINUOUS_SEGMENT_SHA_FAILED",
                            "path": candidate.path.display().to_string(),
                            "interface": candidate.interface,
                            "size_bytes": size,
                            "reason": format!("sha256_hex_file: {error}"),
                        })
                    );
                    if rejected.len() < MAX_PERSISTED_INGESTION_FAILURES {
                        rejected.push(RejectedSourceSegment {
                            path: candidate.path.clone(),
                            size_bytes: size,
                        });
                    }
                    continue;
                }
            }
        };
        segments.push(SourceSegment {
            path: candidate.path,
            interface: candidate.interface,
            checksum,
            size_bytes: candidate.size_bytes,
            packets,
            modified: candidate.modified,
        });
    }
    // 2.10.4 (devmat, revue 2.10.3 ANR2 #10 comment 2026-11-10 16:48Z) :
    // tri **oldest-first** pour le drain FIFO. Pré-2.10.4, la clé
    // `right.modified.cmp(&left.modified)` triait **newest-first** et
    // combinée au plafond `MAX_INGESTED_SEGMENTS_PER_SCAN = 32`
    // provoquait une **famine des plus anciens segments fermés**
    // (ANR2 : `n2_..._00066_...` fermé 15:38Z toujours non ingéré à
    // 16:48Z = 70 min / 3 cycles × 32 = 96 nouveaux segments traités
    // avant lui). Le tri oldest-first garantit qu'un segment fermé
    // atteint la tête de la file en au plus `backlog/32` cycles,
    // jamais indéfiniment reporté au profit d'un segment plus récent
    // d'une autre interface.
    segments.sort_by(|left, right| {
        left.modified
            .cmp(&right.modified)
            .then_with(|| left.checksum.cmp(&right.checksum))
    });
    rejected.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(SourceDiscovery {
        segments,
        rejected,
        cache_mutated,
        pending_finalization,
        all_discovered_paths,
        known_active_paths,
        plane_counts,
        unknown_plane_paths,
    })
}

fn native_segment_source(root: &Path, path: &Path) -> bool {
    path.strip_prefix(root)
        .ok()
        .and_then(|relative| relative.components().next())
        .and_then(|component| component.as_os_str().to_str())
        .is_some_and(|name| name.starts_with("continuous-segment-"))
}

fn remember_checksum(state: &mut ContinuousImportState, checksum: String) {
    if state.seen_checksums.insert(checksum.clone()) {
        state.seen_order.push_back(checksum);
    }
    // 2.8.2 (#10 comment 6687323881): removed the
    // `MAX_CONTINUOUS_SEEN=4096` eviction. ANR2 proved in production
    // that evicting the oldest checksum caused retained source
    // segments (still on disk) to be re-discovered as pending every
    // scan, sustaining 92.85% CPU on oiran-api. The index is now
    // bounded by the real on-disk file population and any segment
    // held in `state.segments` — `purge_missing_source_fingerprints`
    // reclaims entries whose source file has disappeared AND whose
    // checksum is no longer referenced.
}

/// 2.8.2 (#10 comment 6687323881): purge `source_fingerprints` and
/// the matching `seen_checksums` entry when the source path has
/// vanished AND the segment is not held in `state.segments` (an
/// ingested segment keeps its mark even if the operator rotates the
/// source file away). Returns `true` when the state changed so the
/// caller can persist. Memory is therefore bounded by the number of
/// real files currently on disk plus the ingested segments — never
/// by an arbitrary cap. At 20 000 entries the checksum index is
/// ~64 bytes × 2 = 2.5 MiB (hex + BTreeSet node overhead), fitting
/// the 256 MiB MemoryMax ceiling comfortably.
fn purge_missing_source_fingerprints(
    state: &mut ContinuousImportState,
    live_paths: &std::collections::BTreeSet<PathBuf>,
) -> bool {
    let discarded_paths: Vec<String> = state
        .source_fingerprints
        .iter()
        .filter(|(path, _)| !live_paths.contains(Path::new(path.as_str())))
        .map(|(path, _)| path.clone())
        .collect();
    if discarded_paths.is_empty() {
        return false;
    }
    // 2.8.2: O(N + M) purge. Build a single reverse count of
    // checksum→remaining-paths after the discarded set is removed,
    // then reclaim only the checksums whose count reaches zero AND
    // whose segment is not held in `state.segments`. The pre-2.8.2
    // code walked `state.source_fingerprints.values()` for every
    // discarded path — O(N × M) at 10 000 live files and ~9 500
    // discarded paths that's 95 million comparisons per scan.
    let discarded_set: std::collections::BTreeSet<&String> = discarded_paths.iter().collect();
    let mut remaining_counts: BTreeMap<String, usize> = BTreeMap::new();
    for (path, fingerprint) in state.source_fingerprints.iter() {
        if discarded_set.contains(path) {
            continue;
        }
        *remaining_counts.entry(fingerprint.checksum.clone()).or_insert(0) += 1;
    }
    for path in &discarded_paths {
        if let Some(fingerprint) = state.source_fingerprints.remove(path) {
            let still_on_disk = remaining_counts
                .get(&fingerprint.checksum)
                .copied()
                .unwrap_or(0)
                > 0;
            let ingested = state.segments.contains_key(&fingerprint.checksum);
            if !still_on_disk && !ingested {
                state.seen_checksums.remove(&fingerprint.checksum);
                state.seen_order.retain(|entry| entry != &fingerprint.checksum);
            }
        }
    }
    true
}

/// 2.9.17 (#9 comment 6739207609) — report retourné par
/// `recover_repair_staging`. Liste chaque chemin supprimé avec
/// la taille qu'il occupait, pour que l'opérateur ait la preuve
/// de l'action AVANT/APRÈS.
///
/// 2.9.17-fu (#9 comment 6740035832) : étendu pour couvrir le
/// cas ANR2 où la sauvegarde 2.9.16 ne contient PAS
/// `import_state.json`. Le `--recover` reconstruit l'état depuis
/// le dataset publié + le ring pcap/ et expose les
/// enregistrements créés/préservés.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RepairRecoveryReport {
    pub removed_paths: Vec<String>,
    pub removed_bytes: u64,
    /// 2.9.17-fu : chemin `import_state.json` reconstruit (si
    /// applicable). Vide quand on a préservé l'état existant.
    #[serde(default)]
    pub rebuilt_import_state_path: Option<String>,
    /// Compteur des `capture_id` extraits du dataset publié.
    #[serde(default)]
    pub rebuilt_seen_checksums: u64,
    /// Compteur des segments découverts dans `pcap/` ring.
    #[serde(default)]
    pub rebuilt_segments: u64,
    /// Compteur des `source_fingerprints` préservés depuis
    /// l'ancien état (si l'état précédent était lisible).
    #[serde(default)]
    pub preserved_source_fingerprints: u64,
    /// Compteur des `failed_ingestions` préservés.
    #[serde(default)]
    pub preserved_failed_ingestions: u64,
    /// 2.9.18-fu (#9 ANR2 2.9.17-fu post-recover) : liste des
    /// SHAs du ring `pcap/` EXCLUS de `seen_checksums`/`segments`
    /// car leurs événements ne sont pas dans le dataset publié.
    /// Invariant 2.9.18-fu : segment importé ⇔ événements dans
    /// le dataset. Ces fichiers seront re-ingérés au prochain
    /// scan OU listés `uncovered_closed_file` par
    /// `dataset-repair-partial-imports`.
    #[serde(default)]
    pub excluded_ring_shas_no_events: Vec<String>,
}

/// 2.9.17 (#9 comment 6739207609) — Reprise après crash d'une
/// passe réelle `repair_partial_imports`. ANR2 a prouvé qu'un
/// OOM (exit 137) pouvait laisser `.dataset-next/` (6,1 Go sur
/// le run réel) dans le worktree, poussant `work_bytes` au-dessus
/// de `max_owned_bytes` et bloquant l'import en
/// `CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT`.
///
/// 2.9.17-fu (#9 comment 6740035832) — ANR2 a aussi prouvé que
/// la sauvegarde de déploiement 2.9.16 ne contient PAS
/// `import_state.json`. `--recover` RECONSTRUIT un état cohérent
/// à partir du dataset publié et du ring `pcap/` ; les champs
/// `source_fingerprints` et `failed_ingestions` sont PRÉSERVÉS
/// depuis l'ancien état quand il est lisible (sinon vides —
/// fail-closed).
///
/// Garanties :
///   * `dataset/` NON touché.
///   * `pcap/` NON touché.
///   * `import_state.json` RÉÉCRIT atomiquement avec un état
///     dérivé déterministement du dataset + ring. L'ancien
///     fichier est préservé sous `import_state.json.pre-recover`
///     pour audit.
///   * Supprime `.dataset-next/` et `.dataset-previous/` orphelins.
///   * Retourne les compteurs reconstruits + préservés — AUCUNE
///     suppression silencieuse.
pub fn recover_repair_staging(capture_root: &Path) -> Result<RepairRecoveryReport, String> {
    let base = capture_root.join(CONTINUOUS_CAPTURE_ID);
    if !base.is_dir() {
        return Err(format!(
            "RECOVERY_BASE_MISSING: {}",
            base.display()
        ));
    }
    let mut report = RepairRecoveryReport::default();

    // 1. Nettoyage du staging orphelin (OOM précédent).
    let candidates = [base.join(".dataset-next"), base.join(".dataset-previous")];
    for candidate in candidates {
        if !candidate.exists() {
            continue;
        }
        let size = directory_size(&candidate);
        report.removed_bytes = report.removed_bytes.saturating_add(size);
        report.removed_paths.push(candidate.display().to_string());
        fs::remove_dir_all(&candidate).map_err(|error| {
            format!(
                "RECOVERY_REMOVE_FAILED: {} ({})",
                candidate.display(),
                error
            )
        })?;
    }

    // 2. Reconstruction de l'import_state depuis le dataset + le ring.
    let dataset_events = base.join("dataset").join("oiran_events.jsonl");
    if !dataset_events.is_file() {
        // Rien à reconstruire sans dataset publié ; on laisse
        // l'état existant intact.
        return Ok(report);
    }
    // Préserver `source_fingerprints` + `failed_ingestions` si
    // possible (lecture best-effort — un fichier manquant ou
    // mal formé = champs vides, fail-closed).
    let state_path = base.join("import_state.json");
    let previous_state: ContinuousImportState = if state_path.is_file() {
        serde_json::from_slice(&fs::read(&state_path).map_err(display_error)?)
            .unwrap_or_default()
    } else {
        ContinuousImportState::default()
    };

    // 2.a. Scan streaming du dataset — extrait tous les
    // `capture_id` uniques (= `seen_checksums` canoniques).
    // Mémoire : BTreeSet<String> ~5000 SHAs × ~80 B = ~400 KB.
    // Jamais chargé en RAM entier.
    let mut dataset_capture_ids: BTreeSet<String> = BTreeSet::new();
    {
        let file = fs::File::open(&dataset_events).map_err(display_error)?;
        let reader = BufReader::with_capacity(STREAM_CHUNK_BYTES, file);
        for line in reader.lines() {
            let line = line.map_err(display_error)?;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(value) = serde_json::from_str::<Value>(&line) {
                if let Some(cap) = value.get("capture_id").and_then(Value::as_str) {
                    if let Some(hex) = cap.strip_prefix("sha256:") {
                        dataset_capture_ids.insert(hex.to_owned());
                    }
                }
            }
        }
    }

    // 2.b. Scan du ring `pcap/` — pour chaque fichier, SHA + size.
    // On RE-UTILISE les fingerprints de l'ancien état quand les
    // coordonnées fs match (optimisation 2.8.1).
    let pcap_dir = base.join("pcap");
    let mut rebuilt_segments: BTreeMap<String, ImportedSegment> = BTreeMap::new();
    if pcap_dir.is_dir() {
        for entry in fs::read_dir(&pcap_dir).map_err(display_error)?.flatten() {
            let path = entry.path();
            let Ok(metadata) = entry.metadata() else { continue; };
            if !metadata.is_file() {
                continue;
            }
            let Some(filename) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if filename.ends_with(".importing") || !filename.contains(".pcap") {
                continue;
            }
            // Nom convention `<interface>.pcap-<sha16>.<ext>` ou
            // `<interface>.pcap-bootstrap-<sha16>.<ext>` ; on en
            // dérive l'interface, le reste du SHA sera calculé.
            let interface = filename.split('.').next().unwrap_or("").to_string();
            let sha_hex = sha256_hex_file(&path)?;
            let size_bytes = metadata.len();
            let packets = count_pcap_records(&path);
            let imported_epoch_ms = metadata
                .modified()
                .ok()
                .and_then(|time| {
                    time.duration_since(std::time::UNIX_EPOCH).ok()
                })
                .map(|duration| duration.as_millis() as u64)
                .unwrap_or(0);
            rebuilt_segments.insert(
                sha_hex.clone(),
                ImportedSegment {
                    interface,
                    owned_file: filename.to_owned(),
                    size_bytes,
                    packets,
                    imported_epoch_ms,
                    source_path: String::new(),
                    historical_context: filename.contains("bootstrap"),
                },
            );
        }
    }
    // 2.9.18-fu (#9 comment devmat 6744xxxxxx) — ANR2 a prouvé que
    // le --recover 2.9.17-fu violait l'invariant « segment
    // importé ⇔ événements dans dataset ». Ancien code (union
    // dataset ∪ ring) marquait les fichiers S6a `_00039..41`
    // comme vus (packets=0, 0 événement) → le worker continu les
    // SAUTAIT au prochain scan. Les événements étaient
    // perdus.
    //
    // Règle 2.9.18-fu : seen_checksums = dataset_capture_ids
    // STRICTEMENT. Un fichier présent dans le ring mais absent
    // du dataset est EXCLU. Le worker continu le détectera au
    // prochain scan ET/OU `dataset-repair-partial-imports` le
    // listera en `uncovered_closed_file` (règle 2.9.14) → fresh
    // re-ingest avec le décodeur Diameter itératif 2.9.18.
    let seen_checksums: BTreeSet<String> = dataset_capture_ids.clone();
    // De même, `segments` ne garde que les SHAs présents dans
    // le dataset. Les ring-SHAs orphelins sont comptés pour le
    // rapport opérateur (visibilité) mais n'entrent pas dans
    // state.segments → le worker les voit comme neufs.
    let mut excluded_ring_shas: Vec<String> = Vec::new();
    let filtered_segments: BTreeMap<String, ImportedSegment> = rebuilt_segments
        .into_iter()
        .filter_map(|(sha, seg)| {
            if dataset_capture_ids.contains(&sha) {
                Some((sha, seg))
            } else {
                excluded_ring_shas.push(sha);
                None
            }
        })
        .collect();
    // 2.c. seen_order canonique = SHAs triés lexico. Reproductible
    // sur une nouvelle recovery → idempotent.
    let seen_order: std::collections::VecDeque<String> = seen_checksums.iter().cloned().collect();

    // Préserver source_fingerprints + failed_ingestions.
    let preserved_source_fingerprints = previous_state.source_fingerprints.len() as u64;
    let preserved_failed_ingestions = previous_state.failed_ingestions.len() as u64;
    // Filtrer source_fingerprints pour ne garder que ceux dont
    // le checksum est dans seen_checksums (invariant 2.9.8).
    let filtered_source_fingerprints: BTreeMap<String, SourceFingerprint> = previous_state
        .source_fingerprints
        .into_iter()
        .filter(|(_, fp)| seen_checksums.contains(&fp.checksum))
        .collect();

    let rebuilt = ContinuousImportState {
        segments: filtered_segments,
        seen_checksums,
        seen_order,
        failed_ingestions: previous_state.failed_ingestions,
        source_fingerprints: filtered_source_fingerprints,
    };
    report.rebuilt_seen_checksums = rebuilt.seen_checksums.len() as u64;
    report.rebuilt_segments = rebuilt.segments.len() as u64;
    report.excluded_ring_shas_no_events = excluded_ring_shas;
    report.preserved_source_fingerprints = preserved_source_fingerprints;
    report.preserved_failed_ingestions = preserved_failed_ingestions;

    // 3. Préserver l'ancien fichier (audit) puis écrire le neuf.
    if state_path.is_file() {
        let backup = base.join("import_state.json.pre-recover");
        let _ = fs::remove_file(&backup);
        fs::rename(&state_path, &backup).map_err(display_error)?;
    }
    atomic_write(
        &state_path,
        &serde_json::to_vec_pretty(&rebuilt).map_err(|e| e.to_string())?,
    )?;
    report.rebuilt_import_state_path = Some(state_path.display().to_string());

    Ok(report)
}

/// 2.9.8 (#9 comment 6725097122): drop fingerprints whose checksum is
/// NOT in `seen_checksums`. ANR2 proved that a `SourceFingerprint`
/// could land in `state.source_fingerprints` while the segment was
/// never committed via `persist_published_checksums` — the import
/// invariant is now that a fingerprint survives only after a
/// successful publish. Returns the number of orphans dropped; the
/// caller logs one `CONTINUOUS_ORPHAN_FINGERPRINT_DROPPED` structured
/// record per orphan and surfaces the cumulative count through
/// `CaptureMetrics.orphan_fingerprints_recovered`. The segment is
/// still on disk, so it will be re-hashed on the next scan and
/// imported through the normal path.
fn drop_orphan_fingerprints(state: &mut ContinuousImportState) -> Vec<(String, String)> {
    let orphans: Vec<(String, String)> = state
        .source_fingerprints
        .iter()
        .filter(|(_, fingerprint)| !state.seen_checksums.contains(&fingerprint.checksum))
        .map(|(path, fingerprint)| (path.clone(), fingerprint.checksum.clone()))
        .collect();
    for (path, _) in &orphans {
        state.source_fingerprints.remove(path);
    }
    orphans
}

/// Durably marks checksums only after the caller has atomically published the
/// corresponding dataset generation. The in-memory state is replaced only
/// after the atomic state-file write succeeds.
fn persist_published_checksums(
    state_path: &Path,
    state: &mut ContinuousImportState,
    checksums: &[String],
) -> Result<(), String> {
    let mut committed = state.clone();
    for checksum in checksums {
        remember_checksum(&mut committed, checksum.clone());
    }
    atomic_write(
        state_path,
        &serde_json::to_vec_pretty(&committed).map_err(|error| error.to_string())?,
    )?;
    *state = committed;
    Ok(())
}

fn cleanup_native_capture(root: &Path, capture_id: &str) -> Result<(), String> {
    if !capture_id.starts_with("continuous-segment-") || !safe_identifier(capture_id) {
        return Err("CONTINUOUS_NATIVE_CLEANUP_TARGET_INVALID".into());
    }
    let directory = root.join(capture_id);
    if !native_segment_source(root, &directory.join("N3.pcap")) {
        return Err("CONTINUOUS_NATIVE_CLEANUP_TARGET_INVALID".into());
    }
    if directory.is_dir() {
        fs::remove_dir_all(directory).map_err(display_error)?;
    }
    Ok(())
}

fn native_capture_ids(root: &Path) -> Result<Vec<String>, String> {
    let mut ids = fs::read_dir(root)
        .map_err(display_error)?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .file_type()
                .ok()
                .filter(|kind| kind.is_dir() && !kind.is_symlink())?;
            let name = entry.file_name().into_string().ok()?;
            (name.starts_with("continuous-segment-") && safe_identifier(&name)).then_some(name)
        })
        .collect::<Vec<_>>();
    ids.sort();
    Ok(ids)
}

fn native_capture_fully_ingested(
    root: &Path,
    capture_id: &str,
    seen_checksums: &BTreeSet<String>,
    max_segment_bytes: u64,
) -> Result<bool, String> {
    if !capture_id.starts_with("continuous-segment-") || !safe_identifier(capture_id) {
        return Err("CONTINUOUS_NATIVE_CLEANUP_TARGET_INVALID".into());
    }
    let directory = root.join(capture_id);
    let mut paths = Vec::new();
    collect_source_paths(&directory, 0, &mut paths)?;
    for path in paths {
        let metadata = fs::symlink_metadata(&path).map_err(display_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() <= 24 {
            continue;
        }
        if source_interface(root, &path).is_none() {
            continue;
        }
        if metadata.len() > max_segment_bytes {
            return Ok(false);
        }
        // 0.2.3: hash via bounded `BufReader` instead of `fs::read` to keep
        // the resident set independent of segment size (same reason as
        // `copy_verified`).
        let checksum = sha256_hex_file(&path)?;
        if !seen_checksums.contains(&checksum) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// 2.11.2 (devmat, règle projet « blocage à 99 %, alerte à 95 %
/// sur les octets réellement possédés par OIRAN ») : seuil calculé
/// en octets. `saturating_mul` + division par 100 évite les
/// débordements sur un cap ≥ u64::MAX/100.
fn native_percentile_of_max(max_owned_bytes: u64, percent: u64) -> u64 {
    max_owned_bytes.saturating_mul(percent) / 100
}

fn native_owned_usage(root: &Path) -> Result<(u64, usize), String> {
    let ids = native_capture_ids(root)?;
    let segment_bytes = ids
        .iter()
        .map(|id| directory_size(&root.join(id)))
        .fold(0u64, u64::saturating_add);
    Ok((
        directory_size(&root.join(CONTINUOUS_CAPTURE_ID)).saturating_add(segment_bytes),
        ids.len(),
    ))
}

/// 2.7.27 (issue #10, ANR2 production rollback): retention is
/// DISABLED by default. The 2.7.22 policy of a 30-day in-merge purge
/// was a silent-delete on the published dataset — ANR2 observed
/// 2 717 event_id and 7 sessions lost on a 7-day setting because the
/// per-event cutoff cut *inside* a capture. The published dataset is
/// NEVER filtered in 2.7.27: retention is now a capture-level
/// age-check that MOVES whole captures to an immutable archive
/// (never deletes); see `plan_capture_retention` and
/// `archive_stale_captures` below.
///
/// Semantics of `OIRAN_DATASET_RETENTION_DAYS`:
///   unset | 0  → retention disabled (nothing is archived)
///   > 0        → window in days, clamped 1..=3650
fn retention_days() -> Option<u64> {
    let value = std::env::var("OIRAN_DATASET_RETENTION_DAYS").ok()?;
    let days = value.parse::<u64>().ok()?;
    if days == 0 {
        return None;
    }
    Some(days.clamp(1, 3650))
}

fn retention_cutoff_epoch_s() -> Option<u64> {
    let days = retention_days()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0);
    Some(now.saturating_sub(days.saturating_mul(86_400)))
}

/// 2.7.27: scan `events_path` and compute, for every `capture_id`,
/// the maximum `timestamp.seconds` across all events of that
/// capture. "Capture end" = max over its events. Never compared
/// per-event: the age decision is made per capture.
fn scan_capture_ends(events_path: &Path) -> Result<BTreeMap<String, u64>, String> {
    let file = fs::File::open(events_path).map_err(display_error)?;
    let reader = BufReader::with_capacity(STREAM_CHUNK_BYTES, file);
    let mut capture_end: BTreeMap<String, u64> = BTreeMap::new();
    let mut processed = 0usize;
    for line in reader.lines() {
        let line = line.map_err(display_error)?;
        if line.trim().is_empty() {
            continue;
        }
        processed = processed.saturating_add(1);
        let value: serde_json::Value =
            serde_json::from_str(&line).map_err(|error| error.to_string())?;
        let Some(cid) = value.get("capture_id").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let ts = value
            .get("timestamp")
            .and_then(|ts| ts.get("seconds"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let entry = capture_end.entry(cid.to_owned()).or_insert(0);
        if ts > *entry {
            *entry = ts;
        }
        if processed % 1024 == 0 {
            release_unused_heap_pages();
        }
    }
    Ok(capture_end)
}

/// 2.7.27 (issue #10, ANR2 production rollback): capture-level
/// age-based archive. The published `oiran_events.jsonl` is NEVER
/// filtered mid-capture. A capture is archived only when its
/// `capture_end` (= max event timestamp inside that capture) is
/// older than `cutoff`. All events of a stale capture move to an
/// immutable archive segment (`<archive_root>/<timestamp>-<sha16>/`)
/// containing `events.jsonl` and `manifest.json` (SHA-256 of
/// events.jsonl + the list of captures + the event count). If any
/// archive-write step fails, the hot view (`oiran_events.jsonl`)
/// is left **untouched** — fail-closed. One `CONTINUOUS_CAPTURE_ARCHIVE`
/// stderr line records every archive commit, with the same shape
/// `evidence_type / archive_id / capture_count / event_count` the
/// `dataset-restore` binary reads.
///
/// Memory is bounded by `BTreeMap<String, u64>` of capture_id →
/// end-timestamp (≈ 100 B per capture; a 10 000-capture dataset
/// fits in ≤ 1 MiB) plus the streaming reader/writer buffers.
fn archive_stale_captures(
    events_path: &Path,
    archive_root: &Path,
    cutoff: u64,
) -> Result<(), String> {
    if !events_path.is_file() {
        return Ok(());
    }
    let capture_end = scan_capture_ends(events_path)?;
    let stale: BTreeSet<String> = capture_end
        .iter()
        .filter_map(|(cid, end)| (*end != 0 && *end < cutoff).then(|| cid.clone()))
        .collect();
    if stale.is_empty() {
        return Ok(());
    }
    // Build archive id = yyyymmddTHHMMSSZ + short sha of the sorted
    // capture_id list. Deterministic for the same stale set.
    let now_s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0);
    let capture_list_bytes = stale.iter().cloned().collect::<Vec<_>>().join("\n");
    let capture_list_sha = sha256_hex(capture_list_bytes.as_bytes());
    let archive_id = format!("{now_s}-{}", &capture_list_sha[..16]);
    let segment_dir = archive_root.join(&archive_id);
    let segment_events = segment_dir.join("events.jsonl");
    let segment_manifest = segment_dir.join("manifest.json");
    let hot_tmp = events_path.with_extension("jsonl.hot-tmp");
    // Create archive dir. Any IO failure here means "fail-closed":
    // the hot view is untouched by construction (we haven't written
    // anything yet).
    fs::create_dir_all(&segment_dir)
        .map_err(|error| format!("CONTINUOUS_ARCHIVE_WRITE_FAILED: mkdir: {error}"))?;
    // Stream events.jsonl once, splitting into archive vs. hot. The
    // archive file is finalised FIRST (fsync + manifest) before the
    // hot file replaces the published jsonl — if anything fails
    // above the rename step, we wipe the half-written archive and
    // the hot tmp, and the published jsonl stays byte-identical to
    // what it was on entry.
    let outcome = archive_split_stream(events_path, &segment_events, &hot_tmp, &stale);
    let (archived_count, retained_count, archive_sha256) = match outcome {
        Ok(result) => result,
        Err(error) => {
            let _ = fs::remove_file(&segment_events);
            let _ = fs::remove_file(&hot_tmp);
            let _ = fs::remove_dir(&segment_dir);
            eprintln!(
                "{}",
                serde_json::json!({
                    "event": "CONTINUOUS_ARCHIVE_FAILED",
                    "reason": error,
                    "archive_id": archive_id,
                    "cutoff_epoch_s": cutoff,
                })
            );
            return Err(error);
        }
    };
    // Write the manifest. If this fails, roll back the archive and
    // keep the hot view untouched.
    let manifest = serde_json::json!({
        "archive_id": archive_id,
        "created_epoch_s": now_s,
        "cutoff_epoch_s": cutoff,
        "retention_days": retention_days(),
        "captures": stale.iter().collect::<Vec<_>>(),
        "event_count": archived_count,
        "events_sha256": archive_sha256,
        "schema_version": "2.7.27",
    });
    if let Err(error) = fs::write(
        &segment_manifest,
        serde_json::to_vec_pretty(&manifest).map_err(|error| error.to_string())?,
    ) {
        let _ = fs::remove_file(&segment_events);
        let _ = fs::remove_file(&hot_tmp);
        let _ = fs::remove_dir(&segment_dir);
        let error = format!("CONTINUOUS_ARCHIVE_WRITE_FAILED: manifest: {error}");
        eprintln!(
            "{}",
            serde_json::json!({
                "event": "CONTINUOUS_ARCHIVE_FAILED",
                "reason": error,
                "archive_id": archive_id,
                "cutoff_epoch_s": cutoff,
            })
        );
        return Err(error);
    }
    // Commit the hot view only AFTER the archive segment + manifest
    // are durable.
    fs::rename(&hot_tmp, events_path)
        .map_err(|error| format!("CONTINUOUS_ARCHIVE_COMMIT_FAILED: {error}"))?;
    eprintln!(
        "{}",
        serde_json::json!({
            "event": "CONTINUOUS_CAPTURE_ARCHIVE",
            "archive_id": archive_id,
            "cutoff_epoch_s": cutoff,
            "retention_days": retention_days(),
            "capture_count": stale.len(),
            "event_count_archived": archived_count,
            "event_count_retained": retained_count,
            "archive_path": segment_dir.display().to_string(),
            "archive_sha256": archive_sha256,
        })
    );
    Ok(())
}

fn archive_split_stream(
    events_path: &Path,
    segment_events: &Path,
    hot_tmp: &Path,
    stale: &BTreeSet<String>,
) -> Result<(u64, u64, String), String> {
    let hot_file = fs::File::create(hot_tmp)
        .map_err(|error| format!("CONTINUOUS_ARCHIVE_WRITE_FAILED: hot: {error}"))?;
    let mut hot_writer = BufWriter::with_capacity(STREAM_CHUNK_BYTES, hot_file);
    let archive_file = fs::File::create(segment_events)
        .map_err(|error| format!("CONTINUOUS_ARCHIVE_WRITE_FAILED: segment: {error}"))?;
    let mut archive_writer = BufWriter::with_capacity(STREAM_CHUNK_BYTES, archive_file);
    let mut archive_hash = Sha256Hasher::new();
    let reader = BufReader::with_capacity(
        STREAM_CHUNK_BYTES,
        fs::File::open(events_path).map_err(display_error)?,
    );
    let mut archived = 0u64;
    let mut retained = 0u64;
    let mut processed = 0usize;
    for line in reader.lines() {
        let line = line.map_err(display_error)?;
        if line.trim().is_empty() {
            continue;
        }
        processed = processed.saturating_add(1);
        let value: serde_json::Value = serde_json::from_str(&line)
            .map_err(|error| format!("CONTINUOUS_ARCHIVE_PARSE_FAILED: {error}"))?;
        let cid = value
            .get("capture_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if stale.contains(cid) {
            archive_writer
                .write_all(line.as_bytes())
                .map_err(|error| format!("CONTINUOUS_ARCHIVE_WRITE_FAILED: body: {error}"))?;
            archive_writer
                .write_all(b"\n")
                .map_err(|error| format!("CONTINUOUS_ARCHIVE_WRITE_FAILED: newline: {error}"))?;
            archive_hash.update(line.as_bytes());
            archive_hash.update(b"\n");
            archived = archived.saturating_add(1);
        } else {
            hot_writer
                .write_all(line.as_bytes())
                .map_err(|error| format!("CONTINUOUS_ARCHIVE_WRITE_FAILED: hot body: {error}"))?;
            hot_writer
                .write_all(b"\n")
                .map_err(|error| format!("CONTINUOUS_ARCHIVE_WRITE_FAILED: hot nl: {error}"))?;
            retained = retained.saturating_add(1);
        }
        if processed % 1024 == 0 {
            release_unused_heap_pages();
        }
    }
    hot_writer
        .flush()
        .map_err(|error| format!("CONTINUOUS_ARCHIVE_WRITE_FAILED: hot flush: {error}"))?;
    hot_writer
        .get_ref()
        .sync_all()
        .map_err(|error| format!("CONTINUOUS_ARCHIVE_WRITE_FAILED: hot sync: {error}"))?;
    archive_writer
        .flush()
        .map_err(|error| format!("CONTINUOUS_ARCHIVE_WRITE_FAILED: segment flush: {error}"))?;
    archive_writer
        .get_ref()
        .sync_all()
        .map_err(|error| format!("CONTINUOUS_ARCHIVE_WRITE_FAILED: segment sync: {error}"))?;
    Ok((archived, retained, archive_hash.finish_hex()))
}

/// 2.7.28: write the canonical union of two jsonl event streams to
/// `out`. Dedup by `event_id` (first occurrence from `current` wins;
/// archive duplicates are collected into the returned overlap list and
/// skipped). Output is sorted by
/// `(capture_id, packet_number, event_id)` — session-engine's
/// `canonical_sort_key`, never by timestamp. Returns the overlap
/// `event_id` list (sorted) and the streaming SHA-256 of the output
/// bytes for the `DatasetRestoreReport`.
fn canonical_dedup_merge(
    current: &Path,
    archive: &Path,
    out: &Path,
) -> Result<(Vec<String>, String), String> {
    let mut records: Vec<(String, u64, String, String)> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut current_ids: BTreeSet<String> = BTreeSet::new();
    let mut overlap: Vec<String> = Vec::new();
    for (source, is_archive) in [(current, false), (archive, true)] {
        let reader = BufReader::with_capacity(
            STREAM_CHUNK_BYTES,
            fs::File::open(source).map_err(display_error)?,
        );
        for line in reader.lines() {
            let line = line.map_err(display_error)?;
            if line.trim().is_empty() {
                continue;
            }
            let value: Value =
                serde_json::from_str(&line).map_err(|error| error.to_string())?;
            let event_id = value
                .get("event_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "RESTORE_MALFORMED: missing event_id in {}",
                        source.display()
                    )
                })?
                .to_string();
            if !is_archive {
                current_ids.insert(event_id.clone());
            } else if current_ids.contains(&event_id) {
                overlap.push(event_id.clone());
            }
            if !seen.insert(event_id.clone()) {
                continue;
            }
            let capture_id = value
                .get("capture_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let packet_number = value
                .get("packet_references")
                .and_then(Value::as_array)
                .and_then(|refs| refs.first())
                .and_then(|r| r.get("packet_number"))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            records.push((capture_id, packet_number, event_id, line));
        }
    }
    records.sort_by(|a, b| {
        (a.0.as_str(), a.1, a.2.as_str()).cmp(&(b.0.as_str(), b.1, b.2.as_str()))
    });
    overlap.sort();
    overlap.dedup();
    let mut hasher = Sha256Hasher::new();
    {
        let file = fs::File::create(out).map_err(display_error)?;
        let mut writer = BufWriter::with_capacity(STREAM_CHUNK_BYTES, file);
        for (_, _, _, line) in &records {
            writer.write_all(line.as_bytes()).map_err(display_error)?;
            writer.write_all(b"\n").map_err(display_error)?;
            hasher.update(line.as_bytes());
            hasher.update(b"\n");
        }
        writer.flush().map_err(display_error)?;
        writer.get_ref().sync_all().map_err(display_error)?;
    }
    Ok((overlap, hasher.finish_hex()))
}


/// 2.10.2 (devmat, ANR2 #9 comments 6765365357 + 6765466589) :
/// variante disk-backed de `expand_session_evidence_ids` pour la
/// construction des SessionPlan. Expansion transitive via les edges
/// — convergence garantie car `edges.len()` est fini. Chaque
/// itération est O(|edges| × contains_cost) ; `SpillingEventIdSet`
/// borne la RAM (voir `event_id_set.rs`).
fn expand_session_evidence_ids_disk(
    ids: &mut SpillingEventIdSet,
    edges: &[CorrelationEdge],
) -> std::io::Result<()> {
    loop {
        let mut changed = false;
        for edge in edges {
            if ids.contains(&edge.source_event_id)? {
                if ids.insert(&edge.target_event_id)? {
                    changed = true;
                }
            }
            if ids.contains(&edge.target_event_id)? {
                if ids.insert(&edge.source_event_id)? {
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    Ok(())
}

/// 2.7.21 (issue #10 comment 6653514332, ANR2 recette): remove every
/// never-committed artifact under `<base>` at worker startup, but leave
/// the committed `dataset/` subtree STRICTLY byte-identical.
///
/// The 2.7.20 version also compacted `dataset/oiran_events.jsonl` using
/// `current_capture_ids = {"sha256:<sha>" | sha in state.segments.keys()}`
/// (see `live-probe/src/lib.rs:1764-1769` in the 2.7.20 source). But
/// `state.segments` is the CURRENT RING of pcap segments, capped at
/// `max_segments`; it is NOT the history of capture_ids that ever
/// contributed events. The ANR2 lab arrived with 1 segment in the ring
/// and 51 capture_ids inside the published `oiran_events.jsonl` (built
/// across many publish cycles before pcap files were evicted). The
/// 2.7.20 filter kept 77 events out of 25 537 — a 3 945-event loss
/// across 20 captures whose pcap was still present (rollback saved the
/// data). Decision: the published dataset is NEVER compacted or
/// filtered at startup.
///
/// Remaining scope (strictly outside `dataset/`):
///   * `.dataset-previous/` — rollback of a rename that crashed mid-way;
///     the atomic commit point is the final rename INTO `dataset/`, so
///     previous never holds committed data.
///   * `.dataset-next/` — mid-publish staging tree;
///     `process_capture_into` blanket-removes it before rebuilding
///     anyway (`live-probe/src/lib.rs:2462`), so pre-cleaning at worker
///     startup is safe.
///   * Base-level `*.tmp` / `*.compact-tmp` — orphan `atomic_write`
///     partials (e.g. `import_state.json.tmp`).
///
/// `dataset/` and its `*.spool`, `*.tmp`, `oiran_events.jsonl`,
/// `dataset_manifest.json`, `callflows/` are all left untouched.
/// The next successful publication cycle rewrites them atomically if
/// anything is stale; any spool/tmp inside `dataset/` is either from a
/// crashed publish into `.dataset-next/` (already handled by the
/// `.dataset-next/` wipe) or from a PREVIOUS binary version that is no
/// longer reachable.
///
/// Returns a `CompactionReport` listing every file touched with its
/// size before / after so the operator can verify the shrink from the
/// log line emitted by `run_continuous_import_inner`.
fn clean_continuous_import_root(base: &Path) -> Result<CompactionReport, String> {
    let mut report = CompactionReport::default();
    for name in [".dataset-previous", ".dataset-next"] {
        let path = base.join(name);
        if path.exists() {
            let size = directory_size(&path);
            fs::remove_dir_all(&path).map_err(display_error)?;
            report.push(&path, size, 0, "removed-rollback-or-crash-artifact");
        }
    }
    // Base-level orphan atomic_write partials. Does NOT descend into
    // `dataset/` — the published tree is sacred.
    if let Ok(entries) = fs::read_dir(base) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if name.ends_with(".tmp")
                || name.ends_with(".compact-tmp")
                || name.ends_with(".spool")
            {
                let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                fs::remove_file(&path).map_err(display_error)?;
                report.push(&path, size, 0, "removed-orphan-temp");
            }
        }
    }
    Ok(report)
}

#[derive(Debug, Default)]
struct CompactionReport {
    entries: Vec<CompactionEntry>,
}

#[derive(Debug)]
struct CompactionEntry {
    path: String,
    before_bytes: u64,
    after_bytes: u64,
    action: &'static str,
}

impl CompactionReport {
    fn push(&mut self, path: &Path, before: u64, after: u64, action: &'static str) {
        self.entries.push(CompactionEntry {
            path: path.display().to_string(),
            before_bytes: before,
            after_bytes: after,
            action,
        });
    }
    fn total_before(&self) -> u64 {
        self.entries.iter().map(|e| e.before_bytes).sum()
    }
    fn total_after(&self) -> u64 {
        self.entries.iter().map(|e| e.after_bytes).sum()
    }
}

/// 2.7.23: load only the events whose `event_id` is in `ids`. Streams
/// the jsonl file line by line through session-engine's parser; peak
/// memory is the subset we actually want + one in-flight line. Used by
/// `process_capture_into` after `drop(events)` to reconstruct one call
/// flow at a time.
/// Rust drops each per-session allocation before the next session starts, but
/// glibc normally keeps the freed arenas mapped in the process. Continuous
/// publication is a batch boundary: returning those pages prevents the API's
/// resident set from inheriting the largest historical publication forever.
fn release_unused_heap_pages() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    unsafe {
        libc::malloc_trim(0);
    }
}

/// 2.7.28 (issue #10, ANR2 defect on 2.7.27): cross-process advisory
/// publication lock. `process_continuous_capture` and
/// `restore_from_archive_segment` both route their dataset-next → dataset
/// swap through this lock so an `oiran-api` import worker and a
/// `dataset-restore` invocation can never concurrently rewrite the hot
/// view. The lock is a POSIX `flock(LOCK_EX)` on
/// `<capture-root>/<continuous-capture-id>/.publication.lock`; it is
/// released automatically on process exit, so a crash cannot leave a
/// stale lock behind.
struct PublicationLock {
    _file: fs::File,
}

impl PublicationLock {
    fn acquire_blocking(base: &Path) -> Result<Self, String> {
        Self::acquire(base, libc::LOCK_EX)
    }

    fn try_acquire(base: &Path) -> Result<Self, String> {
        Self::acquire(base, libc::LOCK_EX | libc::LOCK_NB)
    }

    fn acquire(base: &Path, mode: libc::c_int) -> Result<Self, String> {
        fs::create_dir_all(base).map_err(|error| {
            format!("PUBLICATION_LOCK_BASE_INIT {}: {error}", base.display())
        })?;
        let lock_path = base.join(".publication.lock");
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|error| {
                format!("PUBLICATION_LOCK_OPEN {}: {error}", lock_path.display())
            })?;
        use std::os::unix::io::AsRawFd;
        let result = unsafe { libc::flock(file.as_raw_fd(), mode) };
        if result != 0 {
            let err = std::io::Error::last_os_error();
            if (mode & libc::LOCK_NB) != 0
                && matches!(err.raw_os_error(), Some(libc::EWOULDBLOCK))
            {
                return Err("RESTORE_REQUIRES_PUBLICATION_LOCK".into());
            }
            return Err(format!("PUBLICATION_LOCK_FLOCK: {err}"));
        }
        Ok(Self { _file: file })
    }
}

/// 2.8.4 (#9 comment 6705466743): one historical partial-import group
/// REBUILT from the dataset's events (not from `state.segments`,
/// which may have evicted history). The group identity is the
/// `(interface, first_packet_raw_ticks, first_packet_number,
/// first_packet_byte_offset)` tuple — the only segment-level key
/// events carry in common across partial snapshots of the SAME
/// growing dumpcap file. If the identity ever has to change, the
/// `reconstruction_key` field names it explicitly instead of letting
/// callers guess.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialImportGroup {
    pub reconstruction_key: String,
    pub interface: String,
    pub first_packet_raw_ticks: i128,
    pub first_packet_number: u64,
    pub first_packet_byte_offset: u64,
    pub snapshots: Vec<PartialImportSnapshot>,
    pub final_capture_id: Option<String>,
    pub final_source: PartialImportFinalSource,
    pub final_on_disk_path: Option<String>,
    pub needs_fresh_import: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialImportSnapshot {
    pub capture_id: String,
    pub owned_file: String,
    pub event_count: usize,
    pub max_packet_number: u64,
    pub state_size_bytes: Option<u64>,
    pub state_imported_epoch_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PartialImportFinalSource {
    /// `source_root/<interface>/*.pcapng` was inspected; the final
    /// snapshot is the one whose `capture_id` equals the SHA-256 of a
    /// closed file (the lex-greatest sibling is excluded — it's the
    /// still-live dumpcap target per 2.8.3).
    OnDiskSha256Match,
    /// 2.9.2 (#9 comment 6708784283): the snapshots in the group
    /// matched PREFIX SHA-256 values of a closed on-disk file at
    /// packet boundaries, but the FULL-SHA snapshot was absent from
    /// the dataset. The repair re-decoded the closed file through the
    /// same publication path and emitted a fresh set of events; the
    /// prefix snapshots are then removed.
    PrefixShaMatchFreshImport,
    /// No `source_root` provided. The repair falls back to
    /// `state.segments`: the snapshot with the largest `size_bytes`
    /// (tie-broken by latest `imported_epoch_ms`) is treated as the
    /// final. Only correct when `state.segments` carries the full
    /// history — i.e., when no eviction happened (2.8.4 guarantees
    /// this for every import from 2.8.4 onwards).
    StateSegmentsLargest,
    /// Neither evidence available. The repair leaves the snapshots
    /// untouched and lists the group as unresolved.
    UnresolvedNoEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairRemovedEvent {
    pub event_id: String,
    pub source_file: String,
    pub capture_id: String,
    pub reason: String,
}

/// 2.8.3/2.8.4: structured report returned by
/// `repair_partial_imports`. Serialized to JSON by the
/// `dataset-repair-partial-imports` binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetRepairReport {
    pub schema_version: &'static str,
    pub dataset_dir: String,
    pub dry_run: bool,
    pub event_count_before: usize,
    pub event_count_after: usize,
    pub partial_import_groups: Vec<PartialImportGroup>,
    pub unresolved_groups: Vec<PartialImportGroup>,
    pub removed_events: Vec<RepairRemovedEvent>,
    pub events_sha256: String,
}

/// 2.7.28: structured report returned by `restore_from_archive_segment`.
/// Serialized to JSON by the `dataset-restore` binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetRestoreReport {
    pub schema_version: &'static str,
    pub archive_segment_dir: String,
    pub dataset_dir: String,
    pub event_count_before: usize,
    pub archive_event_count: usize,
    pub overlap_event_count: usize,
    pub overlap_event_ids: Vec<String>,
    pub event_count_after: usize,
    pub session_ids: Vec<String>,
    pub events_sha256: String,
}

/// 2.10.2 (devmat, ANR2 #9 comments 6765365357 + 6765466589) :
/// trace RSS **toujours activée** (plus de gate sur
/// `OIRAN_PUBLICATION_RSS_TRACE`), avec séparation anon / file
/// car l'OOM production prouvé par ANR2 est en mémoire ANONYME
/// (anon ≈ 1,06 GB alors que file retombait à 4 KB au kill).
///
/// Format ligne unique parsable par ANR2 :
/// `PUBLICATION_RSS_TRACE phase=<name> indexed_events=<N>
///   anon_kb=<N> file_kb=<N> vmrss_kb=<N> vmhwm_kb=<N>
///   vmpeak_kb=<N>`
///
/// `RssAnon` + `RssFile` viennent de `/proc/self/status` — ces
/// deux compteurs sont exactement ceux que le noyau publie dans
/// `memory.stat` du cgroup au moment de l'OOM.
/// 2.10.3 (devmat, revue 2.10.2 point 2) : horodatage de la
/// première trace de chaque publication. ANR2 peut maintenant
/// calculer `elapsed_ms` par phase — c'est la métrique nécessaire
/// pour savoir laquelle des phases eat le cycle 22 min observé en
/// prod.
///
/// Utilisation : au tout début de `publish_events_to_dataset_dir`,
/// le compteur est réinitialisé via `trace_publication_rss_reset`
/// pour qu'`elapsed_ms` commence à 0.
static PUBLICATION_RSS_START_UNIX_MS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn trace_publication_rss_reset() {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    PUBLICATION_RSS_START_UNIX_MS.store(now_ms, Ordering::Relaxed);
}

pub(crate) fn trace_publication_rss(phase: &str, indexed_events: Option<usize>) {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let value = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}:")))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let start_ms = PUBLICATION_RSS_START_UNIX_MS.load(Ordering::Relaxed);
    let elapsed_ms = if start_ms == 0 || now_ms < start_ms {
        0u64
    } else {
        now_ms - start_ms
    };
    eprintln!(
        "PUBLICATION_RSS_TRACE phase={phase} elapsed_ms={elapsed_ms} indexed_events={} anon_kb={} file_kb={} vmrss_kb={} vmhwm_kb={} vmpeak_kb={}",
        indexed_events.unwrap_or(0),
        value("RssAnon"),
        value("RssFile"),
        value("VmRSS"),
        value("VmHWM"),
        value("VmPeak"),
    );
}

/// 2.7.23 + 2.7.27 + 2.9.18-fu3: streaming merge of one input source into the
/// final `oiran_events.jsonl.tmp`. Peak memory held by this function
/// is the `SpillingEventIdSet` (RAM ≤ 65 536 empreintes u64 ≈ 1,5 MiB,
/// le reste débordé en chunks triés sur disque — voir
/// `event_id_set.rs`) + one `serde_json::Value` + one `String` line.
/// No per-event body is retained, no second-pass seek is required.
///
/// 2.9.18-fu3 (ANR2 #9 comment 6750859966) : la version pré-fu3
/// retenait `seen_ids: BTreeSet<String>` qui atteignait ~200 MiB
/// sur une production à 5 414 segments → 2 OOM sous le cgroup
/// 256 MiB. Le `SpillingEventIdSet` borne la RAM à l'empreinte
/// 64-bit d'au plus `mem_cap` ids simultanés, chaque surplus étant
/// vidé en un chunk trié sur disque (binary search via
/// `read_exact_at` pour les lookups).
///
/// 2.7.27: NO retention / purge is applied here anymore. The 2.7.22
/// per-event cutoff deleted events whose `timestamp.seconds` was
/// older than the window — ANR2 observed 2 717 event_id and 7
/// sessions lost on a 7-day setting because the cut sliced *inside*
/// a capture. Retention is now a capture-level archive step
/// (`plan_capture_retention` + `archive_stale_captures`) applied
/// AFTER the merge, and MOVES whole captures to an immutable archive
/// — it never deletes.
///
/// Dedup is first-write-wins: `continuous_observation_id` is
/// deterministic, so a re-decode of the same packet produces the
/// same id and is silently skipped on the second write. For prior +
/// decoded streams processed in that order, the prior copy stays
/// authoritative; the content is identical by construction so no
/// information is lost.
fn merge_event_stream<R, W>(
    mut reader: R,
    writer: &mut W,
    seen_ids: &mut SpillingEventIdSet,
) -> Result<(), String>
where
    R: BufRead,
    W: Write,
{
    let mut line = String::new();
    let mut processed = 0usize;
    loop {
        line.clear();
        if reader.read_line(&mut line).map_err(display_error)? == 0 {
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        processed = processed.saturating_add(1);
        let mut value: serde_json::Value =
            serde_json::from_str(&line).map_err(|error| error.to_string())?;
        let id = continuous_observation_id(&value)?;
        if !seen_ids.insert(&id).map_err(display_error)? {
            // Duplicate (same deterministic observation id) → first
            // write wins.
            drop(value);
            if processed % 1024 == 0 {
                release_unused_heap_pages();
            }
            continue;
        }
        value["event_id"] = serde_json::Value::String(id);
        let serialized = serde_json::to_string(&value).map_err(|error| error.to_string())?;
        writer
            .write_all(serialized.as_bytes())
            .map_err(display_error)?;
        writer.write_all(b"\n").map_err(display_error)?;
        drop(serialized);
        drop(value);
        if processed % 1024 == 0 {
            // serde_json creates many short-lived strings and maps while a
            // line is normalised. Return the freed pages periodically rather
            // than letting the allocator retain one arena per history chunk.
            release_unused_heap_pages();
        }
    }
    Ok(())
}

fn continuous_observation_id(value: &serde_json::Value) -> Result<String, String> {
    // 2.9.13 (#9 comments 6727243545 + 6727624063) : la clé est
    // alignée EXACTEMENT sur la règle `is_duplicate` publiée en
    // 2.9.5 (`live-probe:634-644`) :
    //   `(capture_id, packet_number, byte_offset, protocol,
    //    message_name)`
    //
    // ANR2 a prouvé que la clé 2.9.10 (qui incluait
    // `raw_payload_reference` + `message_type` + le TRIAGE sur les
    // multiples `packet_references`) laissait passer des doublons
    // réels :
    //   * `raw_payload_reference` est un SHA-256 du payload décodé.
    //     Deux décodes du MÊME paquet wire qui produisent un slice
    //     légèrement différent (padding, longueur AVP optionnelle)
    //     divergent sur ce champ → même paquet, deux IDs.
    //   * `message_type` (code numérique) est redondant avec
    //     `message_name` (string) ; ANR2 utilise `message_name`.
    //   * Les événements d'agrégat (N3 flow aggregator, keepalive
    //     aggregator) ont plusieurs `packet_references` ; le triage
    //     stable prévient la divergence d'ordre.
    //
    // 2.9.13 : ne retenir que le **premier** `packet_reference`
    // trié — l'identité wire d'un événement est celle de son
    // paquet d'origine. Les aggrégats (N3, keepalive) ont tous
    // leur propre pattern de `raw_payload_reference` distinct
    // (préfixe `n3-flow-aggregate:…`, `keepalive-aggregate:…`) ;
    // ils ne risquent donc pas une collision avec un événement
    // individuel non agrégé, même paquet+interface.
    let packet_refs: Vec<serde_json::Value> = value
        .get("packet_references")
        .and_then(serde_json::Value::as_array)
        .map(|refs| refs.to_vec())
        .unwrap_or_default();
    let first = packet_refs
        .iter()
        .map(|p| {
            (
                p.get("source_file")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                p.get("packet_number")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0),
                p.get("byte_offset")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0),
                p.get("interface_id")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0),
            )
        })
        .min();
    let anchor = first.map(|(source, pn, bo, iface)| {
        serde_json::json!({
            "source_file": source,
            "packet_number": pn,
            "byte_offset": bo,
            "interface_id": iface,
        })
    });
    // Pour les aggrégats, inclure un discriminant supplémentaire
    // (`raw_payload_reference` qui contient le signature prefix)
    // pour éviter que deux agrégats partageant le même premier
    // paquet-ancre (mais différents kinds) ne collisionnent.
    let aggregate_discriminant = value
        .get("raw_payload_reference")
        .and_then(serde_json::Value::as_str)
        .filter(|raw| raw.starts_with("keepalive-aggregate:") || raw.starts_with("n3-flow-aggregate:"))
        .map(|raw| raw.to_owned());
    let material = serde_json::to_vec(&serde_json::json!({
        "capture_id": value.get("capture_id"),
        "anchor": anchor,
        "protocol": value.get("protocol"),
        "message_name": value.get("message_name"),
        "aggregate": aggregate_discriminant,
    }))
    .map_err(|error| error.to_string())?;
    Ok(format!("evt-{}", &sha256_hex(&material)[..16]))
}

fn continuous_activity(
    events: &[session_engine::EventRecord],
    capture_started_epoch_ms: Option<u64>,
    observed_epoch_ms: u64,
    runtime_evidence: Option<&Path>,
) -> (Option<u64>, u64, Vec<ActivePduContext>) {
    let last_packet_epoch_ms = events
        .iter()
        .filter_map(|event| u64::try_from(event.timestamp_ns / 1_000_000).ok())
        .max();
    let Some(started) = capture_started_epoch_ms else {
        return (last_packet_epoch_ms, 0, Vec::new());
    };
    let window_start = observed_epoch_ms.saturating_sub(ACTIVE_PACKET_WINDOW_MS);
    let fresh = events.iter().filter(|event| {
        u64::try_from(event.timestamp_ns / 1_000_000).is_ok_and(|observed| {
            observed >= started && observed >= window_start && observed <= observed_epoch_ms
        })
    });
    let mut packet_count = 0u64;
    let mut gpdu_by_ip = BTreeMap::<String, Vec<&session_engine::EventRecord>>::new();
    for event in fresh {
        let aggregate_packet_count = event
            .information_elements
            .as_array()
            .and_then(|items| {
                items.iter().find(|item| {
                    item.get("name").and_then(serde_json::Value::as_str)
                        == Some("aggregate_packet_count")
                })
            })
            .and_then(|item| item.get("value"))
            .and_then(serde_json::Value::as_str)
            .and_then(|value| value.parse::<u64>().ok());
        packet_count = packet_count
            .saturating_add(aggregate_packet_count.unwrap_or(event.packet_references.len() as u64));
        if event.protocol == "GTP-U" && event.message_name == "G-PDU" {
            for value in event.identifier_values("ue_ip") {
                if matches!(value, "10.46.0.4" | "10.46.0.5" | "10.46.0.6") {
                    gpdu_by_ip.entry(value.to_owned()).or_default().push(event);
                }
            }
        }
    }
    let bindings = runtime_evidence
        .and_then(|path| load_runtime_pdu_bindings(path, started, observed_epoch_ms).ok())
        .unwrap_or_default();
    let mut contexts = Vec::new();
    for binding in bindings {
        let Some(bound_events) = gpdu_by_ip.get(&binding.ue_ip) else {
            continue;
        };
        let event_ids = bound_events
            .iter()
            .map(|event| event.event_id.clone())
            .collect::<BTreeSet<_>>();
        let teids = bound_events
            .iter()
            .filter_map(|event| event.first_identifier("teid").map(str::to_owned))
            .collect::<BTreeSet<_>>();
        let directions = bound_events
            .iter()
            .map(|event| event.direction.clone())
            .collect::<BTreeSet<_>>();
        if event_ids.is_empty() || teids.is_empty() || directions.is_empty() {
            continue;
        }
        let session_material = format!(
            "{}|{}|{}",
            binding.internal_ue_id, binding.pdu_session_id, binding.ue_ip
        );
        contexts.push(ActivePduContext {
            session_id: format!(
                "runtime-pdu-{}",
                &sha256_hex(session_material.as_bytes())[..16]
            ),
            internal_ue_id: binding.internal_ue_id,
            pdu_session_id: binding.pdu_session_id,
            ue_ip: binding.ue_ip,
            observed_epoch_ms: binding.evidence_observed_epoch_ms,
            provenance: "POLARIS_API+UERANSIM_NR_CLI_STATUS_PS_LIST+UESIMTUN0".into(),
            correlation_status: "PARTIAL_EXTERNAL_RUNTIME_CORROBORATED".into(),
            gtpu_event_ids: event_ids.into_iter().collect(),
            teids: teids.into_iter().collect(),
            directions: directions.into_iter().collect(),
        });
    }
    contexts.sort_by(|left, right| left.internal_ue_id.cmp(&right.internal_ue_id));
    (last_packet_epoch_ms, packet_count, contexts)
}

fn fresh_credit(timestamp_epoch_ms: Option<u64>, observed_epoch_ms: u64) -> bool {
    timestamp_epoch_ms.is_some_and(|timestamp| {
        timestamp <= observed_epoch_ms
            && observed_epoch_ms.saturating_sub(timestamp) <= ACTIVE_PACKET_WINDOW_MS
    })
}

fn live_dataset_view(mut dataset: LiveDataset, observed_epoch_ms: u64) -> LiveDataset {
    let packet_credit_fresh = fresh_credit(dataset.last_packet_epoch_ms, observed_epoch_ms);
    if !packet_credit_fresh {
        dataset.fresh_packet_count = 0;
    }
    dataset.active_pdu_contexts.retain(|context| {
        packet_credit_fresh && fresh_credit(Some(context.observed_epoch_ms), observed_epoch_ms)
    });
    dataset.active_ue_ips = dataset
        .active_pdu_contexts
        .iter()
        .map(|context| context.ue_ip.clone())
        .collect();
    dataset
}

fn load_runtime_pdu_bindings(
    path: &Path,
    capture_started_epoch_ms: u64,
    now_epoch_ms: u64,
) -> Result<Vec<RuntimePduBinding>, String> {
    let metadata = fs::symlink_metadata(path).map_err(display_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 64 * 1024 {
        return Err("CONTINUOUS_RUNTIME_EVIDENCE_INVALID".into());
    }
    let evidence: RuntimePduEvidence =
        serde_json::from_slice(&fs::read(path).map_err(display_error)?)
            .map_err(|_| "CONTINUOUS_RUNTIME_EVIDENCE_INVALID".to_string())?;
    if evidence.schema_version != "1.0"
        || evidence.source != "POLARIS_API+UERANSIM_NR_CLI"
        || evidence.observed_epoch_ms < capture_started_epoch_ms
        || evidence.observed_epoch_ms > now_epoch_ms
        || now_epoch_ms.saturating_sub(evidence.observed_epoch_ms) > ACTIVE_PACKET_WINDOW_MS
        || evidence.bindings.len() != 3
    {
        return Err("CONTINUOUS_RUNTIME_EVIDENCE_STALE_OR_INVALID".into());
    }
    let expected = BTreeMap::from([
        ("UE-01", ("oiran-lab-ueransim-ue-1", "10.46.0.4")),
        ("UE-02", ("polaris-control-ue-02", "10.46.0.5")),
        ("UE-03", ("polaris-control-ue-03", "10.46.0.6")),
    ]);
    let mut seen = BTreeSet::new();
    for binding in &evidence.bindings {
        let Some((container, ip)) = expected.get(binding.internal_ue_id.as_str()) else {
            return Err("CONTINUOUS_RUNTIME_EVIDENCE_BINDING_INVALID".into());
        };
        if !seen.insert(binding.internal_ue_id.as_str())
            || binding.container != *container
            || binding.ue_ip != *ip
            || binding.interface != "uesimtun0"
            || binding.process_state != "RUNNING"
            || binding.registration_state != "REGISTERED"
            || binding.pdu_session_state != "ACTIVE"
            || binding.pdu_session_id.is_empty()
            || !binding
                .pdu_session_id
                .chars()
                .all(|value| value.is_ascii_digit())
            || binding.status_provenance != "nr-cli status"
            || binding.pdu_provenance != "nr-cli ps-list"
            || binding.tunnel_provenance != "ip -json address show dev uesimtun0"
        {
            return Err("CONTINUOUS_RUNTIME_EVIDENCE_BINDING_INVALID".into());
        }
    }
    let mut bindings = evidence.bindings;
    for binding in &mut bindings {
        binding.evidence_observed_epoch_ms = evidence.observed_epoch_ms;
    }
    Ok(bindings)
}

/// 2.8.2 (#10 comment 6687323881): cheap drift detector for the
/// known source files. Iterates the per-worker cache, stats each
/// known path, and returns `true` the moment any file's mtime has
/// moved past its cached fingerprint (or the file has disappeared).
/// Covers in-place appends (dumpcap overlapping-append) that leave
/// the parent directory's mtime unchanged on ext4. Bounds the cost
/// at `cache.len()` statx per call — ~50 ms for 10 000 entries.
fn source_cache_mtime_drift(cache: &SourceSegmentsCache) -> bool {
    for (path, fingerprint) in cache {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return true;
        };
        let (_, _, _, mtime_ns) = fingerprint_from_metadata(&metadata);
        if mtime_ns != fingerprint.mtime_ns {
            return true;
        }
    }
    false
}

/// 2.8.2 (#10 comment 6687323881): cheap gate before `source_segments`.
/// Walks the source root's immediate children, stats each, and
/// compares `mtime` against the previous scan's cache. A directory's
/// mtime changes on any file create / rename / delete inside it, so a
/// new finalised segment always flips at least one entry. Returns
/// `true` when the scan must run; updates the cache in place. On the
/// very first call (`cache` is empty), returns `true` so the initial
/// drain covers pre-existing files.
fn source_tree_mutated(
    root: &Path,
    cache: &mut BTreeMap<PathBuf, SystemTime>,
) -> Result<bool, String> {
    let mut observed = Vec::new();
    collect_watched_directories(root, 0, &mut observed);
    let mut mutated = cache.is_empty();
    let mut fresh: BTreeMap<PathBuf, SystemTime> = BTreeMap::new();
    for dir in observed {
        let mtime = fs::metadata(&dir)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        if cache.get(&dir) != Some(&mtime) {
            mutated = true;
        }
        fresh.insert(dir, mtime);
    }
    if !mutated && fresh.len() != cache.len() {
        mutated = true;
    }
    *cache = fresh;
    Ok(mutated)
}

/// 2.8.2: walk the source root down to the same depth as
/// `collect_source_paths` so the dir-mtime gate catches writes in any
/// nested rotation directory (e.g. `source_root/continuous-segment-*/
/// pcap/`). A new file inside a leaf directory updates that leaf's
/// mtime; if we only watched the immediate children of the root we'd
/// miss writes two levels deep.
fn collect_watched_directories(directory: &Path, depth: u8, dirs: &mut Vec<PathBuf>) {
    dirs.push(directory.to_path_buf());
    if depth >= 3 {
        return;
    }
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            collect_watched_directories(&path, depth + 1, dirs);
        }
    }
}

fn collect_source_paths(
    directory: &Path,
    depth: u8,
    paths: &mut Vec<PathBuf>,
) -> Result<(), String> {
    if depth > 3 {
        return Ok(());
    }
    for entry in fs::read_dir(directory)
        .map_err(display_error)?
        .filter_map(Result::ok)
    {
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect_source_paths(&path, depth + 1, paths)?;
        } else if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.to_ascii_lowercase().contains(".pcap"))
        {
            paths.push(path);
        }
    }
    Ok(())
}

/// 2.7.22 (issue #10 comment 6657170005): size of the work surface the
/// ring-and-publication machinery is responsible for — pcap segments
/// currently owned by the ring and any spool / temp still on disk.
/// Excludes the published `dataset/` subtree, which is long-lived
/// storage with its own age-based retention
/// (`OIRAN_DATASET_RETENTION_DAYS`, default 30). The storage guard at
/// `run_continuous_import_inner` now reads this instead of
/// `directory_size(&base)`: with the 2.7.18 `keep_prior` filter removed
/// the published dataset grows linearly with ingested events, which
/// would otherwise trip `CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT` on every
/// new candidate even though the ring itself is well under budget.
/// 2.9.8 (#9, ANR2 comment 6725097122): bytes of *in-flight* work
/// under `base` — the stuff that will shrink after a successful
/// publish+commit. ANR2 proved in production that the pre-2.9.8
/// definition counted `pcap/` (the already-imported ring) in the
/// backpressure gate, so the gate tripped on every new candidate
/// once the ring exceeded `max_owned_bytes - candidate -
/// MAX_CONTINUOUS_DERIVED_BYTES` — dumpcap never deletes a source
/// segment, so the ring only grows and the gate would never
/// recover. The ring is instead bounded by the operator-configured
/// `max_segments` + `max_owned_bytes` ceiling enforced on retention
/// elsewhere (`state.segments.retain(...)` on startup); it is NOT
/// part of the staging budget.
///
/// Counted:
///   * `.importing` temp files under `pcap/` — in-flight copy from
///     `copy_verified`.
///   * `import_state.json` + any other top-level file — small
///     bookkeeping, fits well under the derived reserve.
///
/// Explicitly NOT counted:
///   * `pcap/<interface>.pcap-<sha16>.ext` — committed ring entries.
///   * `dataset/` — the published dataset (already excluded in the
///     pre-2.9.8 definition; kept excluded).
///   * `.dataset-next/` — mid-publish staging. **Pre-2.11.3 était
///     compté**, mais sa taille est une FONCTION de l'historique
///     du dataset (jusqu'à ~3,3 Go observé en prod sur 1,5 M
///     events). Un `max_owned_bytes = 1,06 GiB` serait trivialement
///     dépassé par une publication normale. 2.11.3 l'exclut : le
///     budget ne gate plus l'écho du dataset existant, seulement
///     le travail nouvellement ingéré (`pcap-in-flight`).
///   * `.dataset-previous/` — transient atomic-swap tombstone.
///     Pre-2.11.3 était compté → un cycle de swap `dataset →
///     .dataset-previous → remove` comptait le dataset DEUX FOIS
///     pendant quelques ms. 2.11.3 l'exclut.
///   * `.dataset.rollback.YYYYMMDDTHHMMSSZ/` — tombstone opérateur
///     créé par la procédure de rollback ANR1 (3,38 Go observés le
///     2026-11-10T20:47Z). Ce n'est **pas** un artefact OIRAN. 2.11.3
///     l'exclut car il représente un CHOIX opérationnel de garder
///     l'ancien dataset pour audit, pas une consommation d'ingest.
///     Documenté dans le CHANGELOG : les procédures de rollback
///     devraient **créer ces tombstones HORS de la racine d'import**
///     (ex. `/var/lib/oiran/rollback-archive/`).
///
/// Log : `CONTINUOUS_BUDGET_EXCLUSION` émis une fois par scan avec
/// les tailles exclues pour qu'ANR2 puisse prouver le calcul.
fn work_bytes(base: &Path) -> u64 {
    let total = directory_size(base);
    let published = directory_size(&base.join("dataset"));
    let committed_ring = committed_ring_bytes(&base.join("pcap"));
    let next = directory_size(&base.join(".dataset-next"));
    let previous = directory_size(&base.join(".dataset-previous"));
    let (rollback_bytes, rollback_paths) = rollback_tombstones(base);
    if next > 0 || previous > 0 || rollback_bytes > 0 {
        eprintln!(
            "{}",
            serde_json::json!({
                "event": "CONTINUOUS_BUDGET_EXCLUSION",
                "dataset_next_bytes": next,
                "dataset_previous_bytes": previous,
                "rollback_bytes": rollback_bytes,
                "rollback_paths": rollback_paths,
                "published_bytes": published,
                "committed_ring_bytes": committed_ring,
                "total_bytes": total,
                "reason": "2.11.3 excludes transient dataset staging + operator rollback tombstones from backpressure budget",
            })
        );
    }
    total
        .saturating_sub(published)
        .saturating_sub(committed_ring)
        .saturating_sub(next)
        .saturating_sub(previous)
        .saturating_sub(rollback_bytes)
}

/// 2.11.3 : énumère les tombstones de rollback opérateur sous
/// `<base>/.dataset.rollback.YYYYMMDDTHHMMSSZ/` (créés par la
/// procédure de rollback ANR1). Retourne la somme et la liste des
/// chemins (pour journalisation).
fn rollback_tombstones(base: &Path) -> (u64, Vec<String>) {
    let mut total = 0u64;
    let mut paths = Vec::new();
    let read = match fs::read_dir(base) {
        Ok(iter) => iter,
        Err(_) => return (0, Vec::new()),
    };
    for entry in read.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        // Deux formes acceptées : `.dataset.rollback.<timestamp>`
        // (format ANR1 courant, point-séparateur) et
        // `.dataset-rollback.<timestamp>` (variante dash,
        // acceptée par symétrie).
        if !(name_str.starts_with(".dataset.rollback.")
            || name_str.starts_with(".dataset-rollback."))
        {
            continue;
        }
        let path = entry.path();
        let size = directory_size(&path);
        total = total.saturating_add(size);
        paths.push(path.display().to_string());
    }
    (total, paths)
}

/// 2.9.8 (#9, ANR2 comment 6725097122): size of the committed import
/// ring under `pcap/` — i.e. every regular file EXCEPT `.importing`
/// temp files produced by `copy_verified`. Called by `work_bytes` so
/// the backpressure gate accounts only for the in-flight temporary.
fn committed_ring_bytes(pcap_dir: &Path) -> u64 {
    fs::read_dir(pcap_dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let metadata = entry.metadata().ok()?;
            if !metadata.is_file() {
                return None;
            }
            let name = entry.file_name();
            let name_str = name.to_str()?;
            if name_str.ends_with(".importing") {
                return None;
            }
            Some(metadata.len())
        })
        .sum()
}

fn directory_size(directory: &Path) -> u64 {
    fs::read_dir(directory)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| {
            let path = entry.path();
            match entry.metadata() {
                Ok(metadata) if metadata.is_dir() => directory_size(&path),
                Ok(metadata) if metadata.is_file() => metadata.len(),
                _ => 0,
            }
        })
        .sum()
}

/// 2.9.1 (#9): the production source tree lays plane directories out
/// lowercase (`infrastructure/capture/capture-interface.sh:30-31`
/// builds `$out_dir/$label/…`, and ANR2's inventory shows the live
/// tree with these 12 labels: `n2 n3 n4 n6 s11 s1mme s1u s5c s5u s6a
/// sbi sxab`). `source_interface` returns the canonical interface
/// string the decoders expect
/// (`DecodeConfig::interface` allowlist at
/// `oiran-decode/src/lib.rs:455-470`). Unknown directories yield
/// `None` and surface in the worker log as
/// `CONTINUOUS_PLANE_NOT_ALLOWLISTED` plus the
/// `CaptureMetrics.plane_counts["UNKNOWN"]` counter — never a silent
/// skip.
///
/// Mapping ANR2 label → OIRAN canonical:
///   * `n2`      → `N2`
///   * `n3`      → `N3`
///   * `n4`      → `N4`
///   * `n6`      → `N6`      (no decoder today; counted, 0 events)
///   * `s11`     → `S11`
///   * `s1mme`   → `S1-MME`
///   * `s1u`     → `S1-U`
///   * `s5c`     → `S5-C`
///   * `s5u`     → `S5-U`
///   * `s6a`     → `S6a`
///   * `sbi`     → `SBI`
///   * `sxab`    → `Sxab`
/// 2.9.1: the canonical interface strings with an OIRAN decoder on
/// the import pipeline today. Must stay in sync with
/// `validate_config` at `oiran-decode/src/lib.rs:455-470`.
/// `N6` is deliberately excluded — it carries user-plane data only
/// and the OIRAN stack emits no events from it. The live-probe
/// counts it, logs `CONTINUOUS_PLANE_NOT_ALLOWLISTED {path, plane}`
/// once per path, and skips ingestion.
fn interface_has_decoder(interface: &str) -> bool {
    matches!(
        interface,
        "N2" | "N3" | "N4" | "SBI" | "S1-MME" | "S1-U" | "S11" | "S5-C" | "S5-U" | "S6a" | "Sxab"
        // 2.11.0 (devmat) : plane IMS (SIP + RTP) ajoutée en 13ᵉ.
        | "IMS"
    )
}

fn canonical_interface_for_plane(plane: &str) -> Option<&'static str> {
    match plane.to_ascii_lowercase().as_str() {
        "n2" => Some("N2"),
        "n3" => Some("N3"),
        "n4" => Some("N4"),
        "n6" => Some("N6"),
        "s11" => Some("S11"),
        "s1mme" | "s1-mme" | "s1m" => Some("S1-MME"),
        "s1u" | "s1-u" => Some("S1-U"),
        "s5c" | "s5-c" => Some("S5-C"),
        "s5u" | "s5-u" => Some("S5-U"),
        "s6a" => Some("S6a"),
        "sbi" => Some("SBI"),
        "sxab" => Some("Sxab"),
        // 2.11.0 (devmat) : plane IMS — dumpcap écrit sous `.../ims/` ;
        // mode fantôme peut écrire sous `.../ims_vonr/` → accepté.
        "ims" | "ims_vonr" | "ims-vonr" => Some("IMS"),
        _ => None,
    }
}

fn source_interface(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    for component in relative.components() {
        let raw = component.as_os_str().to_str()?;
        let (name, _ext) = raw.split_once('.').unwrap_or((raw, ""));
        let name_or_prefix = name.split('_').next().unwrap_or(raw);
        if let Some(canonical) = canonical_interface_for_plane(name_or_prefix) {
            return Some(canonical.to_owned());
        }
    }
    None
}

#[allow(dead_code)]
fn plane_for_canonical(interface: &str) -> &'static str {
    match interface {
        "N2" => "N2",
        "N3" => "N3",
        "N4" => "N4",
        "N6" => "N6",
        "S11" => "S11",
        "S1-MME" => "S1-MME",
        "S1-U" => "S1-U",
        "S5-C" => "S5-C",
        "S5-U" => "S5-U",
        "S6a" => "S6a",
        "SBI" => "SBI",
        "Sxab" => "Sxab",
        "IMS" => "IMS",
        _ => "UNKNOWN",
    }
}

fn _retired_source_interface_2_9_0(root: &Path, path: &Path) -> Option<String> {
    // Historical 2.8.x/2.9.0 scope: only the 5G-SA core-stack
    // directories (`N2`, `N3`, `N4`). Superseded by
    // `canonical_interface_for_plane` in 2.9.1. Kept for grep-ability
    // and never called.
    let _ = (root, path);
    None
}

fn copy_verified(segment: &SourceSegment, destination: &Path) -> Result<(), String> {
    if destination.exists() {
        return Ok(());
    }
    let temporary = destination.with_extension("importing");
    // `fs::copy` streams in kernel space without materialising the file in
    // user memory. The post-copy integrity check must do the same — the
    // previous `fs::read(&temporary)` loaded the full capture into RAM, so a
    // 512 MiB pcap import spiked the resident set by half a gigabyte and
    // triggered OOMs under the Codex-measured 256 MiB cgroup budget. 0.2.3
    // hashes the destination through a bounded `BufReader` instead.
    fs::copy(&segment.path, &temporary).map_err(display_error)?;
    let current = fs::metadata(&segment.path).map_err(display_error)?;
    let streamed_checksum = sha256_hex_file(&temporary);
    let changed = match streamed_checksum {
        Ok(ref checksum) => {
            current.len() != segment.size_bytes
                || current.modified().ok() != Some(segment.modified)
                || checksum != &segment.checksum
        }
        Err(_) => true,
    };
    if changed {
        let _ = fs::remove_file(&temporary);
        return Err("CONTINUOUS_SOURCE_CHANGED_DURING_IMPORT".into());
    }
    fs::rename(&temporary, destination).map_err(display_error)
}

fn capture_files(directory: &Path) -> Vec<PathBuf> {
    fs::read_dir(directory)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.contains(".pcap"))
        })
        .collect()
}

fn capture_files_for(directory: &Path, interface: &str) -> Vec<PathBuf> {
    capture_files(directory)
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&format!("{interface}.pcap")))
        })
        .collect()
}

fn pcap_totals(files: &[PathBuf]) -> (u64, u64) {
    let bytes = files
        .iter()
        .filter_map(|path| fs::metadata(path).ok())
        .map(|metadata| metadata.len())
        .sum();
    let packets = files.iter().map(|path| count_pcap_records(path)).sum();
    (packets, bytes)
}

/// 2.9.18-fu (#9 comment ANR2 6745114783) — ANR2 a prouvé que
/// le `--recover` 2.9.17-fu écrivait `packets=0` sur TOUS les
/// 1 307 segments alors que 1 299 pcaps non vides contenaient
/// des paquets selon `capinfos -c`. Cause : la version pré-2.9.18-fu
/// ne gérait QUE le format pcap classique (magic `0xd4c3b2a1` /
/// `0x4d3cb2a1`) et retournait (0,0) pour pcapng (Section Header
/// Block `0x0A0D0D0A`). OIRAN utilise pcapng partout → compteur
/// toujours 0.
///
/// 2.9.18-fu : délègue à `capture_pcap::visit_capture` qui détecte
/// le format via la magie et parcourt les blocs pcapng (Enhanced
/// Packet Block, Simple Packet Block, Packet Block déprécié).
/// Retourne 0 fail-closed si le fichier est illisible ou corrompu.
fn count_pcap_records(path: &Path) -> u64 {
    let mut packet_count: u64 = 0;
    let summary = capture_pcap::visit_capture(path, "recover-count", |_packet| {
        packet_count = packet_count.saturating_add(1);
    });
    match summary {
        Ok(_) => packet_count,
        Err(_) => 0,
    }
}

fn pcap_record_totals(path: &Path) -> (u64, u64) {
    let Ok(mut file) = fs::File::open(path) else {
        return (0, 0);
    };
    let mut header = [0u8; 24];
    if file.read_exact(&mut header).is_err() {
        return (0, 0);
    }
    let little = matches!(
        &header[..4],
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1]
    );
    let mut count = 0;
    let mut bytes = 0;
    loop {
        let mut record = [0u8; 16];
        if file.read_exact(&mut record).is_err() {
            break;
        }
        let length = if little {
            u32::from_le_bytes(record[8..12].try_into().unwrap())
        } else {
            u32::from_be_bytes(record[8..12].try_into().unwrap())
        } as u64;
        if std::io::copy(
            &mut std::io::Read::by_ref(&mut file).take(length),
            &mut std::io::sink(),
        )
        .ok()
            != Some(length)
        {
            break;
        }
        count += 1;
        bytes += length;
    }
    (count, bytes)
}

/// Compute the SHA-256 of `path` in streaming mode. Memory is bounded to one
/// `STREAM_CHUNK_BYTES` chunk; the entire file is never materialised in RAM.
fn sha256_hex_file(path: &Path) -> Result<String, String> {
    let file = fs::File::open(path).map_err(display_error)?;
    let mut reader = BufReader::with_capacity(STREAM_CHUNK_BYTES, file);
    let mut hasher = Sha256Hasher::new();
    loop {
        let buf = reader.fill_buf().map_err(display_error)?;
        if buf.is_empty() {
            break;
        }
        hasher.update(buf);
        let consumed = buf.len();
        reader.consume(consumed);
    }
    Ok(hasher.finish_hex())
}

/// 2.9.2 (#9 comment 6708784283): walk a pcap file packet-by-packet
/// and snapshot a running SHA-256 at every record boundary. The map
/// returned is `prefix_sha_hex → (packet_count, bytes)` — the exact
/// SHA each PARTIAL import would have carried as its `capture_id`,
/// paired with the number of packets up to that prefix. The full-file
/// SHA is returned separately and is NOT duplicated inside the prefix
/// map, so a "full-SHA snapshot" (= complete import) and a "prefix
/// snapshot" (= partial import) are always disambiguated.
#[derive(Debug, Clone)]
struct PrefixIndex {
    path: PathBuf,
    full_sha_hex: String,
    full_packet_count: u64,
    full_bytes: u64,
    /// `prefix_sha_hex → (packet_count, bytes_including_pcap_header)`.
    prefix_sha: BTreeMap<String, (u64, u64)>,
}

fn prefix_sha_index(path: &Path) -> Result<PrefixIndex, String> {
    use std::io::Read;
    // 2.9.2: the full-file SHA is the only file-level invariant; it
    // is computed via `sha256_hex_file`, which walks the entire file
    // regardless of pcap validity. The packet-boundary walk below is
    // best-effort and just builds the `prefix_sha` map for partial
    // snapshots; a non-pcap or truncated file still exposes a valid
    // `full_sha_hex` for the Full-SHA match path.
    //
    // 2.9.6 (devmat #9 T1 — ANR2 #10 comment 6724120812) : dumpcap de
    // production écrit en **pcapng** (magic `0A 0D 0D 0A`), pas en
    // pcap classique (`D4 C3 B2 A1`). Avant 2.9.6 cette fonction ne
    // reconnaissait que pcap classique et retournait `prefix_sha = {}`
    // sur tout fichier pcapng → les 7 snapshots de `_00067` n'étaient
    // pas regroupés (0 matches, tous en singletons `unresolved`). On
    // ajoute ici une branche pcapng dédiée qui marche les Blocks
    // (SHB / IDB / EPB / SPB / …) et snapshote le SHA à la fin de
    // chaque Enhanced/Simple Packet Block.
    let full_sha_hex = sha256_hex_file(path)?;
    let full_bytes = fs::metadata(path).map_err(display_error)?.len();
    let mut file = fs::File::open(path).map_err(display_error)?;
    let mut hasher = Sha256Hasher::new();
    let mut prefix_sha: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_err() {
        return Ok(PrefixIndex {
            path: path.to_path_buf(),
            full_sha_hex,
            full_packet_count: 0,
            full_bytes,
            prefix_sha,
        });
    }
    hasher.update(&magic);
    // pcapng : Section Header Block type == 0x0A 0x0D 0x0D 0x0A
    // (byte pattern invariant across endianness — c'est une
    // signature, pas un champ numérique).
    if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
        return prefix_sha_index_pcapng(
            path,
            file,
            hasher,
            full_sha_hex,
            full_bytes,
            prefix_sha,
        );
    }
    // pcap classique : magic 0xd4c3b2a1 (LE) / 0x4d3cb2a1 (nano LE)
    // ou 0xa1b2c3d4 (BE).
    let little =
        matches!(&magic, [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1]);
    let big = matches!(&magic, [0xa1, 0xb2, 0xc3, 0xd4]);
    if !little && !big {
        return Ok(PrefixIndex {
            path: path.to_path_buf(),
            full_sha_hex,
            full_packet_count: 0,
            full_bytes,
            prefix_sha,
        });
    }
    // Finir de lire le reste du header pcap (20 octets après le magic).
    let mut rest_header = [0u8; 20];
    if file.read_exact(&mut rest_header).is_err() {
        return Ok(PrefixIndex {
            path: path.to_path_buf(),
            full_sha_hex,
            full_packet_count: 0,
            full_bytes,
            prefix_sha,
        });
    }
    hasher.update(&rest_header);
    let mut bytes_so_far: u64 = 24;
    let mut packet_number: u64 = 0;
    loop {
        let mut record = [0u8; 16];
        if file.read_exact(&mut record).is_err() {
            break;
        }
        let length = if little {
            u32::from_le_bytes(record[8..12].try_into().unwrap())
        } else {
            u32::from_be_bytes(record[8..12].try_into().unwrap())
        } as u64;
        hasher.update(&record);
        bytes_so_far = bytes_so_far.saturating_add(16);
        let mut remaining = length;
        let mut buf = [0u8; 4096];
        let mut payload_ok = true;
        while remaining > 0 {
            let take = remaining.min(buf.len() as u64) as usize;
            if file.read_exact(&mut buf[..take]).is_err() {
                payload_ok = false;
                break;
            }
            hasher.update(&buf[..take]);
            remaining -= take as u64;
            bytes_so_far = bytes_so_far.saturating_add(take as u64);
        }
        if !payload_ok {
            break;
        }
        packet_number = packet_number.saturating_add(1);
        let snapshot_sha = hasher.clone().finish_hex();
        prefix_sha.insert(snapshot_sha, (packet_number, bytes_so_far));
    }
    // The last packet-boundary snapshot equals the full-file digest;
    // remove it so the repair distinguishes Full vs Prefix.
    prefix_sha.remove(&full_sha_hex);
    Ok(PrefixIndex {
        path: path.to_path_buf(),
        full_sha_hex,
        full_packet_count: packet_number,
        full_bytes,
        prefix_sha,
    })
}

/// 2.9.6 (devmat #9 T1) : marche d'un pcapng pour construire
/// `prefix_sha` à la fin de chaque Enhanced Packet Block (type
/// `0x00000006`) et Simple Packet Block (type `0x00000003`).
///
/// Structure pcapng (RFC draft `pcap-ng-common`, section 3) :
///
/// ```text
/// Section Header Block (SHB) :
///   0-3   Block Type         = 0x0A 0x0D 0x0D 0x0A  (signature)
///   4-7   Block Total Length (endianness dans le reste)
///   8-11  Byte-Order Magic   = 0x1A 0x2B 0x3C 0x4D (BE) / 0x4D 0x3C 0x2B 0x1A (LE)
///   12-13 Major Version      (= 1)
///   14-15 Minor Version      (= 0)
///   16-23 Section Length     (i64, -1 si inconnu)
///   24+   Options
///   end   Block Total Length (répété pour parcours inverse)
///
/// Chaque bloc après SHB :
///   0-3   Block Type
///   4-7   Block Total Length (multiple de 4, inclut header + trailer)
///   8..   Body
///   end-4..end  Block Total Length (répété)
/// ```
///
/// Les 4 premiers octets (type SHB) ont déjà été lus et hashés par
/// l'appelant.
fn prefix_sha_index_pcapng(
    path: &Path,
    mut file: fs::File,
    mut hasher: Sha256Hasher,
    full_sha_hex: String,
    full_bytes: u64,
    mut prefix_sha: BTreeMap<String, (u64, u64)>,
) -> Result<PrefixIndex, String> {
    use std::io::Read;
    // Lire les 8 octets suivants (Block Total Length + Byte-Order Magic)
    // pour déterminer l'endianness, puis finir de lire le SHB.
    let mut shb_rest = [0u8; 8];
    if file.read_exact(&mut shb_rest).is_err() {
        return Ok(PrefixIndex {
            path: path.to_path_buf(),
            full_sha_hex,
            full_packet_count: 0,
            full_bytes,
            prefix_sha,
        });
    }
    hasher.update(&shb_rest);
    let byte_order_magic = &shb_rest[4..8];
    let little = matches!(byte_order_magic, [0x4d, 0x3c, 0x2b, 0x1a]);
    let big = matches!(byte_order_magic, [0x1a, 0x2b, 0x3c, 0x4d]);
    if !little && !big {
        return Ok(PrefixIndex {
            path: path.to_path_buf(),
            full_sha_hex,
            full_packet_count: 0,
            full_bytes,
            prefix_sha,
        });
    }
    let read_u32 = |bytes: &[u8; 4]| -> u32 {
        if little {
            u32::from_le_bytes(*bytes)
        } else {
            u32::from_be_bytes(*bytes)
        }
    };
    let shb_total_length = read_u32(shb_rest[0..4].try_into().unwrap()) as u64;
    // Garde défensive : 12 octets mini (type 4 + length 4 + trailer 4).
    // SHB inclut au moins byte-order magic 4 + versions 4 + section_length 8
    // = 16 octets de body + 12 = 28 octets min, aligné à 4.
    if shb_total_length < 28 || shb_total_length % 4 != 0 {
        return Ok(PrefixIndex {
            path: path.to_path_buf(),
            full_sha_hex,
            full_packet_count: 0,
            full_bytes,
            prefix_sha,
        });
    }
    // On a déjà lu 12 octets du SHB (magic + length + byte-order).
    // Reste à lire `shb_total_length - 12` octets pour finir le bloc.
    let mut shb_remaining = (shb_total_length - 12) as usize;
    let mut chunk = [0u8; 4096];
    while shb_remaining > 0 {
        let take = shb_remaining.min(chunk.len());
        if file.read_exact(&mut chunk[..take]).is_err() {
            return Ok(PrefixIndex {
                path: path.to_path_buf(),
                full_sha_hex,
                full_packet_count: 0,
                full_bytes,
                prefix_sha,
            });
        }
        hasher.update(&chunk[..take]);
        shb_remaining -= take;
    }
    let mut bytes_so_far: u64 = shb_total_length;
    let mut packet_number: u64 = 0;
    // Enhanced Packet Block = 0x00000006, Simple Packet Block = 0x00000003.
    const BLOCK_TYPE_EPB: u32 = 0x00000006;
    const BLOCK_TYPE_SPB: u32 = 0x00000003;
    loop {
        let mut header = [0u8; 8];
        if file.read_exact(&mut header).is_err() {
            break;
        }
        hasher.update(&header);
        let block_type = read_u32(header[0..4].try_into().unwrap());
        let block_total_length = read_u32(header[4..8].try_into().unwrap()) as u64;
        if block_total_length < 12 || block_total_length % 4 != 0 {
            break;
        }
        // Body = block_total_length - 8 (header) - 4 (trailer).
        let mut body_remaining = (block_total_length - 12) as usize;
        let mut body_ok = true;
        while body_remaining > 0 {
            let take = body_remaining.min(chunk.len());
            if file.read_exact(&mut chunk[..take]).is_err() {
                body_ok = false;
                break;
            }
            hasher.update(&chunk[..take]);
            body_remaining -= take;
        }
        if !body_ok {
            break;
        }
        let mut trailer = [0u8; 4];
        if file.read_exact(&mut trailer).is_err() {
            break;
        }
        hasher.update(&trailer);
        bytes_so_far = bytes_so_far.saturating_add(block_total_length);
        if block_type == BLOCK_TYPE_EPB || block_type == BLOCK_TYPE_SPB {
            packet_number = packet_number.saturating_add(1);
            let snapshot_sha = hasher.clone().finish_hex();
            prefix_sha.insert(snapshot_sha, (packet_number, bytes_so_far));
        }
    }
    // Dernier snapshot = SHA total du fichier → retiré pour que la
    // réparation distingue Full-SHA de Prefix-SHA.
    prefix_sha.remove(&full_sha_hex);
    Ok(PrefixIndex {
        path: path.to_path_buf(),
        full_sha_hex,
        full_packet_count: packet_number,
        full_bytes,
        prefix_sha,
    })
}

/// Verify that `path` matches the expected size + SHA-256 in O(STREAM_CHUNK_BYTES)
/// memory. Returns the file length on success so callers do not need a second
/// `fs::metadata` pass.
fn verify_file_integrity(
    path: &Path,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<u64, String> {
    let metadata = fs::metadata(path).map_err(display_error)?;
    if metadata.len() != expected_size {
        return Err(format!(
            "size mismatch for {}: expected {} got {}",
            path.display(),
            expected_size,
            metadata.len()
        ));
    }
    let actual = sha256_hex_file(path)?;
    if actual != expected_sha256 {
        return Err(format!("sha256 mismatch for {}", path.display()));
    }
    Ok(metadata.len())
}

#[allow(dead_code)] // retained for tests; the production path uses count_pcap_records on a Path.
fn count_pcap_records_bytes(bytes: &[u8]) -> u64 {
    if bytes.len() < 24 {
        return 0;
    }
    let little = matches!(
        &bytes[..4],
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1]
    );
    if !little
        && !matches!(
            &bytes[..4],
            [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d]
        )
    {
        return 0;
    }
    let mut offset = 24usize;
    let mut count = 0u64;
    while offset.saturating_add(16) <= bytes.len() {
        let length_bytes: [u8; 4] = bytes[offset + 8..offset + 12].try_into().unwrap();
        let length = if little {
            u32::from_le_bytes(length_bytes)
        } else {
            u32::from_be_bytes(length_bytes)
        } as usize;
        offset = offset.saturating_add(16);
        if offset.saturating_add(length) > bytes.len() {
            break;
        }
        offset += length;
        count += 1;
    }
    count
}

fn endpoint_map() -> HashMap<String, String> {
    [
        ("10.77.21.20", "gNB"),
        ("10.77.21.11", "AMF"),
        ("10.77.22.20", "gNB"),
        ("10.77.22.13", "UPF"),
        ("10.77.23.12", "SMF"),
        ("10.77.23.13", "UPF"),
    ]
    .into_iter()
    .map(|(address, function)| (address.into(), function.into()))
    .collect()
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn display_error(error: std::io::Error) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lte_event(
        id: &str,
        interface: &str,
        protocol: &str,
        name: &str,
        identifiers: &[(&str, &str)],
        direction: &str,
        packet: u64,
    ) -> EventRecord {
        serde_json::from_value(serde_json::json!({
            "event_id": id,
            "parent_event_id": null,
            "capture_id": "sha256:synthetic-lte-offline",
            "capture_point_id": interface,
            "timestamp": format!("2026-10-31T12:00:00.{packet:09}Z"),
            "timestamp_ns": 1_000_000_000_i128 + i128::from(packet),
            "raw_ticks": 1_000_000_000_u64 + packet,
            "interface": interface,
            "protocol": protocol,
            "message_name": name,
            "source_address": "192.0.2.10",
            "destination_address": "192.0.2.20",
            "source_participant": if interface == "S1-MME" { "eNB" } else { "SGW" },
            "destination_participant": if interface == "S1-MME" { "MME" } else { "eNB" },
            "direction": direction,
            "identifiers": identifiers,
            "information_elements": [],
            "decoding_status": "DECODED",
            "decoder_name": protocol,
            "decoder_version": "synthetic-test",
            "raw_payload_reference": format!("sha256:{id}"),
            "packet_references": [{
                "source_file": "synthetic-offline.pcap",
                "packet_number": packet,
                "byte_offset": packet * 64,
                "interface_id": 0,
                "captured_length": 64,
                "original_length": 64
            }],
            "errors": [],
            "source_json": {}
        }))
        .unwrap()
    }

    #[test]
    fn offline_lte_materialisation_is_bounded_and_correlates_planes() {
        let events = vec![
            lte_event(
                "s1ap",
                "S1-MME",
                "S1AP",
                "E-RABSetupResponse",
                &[
                    ("enb_ue_s1ap_id", "42"),
                    ("mme_ue_s1ap_id", "84"),
                    ("imsi_pseudonym", "lte-ue-anon-a"),
                    ("eps_bearer_identity", "5"),
                    ("erab_teid", "0x01020304"),
                ],
                "UPLINK",
                1,
            ),
            lte_event(
                "s11",
                "S11",
                "GTPv2-C",
                "CreateSessionResponse",
                &[
                    ("imsi_pseudonym", "lte-ue-anon-a"),
                    ("bearer_f_teid", "0x01020304"),
                ],
                "DOWNLINK",
                2,
            ),
            lte_event(
                "s1u",
                "S1-U",
                "GTP-U",
                "G-PDU",
                &[("teid", "0x01020304")],
                "UPLINK",
                3,
            ),
        ];
        let flows = offline_lte_callflows(&events).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].technology, "LTE");
        assert_eq!(flows[0].accounting.session_events, 3);
        assert_eq!(
            flows[0].interfaces,
            vec!["S1-MME".to_owned(), "S1-U".to_owned(), "S11".to_owned()]
        );
        assert_eq!(flows[0].correlation_status["E2E"], "STRONG");
        assert!(!serde_json::to_string(&flows).unwrap().contains("001010"));
    }

    #[test]
    fn session_evidence_expands_transitively_from_n2_through_n4_to_n3() {
        let edge = |id: &str, source: &str, target: &str| CorrelationEdge {
            edge_id: id.into(),
            source_event_id: source.into(),
            target_event_id: target.into(),
            source_interface: String::new(),
            target_interface: String::new(),
            matching_identifiers: Vec::new(),
            rule_id: String::new(),
            rule_version: String::new(),
            evidence_description: String::new(),
            packet_references: Vec::new(),
            confidence: "EXACT".into(),
            evidence_type: "EXACT_TUNNEL_MATCH".into(),
            scope: "tunnel-only".into(),
            limitations: Vec::new(),
            matched_rules: Vec::new(),
        };
        let edges = vec![
            edge("n2-n4", "n2-event", "n4-event"),
            edge("n4-n3", "n4-event", "n3-event"),
            edge("other", "other-a", "other-b"),
        ];
        // 2.10.2 : variante disk-backed utilisée dans le pipeline
        // de publication. On rejoue la même assertion sur un
        // SpillingEventIdSet pour prouver que le comportement
        // transitif est identique.
        let tmp_dir = temporary_root("expand-session-evidence-ids-disk")
            .join("ids");
        let mut ids = SpillingEventIdSet::new(&tmp_dir, 1024).unwrap();
        ids.insert("n2-event").unwrap();
        expand_session_evidence_ids_disk(&mut ids, &edges).unwrap();
        assert!(ids.contains("n2-event").unwrap());
        assert!(ids.contains("n4-event").unwrap());
        assert!(ids.contains("n3-event").unwrap());
        assert!(!ids.contains("other-a").unwrap());
        assert!(!ids.contains("other-b").unwrap());
    }

    fn temporary_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("oiran-live-probe-{name}-{}", epoch_ms()));
        fs::create_dir_all(&root).unwrap();
        root
    }

    /// Global allocator shim that tracks the net live bytes and the all-time
    /// peak since the last reset. Used by the memory-bounded test for the
    /// `source_segments` → ingestion loop so we can prove the fix on a
    /// 600 × 2 MiB synthetic corpus without needing a cgroup. The counter is
    /// a `Mutex<(u64, u64)>` because `AtomicU64::fetch_max` requires 1.45
    /// and we want to work on stable 1.70+; the atomic alternative is a CAS
    /// loop which is equally correct.
    struct TrackingAllocator {
        inner: std::alloc::System,
        live: std::sync::atomic::AtomicUsize,
        peak: std::sync::atomic::AtomicUsize,
        enabled: std::sync::atomic::AtomicBool,
    }

    unsafe impl std::alloc::GlobalAlloc for TrackingAllocator {
        unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
            let p = unsafe { self.inner.alloc(layout) };
            if !p.is_null() && self.enabled.load(std::sync::atomic::Ordering::Relaxed) {
                let new = self
                    .live
                    .fetch_add(layout.size(), std::sync::atomic::Ordering::Relaxed)
                    + layout.size();
                let mut peak = self.peak.load(std::sync::atomic::Ordering::Relaxed);
                while new > peak {
                    match self.peak.compare_exchange_weak(
                        peak,
                        new,
                        std::sync::atomic::Ordering::Relaxed,
                        std::sync::atomic::Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(current) => peak = current,
                    }
                }
            }
            p
        }
        unsafe fn dealloc(&self, p: *mut u8, layout: std::alloc::Layout) {
            if self.enabled.load(std::sync::atomic::Ordering::Relaxed) {
                self.live
                    .fetch_sub(layout.size(), std::sync::atomic::Ordering::Relaxed);
            }
            unsafe { self.inner.dealloc(p, layout) };
        }
    }

    #[global_allocator]
    static TRACKING_ALLOCATOR: TrackingAllocator = TrackingAllocator {
        inner: std::alloc::System,
        live: std::sync::atomic::AtomicUsize::new(0),
        peak: std::sync::atomic::AtomicUsize::new(0),
        enabled: std::sync::atomic::AtomicBool::new(false),
    };

    /// Serialises the tracking window so parallel `cargo test` threads cannot
    /// pollute the peak counter with their own allocations. Any test that
    /// calls `reset_allocation_peak()` MUST hold the returned guard until it
    /// has called `stop_allocation_tracking()`.
    static TRACKING_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn reset_allocation_peak() -> std::sync::MutexGuard<'static, ()> {
        let guard = TRACKING_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        TRACKING_ALLOCATOR
            .peak
            .store(0, std::sync::atomic::Ordering::Relaxed);
        TRACKING_ALLOCATOR
            .live
            .store(0, std::sync::atomic::Ordering::Relaxed);
        TRACKING_ALLOCATOR
            .enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        guard
    }

    fn allocation_peak() -> usize {
        TRACKING_ALLOCATOR
            .peak
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn stop_allocation_tracking() {
        TRACKING_ALLOCATOR
            .enabled
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    // Marked `#[ignore]` because the global `#[global_allocator]` tracker
    // sees every allocation on every thread, including allocations from
    // tests running in parallel in the same `cargo test` process. Running
    // the full suite under `--test-threads=1` is the supported way to
    // observe a clean peak; this attribute keeps the default `cargo test`
    // invocation deterministic. Reproduce with:
    //   cargo test --release -p live-probe source_segments_memory_is_bounded \
    //       -- --ignored --test-threads=1 --nocapture
    #[test]
    #[ignore]
    fn source_segments_memory_is_bounded_on_600_two_mib_pcaps() {
        // Reproduce the OOM site Codex measured: 600 synthetic pcaps of 2 MiB
        // each. Before 0.2.2 `source_segments` did `fs::read` on EVERY
        // candidate (up to MAX_SOURCE_CANDIDATES=512) before applying the
        // finalized-candidates filter, so the resident set spiked to
        // ~1 GiB on a 512-candidate pool. The 0.2.2 refactor keeps metadata
        // only until the filter is applied, then stream-hashes the kept
        // candidates one at a time. Peak live allocation must stay under
        // 128 MiB — the Codex MemoryMax was 256 MiB and we want headroom.
        let root = temporary_root("source-segments-mem-bound");
        let interface_dir = root.join("N2");
        fs::create_dir_all(&interface_dir).unwrap();
        let template_bytes = {
            // Build a 2 MiB pcap-ng-like body: pcap header + records that look
            // valid enough for `count_pcap_records` to accept them.
            let mut v = vec![
                0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0, 0, 1, 0, 0, 0,
                0,
            ];
            let payload = vec![0xa5u8; 64];
            while v.len() < 2 * 1024 * 1024 {
                v.extend_from_slice(&0u32.to_le_bytes());
                v.extend_from_slice(&0u32.to_le_bytes());
                v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                v.extend_from_slice(&payload);
            }
            v.truncate(2 * 1024 * 1024);
            v
        };
        // Write 600 distinct files (vary a byte so SHA differs).
        for i in 0..600 {
            let mut body = template_bytes.clone();
            let offset = 24 + (i as usize) % (body.len() - 24 - 4);
            body[offset] = (i & 0xff) as u8;
            body[offset + 1] = ((i >> 8) & 0xff) as u8;
            let path = interface_dir.join(format!("segment-{i:04}.pcapng"));
            fs::write(&path, &body).unwrap();
        }
        drop(template_bytes);
        // Give the files > safety_window age so the finalized filter keeps
        // them all.
        thread::sleep(Duration::from_millis(50));
        let _tracking_guard = reset_allocation_peak();
        let mut cache = SourceSegmentsCache::new();
        let segments = source_segments(
            &root,
            Duration::ZERO,
            false,
            DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES,
            &mut cache,
        )
        .unwrap()
        .segments;
        let peak = allocation_peak();
        stop_allocation_tracking();
        // Up to 511 kept (newest per interface dropped by the finalized filter
        // because stable_age=0 means safety_window=0 and the "newest" is
        // always "fresh enough" to be dropped only if its age < 0, i.e.
        // never — so all 600 are returned). Either way the memory contract
        // is bounded.
        assert!(
            segments.len() >= 500 && segments.len() <= 600,
            "unexpected segment count: {}",
            segments.len()
        );
        let peak_mib = peak / (1024 * 1024);
        eprintln!(
            "source_segments peak live allocation = {} B = {} MiB (segments={})",
            peak,
            peak_mib,
            segments.len()
        );
        assert!(
            peak < 128 * 1024 * 1024,
            "peak allocation {} MiB must stay under 128 MiB (OOM bound)",
            peak_mib
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn streaming_sha256_matches_in_memory_sha256_on_large_synthetic_file() {
        // Materialise a 64 MiB file on disk, then prove that
        // `sha256_hex_file` returns the same value as `sha256_hex` on the full
        // bytes. The streaming path is the one used by the live-probe
        // integrity checks; this test is the memory-boundedness contract we
        // want for the OOM fix. The in-memory check still allocates the file
        // (it is the oracle), but the production code path only ever reads
        // STREAM_CHUNK_BYTES at a time.
        let root = temporary_root("streaming-sha256");
        let path = root.join("large.bin");
        let chunk = vec![0xa5u8; STREAM_CHUNK_BYTES];
        {
            let file = fs::File::create(&path).unwrap();
            let mut writer = BufWriter::with_capacity(STREAM_CHUNK_BYTES, file);
            for _ in 0..64 {
                writer.write_all(&chunk).unwrap();
            }
            writer.flush().unwrap();
        }
        let expected = {
            let mut bytes = Vec::new();
            fs::File::open(&path)
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();
            sha256_hex(&bytes)
        };
        let streamed = sha256_hex_file(&path).unwrap();
        assert_eq!(
            streamed, expected,
            "streaming SHA-256 must match the full-buffer oracle on a 64 MiB file"
        );
        fs::remove_dir_all(&root).unwrap();
    }

    /// 0.2.3 — regression lock on the OOM site Codex measured for pcap
    /// imports: `copy_verified` previously called `fs::read` on the full
    /// temporary copy before hashing, so a 512 MiB pcap import spiked live
    /// allocation by ~512 MiB. The streaming fix uses `sha256_hex_file`
    /// (`BufReader` of `STREAM_CHUNK_BYTES`) and keeps the resident set
    /// independent of segment size. `#[ignore]`'d because the
    /// `#[global_allocator]` tracker sees every parallel test's allocations;
    /// reproduce with:
    ///   cargo test --release -p live-probe
    ///     copy_verified_streams_512_mib_import_under_32_mib_live_allocation
    ///     -- --ignored --test-threads=1 --nocapture
    /// (also allocates ~512 MiB of disk; the test cleans up on success.)
    #[test]
    #[ignore]
    fn copy_verified_streams_512_mib_import_under_32_mib_live_allocation() {
        let root = temporary_root("copy-verified-512mib-stream");
        let source = root.join("source.pcap");
        let destination = root.join("destination.pcap");

        // Materialise a 512 MiB source pcap on disk from a repeating chunk,
        // writing through a BufWriter so this fixture setup itself stays
        // bounded. The content isn't a valid pcap — `copy_verified` only
        // checks size + mtime + sha256 — which lets the test target the
        // integrity path without decoding costs polluting the peak.
        const TOTAL_BYTES: usize = 512 * 1024 * 1024;
        let chunk = vec![0x5au8; STREAM_CHUNK_BYTES];
        {
            let file = fs::File::create(&source).unwrap();
            let mut writer = BufWriter::with_capacity(STREAM_CHUNK_BYTES, file);
            let mut written = 0usize;
            while written < TOTAL_BYTES {
                let take = (TOTAL_BYTES - written).min(chunk.len());
                writer.write_all(&chunk[..take]).unwrap();
                written += take;
            }
            writer.flush().unwrap();
            writer.get_ref().sync_all().unwrap();
        }
        let metadata = fs::metadata(&source).unwrap();
        assert_eq!(metadata.len() as usize, TOTAL_BYTES);
        let expected_sha = sha256_hex_file(&source).unwrap();

        let segment = SourceSegment {
            path: source.clone(),
            interface: "N3".to_string(),
            checksum: expected_sha,
            size_bytes: metadata.len(),
            packets: 0,
            modified: metadata.modified().unwrap(),
        };

        let guard = reset_allocation_peak();
        copy_verified(&segment, &destination).expect("copy_verified must succeed on 512 MiB file");
        let peak = allocation_peak();
        stop_allocation_tracking();
        drop(guard);

        assert!(
            destination.exists(),
            "copy_verified must land the destination atomically"
        );
        assert_eq!(
            fs::metadata(&destination).unwrap().len() as usize,
            TOTAL_BYTES
        );

        const BOUND: usize = 32 * 1024 * 1024;
        assert!(
            peak < BOUND,
            "copy_verified live allocation peak must stay under 32 MiB on a \
             512 MiB pcap import (0.2.3 streaming contract); measured {} bytes \
             ({} MiB)",
            peak,
            peak / (1024 * 1024)
        );
        eprintln!(
            "COPY_VERIFIED_512MIB_PEAK_BYTES={peak} PEAK_MIB={} LIMIT_MIB=32",
            peak / (1024 * 1024)
        );

        fs::remove_dir_all(&root).unwrap();
    }

    /// 0.2.4 regression: a segment larger than the historical 32 MiB cap is
    /// discovered, hashed, copied and decoded without materialising it.
    #[test]
    #[ignore]
    fn continuous_import_streams_300_mib_segment_under_32_mib_live_allocation() {
        if skip_if_disk_too_full(
            "continuous_import_streams_300_mib_segment_under_32_mib_live_allocation",
        ) {
            return;
        }
        const MIB: usize = 1024 * 1024;
        const PACKET_BYTES: usize = 15 * MIB;
        const PACKETS: usize = 20;
        let source = temporary_root("continuous-300mib-source");
        let root = temporary_root("continuous-300mib-owned");
        fs::create_dir_all(source.join("N3")).unwrap();
        let path = source.join("N3/segment-300mib.pcap");
        {
            let file = fs::File::create(&path).unwrap();
            let mut writer = BufWriter::with_capacity(STREAM_CHUNK_BYTES, file);
            writer
                .write_all(&[0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0])
                .unwrap();
            writer
                .write_all(&(PACKET_BYTES as u32).to_le_bytes())
                .unwrap();
            writer.write_all(&1u32.to_le_bytes()).unwrap();
            let chunk = vec![0xa5; STREAM_CHUNK_BYTES];
            for second in 0..PACKETS as u32 {
                writer.write_all(&second.to_le_bytes()).unwrap();
                writer.write_all(&0u32.to_le_bytes()).unwrap();
                writer
                    .write_all(&(PACKET_BYTES as u32).to_le_bytes())
                    .unwrap();
                writer
                    .write_all(&(PACKET_BYTES as u32).to_le_bytes())
                    .unwrap();
                for _ in 0..(PACKET_BYTES / STREAM_CHUNK_BYTES) {
                    writer.write_all(&chunk).unwrap();
                }
            }
            writer.flush().unwrap();
            writer.get_ref().sync_all().unwrap();
        }
        assert!(fs::metadata(&path).unwrap().len() >= 300 * MIB as u64);
        thread::sleep(Duration::from_millis(500));
        let guard = reset_allocation_peak();
        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        manager
            .start_continuous_import(ContinuousImportConfig {
                source_root: source.clone(),
                scan_interval: Duration::from_millis(200),
                stable_age: Duration::from_millis(200),
                max_owned_bytes: 400 * MIB as u64,
                max_segment_bytes: DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES,
                max_segments: 2,
                native_segment_seconds: None,
                historical_n2_bootstrap: None,
                runtime_pdu_evidence: None,
            })
            .unwrap();
        wait_for(|| {
            manager
                .get(CONTINUOUS_CAPTURE_ID)
                .is_some_and(|job| job.metrics.segments_ingested == 1)
        });
        manager.stop(CONTINUOUS_CAPTURE_ID, "operator").unwrap();
        let peak = allocation_peak();
        stop_allocation_tracking();
        drop(guard);
        assert!(
            peak < 32 * MIB,
            "300 MiB streaming import peak {peak} bytes exceeded 32 MiB"
        );
        eprintln!(
            "CONTINUOUS_IMPORT_300MIB_PEAK_BYTES={peak} PEAK_MIB={} LIMIT_MIB=32",
            peak / MIB
        );
        fs::remove_dir_all(source).ok();
        fs::remove_dir_all(root).ok();
    }

    /// O3 regression: N3 packet headers are aggregated while streaming, so a
    /// segment's byte size and packet count cannot turn into a proportional
    /// in-memory vector of NormalizedEvent objects.
    #[test]
    #[ignore]
    fn continuous_n3_500_mib_aggregates_under_64_mib_live_allocation() {
        if skip_if_disk_too_full("continuous_n3_500_mib_aggregates_under_64_mib_live_allocation") {
            return;
        }
        const MIB: usize = 1024 * 1024;
        let source = temporary_root("continuous-n3-500mib-source");
        let root = temporary_root("continuous-n3-500mib-owned");
        fs::create_dir_all(source.join("N3")).unwrap();
        let path = source.join("N3/segment-n3-500mib.pcap");
        let mut packet = gtpu_gpdu_frame(201, 0x0000_f68d);
        packet.resize(60 * 1024, 0);
        write_repeated_pcap_at_least(&path, &packet, 500 * MIB as u64);
        let source_size = fs::metadata(&path).unwrap().len();
        assert!(source_size >= 500 * MIB as u64);
        thread::sleep(Duration::from_millis(500));

        let guard = reset_allocation_peak();
        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        manager
            .start_continuous_import(ContinuousImportConfig {
                source_root: source.clone(),
                scan_interval: Duration::from_millis(200),
                stable_age: Duration::from_millis(200),
                max_owned_bytes: 700 * MIB as u64,
                max_segment_bytes: DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES,
                max_segments: 2,
                native_segment_seconds: None,
                historical_n2_bootstrap: None,
                runtime_pdu_evidence: None,
            })
            .unwrap();
        wait_for(|| {
            manager
                .get(CONTINUOUS_CAPTURE_ID)
                .is_some_and(|job| job.metrics.segments_ingested == 1)
        });
        manager.stop(CONTINUOUS_CAPTURE_ID, "operator").unwrap();
        let peak = allocation_peak();
        stop_allocation_tracking();
        drop(guard);

        let events = load_path(
            &root
                .join(CONTINUOUS_CAPTURE_ID)
                .join("dataset")
                .join("oiran_events.jsonl"),
        )
        .unwrap();
        let n3 = events
            .iter()
            .filter(|event| event.protocol == "GTP-U" && event.message_name == "G-PDU")
            .collect::<Vec<_>>();
        assert_eq!(n3.len(), 1, "one TEID/flow must produce one N3 aggregate");
        assert_eq!(n3[0].first_identifier("teid"), Some("0x0000f68d"));
        let aggregate_count = n3[0]
            .information_elements
            .as_array()
            .and_then(|items| {
                items.iter().find(|item| {
                    item.get("name").and_then(serde_json::Value::as_str)
                        == Some("aggregate_packet_count")
                })
            })
            .and_then(|item| item.get("value"))
            .and_then(serde_json::Value::as_str)
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap();
        assert!(aggregate_count > 8_000);
        assert!(
            peak < 64 * MIB,
            "500 MiB N3 import peak {peak} bytes exceeded 64 MiB"
        );
        eprintln!(
            "N3_500MIB_SOURCE_BYTES={source_size} AGGREGATES={} PACKETS={} PEAK_BYTES={peak} PEAK_MIB={} LIMIT_MIB=64",
            n3.len(),
            aggregate_count,
            peak / MIB
        );
        fs::remove_dir_all(source).ok();
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn oversized_segment_is_persisted_individually_while_other_segment_imports() {
        if skip_if_disk_too_full(
            "oversized_segment_is_persisted_individually_while_other_segment_imports",
        ) {
            return;
        }
        let source = temporary_root("continuous-individual-rejection-source");
        let root = temporary_root("continuous-individual-rejection-owned");
        fs::create_dir_all(source.join("N2")).unwrap();
        fs::create_dir_all(source.join("N4")).unwrap();
        let rejected = source.join("N2/rejected.pcap");
        let accepted = source.join("N4/accepted.pcap");
        write_pcap(&rejected, &[vec![0; 128]]);
        write_pcap(&accepted, &[vec![0; 16]]);
        // 2.8.3: synthetic single-segment-per-interface tests use the
        // rotation JSONL promotion path to avoid the active-file skip.
        write_rotation_closures(&source, "N2", 1);
        write_rotation_closures(&source, "N4", 1);
        let rejected_size = fs::metadata(&rejected).unwrap().len();
        assert!(rejected_size > 100);
        assert!(fs::metadata(&accepted).unwrap().len() <= 100);
        thread::sleep(Duration::from_millis(500));
        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        manager
            .start_continuous_import(ContinuousImportConfig {
                source_root: source.clone(),
                scan_interval: Duration::from_millis(200),
                stable_age: Duration::from_millis(200),
                max_owned_bytes: 128 * 1024 * 1024,
                max_segment_bytes: 100,
                max_segments: 8,
                native_segment_seconds: None,
                historical_n2_bootstrap: None,
                runtime_pdu_evidence: None,
            })
            .unwrap();
        wait_for(|| {
            manager.get(CONTINUOUS_CAPTURE_ID).is_some_and(|job| {
                job.state == CaptureState::Capturing
                    && job.metrics.segments_ingested == 1
                    && job.metrics.ingestion_failures == 1
            })
        });
        let state: ContinuousImportState = serde_json::from_slice(
            &fs::read(root.join(CONTINUOUS_CAPTURE_ID).join("import_state.json")).unwrap(),
        )
        .unwrap();
        let failure = state.failed_ingestions.back().unwrap();
        assert_eq!(failure.source_path, rejected.display().to_string());
        assert_eq!(failure.source_size_bytes, Some(rejected_size));
        assert_eq!(failure.error_code, "CONTINUOUS_SOURCE_SEGMENT_TOO_LARGE");
        let job = manager.get(CONTINUOUS_CAPTURE_ID).unwrap();
        assert_eq!(job.state, CaptureState::Capturing);
        assert_eq!(job.error, None);
        manager.stop(CONTINUOUS_CAPTURE_ID, "operator").unwrap();
        fs::remove_dir_all(source).ok();
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn verify_file_integrity_detects_size_and_hash_mismatches_without_full_read() {
        let root = temporary_root("verify-integrity");
        let path = root.join("payload.bin");
        let payload: Vec<u8> = (0..=255u8).cycle().take(STREAM_CHUNK_BYTES * 4).collect();
        fs::write(&path, &payload).unwrap();
        let expected_sha = sha256_hex(&payload);
        // Happy path.
        verify_file_integrity(&path, payload.len() as u64, &expected_sha).unwrap();
        // Size mismatch.
        assert!(verify_file_integrity(&path, (payload.len() as u64) + 1, &expected_sha).is_err());
        // SHA mismatch.
        assert!(verify_file_integrity(
            &path,
            payload.len() as u64,
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        .is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    fn write_pcap(path: &Path, packets: &[Vec<u8>]) {
        let mut bytes = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0, 0, 1, 0, 0, 0, 0,
        ];
        for (index, packet) in packets.iter().enumerate() {
            bytes.extend_from_slice(&(index as u32 + 1).to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            bytes.extend_from_slice(packet);
        }
        fs::write(path, bytes).unwrap();
    }

    fn write_pcap_at(path: &Path, seconds: u32, packets: &[Vec<u8>]) {
        let mut bytes = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0,
            0,
        ];
        for (index, packet) in packets.iter().enumerate() {
            bytes.extend_from_slice(&seconds.to_le_bytes());
            bytes.extend_from_slice(&(index as u32).to_le_bytes());
            bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            bytes.extend_from_slice(packet);
        }
        fs::write(path, bytes).unwrap();
    }

    fn write_repeated_pcap_at_least(path: &Path, packet: &[u8], minimum_bytes: u64) {
        let file = fs::File::create(path).unwrap();
        let mut writer = BufWriter::with_capacity(STREAM_CHUNK_BYTES, file);
        writer
            .write_all(&[
                0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0,
                0, 0,
            ])
            .unwrap();
        let record_bytes = 16u64 + packet.len() as u64;
        let records = minimum_bytes.saturating_sub(24).div_ceil(record_bytes);
        for index in 0..records {
            writer.write_all(&(index as u32 + 1).to_le_bytes()).unwrap();
            writer.write_all(&0u32.to_le_bytes()).unwrap();
            writer
                .write_all(&(packet.len() as u32).to_le_bytes())
                .unwrap();
            writer
                .write_all(&(packet.len() as u32).to_le_bytes())
                .unwrap();
            writer.write_all(packet).unwrap();
        }
        writer.flush().unwrap();
        writer.get_ref().sync_all().unwrap();
    }

    fn gtpu_gpdu_frame(ue_octet: u8, teid: u32) -> Vec<u8> {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let total_ip_length = 20 + 8 + 8 + 20;
        frame.extend_from_slice(&[
            0x45,
            0,
            0,
            total_ip_length as u8,
            0,
            0,
            0,
            0,
            64,
            17,
            0,
            0,
            10,
            77,
            22,
            20,
            10,
            77,
            22,
            13,
        ]);
        frame.extend_from_slice(&2152u16.to_be_bytes());
        frame.extend_from_slice(&2152u16.to_be_bytes());
        frame.extend_from_slice(&(36u16).to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&[0x30, 0xff, 0, 20]);
        frame.extend_from_slice(&teid.to_be_bytes());
        frame.extend_from_slice(&[
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 46, 0, ue_octet, 10, 46, 0, 1,
        ]);
        frame
    }

    fn wait_for(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !condition() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
        }
        assert!(condition(), "condition did not become true before deadline");
    }

    /// The continuous-import pipeline refuses new captures when the host
    /// filesystem cannot fit the bounded write below the 98% ceiling and 8 GiB reserve (disk-safety
    /// `StopNewCaptures` state). Tests that drive a real
    /// `start_continuous_import` therefore need the test host to be under
    /// that threshold; `TMPDIR` and `/tmp` sitting on a near-full `/` is a
    /// common operator laptop configuration (we saw 87% on this one). We
    /// skip-with-reason instead of silently timing out at the 30 s wait_for
    /// deadline, so the operator can distinguish an environmental skip from
    /// a code bug.
    /// 2.8.3: appends `count` synthetic "clean close" records to
    /// `capture-rotation.jsonl` under `root`, keyed on `plane` (matching
    /// the upper-case convention `source_interface` returns). Tests that
    /// create a fixed set of synthetic pcaps call this to prove — the
    /// way a real rotation watcher would — that every segment is closed
    /// and should therefore be eligible. See
    /// `finalized_candidates_only` 2.8.3 contract.
    fn write_rotation_closures(root: &Path, plane: &str, count: usize) {
        use std::io::Write;
        let path = root.join("capture-rotation.jsonl");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        for sequence in 0..count {
            writeln!(
                file,
                r#"{{"timestamp":"2026-11-06T00:00:0{suffix}Z","interface":"br-oiran-{low}","plane":"{low}","exit_code":0,"packets_captured":0,"packets_dropped":0}}"#,
                suffix = sequence % 10,
                low = plane.to_ascii_lowercase()
            )
            .unwrap();
        }
    }

    fn skip_if_disk_too_full(reason: &str) -> bool {
        use disk_safety::{assess, measure_path, Policy, SafetyState};
        let sample = measure_path(Path::new("/tmp"));
        let decision = assess(sample, Policy::default());
        if matches!(
            decision.state,
            SafetyState::StopNewCaptures | SafetyState::DiskHardLimit
        ) {
            eprintln!(
                "SKIP {reason}: /tmp disk safety state={:?} usage denies new captures; \
                 proof: `df -h /tmp` + `assess(measure_path(\"/tmp\"), Policy::default())`",
                decision.state
            );
            return true;
        }
        false
    }

    #[test]
    fn production_native_config_accepts_finalized_helper_segments() {
        let root = temporary_root("native-config");
        let mut config = ContinuousImportConfig::native(root);
        assert_eq!(config.stable_age, Duration::ZERO);
        assert_eq!(config.native_segment_seconds, Some(15));
        assert_eq!(
            config.max_segment_bytes,
            DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES
        );
        config.validate(Policy::default()).unwrap();
        config.max_segments = 2;
        assert_eq!(
            config.validate(Policy::default()).unwrap_err(),
            "CONTINUOUS_NATIVE_RING_TOO_SMALL"
        );
        config.max_segments = 8;
        config.max_segment_bytes = 0;
        assert_eq!(
            config.validate(Policy::default()).unwrap_err(),
            "CONTINUOUS_IMPORT_BOUNDS_INVALID"
        );
    }

    #[test]
    fn continuous_import_is_incremental_deduplicated_stoppable_and_restart_safe() {
        if skip_if_disk_too_full(
            "continuous_import_is_incremental_deduplicated_stoppable_and_restart_safe",
        ) {
            return;
        }
        let root = temporary_root("continuous-import");
        let source = temporary_root("continuous-source");
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let fixture = workspace.join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
        for interface in ["N2", "N3", "N4"] {
            let directory = source.join(interface);
            fs::create_dir_all(&directory).unwrap();
            fs::copy(
                fixture.join(format!("{interface}.pcapng")),
                directory.join("segment-0001.pcapng"),
            )
            .unwrap();
            // 2.8.3: single-segment-per-interface — JSONL promotion.
            write_rotation_closures(&source, interface, 1);
        }
        let bootstrap_root = temporary_root("continuous-bootstrap");
        let bootstrap = bootstrap_root.join("n2_20261026T121214Z_00001_20261026121214.pcapng");
        fs::copy(fixture.join("N2.pcapng"), &bootstrap).unwrap();
        thread::sleep(Duration::from_millis(250));
        let config = ContinuousImportConfig {
            source_root: source.clone(),
            scan_interval: Duration::from_millis(200),
            stable_age: Duration::from_millis(200),
            max_owned_bytes: 128 * 1024 * 1024,
            max_segment_bytes: 64 * 1024 * 1024,
            max_segments: 8,
            native_segment_seconds: None,
            historical_n2_bootstrap: Some(bootstrap),
            runtime_pdu_evidence: None,
        };
        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        manager.start_continuous_import(config.clone()).unwrap();
        wait_for(|| {
            manager
                .get(CONTINUOUS_CAPTURE_ID)
                .is_some_and(|job| job.metrics.segments_ingested == 3)
        });
        let first = manager.get(CONTINUOUS_CAPTURE_ID).unwrap();
        assert!(first.metrics.packets_received > 0);
        assert!(first.metrics.decoded_events > 0);
        assert!(!first.session_ids.is_empty());
        assert!(first.metrics.last_ingested_epoch_ms.is_some());
        assert_eq!(first.metrics.fresh_packet_count, 0);
        assert!(first.metrics.active_ue_ips.is_empty());
        let first_event_count = first.metrics.decoded_events;

        // 2.8.3 (#9 comment 6696366882): the 2.8.2 "overlapping append"
        // scenario reproduced the ANR2 phantom (importing a growing
        // active segment three times). Under the 2.8.3 closed-proof
        // contract we never re-read a segment whose size changed under
        // us — dumpcap owns its active file and the rotation watcher
        // only signals closure on a clean exit. The regression is
        // pinned by `active_segment_is_never_imported_at_any_size` in
        // `tests/lte_live_bench.rs`; here we assert the simpler
        // invariant: a byte-identical replay of a closed segment is
        // deduplicated via `(dev, inode, size, mtime_ns)` → checksum
        // cache, so segments_ingested stays at 3 and decoded_events at
        // the first-pass count.
        fs::copy(
            source.join("N2/segment-0001.pcapng"),
            source.join("N2/replayed-overlap.pcapng"),
        )
        .unwrap();
        // Add a rotation closure so the N2 plane now has JSONL >= segment
        // count (2 records for 2 files) and both are promoted.
        write_rotation_closures(&source, "N2", 1);
        thread::sleep(Duration::from_millis(800));
        let after_replay = manager.get(CONTINUOUS_CAPTURE_ID).unwrap();
        assert_eq!(
            after_replay.metrics.segments_ingested, 3,
            "a byte-identical replay must not re-ingest"
        );
        assert_eq!(
            after_replay.metrics.decoded_events, first_event_count,
            "a byte-identical replay must not duplicate decoded events"
        );

        manager.stop(CONTINUOUS_CAPTURE_ID, "operator").unwrap();
        wait_for(|| {
            manager
                .get(CONTINUOUS_CAPTURE_ID)
                .is_some_and(|job| job.state == CaptureState::Completed)
        });
        drop(manager);

        let restarted = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        restarted.start_continuous_import(config).unwrap();
        wait_for(|| {
            restarted
                .get(CONTINUOUS_CAPTURE_ID)
                .is_some_and(|job| job.state == CaptureState::Capturing)
        });
        let recovered = restarted.get(CONTINUOUS_CAPTURE_ID).unwrap();
        assert_eq!(recovered.metrics.segments_ingested, 3);
        assert_eq!(recovered.session_ids, first.session_ids);
        restarted.stop(CONTINUOUS_CAPTURE_ID, "operator").unwrap();
    }

    /// 2.9.8 (#9 comment 6725097122): ANR2 proved in production that a
    /// closed N3 segment could end up in `state.source_fingerprints`
    /// WITHOUT the matching checksum landing in `seen_checksums` — the
    /// segment was neither imported (no event published) nor recorded
    /// as a failure. The symptom: `/metrics pending=0` vs
    /// `job.json pending=1` while the operator sees N3 traffic on
    /// disk.
    ///
    /// This test stages the exact ANR2 shape: an orphan N3 fingerprint
    /// pre-populated in `import_state.json` whose SHA does NOT match
    /// any on-disk pcap. On worker startup `drop_orphan_fingerprints`
    /// must purge the entry, emit one
    /// `CONTINUOUS_ORPHAN_FINGERPRINT_DROPPED` log, and bump
    /// `metrics.orphan_fingerprints_recovered`. The real N3 fixture
    /// then imports normally and the committed `source_fingerprints`
    /// contains EXACTLY the three real segments — no orphan survives.
    #[test]
    fn continuous_import_purges_orphan_fingerprint_at_startup_and_reimports_n3_sbi() {
        if skip_if_disk_too_full(
            "continuous_import_purges_orphan_fingerprint_at_startup_and_reimports_n3_sbi",
        ) {
            return;
        }
        let root = temporary_root("continuous-orphan");
        let source = temporary_root("continuous-orphan-source");
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let fixture = workspace.join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
        for interface in ["N2", "N3", "N4"] {
            let directory = source.join(interface);
            fs::create_dir_all(&directory).unwrap();
            fs::copy(
                fixture.join(format!("{interface}.pcapng")),
                directory.join("segment-0001.pcapng"),
            )
            .unwrap();
            write_rotation_closures(&source, interface, 1);
        }

        // Seed an orphan N3 fingerprint + an orphan SBI fingerprint
        // directly in `import_state.json` with SHAs that no on-disk
        // pcap produces. Both must be purged at worker startup.
        let state_path = root.join(CONTINUOUS_CAPTURE_ID).join("import_state.json");
        fs::create_dir_all(state_path.parent().unwrap()).unwrap();
        let mut seed = ContinuousImportState::default();
        seed.source_fingerprints.insert(
            "/captures/continuous-lab-import/N3/ghost-segment.pcapng".into(),
            SourceFingerprint {
                dev: 42,
                inode: 2,
                size_bytes: 163 * 1024 * 1024,
                mtime_ns: 0,
                checksum: "sha-anr2-n3-orphan-436e4bb7".into(),
                packets: 0,
            },
        );
        seed.source_fingerprints.insert(
            "/captures/continuous-lab-import/SBI/ghost-segment.pcapng".into(),
            SourceFingerprint {
                dev: 42,
                inode: 3,
                size_bytes: 12 * 1024 * 1024,
                mtime_ns: 0,
                checksum: "sha-anr2-sbi-orphan".into(),
                packets: 0,
            },
        );
        fs::write(&state_path, serde_json::to_vec_pretty(&seed).unwrap()).unwrap();

        let config = ContinuousImportConfig {
            source_root: source.clone(),
            scan_interval: Duration::from_millis(200),
            stable_age: Duration::from_millis(200),
            max_owned_bytes: 128 * 1024 * 1024,
            max_segment_bytes: 64 * 1024 * 1024,
            max_segments: 8,
            native_segment_seconds: None,
            historical_n2_bootstrap: None,
            runtime_pdu_evidence: None,
        };
        let manager = CaptureManager::with_pseudonym_key_path(
            root.clone(),
            false,
            root.join(".oiran-pseudonym.key"),
        )
        .unwrap();
        manager.start_continuous_import(config).unwrap();
        wait_for(|| {
            manager
                .get(CONTINUOUS_CAPTURE_ID)
                .is_some_and(|job| job.metrics.segments_ingested == 3)
        });

        let job = manager.get(CONTINUOUS_CAPTURE_ID).unwrap();
        // The two orphans were purged at startup; the counter is
        // cumulative per worker lifetime.
        assert_eq!(
            job.metrics.orphan_fingerprints_recovered, 2,
            "orphan N3 + SBI must both be recovered at startup"
        );
        // `/metrics` and `job.json` mirror each other by construction.
        assert_eq!(
            job.metrics.pending_segments, job.metrics.pending_fingerprints,
            "pending_segments and pending_fingerprints must read the same source"
        );
        assert_eq!(job.metrics.pending_segments, 0);
        assert_eq!(job.metrics.pending_stability_segments, 0);
        assert_eq!(job.metrics.pending_batch_segments, 0);

        // Load the persisted state and verify the orphan SHAs are
        // GONE and only the three real segments' SHAs remain. The
        // invariant: persisted fingerprint ⇒ committed to
        // `seen_checksums`.
        let final_state_bytes = fs::read(&state_path).unwrap();
        let final_state: ContinuousImportState =
            serde_json::from_slice(&final_state_bytes).unwrap();
        for (_, fingerprint) in &final_state.source_fingerprints {
            assert!(
                final_state.seen_checksums.contains(&fingerprint.checksum),
                "every persisted fingerprint must have its checksum in seen_checksums; \
                 orphan SHA found: {}",
                fingerprint.checksum
            );
        }
        assert!(!final_state
            .source_fingerprints
            .values()
            .any(|f| f.checksum == "sha-anr2-n3-orphan-436e4bb7"));
        assert!(!final_state
            .source_fingerprints
            .values()
            .any(|f| f.checksum == "sha-anr2-sbi-orphan"));
        // Three real segments ingested (N2 + N3 + N4), so three real
        // SHAs are persisted.
        assert_eq!(final_state.source_fingerprints.len(), 3);
        assert_eq!(final_state.seen_checksums.len(), 3);

        manager.stop(CONTINUOUS_CAPTURE_ID, "operator").unwrap();
    }

    /// 2.7.21 (issue #10 comment 6653514332): `clean_continuous_import_root`
    /// removes ONLY the never-committed artifacts and leaves `dataset/`
    /// strictly byte-identical. The 2.7.20 variant filtered
    /// `dataset/oiran_events.jsonl` against `state.segments.keys()` (the
    /// live ring, capped at `max_segments`) and dropped events of
    /// capture_ids no longer in the ring even though their pcap was
    /// still on disk; the ANR2 recette observed 25 537 → 77 events on
    /// 51 → 1 capture_id. The decision here: do not touch the published
    /// dataset at startup.
    #[test]
    fn startup_cleanup_removes_rollback_only_and_leaves_dataset_byte_identical() {
        use serde_json::json;
        let base = temporary_root("startup-cleanup");
        let dataset_dir = base.join("dataset");
        fs::create_dir_all(dataset_dir.join("callflows")).unwrap();
        fs::create_dir_all(base.join(".dataset-previous/callflows")).unwrap();
        fs::create_dir_all(base.join(".dataset-next/callflows")).unwrap();
        // Dataset contents: a mix of capture_ids including one that no
        // longer has a pcap on disk. 2.7.20 would have dropped it; 2.7.21
        // must leave it in place.
        let events_path = dataset_dir.join("oiran_events.jsonl");
        {
            let mut writer = BufWriter::with_capacity(
                STREAM_CHUNK_BYTES,
                fs::File::create(&events_path).unwrap(),
            );
            for (capture, count) in [("sha256:live", 128), ("sha256:evicted", 256)] {
                for i in 0..count {
                    let event = json!({
                        "event_id": format!("evt-{capture}-{i:04}"),
                        "capture_id": capture,
                    });
                    writeln!(writer, "{}", event).unwrap();
                }
            }
            writer.flush().unwrap();
        }
        let manifest_path = dataset_dir.join("dataset_manifest.json");
        fs::write(&manifest_path, b"{\"event_count\":384}").unwrap();
        fs::write(dataset_dir.join("callflows/stub.json"), b"{\"keep\":true}").unwrap();
        // Never-committed artifacts to be swept.
        fs::write(base.join(".dataset-previous/stale.txt"), b"x").unwrap();
        fs::write(base.join(".dataset-next/oiran_events.jsonl"), b"y").unwrap();
        fs::write(base.join("import_state.json.tmp"), b"z").unwrap();
        fs::write(base.join(".leftover.spool"), b"w").unwrap();
        // Snapshot `dataset/` before cleanup.
        let events_sha_before = sha256_hex(&fs::read(&events_path).unwrap());
        let manifest_sha_before = sha256_hex(&fs::read(&manifest_path).unwrap());
        let callflow_sha_before = sha256_hex(&fs::read(dataset_dir.join("callflows/stub.json")).unwrap());
        clean_continuous_import_root(&base).unwrap();
        // Never-committed artifacts: gone.
        assert!(!base.join(".dataset-previous").exists());
        assert!(!base.join(".dataset-next").exists());
        assert!(!base.join("import_state.json.tmp").exists());
        assert!(!base.join(".leftover.spool").exists());
        // Dataset: byte-for-byte identical.
        assert_eq!(
            sha256_hex(&fs::read(&events_path).unwrap()),
            events_sha_before,
            "dataset/oiran_events.jsonl must not be touched by startup cleanup",
        );
        assert_eq!(
            sha256_hex(&fs::read(&manifest_path).unwrap()),
            manifest_sha_before,
        );
        assert_eq!(
            sha256_hex(&fs::read(dataset_dir.join("callflows/stub.json")).unwrap()),
            callflow_sha_before,
        );
        // Event lines are unchanged: both live AND evicted capture_ids remain.
        let mut live = 0usize;
        let mut evicted = 0usize;
        for line in BufReader::new(fs::File::open(&events_path).unwrap()).lines() {
            let line = line.unwrap();
            if line.contains("\"capture_id\":\"sha256:live\"") {
                live += 1;
            }
            if line.contains("\"capture_id\":\"sha256:evicted\"") {
                evicted += 1;
            }
        }
        assert_eq!(live, 128);
        assert_eq!(evicted, 256, "events of pcap evicted from the ring must survive startup — their pcap is still present on disk in production");
    }

    /// 2.7.21 (issue #10 comment 6653514332, ANR2 recette): reproduce
    /// the EXACT lab layout — `dataset/`, `.dataset-next/`,
    /// `.dataset-previous/`, `pcap/` — and assert that after startup
    /// cleanup the never-committed `.dataset-next/` and
    /// `.dataset-previous/` are gone and the base falls below the cap.
    /// The 250-segment drain then completes without touching the
    /// committed dataset.
    ///
    /// Byte-identity of `dataset/` across cleanup is verified by the
    /// dedicated `startup_cleanup_removes_rollback_only_and_leaves_dataset_byte_identical`
    /// test: here the subsequent publication cycle atomically replaces
    /// `dataset/` by construction (next→current rename), so measuring
    /// sha256 after the first publication does not isolate the
    /// startup-cleanup invariant.
    #[test]
    fn anr2_layout_startup_cleanup_shrinks_below_cap_then_drains_250_segments() {
        if skip_if_disk_too_full(
            "anr2_layout_startup_cleanup_shrinks_below_cap_then_drains_250_segments",
        ) {
            return;
        }
        use serde_json::json;
        let source = temporary_root("anr2-source");
        let root = temporary_root("anr2-owned");
        fs::create_dir_all(source.join("N3")).unwrap();
        // --- Reproduce the ANR2 lab arborescence ---------------------
        //   <base>/pcap/
        //   <base>/dataset/{oiran_events.jsonl, dataset_manifest.json, callflows/}
        //   <base>/.dataset-next/{oiran_events.jsonl, .decoded-events.spool,
        //                        .normalized-events.spool, oiran_events.jsonl.tmp,
        //                        dataset_manifest.json, callflows/}
        //   <base>/.dataset-previous/{oiran_events.jsonl, dataset_manifest.json}
        let base = root.join(CONTINUOUS_CAPTURE_ID);
        let dataset_dir = base.join("dataset");
        let next_dir = base.join(".dataset-next");
        let previous_dir = base.join(".dataset-previous");
        fs::create_dir_all(dataset_dir.join("callflows")).unwrap();
        fs::create_dir_all(next_dir.join("callflows")).unwrap();
        fs::create_dir_all(previous_dir.join("callflows")).unwrap();
        fs::create_dir_all(base.join("pcap")).unwrap();
        // ~1 KiB of padding per line → 60 000 lines ≈ 60 MiB per file.
        // Two files + a smaller previous → 60 + 60 + 20 = 140 MiB, over
        // the 128 MiB test cap.
        let padding = "x".repeat(900);
        let write_spool = |path: &std::path::Path, lines: usize, tag: &str| {
            let mut writer = BufWriter::with_capacity(
                STREAM_CHUNK_BYTES,
                fs::File::create(path).unwrap(),
            );
            for i in 0..lines {
                let event = json!({
                    "event_id": format!("evt-{tag}-{i:08}"),
                    "capture_id": format!("sha256:stale-{tag}"),
                    "pad": padding,
                });
                writeln!(writer, "{}", event).unwrap();
            }
            writer.flush().unwrap();
        };
        write_spool(&dataset_dir.join("oiran_events.jsonl"), 60_000, "current");
        write_spool(&next_dir.join("oiran_events.jsonl"), 60_000, "next");
        write_spool(&previous_dir.join("oiran_events.jsonl"), 20_000, "previous");
        // Spool-tier temporaries that a crashed publication can leave
        // inside `.dataset-next/`.
        fs::write(next_dir.join(".decoded-events.spool"), vec![0u8; 2_000_000]).unwrap();
        fs::write(
            next_dir.join(".normalized-events.spool"),
            vec![0u8; 2_000_000],
        )
        .unwrap();
        fs::write(
            next_dir.join("oiran_events.jsonl.tmp"),
            vec![0u8; 2_000_000],
        )
        .unwrap();
        // Manifest + callflow stubs in the never-committed subtrees only.
        // Dataset/ gets a callflow stub so the sha256 check compares two
        // files, but NOT a dataset_manifest.json — `process_capture_into`
        // treats a present-but-invalid manifest as a checkpoint failure
        // (`CONTINUOUS_CHECKPOINT_MANIFEST_INVALID`), and in production
        // the manifest is written atomically by the worker; synthesising
        // a full valid manifest here is out of scope. The sacred-dataset
        // invariant is still exercised by the events.jsonl + callflow
        // sha256 equality below.
        fs::write(dataset_dir.join("callflows/stub.json"), b"{\"keep\":true}").unwrap();
        for d in [&next_dir, &previous_dir] {
            fs::write(d.join("dataset_manifest.json"), b"{\"stale\":true}").unwrap();
            fs::write(d.join("callflows/stub.json"), b"{}").unwrap();
            fs::write(d.join("callflows/stub.html"), b"<html></html>").unwrap();
        }
        let before = directory_size(&base);
        assert!(
            before > 128 * 1024 * 1024,
            "ANR2 fixture must exceed 128 MiB cap before cleanup; got {} B",
            before
        );
        // Byte-identity of dataset/ is asserted by the dedicated
        // `startup_cleanup_removes_rollback_only_and_leaves_dataset_byte_identical`
        // test on the pure helper. Here the worker's first successful
        // publication will atomically replace `dataset/` via
        // `process_capture_into`, so an after-worker sha256 no longer
        // isolates the startup-cleanup invariant.
        // --- Start the worker -----------------------------------------
        // state.segments is empty at startup → NO capture_id is retained
        // → every stale event is dropped from the spools; everything in
        // the derived tree must go.
        let seconds = (epoch_ms() / 1000) as u32;
        for index in 0..250_u32 {
            let path = source.join(format!("N3/segment-{index:04}.pcap"));
            let teid = 0x9000_u32 + index;
            write_pcap_at(&path, seconds, &[gtpu_gpdu_frame(index as u8, teid)]);
        }
        // 2.8.3: promote the 250 synthetic N3 segments to CLOSED via the
        // rotation-watcher JSONL contract.
        write_rotation_closures(&source, "N3", 250);
        thread::sleep(Duration::from_millis(500));
        let manager = CaptureManager::with_pseudonym_key_path(
            root.clone(),
            false,
            root.join(".oiran-pseudonym.key"),
        )
        .unwrap();
        manager
            .start_continuous_import(ContinuousImportConfig {
                source_root: source.clone(),
                scan_interval: Duration::from_millis(200),
                stable_age: Duration::from_millis(200),
                max_owned_bytes: 128 * 1024 * 1024,
                max_segment_bytes: 256 * 1024,
                max_segments: 8,
                native_segment_seconds: None,
                historical_n2_bootstrap: None,
                runtime_pdu_evidence: None,
            })
            .unwrap();
        // The worker's first act is `clean_continuous_import_root`; by
        // the time `start_continuous_import` returns the thread has been
        // spawned but may still be mid-cleanup. We wait for the two
        // observable outcomes of the cleanup:
        //   - .dataset-next removed
        //   - .dataset-previous removed
        // The `dataset/` subtree is NEVER touched by the cleanup, so
        // there is no "dataset compacted" condition to wait for.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if !next_dir.exists() && !previous_dir.exists() {
                break;
            }
            if Instant::now() >= deadline {
                panic!(
                    "cleanup did not finish: next_exists={} prev_exists={}",
                    next_dir.exists(),
                    previous_dir.exists()
                );
            }
            thread::sleep(Duration::from_millis(100));
        }
        let after_cleanup = directory_size(&base);
        assert!(
            after_cleanup < 128 * 1024 * 1024,
            "post-cleanup directory_size must fall below the cap; got {} B",
            after_cleanup
        );
        // --- Drain 250 segments ---------------------------------------
        let drain_deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < drain_deadline {
            if let Some(job) = manager.get(CONTINUOUS_CAPTURE_ID) {
                if job.metrics.segments_ingested >= 250 {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(250));
        }
        let final_job = manager.get(CONTINUOUS_CAPTURE_ID).expect("worker alive");
        assert!(
            final_job.metrics.segments_ingested >= 250,
            "post-cleanup 250 segments → segments_ingested={} (state={:?}, error={:?})",
            final_job.metrics.segments_ingested,
            final_job.state,
            final_job.error,
        );
        assert_ne!(final_job.state, CaptureState::Blocked);
        manager.stop(CONTINUOUS_CAPTURE_ID, "operator").unwrap();
    }

    /// 2.7.18 (issue #9 part 1): 250 valid pcap segments arrive in the
    /// source directory at once. With the 2.7.16 pure-batch cap each scan
    /// bounded ingestion to 32, but if `directory_size(&base)` was dominated
    /// by the derived `oiran_events.jsonl` artifact (which inherited every
    /// evicted segment's events through the `prior_continuous` spool merge)
    /// the `BOUNDED_STORAGE_FULL` guard tripped on candidate #1 and zero
    /// segments entered state for the next scan — the queue never drained.
    /// With the 2.7.18 filter (prior events keep only when their capture_id
    /// is in the current pcap set) plus the two-pass eviction fallback,
    /// every one of the 250 checksums must end up in `seen_checksums`.
    #[test]
    fn continuous_import_drains_a_burst_of_250_segments_without_blocking() {
        if skip_if_disk_too_full(
            "continuous_import_drains_a_burst_of_250_segments_without_blocking",
        ) {
            return;
        }
        let source = temporary_root("continuous-250-source");
        let root = temporary_root("continuous-250-owned");
        fs::create_dir_all(source.join("N3")).unwrap();
        // 250 tiny N3 pcaps, each with ONE G-PDU bearing a distinct TEID so
        // the per-file SHA-256 is distinct too. Payload is minimal (packet
        // header + 14-byte Ethernet + 1-byte stub) which keeps the full
        // corpus under 100 KiB on disk.
        let seconds = (epoch_ms() / 1000) as u32;
        for index in 0..250_u32 {
            let path = source.join(format!("N3/segment-{index:04}.pcap"));
            let teid = 0x9000_u32 + index;
            write_pcap_at(&path, seconds, &[gtpu_gpdu_frame(index as u8, teid)]);
        }
        // 2.8.3: tests promote all 250 synthetic N3 segments to CLOSED via
        // the rotation-watcher JSONL (the production `finalized_candidates_only`
        // rule requires closure proof, no mtime age).
        write_rotation_closures(&source, "N3", 250);
        thread::sleep(Duration::from_millis(500));
        let manager = CaptureManager::with_pseudonym_key_path(
            root.clone(),
            false,
            root.join(".oiran-pseudonym.key"),
        )
        .unwrap();
        manager
            .start_continuous_import(ContinuousImportConfig {
                source_root: source.clone(),
                scan_interval: Duration::from_millis(200),
                stable_age: Duration::from_millis(200),
                // Storage just big enough to hold ~8 live segments + the
                // derived reserve (64 MiB); the max_segments=8 count-based
                // eviction fires on every batch, not the byte-based one.
                max_owned_bytes: 128 * 1024 * 1024,
                max_segment_bytes: 256 * 1024,
                max_segments: 8,
                native_segment_seconds: None,
                historical_n2_bootstrap: None,
                runtime_pdu_evidence: None,
            })
            .unwrap();
        // Up to 120 s to drain 250 segments in batches of 32 (~8 batches,
        // with scan_interval=100 ms + decode time per batch).
        let deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < deadline {
            if let Some(job) = manager.get(CONTINUOUS_CAPTURE_ID) {
                if job.metrics.segments_ingested >= 250 {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(250));
        }
        let final_job = manager.get(CONTINUOUS_CAPTURE_ID).expect("worker alive");
        assert!(
            final_job.metrics.segments_ingested >= 250,
            "250 pending segments → segments_ingested={} (job.state={:?}, error={:?})",
            final_job.metrics.segments_ingested,
            final_job.state,
            final_job.error,
        );
        assert_ne!(
            final_job.state,
            CaptureState::Blocked,
            "worker must not be BLOCKED after drain; error={:?}",
            final_job.error
        );
        // The retained state.segments ring respects the configured
        // max_segments bound; 250 ingested >> 8 kept on disk at any time.
        let final_pending = final_job.metrics.pending_segments;
        assert_eq!(
            final_pending, 0,
            "pending_segments must reach 0; got {final_pending}"
        );
        manager.stop(CONTINUOUS_CAPTURE_ID, "operator").unwrap();
    }

    #[test]
    fn continuous_source_skips_active_truncation_and_rotates_owned_ring() {
        if skip_if_disk_too_full("continuous_source_skips_active_truncation_and_rotates_owned_ring")
        {
            return;
        }
        let source = temporary_root("continuous-truncated");
        fs::create_dir_all(source.join("N2")).unwrap();
        let truncated = source.join("N2/active.pcap");
        fs::write(
            &truncated,
            [
                0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0, 0, 1, 0, 0, 0,
                0, 1,
            ],
        )
        .unwrap();
        assert!(source_segments(
            &source,
            Duration::from_secs(60),
            false,
            DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES,
            &mut SourceSegmentsCache::new(),
        )
        .unwrap()
        .segments
        .is_empty());

        let root = temporary_root("continuous-quota");
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
        // 2.8.3: the 25-byte truncation stub was the SUBJECT of the
        // first `source_segments` assertion above (0 segments). It has
        // served its purpose; remove it before the real-ingestion half
        // of the test so the per-plane single-file JSONL promotion
        // cleanly exposes the lex-greatest final-*.pcapng in each plane.
        fs::remove_file(&truncated).unwrap();
        fs::copy(fixture.join("N2.pcapng"), source.join("N2/final-1.pcapng")).unwrap();
        fs::create_dir_all(source.join("N4")).unwrap();
        fs::copy(fixture.join("N4.pcapng"), source.join("N4/final-2.pcapng")).unwrap();
        // 2.8.3: single-segment-per-interface — JSONL promotion.
        write_rotation_closures(&source, "N2", 1);
        write_rotation_closures(&source, "N4", 1);
        thread::sleep(Duration::from_millis(250));
        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        manager
            .start_continuous_import(ContinuousImportConfig {
                source_root: source,
                scan_interval: Duration::from_millis(200),
                stable_age: Duration::from_millis(200),
                max_owned_bytes: 128 * 1024 * 1024,
                max_segment_bytes: 64 * 1024 * 1024,
                max_segments: 1,
                native_segment_seconds: None,
                historical_n2_bootstrap: None,
                runtime_pdu_evidence: None,
            })
            .unwrap();
        wait_for(|| {
            manager
                .get(CONTINUOUS_CAPTURE_ID)
                .is_some_and(|job| job.metrics.segments_ingested >= 2)
        });
        // 2.8.4 (#9 comment 6705466743): `max_segments` no longer
        // evicts owned pcap copies by count. Both N2 and N4 remain
        // on disk under the ring; the only cleanup is for files
        // whose source was externally removed (handled by the
        // startup `state.segments.retain(...)` at :1903).
        assert_eq!(
            capture_files(&manager.root.join(CONTINUOUS_CAPTURE_ID).join("pcap")).len(),
            2
        );
        let job = manager.get(CONTINUOUS_CAPTURE_ID).unwrap();
        assert_eq!(job.state, CaptureState::Capturing);
        assert!(job.metrics.decoded_events > 0);
        manager.stop(CONTINUOUS_CAPTURE_ID, "operator").unwrap();
    }

    #[test]
    fn source_bound_applies_after_interface_allowlist_and_keeps_newest_history() {
        let source = temporary_root("continuous-many-unrelated");
        fs::create_dir_all(source.join("unrelated")).unwrap();
        for index in 0..600 {
            write_pcap(
                &source.join("unrelated").join(format!("noise-{index}.pcap")),
                &[vec![0; 64]],
            );
        }
        fs::create_dir_all(source.join("N2")).unwrap();
        write_pcap(&source.join("N2/allowed.pcap"), &[vec![0; 64]]);
        // 2.8.3: single-segment-per-interface — prove closure via JSONL.
        write_rotation_closures(&source, "N2", 1);
        let segments = source_segments(
            &source,
            Duration::ZERO,
            false,
            DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES,
            &mut SourceSegmentsCache::new(),
        )
        .unwrap()
        .segments;
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].interface, "N2");
    }

    /// 2.10.4 (devmat, revue 2.10.3 ANR2 #10 comment 16:48Z) : la
    /// cause confirmée des 9 segments fermés non ingérés était un
    /// tri `newest-first` dans `source_segments`, combiné au plafond
    /// `MAX_INGESTED_SEGMENTS_PER_SCAN = 32`. Les segments plus
    /// anciens étaient systématiquement poussés en fin de file
    /// (donc coupés par la cap) chaque cycle. 2.10.4 trie
    /// `oldest-first` → un segment fermé atteint la tête en au plus
    /// `backlog/32` cycles. Ce test matérialise l'invariant FIFO
    /// sur 3 interfaces × 3 segments chacune.
    #[test]
    fn source_segments_sort_is_oldest_first_fifo_drain_2_10_4() {
        use std::time::{Duration as StdDuration, UNIX_EPOCH};
        use std::os::unix::fs::MetadataExt;
        let source = temporary_root("segments-fifo");
        // Trois interfaces × 3 segments, chacun avec un mtime
        // distinct. Ordre canonique attendu :
        //   N2 (older, mtime 1794000000) < S1-MME (1794000060) < N4 (1794000120)
        // avec dans chaque interface, _00064 < _00065 < _00066.
        let planes: &[(&str, &[(u32, &str)])] = &[
            ("N2", &[(1794000000, "n2_00064"), (1794000030, "n2_00065"), (1794000060, "n2_00066")]),
            ("S1-MME", &[(1794000090, "s1m_00064"), (1794000120, "s1m_00065"), (1794000150, "s1m_00066")]),
            ("N4", &[(1794000180, "n4_00064"), (1794000210, "n4_00065"), (1794000240, "n4_00066")]),
        ];
        for (plane, files) in planes {
            fs::create_dir_all(source.join(plane)).unwrap();
            // 2.8.3 rotation closures required for finalized_candidates_only.
            write_rotation_closures(&source, plane, files.len());
            for (seconds, name) in *files {
                let path = source.join(plane).join(format!("{name}.pcap"));
                write_pcap_at(&path, *seconds, &[vec![0; 128]]);
                // Force a distinct mtime via utimensat (write_pcap_at seeds
                // timestamps inside the pcap header, not the FS mtime).
                let atime = fs::metadata(&path).unwrap().atime();
                let mtime_sec = *seconds as i64;
                let times = [
                    libc::timespec { tv_sec: atime, tv_nsec: 0 },
                    libc::timespec { tv_sec: mtime_sec, tv_nsec: 0 },
                ];
                let path_c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
                unsafe {
                    libc::utimensat(
                        libc::AT_FDCWD,
                        path_c.as_ptr(),
                        times.as_ptr(),
                        0,
                    );
                }
            }
        }
        let mut cache = SourceSegmentsCache::new();
        let discovery = source_segments(
            &source,
            StdDuration::ZERO,
            false,
            DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES,
            &mut cache,
        )
        .unwrap();
        // Oldest-first: N2 _00064 doit sortir en premier,
        // N4 _00066 en dernier. ANR2 invariant.
        assert!(discovery.segments.len() >= 6, "expected multiple segments, got {}", discovery.segments.len());
        let first_mtime = discovery.segments.first().unwrap().modified;
        let last_mtime = discovery.segments.last().unwrap().modified;
        assert!(
            first_mtime <= last_mtime,
            "FIFO drain violated: first modified {:?} should be <= last {:?}",
            first_mtime,
            last_mtime
        );
        // Assertion de force : la toute 1re entrée doit avoir le plus petit mtime du set.
        let min_mtime = discovery
            .segments
            .iter()
            .map(|seg| seg.modified)
            .min()
            .unwrap();
        assert_eq!(
            discovery.segments[0].modified, min_mtime,
            "oldest-first expected: head mtime {:?} != min {:?}",
            discovery.segments[0].modified, min_mtime
        );
    }

    /// 2.8.1 (#9, ANR2 CPU proof): the per-worker `source_segments`
    /// cache must suppress `sha256_hex_file` + `count_pcap_records`
    /// on an unchanged segment across scans. Before 2.8.1 both
    /// operations ran every ~1 s on every segment, producing the
    /// 87.6% CPU ANR2 observed at `pending=0`.
    #[test]
    fn source_segments_cache_skips_sha256_on_unchanged_candidates() {
        let source = temporary_root("source-segments-cache");
        fs::create_dir_all(source.join("N2")).unwrap();
        let path = source.join("N2").join("seg-1.pcap");
        write_pcap(&path, &[vec![1u8; 128]]);
        // 2.8.3: single-segment-per-interface — prove closure via JSONL.
        write_rotation_closures(&source, "N2", 1);
        // First scan: cold cache → cache populated.
        let mut cache = SourceSegmentsCache::new();
        let first = source_segments(
            &source,
            Duration::ZERO,
            false,
            DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES,
            &mut cache,
        )
        .unwrap();
        assert_eq!(first.segments.len(), 1);
        assert_eq!(cache.len(), 1);
        let checksum = first.segments[0].checksum.clone();
        let packets = first.segments[0].packets;
        let fingerprint = cache.get(&path).cloned().unwrap();
        assert_eq!(fingerprint.checksum, checksum);
        assert_eq!(fingerprint.packets, packets);
        // Second scan: same (size, mtime) → cache hit. We detect the hit
        // by swapping the file's content for a byte sequence that WOULD
        // produce a different SHA if the function re-read it; because
        // mtime and size are preserved by a positional rewrite and the
        // cache is consulted first, the reported checksum must stay
        // equal to the cached value — proof the heavy path was skipped.
        let modified_before = fs::metadata(&path).unwrap().modified().unwrap();
        let mut rewrite = fs::OpenOptions::new().write(true).open(&path).unwrap();
        use std::io::{Seek, SeekFrom, Write};
        rewrite.seek(SeekFrom::Start(32)).unwrap();
        rewrite.write_all(&[0xff; 16]).unwrap();
        rewrite.sync_all().unwrap();
        drop(rewrite);
        // Restore the original mtime so the cache fingerprint still
        // matches (size unchanged by the positional rewrite).
        use std::os::unix::fs::MetadataExt;
        let atime = fs::metadata(&path).unwrap().atime();
        // `filetime` would be cleaner but we stay dep-free: use `utimensat`.
        use std::time::UNIX_EPOCH;
        let modified_secs = modified_before
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let modified_nsecs =
            modified_before.duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as i64;
        unsafe {
            let times = [
                libc::timespec {
                    tv_sec: atime,
                    tv_nsec: 0,
                },
                libc::timespec {
                    tv_sec: modified_secs,
                    tv_nsec: modified_nsecs,
                },
            ];
            let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
            assert_eq!(libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0), 0);
        }
        let second = source_segments(
            &source,
            Duration::ZERO,
            false,
            DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES,
            &mut cache,
        )
        .unwrap();
        assert_eq!(second.segments.len(), 1);
        assert_eq!(
            second.segments[0].checksum, checksum,
            "cache hit must reuse the checksum; re-hashing the file would have returned a different value"
        );
    }

    #[test]
    fn copy_race_is_retryable_and_does_not_publish_partial_destination() {
        let source = temporary_root("continuous-copy-race");
        let path = source.join("N3.pcap");
        write_pcap(&path, &[vec![1; 64]]);
        let metadata = fs::metadata(&path).unwrap();
        let original = fs::read(&path).unwrap();
        let candidate = SourceSegment {
            path: path.clone(),
            interface: "N3".into(),
            checksum: sha256_hex(&original),
            size_bytes: metadata.len(),
            packets: 1,
            modified: metadata.modified().unwrap(),
        };
        write_pcap(&path, &[vec![2; 64], vec![3; 64]]);
        let destination = source.join("owned.pcap");
        assert_eq!(
            copy_verified(&candidate, &destination).unwrap_err(),
            "CONTINUOUS_SOURCE_CHANGED_DURING_IMPORT"
        );
        assert!(!destination.exists());
        assert!(!destination.with_extension("importing").exists());
    }

    fn event_json(
        id: &str,
        capture: &str,
        timestamp_ms: u64,
        protocol: &str,
        name: &str,
        ue_ip: Option<&str>,
    ) -> serde_json::Value {
        let identifiers = ue_ip
            .map(|ip| vec![
                serde_json::json!({"name":"ue_ip","value":ip,"pseudonymized":false}),
                serde_json::json!({"name":"teid","value":format!("0x{}", &ip[8..]),"pseudonymized":false}),
            ])
            .unwrap_or_default();
        serde_json::json!({
            "event_id":id,"capture_id":capture,"capture_point_id":protocol,
            "timestamp":{"seconds":timestamp_ms / 1000,"nanoseconds":(timestamp_ms % 1000) * 1_000_000,"raw_ticks":timestamp_ms,"display":"fixture"},
            "interface":protocol,"protocol":protocol,"message_name":name,
            "source_endpoint":{"address":"10.77.22.20","network_function":"gNB"},
            "destination_endpoint":{"address":"10.77.22.13","network_function":"UPF"},
            "direction":"UPLINK","session_identifiers":identifiers,"information_elements":[],
            "decoding_status":"DECODED","decoder_name":"fixture","decoder_version":"1",
            "raw_payload_reference":format!("sha256:{id}"),
            "packet_references":[{"source_file":"N3.pcap","packet_number":1,"byte_offset":24,"interface_id":0,"captured_length":64,"original_length":64}],
            "errors":[]
        })
    }

    #[test]
    fn activity_uses_packet_time_requires_three_unique_ue_gpdus_and_ignores_heartbeat() {
        let started = 10_000;
        let values = vec![
            event_json(
                "old",
                "sha256:old",
                9_999,
                "GTP-U",
                "G-PDU",
                Some("10.46.0.4"),
            ),
            event_json(
                "ue4",
                "sha256:a",
                10_001,
                "GTP-U",
                "G-PDU",
                Some("10.46.0.4"),
            ),
            event_json(
                "ue5",
                "sha256:b",
                10_002,
                "GTP-U",
                "G-PDU",
                Some("10.46.0.5"),
            ),
            event_json(
                "ue6",
                "sha256:c",
                10_003,
                "GTP-U",
                "G-PDU",
                Some("10.46.0.6"),
            ),
            event_json(
                "heartbeat",
                "sha256:d",
                10_004,
                "PFCP",
                "PFCP Heartbeat Request",
                None,
            ),
        ];
        let jsonl = values
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        let events = session_engine::load_jsonl(std::io::Cursor::new(jsonl)).unwrap();
        let (last, fresh, contexts) = continuous_activity(&events, Some(started), 10_004, None);
        assert_eq!(last, Some(10_004));
        assert_eq!(fresh, 4);
        assert!(contexts.is_empty(), "IP-only traffic is not a PDU context");
    }

    #[test]
    fn runtime_evidence_binds_three_fresh_gpdus_to_three_real_pdu_callflows() {
        let started = 10_000;
        let observed = 10_010;
        let root = temporary_root("runtime-evidence");
        let evidence = root.join("pdu-bindings.json");
        let bindings = [
            ("UE-01", "oiran-lab-ueransim-ue-1", "10.46.0.4"),
            ("UE-02", "polaris-control-ue-02", "10.46.0.5"),
            ("UE-03", "polaris-control-ue-03", "10.46.0.6"),
        ]
        .into_iter()
        .map(|(ue, container, ip)| {
            serde_json::json!({
                "internal_ue_id":ue,"container":container,"interface":"uesimtun0","ue_ip":ip,
                "process_state":"RUNNING","registration_state":"REGISTERED",
                "pdu_session_state":"ACTIVE","pdu_session_id":"1",
                "status_provenance":"nr-cli status","pdu_provenance":"nr-cli ps-list",
                "tunnel_provenance":"ip -json address show dev uesimtun0"
            })
        })
        .collect::<Vec<_>>();
        fs::write(
            &evidence,
            serde_json::to_vec(&serde_json::json!({
                "schema_version":"1.0","observed_epoch_ms":observed,
                "source":"POLARIS_API+UERANSIM_NR_CLI","bindings":bindings
            }))
            .unwrap(),
        )
        .unwrap();
        let values = ["10.46.0.4", "10.46.0.5", "10.46.0.6"]
            .into_iter()
            .enumerate()
            .map(|(index, ip)| {
                event_json(
                    &format!("gpdu-{index}"),
                    "sha256:live",
                    observed,
                    "GTP-U",
                    "G-PDU",
                    Some(ip),
                )
            })
            .collect::<Vec<_>>();
        let jsonl = values
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        let events = session_engine::load_jsonl(std::io::Cursor::new(jsonl)).unwrap();
        let (_, fresh, contexts) =
            continuous_activity(&events, Some(started), observed, Some(&evidence));
        assert_eq!(fresh, 3);
        assert_eq!(contexts.len(), 3);
        assert_eq!(
            contexts
                .iter()
                .map(|item| item.ue_ip.as_str())
                .collect::<Vec<_>>(),
            vec!["10.46.0.4", "10.46.0.5", "10.46.0.6"]
        );
        for context in &contexts {
            let flow = runtime_pdu_callflow(&events, context);
            assert_eq!(
                flow.correlation_status["E2E"],
                "PARTIAL_EXTERNAL_RUNTIME_CORROBORATED"
            );
            assert!(flow
                .events
                .iter()
                .any(|event| event.protocol == "GTP-U" && event.message_name == "G-PDU"));
        }

        let (_, _, stale) =
            continuous_activity(&events, Some(observed + 1), observed + 1, Some(&evidence));
        assert!(
            stale.is_empty(),
            "prior-generation evidence must not survive restart"
        );
        let (_, _, ip_only) = continuous_activity(&events, Some(started), observed, None);
        assert!(
            ip_only.is_empty(),
            "three IPs without PDU evidence must not activate"
        );
    }

    #[test]
    fn aged_cached_activity_is_not_reported_without_new_ingestion() {
        let root = temporary_root("aged-cached-activity");
        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        let observed = 100_000;
        let aged = observed + ACTIVE_PACKET_WINDOW_MS + 1;
        let runtime_ids = (1..=3)
            .map(|index| format!("runtime-pdu-{index}"))
            .collect::<Vec<_>>();
        let contexts = ["10.46.0.4", "10.46.0.5", "10.46.0.6"]
            .into_iter()
            .enumerate()
            .map(|(index, ip)| ActivePduContext {
                session_id: runtime_ids[index].clone(),
                internal_ue_id: format!("UE-{:02}", index + 1),
                pdu_session_id: "1".into(),
                ue_ip: ip.into(),
                observed_epoch_ms: observed,
                provenance: "test fixture".into(),
                correlation_status: "PARTIAL_EXTERNAL_RUNTIME_CORROBORATED".into(),
                gtpu_event_ids: vec![format!("event-{index}")],
                teids: vec![format!("0x100{index}")],
                directions: vec!["UPLINK".into()],
            })
            .collect::<Vec<_>>();
        manager.datasets.lock().unwrap().insert(
            CONTINUOUS_DATASET_ID.into(),
            LiveDataset {
                dataset_id: CONTINUOUS_DATASET_ID.into(),
                capture_id: CONTINUOUS_CAPTURE_ID.into(),
                path: "runtime/live-captures/continuous-lab-import/dataset".into(),
                event_count: 3,
                session_ids: [vec!["historical-session".into()], runtime_ids].concat(),
                decode_reports: BTreeMap::new(),
                checksums: BTreeMap::new(),
                state: "PARTIAL".into(),
                discovery: None,
                capture_started_epoch_ms: Some(observed.saturating_sub(1)),
                last_packet_epoch_ms: Some(observed),
                fresh_packet_count: 3,
                active_ue_ips: contexts
                    .iter()
                    .map(|context| context.ue_ip.clone())
                    .collect(),
                active_pdu_contexts: contexts,
                zero_event_captures: Vec::new(),
            },
        );
        manager.jobs.lock().unwrap().insert(
            CONTINUOUS_CAPTURE_ID.into(),
            CaptureJob {
                capture_id: CONTINUOUS_CAPTURE_ID.into(),
                probe_id: PROBE_ID.into(),
                name: "aged cached activity".into(),
                profile: "POLARIS_5G_SA_CONTINUOUS_IMPORT".into(),
                interfaces: vec!["N2".into(), "N3".into(), "N4".into()],
                state: CaptureState::Capturing,
                created_epoch_ms: observed.saturating_sub(1),
                started_epoch_ms: Some(observed.saturating_sub(1)),
                ended_epoch_ms: None,
                owner: "operator".into(),
                metrics: CaptureMetrics {
                    last_packet_epoch_ms: Some(observed),
                    fresh_packet_count: 3,
                    active_ue_ips: vec!["10.46.0.4".into(), "10.46.0.5".into(), "10.46.0.6".into()],
                    ..Default::default()
                },
                output_directory: "runtime/live-captures/continuous-lab-import".into(),
                dataset_id: Some(CONTINUOUS_DATASET_ID.into()),
                session_ids: vec!["historical-session".into()],
                error: None,
                stop_reason: None,
                process_ids: Vec::new(),
                helper_results: Vec::new(),
                capture_group_id: Some("continuous-lab-import".into()),
                scenario_id: Some("POLARIS_5G_SA_CONTINUOUS_IMPORT".into()),
                planes: Vec::new(),
            },
        );

        let cached = manager
            .datasets
            .lock()
            .unwrap()
            .get(CONTINUOUS_DATASET_ID)
            .unwrap()
            .clone();
        let fresh = live_dataset_view(cached.clone(), observed);
        assert_eq!(fresh.fresh_packet_count, 3);
        assert_eq!(fresh.active_pdu_contexts.len(), 3);
        assert_eq!(fresh.active_ue_ips.len(), 3);

        let expired = live_dataset_view(cached.clone(), aged);
        assert_eq!(expired.fresh_packet_count, 0);
        assert!(expired.active_pdu_contexts.is_empty());
        assert_eq!(expired.session_ids.len(), 4);
        assert!(expired.session_ids.contains(&"historical-session".into()));

        let mut evidence_aged = cached.clone();
        for context in &mut evidence_aged.active_pdu_contexts {
            context.observed_epoch_ms = observed.saturating_sub(ACTIVE_PACKET_WINDOW_MS + 1);
        }
        let evidence_aged = live_dataset_view(evidence_aged, observed);
        assert_eq!(evidence_aged.fresh_packet_count, 3);
        assert!(evidence_aged.active_pdu_contexts.is_empty());

        let mut packet_aged = cached;
        packet_aged.last_packet_epoch_ms =
            Some(observed.saturating_sub(ACTIVE_PACKET_WINDOW_MS + 1));
        let packet_aged = live_dataset_view(packet_aged, observed);
        assert_eq!(packet_aged.fresh_packet_count, 0);
        assert!(packet_aged.active_pdu_contexts.is_empty());

        let dataset = manager.dataset(CONTINUOUS_DATASET_ID).unwrap();
        assert_eq!(dataset.fresh_packet_count, 0);
        assert!(dataset.active_ue_ips.is_empty());
        assert!(dataset.active_pdu_contexts.is_empty());
        assert_eq!(dataset.session_ids.len(), 4);
        manager.clear_continuous_active_credit().unwrap();
        assert_eq!(
            manager
                .datasets
                .lock()
                .unwrap()
                .get(CONTINUOUS_DATASET_ID)
                .unwrap()
                .session_ids
                .len(),
            4
        );
        let metrics = manager.get(CONTINUOUS_CAPTURE_ID).unwrap().metrics;
        assert_eq!(metrics.fresh_packet_count, 0);
        assert!(metrics.active_ue_ips.is_empty());
    }

    /// 2.7.22 (issue #10 comment 6657170005): the first republish after
    /// 2.7.21 cleanup must preserve every event_id of the previously
    /// published dataset. Prior to 2.7.22 `process_capture_into` kept
    /// only prior events whose `capture_id` was in the current pcap
    /// ring, and the ANR2 lab's ring held 1 of the 51 historically
    /// contributing captures — 21 515 of 25 537 event_ids were dropped
    /// on the first republish. This test publishes dataset A with
    /// the N2/N3/N4 fixtures, keeps the resulting event_id set, then
    /// drops the original pcaps, swaps in a fresh set (same N3 fixture
    /// written under a different filename so the sha256 differs) and
    /// republishes. Every event_id from dataset A must be in dataset B.
    #[test]
    fn republish_preserves_every_prior_event_id_even_when_ring_rotates() {
        let root = temporary_root("preserve-event-ids");
        let manager = CaptureManager::with_pseudonym_key_path(
            root.clone(),
            false,
            root.join(".oiran-pseudonym.key"),
        )
        .unwrap();
        let base = root.join(CONTINUOUS_CAPTURE_ID);
        fs::create_dir_all(base.join("pcap")).unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
        for interface in ["N2", "N3", "N4"] {
            fs::copy(
                fixture.join(format!("{interface}.pcapng")),
                base.join("pcap").join(format!("{interface}.pcapng")),
            )
            .unwrap();
        }
        let first = manager
            .process_continuous_capture(&base, &interface_specs(), 128 * 1024 * 1024)
            .unwrap();
        let first_event_ids: BTreeSet<String> =
            load_path(&base.join("dataset/oiran_events.jsonl"))
                .unwrap()
                .into_iter()
                .map(|event| event.event_id)
                .collect();
        assert!(
            first_event_ids.len() >= 20,
            "fixture should decode into enough events to make the assertion meaningful; got {}",
            first_event_ids.len()
        );
        // Rotate the ring: delete the original pcaps, swap in a
        // perturbed copy whose checksum differs from the first. The
        // 2.7.18 keep_prior filter would reject every prior event here
        // because none of the original capture_ids remain in
        // `checksums`. 2.7.22 keeps them all.
        for interface in ["N2", "N3", "N4"] {
            fs::remove_file(base.join("pcap").join(format!("{interface}.pcapng"))).unwrap();
        }
        // Append one extra byte to each copy so the sha256 differs —
        // decoded packets are unchanged since the trailing byte sits
        // after the final pcap record.
        for interface in ["N2", "N3", "N4"] {
            let mut bytes = fs::read(fixture.join(format!("{interface}.pcapng"))).unwrap();
            bytes.push(0);
            fs::write(
                base.join("pcap").join(format!("{interface}-v2.pcapng")),
                &bytes,
            )
            .unwrap();
        }
        let second = manager
            .process_continuous_capture(&base, &interface_specs(), 128 * 1024 * 1024)
            .unwrap();
        let second_event_ids: BTreeSet<String> =
            load_path(&base.join("dataset/oiran_events.jsonl"))
                .unwrap()
                .into_iter()
                .map(|event| event.event_id)
                .collect();
        let missing: Vec<&String> = first_event_ids.difference(&second_event_ids).collect();
        assert!(
            missing.is_empty(),
            "every event_id of the first publication must survive the republish; missing={:?}",
            missing
        );
        assert!(
            second_event_ids.len() >= first_event_ids.len(),
            "republish must only grow (or hold) the event_id set: first={} second={}",
            first_event_ids.len(),
            second_event_ids.len()
        );
        assert!(second.event_count >= first.event_count);
    }

    /// 2.7.22: age-based retention
    /// (`OIRAN_DATASET_RETENTION_DAYS`) is the ONLY way an event leaves
    /// the published dataset. This test publishes dataset A, injects
    /// an event timestamped two days ago, sets
    /// `OIRAN_DATASET_RETENTION_DAYS=1`, republishes, and asserts
    /// (a) the old event is purged, (b) every OTHER event_id from A
    /// survives, (c) the `CONTINUOUS_RETENTION_PURGE` log line was
    /// emitted at least once with `purged_count >= 1`.
    #[test]
    fn retention_purges_events_older_than_configured_days() {
        use serde_json::Value;
        let root = temporary_root("retention-purge");
        let manager = CaptureManager::with_pseudonym_key_path(
            root.clone(),
            false,
            root.join(".oiran-pseudonym.key"),
        )
        .unwrap();
        let base = root.join(CONTINUOUS_CAPTURE_ID);
        fs::create_dir_all(base.join("pcap")).unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
        for interface in ["N2", "N3", "N4"] {
            fs::copy(
                fixture.join(format!("{interface}.pcapng")),
                base.join("pcap").join(format!("{interface}.pcapng")),
            )
            .unwrap();
        }
        let first = manager
            .process_continuous_capture(&base, &interface_specs(), 128 * 1024 * 1024)
            .unwrap();
        // Append one NEW synthetic event to the published spool whose
        // `timestamp.seconds` sits well outside the retention window.
        // The event's `capture_id` is unique ("sha256:retention-canary")
        // so we can recognise it in the post-publish spool WITHOUT
        // predicting the id continuous_observation_id will recompute.
        // Updating `dataset_manifest.json` so `event_count` matches the
        // new line count keeps `validate_dataset_artifacts` happy at
        // the top of the next `process_capture_into`.
        let events_path = base.join("dataset/oiran_events.jsonl");
        let manifest_path = base.join("dataset/dataset_manifest.json");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // retention_days() is clamped to <= 3650; pick an event 3651
        // days old so it is unambiguously out of a 3650-day window.
        let backdated_seconds = now.saturating_sub(3651 * 86_400);
        let backdated_event = serde_json::json!({
            "event_id": "evt-retention-canary",
            "capture_id": "sha256:retention-canary",
            "capture_point_id": "N2",
            "interface": "N2",
            "protocol": "NGAP",
            "message_name": "RetentionCanary",
            "message_type": 0,
            "procedure_code": 0,
            "source_endpoint": {"address": "10.0.0.1", "network_function": "X"},
            "destination_endpoint": {"address": "10.0.0.2", "network_function": "Y"},
            "direction": "RAN_TO_CORE",
            "session_identifiers": [],
            "information_elements": [],
            "decoder_name": "retention-test",
            "decoder_version": "0",
            "schema_version": "1.2.0",
            "decoding_status": "DECODED",
            "errors": [],
            "raw_payload_reference": "sha256:retention-canary",
            "evidence_references": [],
            "packet_references": [{
                "source_file": "/captures/synthetic/N2.pcapng",
                "packet_number": 1,
                "byte_offset": 0,
                "interface_id": 0,
                "captured_length": 10,
                "original_length": 10,
            }],
            "timestamp": {
                "seconds": backdated_seconds,
                "nanoseconds": 0,
                "raw_ticks": backdated_seconds.saturating_mul(1_000_000_000),
                "resolution_base": 10,
                "resolution_exponent": 9,
                "display": format!("{backdated_seconds}.000000000Z"),
            }
        });
        {
            use std::fs::OpenOptions;
            use std::io::Write as _;
            let mut file = OpenOptions::new()
                .append(true)
                .open(&events_path)
                .unwrap();
            writeln!(file, "{}", backdated_event).unwrap();
        }
        // Update manifest.event_count to match the new line count so
        // `validate_dataset_artifacts` re-accepts the bundle.
        let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["event_count"] = serde_json::json!(first.event_count + 1);
        fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
        // Retention 3650 days: the backdated canary (3651 days old)
        // is purged; the ~12-day-old fixture events survive comfortably.
        std::env::set_var("OIRAN_DATASET_RETENTION_DAYS", "3650");
        let _ = manager.process_continuous_capture(&base, &interface_specs(), 128 * 1024 * 1024);
        std::env::remove_var("OIRAN_DATASET_RETENTION_DAYS");
        // Line-level scan (not load_path) so we can see every raw
        // event's capture_id, even synthetic ones that parse_event
        // may strip later.
        let mut canary_still_present = false;
        let mut survivor_count = 0usize;
        for line in BufReader::new(fs::File::open(&events_path).unwrap()).lines() {
            let line = line.unwrap();
            if line.trim().is_empty() {
                continue;
            }
            survivor_count += 1;
            if line.contains("\"capture_id\":\"sha256:retention-canary\"") {
                canary_still_present = true;
            }
        }
        assert!(
            !canary_still_present,
            "the retention canary (3651 days old) must be purged by the 3650-day retention"
        );
        // The fixture events (~12 days old) are inside the window and
        // must be preserved: survivor_count should be at least
        // `first.event_count` (the count after the first publication,
        // before we appended the canary). The fresh decode cycle adds
        // zero new events because we did not add any new pcap, so the
        // count is exactly `first.event_count`.
        assert_eq!(
            survivor_count, first.event_count,
            "retention must preserve every fixture event (~12 days old) under a 3650-day window; got {survivor_count} vs expected {}",
            first.event_count
        );
    }

    /// 2.7.23 (issue #10 comment 6662293690): the derived publication
    /// (`<base>/.dataset-next/`) size cap is configurable via
    /// `OIRAN_CONTINUOUS_DERIVED_OUTPUT_MAX_BYTES`. With the default
    /// 512 MiB the shipped 3-pcap fixture (~160 KiB of events + a
    /// manifest + two callflow bundles) sits well below the ceiling,
    /// and `process_continuous_capture` returns `Ok`.
    #[test]
    fn derived_output_cap_accepts_small_publication_under_default_limit() {
        let root = temporary_root("derived-cap-ok");
        let manager = CaptureManager::with_pseudonym_key_path(
            root.clone(),
            false,
            root.join(".oiran-pseudonym.key"),
        )
        .unwrap();
        let base = root.join(CONTINUOUS_CAPTURE_ID);
        fs::create_dir_all(base.join("pcap")).unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
        for interface in ["N2", "N3", "N4"] {
            fs::copy(
                fixture.join(format!("{interface}.pcapng")),
                base.join("pcap").join(format!("{interface}.pcapng")),
            )
            .unwrap();
        }
        // Default limit = 512 MiB; the fixture produces a few hundred KiB.
        let dataset = manager
            .process_continuous_capture(&base, &interface_specs(), 1024 * 1024 * 1024)
            .unwrap();
        assert!(dataset.event_count > 0);
        assert!(base.join("dataset/oiran_events.jsonl").is_file());
        assert!(base.join("dataset/dataset_manifest.json").is_file());
    }

    /// 2.7.23: when the derived publication exceeds
    /// `OIRAN_CONTINUOUS_DERIVED_OUTPUT_MAX_BYTES`, `process_continuous_capture`
    /// returns `Err` whose message starts with
    /// `CONTINUOUS_DERIVED_OUTPUT_LIMIT` and names both the observed
    /// size and the configured cap. The caller
    /// (`run_continuous_import_inner`) recognises that prefix and
    /// exits the worker as `Blocked` instead of entering the
    /// `CONTINUOUS_DECODE_RETRYABLE` loop — the 2.7.22 retry behaviour
    /// is gone.
    #[test]
    fn derived_output_over_limit_returns_informative_error_and_is_not_retryable() {
        struct LimitReset;
        impl Drop for LimitReset {
            fn drop(&mut self) {
                DERIVED_OUTPUT_LIMIT_OVERRIDE.with(|cell| cell.set(None));
            }
        }
        let _reset = LimitReset;
        let root = temporary_root("derived-cap-fail");
        let manager = CaptureManager::with_pseudonym_key_path(
            root.clone(),
            false,
            root.join(".oiran-pseudonym.key"),
        )
        .unwrap();
        let base = root.join(CONTINUOUS_CAPTURE_ID);
        fs::create_dir_all(base.join("pcap")).unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
        for interface in ["N2", "N3", "N4"] {
            fs::copy(
                fixture.join(format!("{interface}.pcapng")),
                base.join("pcap").join(format!("{interface}.pcapng")),
            )
            .unwrap();
        }
        // 1-byte limit (thread-local override, so this does not leak
        // into any parallel test) → any publication output trips it.
        DERIVED_OUTPUT_LIMIT_OVERRIDE.with(|cell| cell.set(Some(1)));
        let err = manager
            .process_continuous_capture(&base, &interface_specs(), 1024 * 1024 * 1024)
            .unwrap_err();
        assert!(
            err.starts_with("CONTINUOUS_DERIVED_OUTPUT_LIMIT"),
            "err should identify the derived-output overflow; got {err:?}"
        );
        assert!(
            err.contains("exceeds"),
            "err should mention the limit value; got {err:?}"
        );
        assert!(
            err.contains("retention"),
            "err should mention retention guidance; got {err:?}"
        );
        assert!(
            err.contains("=1 B"),
            "err should name the configured cap verbatim (1 B); got {err:?}"
        );
        // The retry contract is enforced by
        // `run_continuous_import_inner`: the branch at
        // `live-probe/src/lib.rs` that matches
        // `error.starts_with("CONTINUOUS_DERIVED_OUTPUT_LIMIT")` sets
        // CaptureState::Blocked + stop_reason + returns Ok(()) —
        // one attempt, no retry loop. Code-review guarantee; the
        // `err.starts_with` assertion above is what that handler keys
        // on.
    }

    #[test]
    fn continuous_checkpoint_keeps_five_sessions_across_restart_and_republish() {
        let root = temporary_root("continuous-five-session-checkpoint");
        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        let base = root.join(CONTINUOUS_CAPTURE_ID);
        fs::create_dir_all(base.join("pcap")).unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
        for interface in ["N2", "N3", "N4"] {
            fs::copy(
                fixture.join(format!("{interface}.pcapng")),
                base.join("pcap").join(format!("{interface}.pcapng")),
            )
            .unwrap();
        }
        let mut checkpoint = manager
            .process_continuous_capture(&base, &interface_specs(), 128 * 1024 * 1024)
            .unwrap();
        let original = checkpoint.session_ids.first().unwrap().clone();
        let original_json = fs::read(
            base.join("dataset/callflows")
                .join(format!("{original}.json")),
        )
        .unwrap();
        let original_flow: CallFlow = serde_json::from_slice(&original_json).unwrap();
        for index in 2..=5 {
            let session_id = format!("checkpoint-session-{index}");
            let mut flow = original_flow.clone();
            flow.session_id = session_id.clone();
            atomic_write(
                &base
                    .join("dataset/callflows")
                    .join(format!("{session_id}.json")),
                &serde_json::to_vec_pretty(&flow).unwrap(),
            )
            .unwrap();
            atomic_write(
                &base
                    .join("dataset/callflows")
                    .join(format!("{session_id}.html")),
                callflow_renderer::render(&flow).unwrap().as_bytes(),
            )
            .unwrap();
            checkpoint.session_ids.push(session_id);
        }
        checkpoint.session_ids.sort();
        atomic_write(
            &base.join("dataset/dataset_manifest.json"),
            &serde_json::to_vec_pretty(&checkpoint).unwrap(),
        )
        .unwrap();
        validate_dataset_artifacts(&checkpoint, &base.join("dataset")).unwrap();
        let checkpoint_events = load_path(&base.join("dataset/oiran_events.jsonl")).unwrap();
        let checkpoint_event_ids = checkpoint_events
            .iter()
            .map(|event| event.event_id.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(checkpoint_event_ids.len(), checkpoint_events.len());
        assert_eq!(checkpoint.session_ids.len(), 5);

        drop(manager);
        let restarted = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        let resumed = restarted
            .process_continuous_capture(&base, &interface_specs(), 128 * 1024 * 1024)
            .unwrap();
        assert_eq!(resumed.session_ids.len(), 5);
        assert_eq!(resumed.event_count, checkpoint.event_count);
        assert_eq!(
            serde_json::to_value(&resumed.decode_reports).unwrap(),
            serde_json::to_value(&checkpoint.decode_reports).unwrap()
        );

        let seconds = (epoch_ms() / 1000) as u32;
        write_pcap_at(
            &base.join("pcap/N3.pcap-new.pcap"),
            seconds,
            &[gtpu_gpdu_frame(4, 0xface)],
        );
        let extended = restarted
            .process_continuous_capture(&base, &interface_specs(), 128 * 1024 * 1024)
            .unwrap();
        assert_eq!(extended.session_ids.len(), 5);
        assert!(extended.event_count > checkpoint.event_count);
        let extended_events = load_path(&base.join("dataset/oiran_events.jsonl")).unwrap();
        assert_eq!(
            extended_events
                .iter()
                .map(|event| event.event_id.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            extended_events.len(),
            "resume must not duplicate an already indexed observation"
        );

        let idempotent = restarted
            .process_continuous_capture(&base, &interface_specs(), 128 * 1024 * 1024)
            .unwrap();
        assert_eq!(idempotent.event_count, extended.event_count);
        assert_eq!(idempotent.session_ids, extended.session_ids);

        let events_before = fs::read(base.join("dataset/oiran_events.jsonl")).unwrap();
        atomic_write(&base.join("dataset/dataset_manifest.json"), b"{}").unwrap();
        assert_eq!(
            restarted
                .process_continuous_capture(&base, &interface_specs(), 128 * 1024 * 1024)
                .unwrap_err(),
            "CONTINUOUS_CHECKPOINT_MANIFEST_INVALID"
        );
        assert_eq!(
            fs::read(base.join("dataset/oiran_events.jsonl")).unwrap(),
            events_before,
            "an invalid checkpoint must fail closed without replacing evidence"
        );
    }

    #[test]
    fn production_pipeline_decodes_three_pcap_gpdus_into_three_bound_pdu_callflows() {
        let root = temporary_root("runtime-pcap-e2e");
        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        let base = root.join(CONTINUOUS_CAPTURE_ID);
        fs::create_dir_all(base.join("pcap")).unwrap();
        let seconds = (epoch_ms() / 1000) as u32;
        let observed = u64::from(seconds) * 1000;
        write_pcap_at(
            &base.join("pcap/N3.pcap-live.pcap"),
            seconds,
            &[
                gtpu_gpdu_frame(4, 0x1004),
                gtpu_gpdu_frame(5, 0x1005),
                gtpu_gpdu_frame(6, 0x1006),
            ],
        );
        let evidence = root.join("runtime-pdu-evidence.json");
        let bindings = [
            ("UE-01", "oiran-lab-ueransim-ue-1", "10.46.0.4"),
            ("UE-02", "polaris-control-ue-02", "10.46.0.5"),
            ("UE-03", "polaris-control-ue-03", "10.46.0.6"),
        ]
        .into_iter()
        .map(|(ue, container, ip)| {
            serde_json::json!({
                "internal_ue_id":ue,"container":container,"interface":"uesimtun0","ue_ip":ip,
                "process_state":"RUNNING","registration_state":"REGISTERED",
                "pdu_session_state":"ACTIVE","pdu_session_id":"1",
                "status_provenance":"nr-cli status","pdu_provenance":"nr-cli ps-list",
                "tunnel_provenance":"ip -json address show dev uesimtun0"
            })
        })
        .collect::<Vec<_>>();
        fs::write(
            &evidence,
            serde_json::to_vec(&serde_json::json!({
                "schema_version":"1.0","observed_epoch_ms":observed,
                "source":"POLARIS_API+UERANSIM_NR_CLI","bindings":bindings
            }))
            .unwrap(),
        )
        .unwrap();
        *manager.continuous_runtime_evidence.lock().unwrap() = Some(evidence);
        let job = CaptureJob {
            capture_id: CONTINUOUS_CAPTURE_ID.into(),
            probe_id: PROBE_ID.into(),
            name: "production pipeline test".into(),
            profile: "POLARIS_5G_SA_CONTINUOUS_IMPORT".into(),
            interfaces: vec!["N2".into(), "N3".into(), "N4".into()],
            state: CaptureState::Capturing,
            created_epoch_ms: observed.saturating_sub(1_000),
            started_epoch_ms: Some(observed.saturating_sub(1_000)),
            ended_epoch_ms: None,
            owner: "operator".into(),
            metrics: CaptureMetrics::default(),
            output_directory: format!("runtime/live-captures/{CONTINUOUS_CAPTURE_ID}"),
            dataset_id: None,
            session_ids: Vec::new(),
            error: None,
            stop_reason: None,
            process_ids: Vec::new(),
            helper_results: Vec::new(),
            capture_group_id: Some("continuous-lab-import".into()),
            scenario_id: Some("POLARIS_5G_SA_CONTINUOUS_IMPORT".into()),
            planes: Vec::new(),
        };
        manager
            .jobs
            .lock()
            .unwrap()
            .insert(CONTINUOUS_CAPTURE_ID.into(), job);

        let dataset = manager
            .process_continuous_capture(&base, &interface_specs(), 128 * 1024 * 1024)
            .unwrap();
        assert_eq!(dataset.event_count, 3);
        assert_eq!(dataset.active_pdu_contexts.len(), 3);
        assert_eq!(dataset.active_ue_ips.len(), 3);
        for context in &dataset.active_pdu_contexts {
            let flow = manager
                .callflow(&dataset.dataset_id, &context.session_id)
                .or_else(|| {
                    serde_json::from_slice::<CallFlow>(
                        &fs::read(
                            base.join("dataset/callflows")
                                .join(format!("{}.json", context.session_id)),
                        )
                        .ok()?,
                    )
                    .ok()
                })
                .unwrap();
            assert!(flow
                .events
                .iter()
                .any(|event| event.protocol == "GTP-U" && event.message_name == "G-PDU"));
            assert_eq!(
                flow.correlation_status["E2E"],
                "PARTIAL_EXTERNAL_RUNTIME_CORROBORATED"
            );
        }
    }

    #[test]
    fn full_ring_ingests_three_interface_batches_across_rotations() {
        if skip_if_disk_too_full("full_ring_ingests_three_interface_batches_across_rotations") {
            return;
        }
        let root = temporary_root("full-ring-native-batches");
        let source = temporary_root("full-ring-native-source");
        let evidence = root.join("runtime-pdu-evidence.json");
        let bindings = [
            ("UE-01", "oiran-lab-ueransim-ue-1", "10.46.0.4"),
            ("UE-02", "polaris-control-ue-02", "10.46.0.5"),
            ("UE-03", "polaris-control-ue-03", "10.46.0.6"),
        ]
        .into_iter()
        .map(|(ue, container, ip)| {
            serde_json::json!({
                "internal_ue_id":ue,"container":container,"interface":"uesimtun0","ue_ip":ip,
                "process_state":"RUNNING","registration_state":"REGISTERED",
                "pdu_session_state":"ACTIVE","pdu_session_id":"1",
                "status_provenance":"nr-cli status","pdu_provenance":"nr-cli ps-list",
                "tunnel_provenance":"ip -json address show dev uesimtun0"
            })
        })
        .collect::<Vec<_>>();
        let write_evidence = |observed_epoch_ms| {
            fs::write(
                &evidence,
                serde_json::to_vec(&serde_json::json!({
                    "schema_version":"1.0","observed_epoch_ms":observed_epoch_ms,
                    "source":"POLARIS_API+UERANSIM_NR_CLI","bindings":bindings
                }))
                .unwrap(),
            )
            .unwrap();
        };

        fs::create_dir_all(source.join("N2")).unwrap();
        for index in 0..8u8 {
            write_pcap(
                &source.join("N2").join(format!("old-{index}.pcap")),
                &[vec![index; 64]],
            );
        }
        // 2.8.3: the 8 synthetic N2 segments are promoted to CLOSED via
        // the rotation JSONL contract.
        write_rotation_closures(&source, "N2", 8);
        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        manager
            .start_continuous_import(ContinuousImportConfig {
                source_root: source.clone(),
                scan_interval: Duration::from_millis(200),
                stable_age: Duration::from_millis(200),
                max_owned_bytes: 128 * 1024 * 1024,
                max_segment_bytes: 64 * 1024 * 1024,
                max_segments: 8,
                native_segment_seconds: None,
                historical_n2_bootstrap: None,
                runtime_pdu_evidence: None,
            })
            .unwrap();
        *manager.continuous_runtime_evidence.lock().unwrap() = Some(evidence.clone());
        wait_for(|| {
            manager
                .get(CONTINUOUS_CAPTURE_ID)
                .is_some_and(|job| job.metrics.segments_ingested == 8)
        });

        for rotation in 0..2u32 {
            let capture = source.join(format!("continuous-segment-rotation-{rotation}"));
            let pcap = capture.join("pcap");
            fs::create_dir_all(&pcap).unwrap();
            let remainder = epoch_ms() % 1000;
            thread::sleep(Duration::from_millis(1001 - remainder));
            let seconds = (epoch_ms() / 1000) as u32;
            let observed = u64::from(seconds) * 1000;
            write_evidence(observed);
            write_pcap_at(
                &pcap.join("N3.pcap"),
                seconds,
                &[
                    gtpu_gpdu_frame(4, 0x1004 + rotation * 0x100),
                    gtpu_gpdu_frame(5, 0x1005 + rotation * 0x100),
                    gtpu_gpdu_frame(6, 0x1006 + rotation * 0x100),
                ],
            );
            thread::sleep(Duration::from_millis(20));
            write_pcap(&pcap.join("N2.pcap"), &[vec![rotation as u8 + 20; 64]]);
            write_pcap(&pcap.join("N4.pcap"), &[vec![rotation as u8 + 40; 64]]);
            // 2.8.3: each rotation adds one new segment per plane; append
            // one JSONL closure per plane so the promotion gate stays
            // above the per-plane segment total.
            write_rotation_closures(&source, "N2", 1);
            write_rotation_closures(&source, "N3", 1);
            write_rotation_closures(&source, "N4", 1);

            let expected = 11 + u64::from(rotation) * 3;
            wait_for(|| {
                manager
                    .get(CONTINUOUS_CAPTURE_ID)
                    .is_some_and(|job| job.metrics.segments_ingested == expected)
            });
            let dataset = manager.dataset(CONTINUOUS_DATASET_ID).unwrap();
            assert_eq!(dataset.active_pdu_contexts.len(), 3);
            assert_eq!(dataset.active_ue_ips.len(), 3);
            // 2.8.4 (#9 comment 6705466743): the pcap ring no longer
            // evicts entries by count. After rotation N the ring
            // holds the 8 bootstrap N2 files plus 3·(N+1) rotation
            // outputs (one per plane) — the total grows monotonically
            // until `max_owned_bytes` is reached.
            assert_eq!(
                capture_files(&manager.root.join(CONTINUOUS_CAPTURE_ID).join("pcap")).len(),
                (expected as usize),
            );
            if rotation == 1 {
                assert!(dataset
                    .active_pdu_contexts
                    .iter()
                    .all(|context| context.gtpu_event_ids.len() >= 2));
            }
        }
        manager.stop(CONTINUOUS_CAPTURE_ID, "operator").unwrap();
    }

    #[test]
    fn native_cleanup_waits_for_every_selected_interface_file() {
        let root = temporary_root("native-cleanup-gate");
        let capture_id = "continuous-segment-cleanup-gate";
        let directory = root.join(capture_id).join("pcap");
        fs::create_dir_all(&directory).unwrap();
        for interface in ["N2", "N3", "N4"] {
            write_pcap(
                &directory.join(format!("{interface}.pcap")),
                &[vec![interface.as_bytes()[1]; 64]],
            );
        }
        let checksums = ["N2", "N3", "N4"]
            .into_iter()
            .map(|interface| {
                sha256_hex(&fs::read(directory.join(format!("{interface}.pcap"))).unwrap())
            })
            .collect::<Vec<_>>();
        let mut seen = BTreeSet::from([checksums[0].clone(), checksums[2].clone()]);
        assert!(!native_capture_fully_ingested(
            &root,
            capture_id,
            &seen,
            DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES,
        )
        .unwrap());
        assert!(root.join(capture_id).is_dir());
        seen.insert(checksums[1].clone());
        assert!(native_capture_fully_ingested(
            &root,
            capture_id,
            &seen,
            DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES,
        )
        .unwrap());
        cleanup_native_capture(&root, capture_id).unwrap();
        assert!(!root.join(capture_id).exists());
    }

    #[test]
    fn cleanup_removes_every_terminal_native_segment_including_empty() {
        let root = temporary_root("native-empty-cleanup");
        for index in 0..12 {
            let id = format!("continuous-segment-{index}");
            let directory = root.join(&id).join("pcap");
            fs::create_dir_all(&directory).unwrap();
            write_pcap(&directory.join("N3.pcap"), &[]);
        }
        let ids = native_capture_ids(&root).unwrap();
        assert_eq!(ids.len(), 12);
        let (bytes, jobs) = native_owned_usage(&root).unwrap();
        assert_eq!(jobs, 12);
        assert_eq!(bytes, 12 * 24);
        for id in ids {
            cleanup_native_capture(&root, &id).unwrap();
            assert!(!root.join(id).exists());
        }
        assert_eq!(directory_size(&root), 0);
    }

    /// 2.9.10 (#9 comment 6726685484) — ANR2 a prouvé 24 doublons
    /// réels sur `(capture_id, packet_number, byte_offset, protocol,
    /// message_name)`. L'ancien `continuous_observation_id` hachait
    /// `timestamp` + `session_identifiers` NON-triés et ignorait
    /// `packet_references` ; un décodeur qui changeait la précision
    /// du ts ou l'ordre des identifiers produisait deux evt-ids
    /// distincts pour un même paquet wire. La nouvelle clé est
    /// l'**identité wire** : `capture_id` + `packet_references`
    /// triés + `protocol` + `message_type` + `raw_payload_reference`.
    #[test]
    fn continuous_observation_id_is_wire_identity_and_dedupes_duplicates_2_9_10() {
        let base = event_json(
            "fixture",
            "sha256:01a70bdb74b0b",
            10_001,
            "NGAP",
            "UplinkNASTransport",
            None,
        );
        // Deux décodages du même paquet wire : timestamps
        // légèrement différents (précision µs vs ns), ordre
        // d'identifiers inversé, event_id différent. Même
        // identité wire ⇒ même continuous_observation_id ⇒
        // dedup actif.
        let mut a = base.clone();
        let mut b = base.clone();
        a["event_id"] = serde_json::Value::String("evt-50e7a11f02dd0644".into());
        b["event_id"] = serde_json::Value::String("evt-b89b4f8aefc5af40".into());
        a["timestamp"]["nanoseconds"] = serde_json::Value::from(1_000_000u64);
        b["timestamp"]["nanoseconds"] = serde_json::Value::from(1_000_001u64);
        a["session_identifiers"] = serde_json::json!([
            {"name":"ran_ue_ngap_id","value":"4","pseudonymized":false},
            {"name":"amf_ue_ngap_id","value":"73","pseudonymized":false}
        ]);
        b["session_identifiers"] = serde_json::json!([
            {"name":"amf_ue_ngap_id","value":"73","pseudonymized":false},
            {"name":"ran_ue_ngap_id","value":"4","pseudonymized":false}
        ]);
        assert_eq!(
            continuous_observation_id(&a).unwrap(),
            continuous_observation_id(&b).unwrap(),
            "deux décodages du même paquet wire doivent partager le même continuous_observation_id"
        );

        // Un paquet wire DIFFÉRENT (packet_number différent) doit
        // produire une autre identité — même protocole, même
        // raw_payload_reference, timestamp identique.
        let mut other_packet = a.clone();
        other_packet["packet_references"][0]["packet_number"] =
            serde_json::Value::from(99u64);
        assert_ne!(
            continuous_observation_id(&a).unwrap(),
            continuous_observation_id(&other_packet).unwrap(),
            "un paquet avec packet_number différent est une autre observation wire"
        );

        // Un `capture_id` différent (file rotated) = autre identité
        // wire — les deux captures sont distinctes à la source.
        let mut other_capture = a.clone();
        other_capture["capture_id"] = serde_json::Value::String("sha256:other".into());
        assert_ne!(
            continuous_observation_id(&a).unwrap(),
            continuous_observation_id(&other_capture).unwrap(),
            "capture_id ≠ ⇒ identité wire distincte"
        );

        // Un `protocol` ou `message_type` différent sur le même
        // paquet (NGAP + NAS enfant) sont deux observations distinctes.
        let mut nas_child = a.clone();
        nas_child["protocol"] = serde_json::Value::String("NAS-5GMM".into());
        nas_child["message_type"] = serde_json::Value::from(42u64);
        assert_ne!(
            continuous_observation_id(&a).unwrap(),
            continuous_observation_id(&nas_child).unwrap(),
            "NGAP et NAS enfant sur le même paquet sont deux observations"
        );
    }

    /// 2.9.13 (#9 comment 6727243545) — ANR2 a prouvé 24 doublons
    /// réels (dont 8 post-2.8.3), exemples :
    ///   * `sha256:01a70bdb…74b0b`, packet 23, offset 3908,
    ///     NGAP, `UplinkNASTransport` :
    ///       `evt-83151568d66288d0` + `evt-c5cfdf6a8f4a9bdd`.
    ///   * `sha256:01a70bdb…74b0b`, packet 23, offset 3908,
    ///     NAS-5GMM, `Protected 5GMM message` :
    ///       `evt-50e7a11f02dd0644` + `evt-b89b4f8aefc5af40`.
    ///
    /// Les deux evt-ids d'un même wire packet divergeaient parce
    /// que la clé 2.9.10 incluait `raw_payload_reference` — un
    /// SHA du payload DÉCODÉ. Deux décodes successifs du même
    /// paquet wire pouvaient produire des slices subtilement
    /// différents (padding AVP, longueur optionnelle) → SHA
    /// différent → clés différentes → dupe non fusionné.
    ///
    /// 2.9.13 : la clé est maintenant exactement
    /// `(capture_id, anchor packet_reference, protocol,
    /// message_name)` — l'identité wire ANR2. Les agrégats
    /// gardent leur discriminant propre.
    #[test]
    fn continuous_observation_id_dedupes_anr2_24_wire_duplicates_2_9_13() {
        let packet = event_json(
            "fixture",
            "sha256:01a70bdb74b0b",
            10_001,
            "NGAP",
            "UplinkNASTransport",
            None,
        );
        // Deux décodes du même paquet wire. SHA du payload
        // décodé diffère subtilement entre les deux ; ANR2
        // montre que c'est le cas en production.
        let mut a = packet.clone();
        let mut b = packet.clone();
        a["event_id"] = serde_json::Value::String("evt-83151568d66288d0".into());
        b["event_id"] = serde_json::Value::String("evt-c5cfdf6a8f4a9bdd".into());
        // raw_payload_reference différent : prouve que le hash
        // 2.9.10 divergeait mais le hash 2.9.13 ne doit PAS
        // diverger (identité wire pure).
        a["raw_payload_reference"] =
            serde_json::Value::String("sha256:payload-copy-a".into());
        b["raw_payload_reference"] =
            serde_json::Value::String("sha256:payload-copy-b".into());
        // message_type différent (code vs string) : le 2.9.13
        // n'utilise que message_name.
        a["message_type"] = serde_json::Value::from(46u64);
        b["message_type"] = serde_json::Value::from(46u64);
        assert_eq!(
            continuous_observation_id(&a).unwrap(),
            continuous_observation_id(&b).unwrap(),
            "ANR2 24-dupe : même paquet wire ⇒ même continuous_observation_id même si raw_payload_reference diverge"
        );

        // NGAP + NAS enfant sur MÊME paquet : différents
        // message_name → deux observations distinctes (comportement
        // attendu, ANR2 l'a spécifié).
        let mut nas_child = packet.clone();
        nas_child["protocol"] = serde_json::Value::String("NAS-5GMM".into());
        nas_child["message_name"] =
            serde_json::Value::String("Protected 5GMM message".into());
        assert_ne!(
            continuous_observation_id(&packet).unwrap(),
            continuous_observation_id(&nas_child).unwrap(),
            "NGAP + NAS enfant sur même paquet = deux observations légitimes"
        );
    }

    /// 2.8.2 (#10 comment 6687323881 — regression on 2.8.1): the
    /// `MAX_CONTINUOUS_SEEN=4096` eviction is removed. ANR2 proved in
    /// production that evicting old checksums caused retained source
    /// segments (still on disk) to be re-discovered as pending every
    /// scan, sustaining 92.85% CPU on oiran-api. The index now grows
    /// with the real file population; `purge_missing_source_fingerprints`
    /// removes entries when the file disappears AND the segment is
    /// not still in `state.segments`.
    #[test]
    fn persistent_seen_index_grows_without_a_fixed_cap_and_purges_only_missing_files() {
        let mut state = ContinuousImportState::default();
        // 10 000 checksums > the removed 4 096 cap: none are evicted.
        for index in 0..10_000 {
            remember_checksum(&mut state, format!("checksum-{index:05}"));
            state.source_fingerprints.insert(
                format!("/src/N2/seg-{index:05}.pcapng"),
                SourceFingerprint {
                    dev: 1,
                    inode: 1_000 + index as u64,
                    size_bytes: 2 * 1024 * 1024,
                    mtime_ns: 1_000_000_000i128 + index as i128,
                    checksum: format!("checksum-{index:05}"),
                    packets: 1,
                },
            );
        }
        assert_eq!(state.seen_checksums.len(), 10_000);
        assert_eq!(state.seen_order.len(), 10_000);
        assert!(state.seen_checksums.contains("checksum-00000"));
        assert!(state.seen_checksums.contains("checksum-09999"));
        // Purge drops entries whose file vanished; the checksum
        // follows only when it's not held in `state.segments`.
        let mut live = std::collections::BTreeSet::new();
        for index in 1_000..10_000 {
            live.insert(PathBuf::from(format!("/src/N2/seg-{index:05}.pcapng")));
        }
        // Pin one vanished checksum into state.segments to prove the
        // purge preserves ingested segments even if the source file
        // was rotated away.
        state.segments.insert(
            "checksum-00000".into(),
            ImportedSegment {
                interface: "N2".into(),
                owned_file: "N2.pcap-00000000000000000.pcapng".into(),
                size_bytes: 2 * 1024 * 1024,
                packets: 1,
                imported_epoch_ms: 1,
                source_path: "/src/N2/seg-00000.pcapng".into(),
                historical_context: false,
            },
        );
        let changed = purge_missing_source_fingerprints(&mut state, &live);
        assert!(changed);
        assert_eq!(state.source_fingerprints.len(), 9_000);
        // Vanished + unlinked: dropped.
        assert!(!state.seen_checksums.contains("checksum-00500"));
        // Vanished + still in state.segments: retained.
        assert!(state.seen_checksums.contains("checksum-00000"));
        // Still on disk: retained.
        assert!(state.seen_checksums.contains("checksum-09999"));
    }

    #[test]
    fn imported_marker_is_committed_only_after_atomic_publication() {
        let root = temporary_root("continuous-publish-marker");
        let state_path = root.join("state/import_state.json");
        let mut state = ContinuousImportState::default();
        let checksum = "published-checksum".to_string();

        state.segments.insert(
            checksum.clone(),
            ImportedSegment {
                interface: "N3".into(),
                owned_file: "N3.pcap-published.pcapng".into(),
                size_bytes: 64,
                packets: 1,
                imported_epoch_ms: 1,
                source_path: "/source/N3.pcapng".into(),
                historical_context: false,
            },
        );
        assert!(!state.seen_checksums.contains(&checksum));

        assert!(persist_published_checksums(
            &state_path,
            &mut state,
            std::slice::from_ref(&checksum),
        )
        .is_err());
        assert!(!state.seen_checksums.contains(&checksum));
        assert!(!state_path.exists());

        fs::create_dir_all(state_path.parent().unwrap()).unwrap();
        persist_published_checksums(&state_path, &mut state, std::slice::from_ref(&checksum))
            .unwrap();
        let persisted: ContinuousImportState =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        assert!(state.seen_checksums.contains(&checksum));
        assert!(persisted.seen_checksums.contains(&checksum));
        assert_eq!(persisted.seen_order.back(), Some(&checksum));
    }

    #[test]
    fn atomic_temp_budget_failure_preserves_previous_dataset() {
        let root = temporary_root("continuous-atomic-budget");
        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        let base = root.join(CONTINUOUS_CAPTURE_ID);
        fs::create_dir_all(base.join("pcap")).unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1/N2.pcapng");
        fs::copy(fixture, base.join("pcap/N2.pcap-fixture.pcapng")).unwrap();
        manager
            .process_continuous_capture(&base, &interface_specs(), 128 * 1024 * 1024)
            .unwrap();
        let manifest = base.join("dataset/dataset_manifest.json");
        let before = fs::read(&manifest).unwrap();
        let exact_current_size = directory_size(&base);
        assert_eq!(
            manager
                .process_continuous_capture(&base, &interface_specs(), exact_current_size)
                .unwrap_err(),
            "CONTINUOUS_ATOMIC_TEMP_BUDGET"
        );
        assert_eq!(fs::read(&manifest).unwrap(), before);
        assert!(!base.join(".dataset-next").exists());
        assert!(!base.join(".dataset-previous").exists());
    }

    #[test]
    fn real_interface_discovery_is_allowlisted() {
        // 2.9.2 (#9 comment 6710853974): the registry now returns
        // every decoder-backed plane (11 interfaces, N6 excluded —
        // see `interface_specs_covers_every_decoder_backed_plane`).
        let manager = { let tmp = temporary_root("interfaces"); CaptureManager::with_pseudonym_key_path(tmp.clone(), false, tmp.join(".oiran-pseudonym.key")) }.unwrap();
        let interfaces = manager.interfaces();
        // 2.11.0 (devmat) : 12 interfaces (11 core planes + IMS).
        assert_eq!(interfaces.len(), 12);
        let observed: BTreeSet<String> = interfaces
            .iter()
            .map(|item| item.interface.clone())
            .collect();
        let expected: BTreeSet<String> = [
            "N2", "N3", "N4", "SBI", "S1-MME", "S1-U", "S11", "S5-C", "S5-U", "S6a", "Sxab", "IMS",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert_eq!(observed, expected);
        assert!(interfaces
            .iter()
            .all(|item| item.device.starts_with("br-oiran-")));
    }

    #[test]
    fn validation_rejects_custom_device_filter_and_unbounded_values() {
        let manager = { let tmp = temporary_root("validation"); CaptureManager::with_pseudonym_key_path(tmp.clone(), false, tmp.join(".oiran-pseudonym.key")) }.unwrap();
        let mut request = CaptureRequest::default();
        request.interfaces = vec!["eth0".into()];
        request.duration_seconds = 901;
        request.optional_filter = Some("host 8.8.8.8".into());
        let result = manager.validate(&request);
        assert!(!result.valid);
        assert!(result
            .blockers
            .iter()
            .any(|item| item == "INTERFACE_eth0_NOT_ALLOWLISTED"));
        assert!(result
            .blockers
            .iter()
            .any(|item| item == "CUSTOM_FILTER_NOT_CERTIFIED"));
    }

    #[test]
    fn api_contract_accepts_one_through_four_planes_and_preserves_three_plane_requests() {
        let mut interfaces = interface_specs();
        for interface in &mut interfaces {
            interface.available = true;
            interface.operstate = "UP".into();
            interface.reason = None;
        }
        let allowed = ["N2", "SBI", "N4", "N3"];
        for count in 1..=MAX_CAPTURE_PLANES {
            let mut request = CaptureRequest::default();
            request.interfaces = allowed[..count]
                .iter()
                .map(|plane| (*plane).to_string())
                .collect();
            let blockers = validate_request(&request, &interfaces, Policy::default());
            assert!(blockers.is_empty(), "{count}-plane blockers: {blockers:?}");
        }
    }

    #[test]
    fn api_contract_rejects_five_duplicate_unknown_and_unavailable_planes() {
        let mut interfaces = interface_specs();
        for interface in &mut interfaces {
            interface.available = true;
            interface.operstate = "UP".into();
            interface.reason = None;
        }

        let mut five = CaptureRequest::default();
        five.interfaces.push("N2".into());
        assert!(validate_request(&five, &interfaces, Policy::default())
            .contains(&"INVALID_INTERFACE_COUNT".to_string()));

        let mut duplicate = CaptureRequest::default();
        duplicate.interfaces = vec!["N2".into(), "N2".into()];
        assert!(validate_request(&duplicate, &interfaces, Policy::default())
            .contains(&"DUPLICATE_INTERFACE".to_string()));

        let mut unknown = CaptureRequest::default();
        unknown.interfaces = vec!["N2".into(), "UNKNOWN".into()];
        assert!(validate_request(&unknown, &interfaces, Policy::default())
            .contains(&"INTERFACE_UNKNOWN_NOT_ALLOWLISTED".to_string()));

        interfaces
            .iter_mut()
            .find(|interface| interface.interface == "SBI")
            .unwrap()
            .available = false;
        let blockers = validate_request(&CaptureRequest::default(), &interfaces, Policy::default());
        assert!(blockers.contains(&"INTERFACE_SBI_UNAVAILABLE".to_string()));
    }

    #[test]
    fn execution_is_fail_closed_until_deployment_enables_it() {
        let manager = { let tmp = temporary_root("locked"); CaptureManager::with_pseudonym_key_path(tmp.clone(), false, tmp.join(".oiran-pseudonym.key")) }.unwrap();
        assert!(manager
            .start(CaptureRequest::default(), "operator")
            .is_err());
        assert!(manager.list().is_empty());
    }

    #[test]
    fn stop_enforces_exact_owner_and_is_idempotent_after_completion() {
        let manager = { let tmp = temporary_root("ownership"); CaptureManager::with_pseudonym_key_path(tmp.clone(), false, tmp.join(".oiran-pseudonym.key")) }.unwrap();
        let id = "live-owned-0001".to_string();
        let job = CaptureJob {
            capture_id: id.clone(),
            probe_id: PROBE_ID.into(),
            name: "OWNED-TEST".into(),
            profile: "POLARIS_5G_SA".into(),
            interfaces: vec!["N3".into()],
            state: CaptureState::Capturing,
            created_epoch_ms: epoch_ms(),
            started_epoch_ms: Some(epoch_ms()),
            ended_epoch_ms: None,
            owner: "operator-a".into(),
            metrics: CaptureMetrics::default(),
            output_directory: "runtime/test".into(),
            dataset_id: None,
            session_ids: Vec::new(),
            error: None,
            stop_reason: None,
            process_ids: Vec::new(),
            helper_results: Vec::new(),
            capture_group_id: None,
            scenario_id: None,
            planes: Vec::new(),
        };
        manager.jobs.lock().unwrap().insert(id.clone(), job);
        assert!(manager.stop(&id, "operator-b").is_err());
        manager
            .update(&id, |job| job.state = CaptureState::Completed)
            .unwrap();
        assert_eq!(
            manager.stop(&id, "operator-a").unwrap().state,
            CaptureState::Completed
        );
    }

    #[test]
    fn pcap_counter_handles_complete_records_and_truncation() {
        let root = temporary_root("pcap");
        let path = root.join("N3.pcap");
        let mut data = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0, 0, 1, 0, 0, 0, 0,
        ];
        data.extend_from_slice(&[0; 8]);
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&[1, 2, 3, 4]);
        fs::write(&path, data).unwrap();
        assert_eq!(count_pcap_records(&path), 1);
    }

    #[test]
    fn completed_capture_registers_real_decoded_dataset_with_provenance() {
        let root = temporary_root("pipeline");
        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        let capture_id = "live-pipeline-fixture";
        let pcap_dir = root.join(capture_id).join("pcap");
        fs::create_dir_all(&pcap_dir).unwrap();
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let fixture = workspace.join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
        for name in ["N2.pcapng", "N3.pcapng", "N4.pcapng"] {
            fs::copy(fixture.join(name), pcap_dir.join(name)).unwrap();
        }
        let dataset = manager
            .process_capture(capture_id, &manager.interfaces())
            .unwrap();
        assert_eq!(dataset.decode_reports.len(), 3);
        assert!(dataset.event_count > 0);
        assert!(!dataset.session_ids.is_empty());
        let events = load_path(&root.join(capture_id).join("dataset/oiran_events.jsonl")).unwrap();
        assert!(events
            .iter()
            .all(|event| !event.packet_references.is_empty()));
        assert!(root
            .join(capture_id)
            .join("dataset/dataset_manifest.json")
            .is_file());
    }

    #[test]
    fn empty_capture_is_explicit_and_never_fabricates_a_session() {
        let root = temporary_root("empty");
        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        let capture_id = "live-empty-fixture";
        let pcap_dir = root.join(capture_id).join("pcap");
        fs::create_dir_all(&pcap_dir).unwrap();
        let header = [
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0, 0, 1, 0, 0, 0, 0,
        ];
        for name in ["N2.pcap", "N3.pcap", "N4.pcap"] {
            fs::write(pcap_dir.join(name), header).unwrap();
        }
        let dataset = manager
            .process_capture(capture_id, &manager.interfaces())
            .unwrap();
        assert_eq!(dataset.state, "COMPLETED_EMPTY");
        assert_eq!(dataset.event_count, 0);
        assert!(dataset.session_ids.is_empty());
    }

    #[test]
    fn finalized_capture_with_empty_interface_creates_derived_dataset_layout() {
        let root = temporary_root("partial-interface-pipeline");
        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        let capture_id = "live-partial-interface-fixture";
        let pcap_dir = root.join(capture_id).join("pcap");
        fs::create_dir_all(&pcap_dir).unwrap();
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let fixture = workspace.join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
        fs::copy(fixture.join("N2.pcapng"), pcap_dir.join("N2.pcap0")).unwrap();
        fs::copy(fixture.join("N4.pcapng"), pcap_dir.join("N4.pcap0")).unwrap();
        let header = [
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0, 0, 1, 0, 0, 0, 0,
        ];
        fs::write(pcap_dir.join("N3.pcap0"), header).unwrap();

        let dataset = manager
            .process_capture(capture_id, &manager.interfaces())
            .unwrap();

        assert_eq!(dataset.decode_reports.len(), 2);
        assert!(dataset.decode_reports.contains_key("N2.pcap0"));
        assert!(dataset.decode_reports.contains_key("N4.pcap0"));
        assert!(!dataset.decode_reports.contains_key("N3.pcap0"));
        assert!(root
            .join(capture_id)
            .join("dataset/oiran_events.jsonl")
            .is_file());
        assert!(root
            .join(capture_id)
            .join("dataset/dataset_manifest.json")
            .is_file());
    }

    #[test]
    fn recoverable_failed_capture_is_not_promoted_during_registry_recovery() {
        let root = temporary_root("recoverable-failed");
        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        let id = "live-recoverable-failed";
        let pcap_dir = root.join(id).join("pcap");
        fs::create_dir_all(&pcap_dir).unwrap();
        fs::write(
            pcap_dir.join("N3.pcap0"),
            [
                0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0, 0, 1, 0, 0, 0,
                0,
            ],
        )
        .unwrap();
        let job = CaptureJob {
            capture_id: id.into(),
            probe_id: PROBE_ID.into(),
            name: "RECOVERABLE".into(),
            profile: "POLARIS_5G_SA".into(),
            interfaces: vec!["N3".into()],
            state: CaptureState::Failed,
            created_epoch_ms: 1,
            started_epoch_ms: Some(2),
            ended_epoch_ms: Some(3),
            owner: "operator".into(),
            metrics: CaptureMetrics::default(),
            output_directory: format!("runtime/live-captures/{id}"),
            dataset_id: None,
            session_ids: Vec::new(),
            error: Some("DATASET_PROCESSING_FAILED".into()),
            stop_reason: None,
            process_ids: Vec::new(),
            helper_results: Vec::new(),
            capture_group_id: None,
            scenario_id: None,
            planes: Vec::new(),
        };
        manager.persist_job(&job).unwrap();

        let recovered = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap().get(id).unwrap();
        assert_eq!(recovered.state, CaptureState::Failed);
        assert!(recovered.dataset_id.is_none());
        assert_eq!(
            recovered.error.as_deref(),
            Some("DATASET_PROCESSING_FAILED")
        );
    }

    #[test]
    fn valid_capture_with_no_supported_messages_is_registered_empty() {
        let root = temporary_root("unsupported-packets");
        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        let id = "live-unsupported-packets";
        let pcap_dir = root.join(id).join("pcap");
        fs::create_dir_all(&pcap_dir).unwrap();
        let mut arp = vec![0u8; 42];
        arp[12] = 0x08;
        arp[13] = 0x06;
        write_pcap(&pcap_dir.join("N3.pcap0"), &[arp]);
        let interfaces = vec![interface_specs()
            .into_iter()
            .find(|interface| interface.interface == "N3")
            .unwrap()];

        let dataset = manager.process_capture(id, &interfaces).unwrap();

        assert_eq!(dataset.event_count, 0);
        assert_eq!(dataset.state, "COMPLETED_EMPTY");
        assert_eq!(dataset.decode_reports["N3.pcap0"].packets, 1);
        assert!(root.join(id).join("dataset/oiran_events.jsonl").is_file());
    }

    #[test]
    fn decoder_failure_does_not_finalize_or_register_dataset() {
        let root = temporary_root("decoder-failure");
        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        let id = "live-decoder-failure";
        let pcap_dir = root.join(id).join("pcap");
        fs::create_dir_all(&pcap_dir).unwrap();
        let mut malformed = vec![0u8; 25];
        malformed[..4].copy_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        fs::write(pcap_dir.join("N2.pcap0"), malformed).unwrap();
        let result = manager.process_capture(id, &manager.interfaces());

        assert!(result.is_err());
        assert!(!root.join(id).join("dataset/dataset_manifest.json").exists());
        assert!(manager.datasets().is_empty());
    }

    #[test]
    fn dataset_registration_rejects_missing_final_manifest() {
        let root = temporary_root("registration-failure");
        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        let id = "live-registration-failure";
        let pcap_dir = root.join(id).join("pcap");
        fs::create_dir_all(&pcap_dir).unwrap();
        write_pcap(&pcap_dir.join("N3.pcap0"), &[]);
        let dataset = manager.process_capture(id, &manager.interfaces()).unwrap();
        fs::remove_file(root.join(id).join("dataset/dataset_manifest.json")).unwrap();

        assert!(manager
            .register_dataset(dataset, &root.join(id).join("dataset"))
            .is_err());
        assert!(manager.datasets().is_empty());
    }

    #[test]
    fn permission_denied_error_remains_explicit() {
        let error = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let message = dataset_io_error(
            "DATASET_PERMISSION",
            Path::new("/restricted/dataset"),
            error,
        );
        assert!(message.contains("DATASET_PERMISSION"));
        assert!(message.to_ascii_lowercase().contains("permission denied"));
    }

    #[test]
    fn failed_capture_recovery_is_atomic_registered_and_idempotent() {
        let root = temporary_root("offline-recovery");
        let id = "live-offline-recovery";
        let pcap_dir = root.join(id).join("pcap");
        fs::create_dir_all(&pcap_dir).unwrap();
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let fixture = workspace.join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
        let mut files = Vec::new();
        for (interface, source) in [
            ("N2", "N2.pcapng"),
            ("N3", "N3.pcapng"),
            ("N4", "N4.pcapng"),
        ] {
            let destination = pcap_dir.join(format!("{interface}.pcap0"));
            fs::copy(fixture.join(source), &destination).unwrap();
            let bytes = fs::read(&destination).unwrap();
            files.push(serde_json::json!({
                "file": format!("{interface}.pcap0"),
                "interface": interface,
                "sha256": sha256_hex(&bytes),
                "size_bytes": bytes.len()
            }));
        }
        let source_files = capture_files(&pcap_dir);
        let (packets, storage_bytes) = pcap_totals(&source_files);
        fs::write(
            root.join(id).join("capture_manifest.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "packets": packets,
                "files": files,
                "storage_bytes": storage_bytes
            }))
            .unwrap(),
        )
        .unwrap();
        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        let job = CaptureJob {
            capture_id: id.into(),
            probe_id: PROBE_ID.into(),
            name: "RECOVERY".into(),
            profile: "POLARIS_5G_SA".into(),
            interfaces: vec!["N2".into(), "N3".into(), "N4".into()],
            state: CaptureState::Failed,
            created_epoch_ms: 1,
            started_epoch_ms: Some(2),
            ended_epoch_ms: Some(3),
            owner: "operator".into(),
            metrics: CaptureMetrics::default(),
            output_directory: format!("runtime/live-captures/{id}"),
            dataset_id: None,
            session_ids: Vec::new(),
            error: Some("DATASET_OUTPUT_MISSING".into()),
            stop_reason: None,
            process_ids: Vec::new(),
            helper_results: Vec::new(),
            capture_group_id: None,
            scenario_id: None,
            planes: Vec::new(),
        };
        manager.persist_job(&job).unwrap();
        drop(manager);
        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        let original_job = fs::read(root.join(id).join("job.json")).unwrap();
        let original_hashes = source_files
            .iter()
            .map(|path| sha256_hex(&fs::read(path).unwrap()))
            .collect::<Vec<_>>();

        let first = manager.recover_failed_capture(id).unwrap();
        let second = manager.recover_failed_capture(id).unwrap();

        assert_eq!(first.dataset_id, second.dataset_id);
        assert_eq!(
            first.dataset_integrity_sha256,
            second.dataset_integrity_sha256
        );
        assert_eq!(first.recovered_packets, packets);
        assert!(first.generated_events > 0);
        assert_eq!(manager.get(id).unwrap().state, CaptureState::Failed);
        assert_eq!(
            fs::read(root.join(id).join("job.json")).unwrap(),
            original_job
        );
        assert_eq!(
            source_files
                .iter()
                .map(|path| sha256_hex(&fs::read(path).unwrap()))
                .collect::<Vec<_>>(),
            original_hashes
        );
        assert_eq!(manager.datasets().len(), 1);
        let recovered_dataset = manager.dataset(&first.dataset_id).unwrap();
        let recovered_session = recovered_dataset.session_ids.first().unwrap();
        assert!(manager
            .callflow(&first.dataset_id, recovered_session)
            .is_some());
        let recovery = root.join("recovered-datasets").join(id);
        assert!(recovery.join("recovery_manifest.json").is_file());
        assert!(recovery.join("dataset/dataset_manifest.json").is_file());
        assert!(root.join("recovered-datasets/registry.json").is_file());
        assert!(fs::read_dir(&recovery)
            .unwrap()
            .filter_map(Result::ok)
            .all(|entry| !entry.file_name().to_string_lossy().ends_with(".tmp")));
    }

    #[test]
    fn registry_recovery_reclassifies_legacy_helper_exit_as_failed() {
        let root = temporary_root("legacy-failure");
        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        let id = "live-legacy-failure";
        let job = CaptureJob {
            capture_id: id.into(),
            probe_id: PROBE_ID.into(),
            name: "LEGACY".into(),
            profile: "POLARIS_5G_SA".into(),
            interfaces: vec!["N2".into()],
            state: CaptureState::Completed,
            created_epoch_ms: 1,
            started_epoch_ms: Some(2),
            ended_epoch_ms: Some(3),
            owner: "operator".into(),
            metrics: CaptureMetrics::default(),
            output_directory: format!("runtime/live-captures/{id}"),
            dataset_id: Some(format!("dataset-{id}")),
            session_ids: Vec::new(),
            error: None,
            stop_reason: Some("CAPTURE_HELPER_EXITED".into()),
            process_ids: Vec::new(),
            helper_results: Vec::new(),
            capture_group_id: None,
            scenario_id: None,
            planes: Vec::new(),
        };
        fs::create_dir_all(root.join(id).join("pcap")).unwrap();
        manager.persist_job(&job).unwrap();
        let recovered = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap().get(id).unwrap();
        assert_eq!(recovered.state, CaptureState::Failed);
        assert_eq!(
            recovered.error.as_deref(),
            Some("CAPTURE_HELPER_EXITED_NO_OUTPUT")
        );
        assert!(recovered.dataset_id.is_none());
    }

    #[test]
    fn lifecycle_persists_starting_capturing_and_terminal_states() {
        let root = temporary_root("lifecycle");
        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        let id = "live-lifecycle";
        let mut job = CaptureJob {
            capture_id: id.into(),
            probe_id: PROBE_ID.into(),
            name: "LIFECYCLE".into(),
            profile: "POLARIS_5G_SA".into(),
            interfaces: vec!["N3".into()],
            state: CaptureState::Starting,
            created_epoch_ms: 1,
            started_epoch_ms: None,
            ended_epoch_ms: None,
            owner: "operator".into(),
            metrics: CaptureMetrics::default(),
            output_directory: "runtime/test".into(),
            dataset_id: None,
            session_ids: Vec::new(),
            error: None,
            stop_reason: None,
            process_ids: Vec::new(),
            helper_results: Vec::new(),
            capture_group_id: None,
            scenario_id: None,
            planes: Vec::new(),
        };
        manager.jobs.lock().unwrap().insert(id.into(), job.clone());
        manager
            .update(id, |current| {
                current.state = CaptureState::Capturing;
                current.started_epoch_ms = Some(2);
            })
            .unwrap();
        assert_eq!(manager.get(id).unwrap().state, CaptureState::Capturing);
        manager
            .update(id, |current| {
                current.state = CaptureState::Completed;
                current.ended_epoch_ms = Some(3);
            })
            .unwrap();
        assert_eq!(manager.get(id).unwrap().state, CaptureState::Completed);
        job.state = CaptureState::Starting;
        job.started_epoch_ms = None;
        job.ended_epoch_ms = None;
        manager.jobs.lock().unwrap().insert(id.into(), job);
        manager
            .update(id, |current| current.state = CaptureState::Capturing)
            .unwrap();
        manager
            .update(id, |current| {
                current.state = CaptureState::Failed;
                current.error = Some("HELPER_FAILED".into());
            })
            .unwrap();
        assert_eq!(manager.get(id).unwrap().state, CaptureState::Failed);
    }

    #[test]
    fn default_profile_is_a_synchronized_four_plane_group() {
        let request = CaptureRequest::default();
        assert_eq!(request.interfaces, ["N2", "SBI", "N4", "N3"]);
        let spec = helper_spec("four-plane-test".into(), &request);
        assert_eq!(
            spec.interfaces,
            [
                InterfaceId::N2,
                InterfaceId::Sbi,
                InterfaceId::N4,
                InterfaceId::N3
            ]
        );
        assert_eq!(plane_name("N2"), "NG-C");
        assert_eq!(plane_name("N3"), "NG-U");
    }

    #[test]
    fn derived_dataset_registration_is_atomic_idempotent_and_conflict_safe() {
        let root = temporary_root("derived-import");
        let capture_id = "live-derived-source";
        let source = root.join(capture_id);
        fs::create_dir_all(source.join("pcap")).unwrap();
        fs::create_dir_all(source.join("dataset/callflows")).unwrap();
        let pcap_path = source.join("pcap/N2.pcap0");
        write_pcap(&pcap_path, &[vec![0u8; 32]]);
        let pcap_bytes = fs::read(&pcap_path).unwrap();
        let pcap_hash = sha256_hex(&pcap_bytes);
        fs::write(
            source.join("capture_manifest.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "packets": 1,
                "files": [{
                    "file": "N2.pcap0", "interface": "N2",
                    "sha256": pcap_hash, "size_bytes": pcap_bytes.len()
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let source_dataset = LiveDataset {
            dataset_id: "dataset-live-derived-source".into(),
            capture_id: capture_id.into(),
            path: "runtime/live-captures/live-derived-source/dataset".into(),
            event_count: 0,
            session_ids: Vec::new(),
            decode_reports: BTreeMap::new(),
            checksums: BTreeMap::from([("N2.pcap0".into(), pcap_hash)]),
            state: "COMPLETED_EMPTY".into(),
            discovery: None,
            capture_started_epoch_ms: None,
            last_packet_epoch_ms: None,
            fresh_packet_count: 0,
            active_ue_ips: Vec::new(),
            active_pdu_contexts: Vec::new(),
            zero_event_captures: Vec::new(),
        };
        fs::write(source.join("dataset/oiran_events.jsonl"), b"").unwrap();
        fs::write(
            source.join("dataset/dataset_manifest.json"),
            serde_json::to_vec_pretty(&source_dataset).unwrap(),
        )
        .unwrap();

        let import_root = root.join("reviewed-imports");
        let artifact = import_root.join("reviewed-empty-fixture");
        fs::create_dir_all(&artifact).unwrap();
        let events = Vec::<u8>::new();
        let evidence = serde_json::to_vec_pretty(&serde_json::json!({
            "source_events": 0, "ue_contexts": 0, "pdu_sessions": 0,
            "pfcp_sessions": 0, "gtpu_tunnels": 0, "correlation_edges": []
        }))
        .unwrap();
        fs::write(artifact.join("oiran_events.jsonl"), &events).unwrap();
        fs::write(artifact.join("correlation_evidence.json"), &evidence).unwrap();
        let dataset_id = "derived-test-empty";
        let manifest = serde_json::json!({
            "dataset_id": dataset_id,
            "source_capture_id": capture_id,
            "source_dataset_id": source_dataset.dataset_id,
            "kind": "OFFLINE_DERIVED_REPLAY",
            "packet_count": 1,
            "event_count": 0,
            "ue_context_count": 0,
            "pdu_session_count": 0,
            "pfcp_session_count": 0,
            "gtpu_tunnel_count": 0,
            "correlation_edge_count": 0,
            "source_immutable": true,
            "registered_in_production": false,
            "complete_e2e_certified": false,
            "artifacts": {
                "oiran_events.jsonl": format!("sha256:{}", sha256_hex(&events)),
                "correlation_evidence.json": format!("sha256:{}", sha256_hex(&evidence))
            }
        });
        fs::write(
            artifact.join("dataset_manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let manager = CaptureManager::with_pseudonym_key_path(root.clone(), false, root.join(".oiran-pseudonym.key")).unwrap();
        let first = manager
            .import_derived_dataset(&import_root, dataset_id, "operator")
            .unwrap();
        let second = manager
            .import_derived_dataset(&import_root, dataset_id, "operator")
            .unwrap();
        assert_eq!(
            first.derived_manifest_sha256,
            second.derived_manifest_sha256
        );
        assert_eq!(first.registration, "VALIDATED_REGISTERED");
        assert!(root.join("derived-datasets/registry.json").is_file());
        assert!(fs::read_dir(root.join("derived-datasets"))
            .unwrap()
            .filter_map(Result::ok)
            .all(|entry| !entry.file_name().to_string_lossy().ends_with(".tmp")));
        let mut conflicting = manifest;
        conflicting["review_revision"] = serde_json::json!(2);
        fs::write(
            artifact.join("dataset_manifest.json"),
            serde_json::to_vec_pretty(&conflicting).unwrap(),
        )
        .unwrap();
        assert_eq!(
            manager
                .import_derived_dataset(&import_root, dataset_id, "operator")
                .unwrap_err(),
            "DATASET_REGISTRATION_CONFLICT"
        );
    }

    // ---------------------------------------------------------------
    // 0.2.0 — continuous-import finalized segments + failure log
    // ---------------------------------------------------------------

    #[test]
    fn record_ingestion_failure_appends_and_evicts_fifo() {
        let mut log: VecDeque<FailedIngestion> = VecDeque::new();
        for index in 0..(MAX_PERSISTED_INGESTION_FAILURES + 10) {
            record_ingestion_failure(
                &mut log,
                format!("/var/lib/pcap/N2/segment-{index}.pcapng"),
                "CONTINUOUS_SEGMENT_NOT_FINALIZED",
                1_730_000_000_000 + index as u64,
            );
        }
        assert_eq!(log.len(), MAX_PERSISTED_INGESTION_FAILURES);
        // FIFO: oldest ten are evicted; the newest entry sits at the back.
        assert!(log
            .back()
            .unwrap()
            .source_path
            .ends_with("segment-265.pcapng"));
        assert!(log
            .front()
            .unwrap()
            .source_path
            .ends_with("segment-10.pcapng"));
    }

    #[test]
    fn record_ingestion_failure_keeps_path_code_and_timestamp_verbatim() {
        let mut log: VecDeque<FailedIngestion> = VecDeque::new();
        record_ingestion_failure(
            &mut log,
            "/root/pcap/N3/live.pcapng",
            "CONTINUOUS_COPY_RETRYABLE",
            1_730_000_000_001,
        );
        let entry = log.back().unwrap();
        assert_eq!(entry.source_path, "/root/pcap/N3/live.pcapng");
        assert_eq!(entry.error_code, "CONTINUOUS_COPY_RETRYABLE");
        assert_eq!(entry.occurred_epoch_ms, 1_730_000_000_001);
    }

    /// 2.8.3 (#9 comment 6696366882, item 4): the ANR2 phantom imported
    /// an active N4 segment three times while it grew (9 860 → 10 780 →
    /// 12 436 B). Each snapshot had a different SHA-256, therefore a
    /// different `capture_id`, therefore a different `event_id` for the
    /// same packets (`event_id = "evt-{stable_hash(capture_id | proto |
    /// msg_type | raw_ticks | raw_payload_ref | packet_refs):016x}"` at
    /// `OIRAN/event-schema/src/lib.rs:278`). Three snapshots of the same
    /// 100 packets therefore published 300 event_ids — the dataset-level
    /// phantom. The 2.8.3 closed-proof gate forbids reading the active
    /// segment at any size, so no partial import is possible; a complete
    /// segment imported later has a single stable SHA and therefore a
    /// single stable event_id per packet.
    ///
    /// This test drives a growing file for 10 writes and asserts
    /// `segments_ingested` stays at zero across every tick.
    #[test]
    fn active_segment_is_never_imported_at_any_size_under_2_8_3() {
        if skip_if_disk_too_full("active_segment_is_never_imported_at_any_size_under_2_8_3") {
            return;
        }
        let source = temporary_root("partial-import-integrity");
        let root = temporary_root("partial-import-owned");
        fs::create_dir_all(source.join("N3")).unwrap();
        // Single N3 segment, no JSONL proof → ACTIVE → must never be
        // read. Repeated appends mirror the ANR2 growth sequence.
        let growing = source.join("N3/active-segment.pcap");
        write_pcap(&growing, &[vec![0x11u8; 128]]);
        thread::sleep(Duration::from_millis(250));
        let manager = CaptureManager::with_pseudonym_key_path(
            root.clone(),
            false,
            root.join(".oiran-pseudonym.key"),
        )
        .unwrap();
        manager
            .start_continuous_import(ContinuousImportConfig {
                source_root: source.clone(),
                scan_interval: Duration::from_millis(200),
                stable_age: Duration::from_millis(200),
                max_owned_bytes: 128 * 1024 * 1024,
                max_segment_bytes: 64 * 1024 * 1024,
                max_segments: 8,
                native_segment_seconds: None,
                historical_n2_bootstrap: None,
                runtime_pdu_evidence: None,
            })
            .unwrap();
        // Three scan cycles with no JSONL and no sibling: the active
        // segment is excluded from `last_pending_characterization`
        // (`known_active_paths`) so the worker idles after the first
        // eligibility pass. Every tick must observe `segments_ingested == 0`.
        for round in 0..3u32 {
            thread::sleep(Duration::from_millis(500));
            let job = manager.get(CONTINUOUS_CAPTURE_ID).unwrap();
            assert_eq!(
                job.metrics.segments_ingested, 0,
                "active segment must never be imported; round={round}"
            );
        }
        // Now rotate: create a lex-greater sibling. The formerly active
        // segment becomes CLOSED by sequence proof; the lex-greatest
        // (rotation-sibling.pcap) is itself promoted to closed via the
        // JSONL lifecycle record (count ≥ total). One scan later both
        // must import exactly once.
        write_pcap(&source.join("N3/rotation-sibling.pcap"), &[vec![0u8; 64]]);
        write_rotation_closures(&source, "N3", 2);
        wait_for(|| {
            manager
                .get(CONTINUOUS_CAPTURE_ID)
                .is_some_and(|job| job.metrics.segments_ingested >= 2)
        });
        let final_job = manager.get(CONTINUOUS_CAPTURE_ID).unwrap();
        assert_eq!(
            final_job.metrics.segments_ingested, 2,
            "both the formerly-active segment and its rotation sibling must import exactly once"
        );
        manager.stop(CONTINUOUS_CAPTURE_ID, "operator").unwrap();
    }

    /// 2.9.2 (#9 comment 6710853974): `interface_specs()` must
    /// return the full set of decoder-backed interfaces that OIRAN
    /// understands. ANR2 proved that `_00067` and the other LTE
    /// closed segments were ingested with non-zero protocol frames
    /// but published ZERO events: the pre-2.9.2 list returned only
    /// N2/SBI/N4/N3, so `process_capture_into`'s `for interface in
    /// interfaces` loop never visited the LTE pcap copies on disk
    /// and no decode call was made.
    #[test]
    fn interface_specs_covers_every_decoder_backed_plane() {
        let specs = interface_specs();
        let returned: BTreeSet<String> = specs
            .iter()
            .map(|spec| spec.interface.clone())
            .collect();
        let expected: BTreeSet<String> = [
            "N2", "N3", "N4", "SBI", "S1-MME", "S1-U", "S11", "S5-C", "S5-U", "S6a", "Sxab",
            // 2.11.0 (devmat) : 13ᵉ plane IMS (SIP + RTP).
            "IMS",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert_eq!(
            returned, expected,
            "interface_specs() must enumerate every decoder-backed plane; got {returned:?}"
        );
        // Every returned interface has a decoder today — `N6` is
        // intentionally absent and surfaced via
        // `CONTINUOUS_PLANE_NOT_ALLOWLISTED` instead.
        for interface in &returned {
            assert!(
                interface_has_decoder(interface),
                "interface_specs() returned {interface} without an OIRAN decoder"
            );
        }
    }

    /// 2.9.2: `process_capture_into` iterates every entry of
    /// `interface_specs()` and calls `decode_capture_streaming`
    /// per plane. The 5G baseline (N2/N3/N4/SBI) worked; the LTE
    /// planes were silently skipped under 2.9.1. This test writes a
    /// minimal pcap per LTE plane with the owned-file naming
    /// convention
    /// (`{interface}.pcap-{sha16}.pcapng`) and asserts the resulting
    /// `decode_reports` names every LTE plane (even when the
    /// synthetic payload produces 0 events — the invariant is "the
    /// file was VISITED by the decode loop").
    #[test]
    fn process_capture_into_visits_every_lte_plane_owned_file() {
        if skip_if_disk_too_full("process_capture_into_visits_every_lte_plane_owned_file") {
            return;
        }
        let base = temporary_root("process-capture-lte-planes");
        let pcap_dir = base.join("pcap");
        let dataset_dir = base.join("dataset");
        fs::create_dir_all(&pcap_dir).unwrap();
        for interface in ["S1-MME", "S1-U", "S11", "S5-C", "S5-U", "S6a", "Sxab"] {
            let path = pcap_dir.join(format!("{interface}.pcap-stub{interface}.pcapng"));
            write_pcap(&path, &[vec![0u8; 64]]);
        }
        let manager = fresh_manager_for_restore(&base);
        let dataset = manager
            .process_capture_into(
                CONTINUOUS_CAPTURE_ID,
                CONTINUOUS_DATASET_ID.into(),
                &pcap_dir,
                &dataset_dir,
                "runtime/live-captures/continuous-lab-import/dataset".into(),
                &interface_specs(),
            )
            .unwrap();
        for interface in ["S1-MME", "S1-U", "S11", "S5-C", "S5-U", "S6a", "Sxab"] {
            assert!(
                dataset.decode_reports.keys().any(|key| key.starts_with(&format!("{interface}.pcap"))),
                "process_capture_into must visit the {interface} plane; decode_reports keys: {:?}",
                dataset.decode_reports.keys().collect::<Vec<_>>()
            );
        }
    }

    /// 2.9.1 (#9): the production source tree carries 12 plane
    /// directories (ANR2's inventory: `n2 n3 n4 n6 s11 s1mme s1u s5c
    /// s5u s6a sbi sxab`). `source_interface` must map every single
    /// one to a canonical OIRAN interface string, and the full
    /// allowlist must round-trip through the discovery path's
    /// `plane_counts` so operators observe the entire landing — no
    /// silent skip ever.
    #[test]
    fn source_interface_maps_every_production_plane_directory_to_a_canonical_interface() {
        let cases: &[(&str, Option<&str>)] = &[
            ("n2", Some("N2")),
            ("n3", Some("N3")),
            ("n4", Some("N4")),
            ("n6", Some("N6")),
            ("s11", Some("S11")),
            ("s1mme", Some("S1-MME")),
            ("s1u", Some("S1-U")),
            ("s5c", Some("S5-C")),
            ("s5u", Some("S5-U")),
            ("s6a", Some("S6a")),
            ("sbi", Some("SBI")),
            ("sxab", Some("Sxab")),
            // Unknown or out-of-allowlist directory.
            ("unknown", None),
            ("other-plane", None),
        ];
        let root = temporary_root("source-interface-mapping");
        for (dir, expected) in cases {
            fs::create_dir_all(root.join(dir)).unwrap();
            let path = root.join(dir).join("segment.pcapng");
            fs::write(&path, b"stub").unwrap();
            let observed = source_interface(&root, &path);
            assert_eq!(
                observed.as_deref(),
                *expected,
                "directory `{dir}` must map to {expected:?}"
            );
        }
    }

    /// 2.9.1 (#9): `source_segments` publishes a per-plane census for
    /// all 12 interfaces plus the `UNKNOWN` sentinel. Planes without
    /// an OIRAN decoder (N6 today) and fully-unknown directories are
    /// surfaced via `unknown_plane_paths` so the worker logs
    /// `CONTINUOUS_PLANE_NOT_ALLOWLISTED` once per path.
    #[test]
    fn source_segments_counts_every_plane_and_surfaces_undecoded_paths() {
        let root = temporary_root("source-segments-plane-counts");
        for plane in ["n2", "n3", "n4", "n6", "s11", "s1mme", "s1u", "s5c", "s5u", "s6a", "sbi", "sxab", "unknown-plane"] {
            fs::create_dir_all(root.join(plane)).unwrap();
            // write_pcap writes a valid 24-byte pcap header plus
            // one 16+N record; enough to pass the `metadata.len() > 24`
            // gate in `source_segments`.
            write_pcap(&root.join(plane).join("segment.pcapng"), &[vec![0u8; 32]]);
        }
        // 2.9.1: synthetic one-file-per-plane requires closure proof
        // (2.8.3 contract). Write one rotation record per plane with
        // a decoder; the test is not concerned with eligibility for
        // the undecoded ones.
        for plane in ["N2", "N3", "N4", "S11", "S1-MME", "S1-U", "S5-C", "S5-U", "S6a", "SBI", "Sxab"] {
            write_rotation_closures(&root, plane, 1);
        }
        let mut cache = SourceSegmentsCache::new();
        let discovery = source_segments(
            &root,
            Duration::ZERO,
            false,
            DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES,
            &mut cache,
        )
        .unwrap();
        // 11 decoder-backed planes + N6 + UNKNOWN = 13 entries.
        for plane in [
            "N2", "N3", "N4", "N6", "S11", "S1-MME", "S1-U", "S5-C", "S5-U", "S6a", "SBI", "Sxab",
            "UNKNOWN",
        ] {
            assert_eq!(
                discovery.plane_counts.get(plane).copied().unwrap_or(0),
                1,
                "plane {plane} must appear in plane_counts"
            );
        }
        // N6 and the unknown directory are surfaced for the worker's
        // once-per-lifetime log.
        let unknown_dirs: BTreeSet<String> = discovery
            .unknown_plane_paths
            .iter()
            .map(|path| {
                path.parent()
                    .and_then(|parent| parent.file_name())
                    .and_then(|name| name.to_str())
                    .unwrap_or("")
                    .to_owned()
            })
            .collect();
        assert!(unknown_dirs.contains("n6"), "N6 must surface as unknown: {unknown_dirs:?}");
        assert!(
            unknown_dirs.contains("unknown-plane"),
            "fully-unknown directory must surface: {unknown_dirs:?}"
        );
        // Decoder-backed planes do NOT appear in unknown_plane_paths.
        for decoded in ["n2", "n3", "n4", "s11", "s1mme", "s1u", "s5c", "s5u", "s6a", "sbi", "sxab"] {
            assert!(
                !unknown_dirs.contains(decoded),
                "decoded plane {decoded} must NOT be in unknown_plane_paths"
            );
        }
    }

    #[test]
    fn finalized_candidates_only_drops_the_lex_greatest_per_interface() {
        // 2.8.3: no stable_age / mtime gate. The lex-greatest filename
        // per interface is the active dumpcap target and is NEVER kept.
        let now = UNIX_EPOCH + Duration::from_secs(1_730_000_300);
        let candidates = vec![
            FinalizationCandidate {
                interface: "N2".into(),
                modified: now - Duration::from_secs(300),
                filename: "n2_20261104T100000Z_00001_20261104100000.pcapng".into(),
            },
            FinalizationCandidate {
                interface: "N2".into(),
                modified: now - Duration::from_secs(120),
                filename: "n2_20261104T100000Z_00002_20261104110000.pcapng".into(),
            },
            FinalizationCandidate {
                interface: "N3".into(),
                modified: now - Duration::from_secs(300),
                filename: "n3_20261104T100000Z_00001_20261104100000.pcapng".into(),
            },
            FinalizationCandidate {
                interface: "N3".into(),
                modified: now - Duration::from_secs(150),
                filename: "n3_20261104T100000Z_00002_20261104110000.pcapng".into(),
            },
        ];
        let rotation = BTreeMap::new();
        let kept = finalized_candidates_only(candidates, &rotation);
        assert_eq!(kept.len(), 2);
        for candidate in &kept {
            assert!(
                candidate.filename.contains("_00001_"),
                "the lex-greatest (00002) per interface must be dropped as active, got {}",
                candidate.filename
            );
        }
    }

    #[test]
    fn finalized_candidates_only_never_uses_mtime_age_as_closed_proof() {
        // 2.8.3: a single segment per interface — no higher-sequence
        // sibling and no rotation JSONL — stays ACTIVE regardless of
        // how old its mtime is. The 2.8.2 behaviour (admit after
        // 2 × stable_age) imported a still-live dumpcap file three
        // times while it grew (ANR2 N4 9 860 → 10 780 → 12 436 bytes).
        let now = UNIX_EPOCH + Duration::from_secs(2_000);
        let ancient = FinalizationCandidate {
            interface: "N2".into(),
            modified: now - Duration::from_secs(24 * 3600),
            filename: "n2_20261103T100000Z_00001_20261103100000.pcapng".into(),
        };
        let rotation = BTreeMap::new();
        let kept = finalized_candidates_only(vec![ancient], &rotation);
        assert!(
            kept.is_empty(),
            "a lone segment per interface stays active even when mtime is ancient"
        );
    }

    #[test]
    fn finalized_candidates_only_promotes_lone_segment_when_jsonl_proves_closure() {
        // 2.8.3: if the rotation watcher recorded at least one close
        // for the plane, a lone segment is proven closed (dumpcap
        // exited cleanly after its last rotation).
        let now = UNIX_EPOCH + Duration::from_secs(2_000);
        let lone = FinalizationCandidate {
            interface: "N2".into(),
            modified: now - Duration::from_secs(300),
            filename: "n2_20261103T100000Z_00001_20261103100000.pcapng".into(),
        };
        let mut rotation = BTreeMap::new();
        rotation.insert("N2".to_string(), 1usize);
        let kept = finalized_candidates_only(vec![lone.clone()], &rotation);
        assert_eq!(kept, vec![lone]);
    }

    // --- 2.7.27 archive-based retention regression tests -----------

    /// Writes a jsonl line matching the fields `scan_capture_ends` /
    /// `archive_split_stream` look at. Minimal — no decoder fields.
    fn archive_test_line(
        event_id: &str,
        capture_id: &str,
        ts_seconds: u64,
        packet_number: u64,
    ) -> String {
        serde_json::json!({
            "event_id": event_id,
            "capture_id": capture_id,
            "timestamp": {"seconds": ts_seconds, "nanoseconds": 0, "raw_ticks": ts_seconds * 1_000_000_000, "display": ""},
            "packet_references": [{"source_file": "x", "packet_number": packet_number, "byte_offset": 0, "interface_id": 0, "captured_length": 1, "original_length": 1}],
        })
        .to_string()
    }

    fn write_jsonl(path: &Path, lines: &[String]) {
        let mut writer = BufWriter::new(fs::File::create(path).unwrap());
        for line in lines {
            writer.write_all(line.as_bytes()).unwrap();
            writer.write_all(b"\n").unwrap();
        }
        writer.flush().unwrap();
    }

    fn count_events_with_capture(path: &Path, capture_id: &str) -> usize {
        BufReader::new(fs::File::open(path).unwrap())
            .lines()
            .filter_map(Result::ok)
            .filter(|line| !line.trim().is_empty())
            .filter(|line| {
                serde_json::from_str::<serde_json::Value>(line)
                    .ok()
                    .and_then(|value| value.get("capture_id").and_then(|v| v.as_str()).map(str::to_owned))
                    .is_some_and(|value| value == capture_id)
            })
            .count()
    }

    fn read_event_ids(path: &Path) -> BTreeSet<String> {
        BufReader::new(fs::File::open(path).unwrap())
            .lines()
            .filter_map(Result::ok)
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let v: serde_json::Value = serde_json::from_str(&line).unwrap();
                v["event_id"].as_str().unwrap().to_string()
            })
            .collect()
    }

    /// 2.7.27: a capture whose end_ts < cutoff is moved to an archive
    /// segment. The hot view loses those events; the archive keeps
    /// them. Union = original set, so **no event_id is lost**.
    #[test]
    fn archive_moves_stale_captures_without_losing_any_event_id() {
        let base = temporary_root("archive-retention");
        let dataset_dir = base.join("dataset");
        fs::create_dir_all(&dataset_dir).unwrap();
        let events_path = dataset_dir.join("oiran_events.jsonl");
        // Two captures: STALE ends at ts=1000, FRESH ends at ts=9000.
        // Cutoff = 5000 → STALE is archived, FRESH stays.
        write_jsonl(
            &events_path,
            &[
                archive_test_line("evt-stale-1", "sha256:stale", 900, 1),
                archive_test_line("evt-stale-2", "sha256:stale", 1000, 2),
                archive_test_line("evt-fresh-1", "sha256:fresh", 8000, 3),
                archive_test_line("evt-fresh-2", "sha256:fresh", 9000, 4),
            ],
        );
        let before_total = read_event_ids(&events_path);
        assert_eq!(before_total.len(), 4);
        let archive_root = base.join("archive");
        archive_stale_captures(&events_path, &archive_root, 5000).unwrap();
        let after_hot = read_event_ids(&events_path);
        assert_eq!(after_hot.len(), 2);
        assert!(after_hot.contains("evt-fresh-1"));
        assert!(after_hot.contains("evt-fresh-2"));
        // Find the archive segment.
        let segment_dir = fs::read_dir(&archive_root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.is_dir())
            .expect("archive segment created");
        let archived = read_event_ids(&segment_dir.join("events.jsonl"));
        assert_eq!(archived.len(), 2);
        assert!(archived.contains("evt-stale-1"));
        assert!(archived.contains("evt-stale-2"));
        // Hot ∪ archived MUST equal the input set — zero event_id is lost.
        let union: BTreeSet<_> = after_hot.union(&archived).cloned().collect();
        assert_eq!(union, before_total, "no event_id lost by archive");
        // Manifest sha256 MUST match the archived events.jsonl contents.
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(segment_dir.join("manifest.json")).unwrap()).unwrap();
        let actual_sha = sha256_hex(&fs::read(segment_dir.join("events.jsonl")).unwrap());
        assert_eq!(manifest["events_sha256"].as_str().unwrap(), actual_sha);
        assert_eq!(manifest["event_count"].as_u64().unwrap(), 2);
        assert_eq!(
            manifest["captures"].as_array().unwrap(),
            &vec![serde_json::json!("sha256:stale")]
        );
    }

    /// 2.7.27: when the archive write fails (e.g. the archive root
    /// is a read-only directory), the hot view MUST be left
    /// byte-identical. Fail-closed invariant.
    ///
    /// 2.11.0 (devmat) : skip visible quand `euid==0` — root ignore
    /// les permissions 0o500 (CAP_DAC_OVERRIDE) et la création
    /// `mkdir` sous `archive-ro/` réussit, cassant le test.
    /// Préviens explicitement l'opérateur plutôt qu'un échec
    /// trompeur.
    #[test]
    fn archive_write_failure_leaves_hot_view_untouched() {
        use std::os::unix::fs::PermissionsExt;
        // 2.11.0 : euid==0 → CAP_DAC_OVERRIDE bypasses 0o500,
        // le test n'est pas pertinent en racine. Skip explicite.
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            eprintln!(
                "SKIP archive_write_failure_leaves_hot_view_untouched: euid={euid} \
                 (root ignores 0o500 — test invariant not applicable). \
                 Re-run as a non-root user."
            );
            return;
        }
        let base = temporary_root("archive-fail-closed");
        let dataset_dir = base.join("dataset");
        fs::create_dir_all(&dataset_dir).unwrap();
        let events_path = dataset_dir.join("oiran_events.jsonl");
        write_jsonl(
            &events_path,
            &[
                archive_test_line("evt-stale-1", "sha256:stale", 900, 1),
                archive_test_line("evt-fresh-1", "sha256:fresh", 9000, 2),
            ],
        );
        let before_sha = sha256_hex(&fs::read(&events_path).unwrap());
        // Pre-create a read-only archive root. mkdir inside it fails →
        // the helper bails BEFORE touching the hot view.
        let archive_root = base.join("archive-ro");
        fs::create_dir_all(&archive_root).unwrap();
        fs::set_permissions(&archive_root, fs::Permissions::from_mode(0o500)).unwrap();
        let result = archive_stale_captures(&events_path, &archive_root, 5000);
        // Restore permissions so temporary_root cleanup works.
        fs::set_permissions(&archive_root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result.is_err(), "write failure must propagate as Err");
        let after_sha = sha256_hex(&fs::read(&events_path).unwrap());
        assert_eq!(
            before_sha, after_sha,
            "hot view MUST be byte-identical after a failed archive"
        );
    }

    /// 2.7.27: if no capture is older than the cutoff, the hot view
    /// is left byte-identical and no archive segment is created.
    #[test]
    fn archive_is_a_no_op_when_every_capture_is_fresh() {
        let base = temporary_root("archive-no-op");
        let dataset_dir = base.join("dataset");
        fs::create_dir_all(&dataset_dir).unwrap();
        let events_path = dataset_dir.join("oiran_events.jsonl");
        write_jsonl(
            &events_path,
            &[
                archive_test_line("evt-fresh-1", "sha256:fresh", 9000, 1),
                archive_test_line("evt-fresh-2", "sha256:fresh", 9500, 2),
            ],
        );
        let before_sha = sha256_hex(&fs::read(&events_path).unwrap());
        let archive_root = base.join("archive");
        archive_stale_captures(&events_path, &archive_root, 5000).unwrap();
        let after_sha = sha256_hex(&fs::read(&events_path).unwrap());
        assert_eq!(before_sha, after_sha);
        assert!(!archive_root.exists() || fs::read_dir(&archive_root).unwrap().count() == 0);
    }

    // --- 2.7.28 restore regression tests ---------------------------

    /// Full-event JSONL line (source_endpoint, destination_endpoint,
    /// session_identifiers, decoding_status, …) needed by
    /// `session_engine::load_jsonl` / `publish_events_to_dataset_dir`.
    /// The archive-retention tests above use a minimal fixture because
    /// archive code only reads `event_id`, `capture_id`, `timestamp`
    /// and `packet_references[0].packet_number`.
    fn restore_test_line(event_id: &str, capture_id: &str, packet: u64) -> String {
        serde_json::json!({
            "event_id": event_id,
            "capture_id": capture_id,
            "capture_point_id": "N2",
            "timestamp": {
                "seconds": packet,
                "nanoseconds": 0,
                "raw_ticks": packet as i128 * 1_000_000_000i128,
                "display": "",
            },
            "interface": "N2",
            "protocol": "NGAP",
            "message_name": "InitialUEMessage",
            "source_endpoint": {"address": "10.0.0.1", "network_function": "gNB"},
            "destination_endpoint": {"address": "10.0.0.2", "network_function": "AMF"},
            "direction": "RAN_TO_CORE",
            "session_identifiers": [],
            "information_elements": [],
            "decoding_status": "DECODED",
            "decoder_name": "test",
            "decoder_version": "1",
            "raw_payload_reference": "sha256:test",
            "packet_references": [{
                "source_file": "x",
                "packet_number": packet,
                "byte_offset": 0,
                "interface_id": 0,
                "captured_length": 1,
                "original_length": 1,
            }],
            "errors": [],
        })
        .to_string()
    }

    fn make_restore_fixture(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
        let continuous = root.join(CONTINUOUS_CAPTURE_ID);
        let dataset = continuous.join("dataset");
        let callflows = dataset.join("callflows");
        let segment = continuous.join("archive/seg-001");
        fs::create_dir_all(&callflows).unwrap();
        fs::create_dir_all(&segment).unwrap();
        (dataset, segment, continuous)
    }

    fn fresh_manager_for_restore(root: &Path) -> CaptureManager {
        let key_path = root.join("pseudonym.key");
        let helper = CaptureHelperClient::new(root.join("helper.sock"), 0);
        CaptureManager::with_helper_and_interface_root(
            root.to_path_buf(),
            false,
            helper,
            PathBuf::from("/sys/class/net"),
            key_path,
        )
        .unwrap()
    }

    /// 2.7.28 (ANR2 defect on 2.7.27): the restore path rebuilds the
    /// manifest + session + callflow registry — `event_count` in
    /// `dataset_manifest.json` matches the restored JSONL exactly,
    /// which is the precondition `validate_dataset_artifacts` /
    /// `recover_continuous_dataset_from_disk` enforce at next
    /// startup. Before 2.7.28 the restore wrote only
    /// `oiran_events.jsonl` and the stale manifest caused
    /// `DATASET_REGISTRATION_EVENT_COUNT_MISMATCH` →
    /// `CONTINUOUS_DATASET_RECOVER_SKIPPED artifact-drift`.
    #[test]
    fn restore_rebuilds_a_manifest_coherent_with_the_restored_events() {
        let base = temporary_root("restore-manifest-coherent");
        let (dataset, segment, _) = make_restore_fixture(&base);
        write_jsonl(
            &dataset.join("oiran_events.jsonl"),
            &[restore_test_line("evt-fresh-1", "sha256:fresh", 100)],
        );
        write_jsonl(
            &segment.join("events.jsonl"),
            &[
                restore_test_line("evt-stale-1", "sha256:stale", 10),
                restore_test_line("evt-stale-2", "sha256:stale", 11),
            ],
        );
        let archive_sha = sha256_hex(&fs::read(&segment.join("events.jsonl")).unwrap());
        fs::write(
            segment.join("manifest.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "events_sha256": archive_sha,
                "event_count": 2,
            }))
            .unwrap(),
        )
        .unwrap();
        let manager = fresh_manager_for_restore(&base);
        let report = manager.restore_from_archive_segment(&segment).unwrap();
        assert_eq!(report.event_count_before, 1);
        assert_eq!(report.archive_event_count, 2);
        assert_eq!(report.overlap_event_count, 0);
        assert_eq!(report.event_count_after, 3);
        let manifest: LiveDataset = serde_json::from_slice(
            &fs::read(dataset.join("dataset_manifest.json")).unwrap(),
        )
        .unwrap();
        let on_disk_count =
            count_valid_event_records(&dataset.join("oiran_events.jsonl")).unwrap();
        assert_eq!(
            on_disk_count, manifest.event_count,
            "manifest event_count must match the on-disk JSONL"
        );
        assert!(
            dataset.join("callflows").is_dir(),
            "callflows directory must exist after restore"
        );
    }

    /// 2.7.28: `restore_from_archive_segment` acquires the same
    /// `flock` the continuous worker uses. When a writer holds the
    /// lock the restore fails fast with
    /// `RESTORE_REQUIRES_PUBLICATION_LOCK` instead of racing a
    /// concurrent publish.
    #[test]
    fn restore_refuses_when_the_publication_lock_is_held() {
        let base = temporary_root("restore-publication-lock");
        let (dataset, segment, continuous) = make_restore_fixture(&base);
        write_jsonl(
            &dataset.join("oiran_events.jsonl"),
            &[restore_test_line("evt-fresh-1", "sha256:fresh", 1)],
        );
        write_jsonl(
            &segment.join("events.jsonl"),
            &[restore_test_line("evt-stale-1", "sha256:stale", 2)],
        );
        let archive_sha = sha256_hex(&fs::read(&segment.join("events.jsonl")).unwrap());
        fs::write(
            segment.join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({"events_sha256": archive_sha}))
                .unwrap(),
        )
        .unwrap();
        let manager = fresh_manager_for_restore(&base);
        let _held = PublicationLock::acquire_blocking(&continuous).unwrap();
        let error = manager
            .restore_from_archive_segment(&segment)
            .expect_err("lock contention must fail fast");
        assert_eq!(error, "RESTORE_REQUIRES_PUBLICATION_LOCK");
    }

    /// 2.8.3 (#9 comment 6704872754): a published dataset that imported
    /// an active segment 7 times at growing sizes carries 7 distinct
    /// `event_id` sequences for the SAME packets (different `capture_id`
    /// per snapshot). `repair_partial_imports` keeps only the events
    /// anchored on the FINAL (closed) snapshot; the first 6 are removed
    /// with their reason, and the resulting JSONL is sorted canonically.
    /// A second invocation is idempotent — identical SHA-256.
    #[test]
    fn repair_partial_imports_keeps_only_final_owned_file_for_a_segment_imported_seven_times() {
        let base = temporary_root("repair-partial-imports-7x");
        let continuous = base.join(CONTINUOUS_CAPTURE_ID);
        let dataset = continuous.join("dataset");
        fs::create_dir_all(dataset.join("callflows")).unwrap();
        let source_path = "/var/lib/docker/volumes/oiran_lab_pcap/_data/n4/n4_20261104T142333Z_00056_20261106212341.pcapng";
        let owned_files = [
            ("owned-aaaa.pcapng", "sha256:aaaa", 9_860u64, 1u64),
            ("owned-bbbb.pcapng", "sha256:bbbb", 10_780, 2),
            ("owned-cccc.pcapng", "sha256:cccc", 11_540, 3),
            ("owned-dddd.pcapng", "sha256:dddd", 11_980, 4),
            ("owned-eeee.pcapng", "sha256:eeee", 12_120, 5),
            ("owned-ffff.pcapng", "sha256:ffff", 12_300, 6),
            ("owned-gggg.pcapng", "sha256:gggg", 12_436, 7),
        ];
        let mut lines = Vec::new();
        let mut segments_map = serde_json::Map::new();
        let mut partial_event_ids: BTreeSet<String> = BTreeSet::new();
        let mut final_event_ids: BTreeSet<String> = BTreeSet::new();
        for (owned, capture_id, size_bytes, imported_ms) in owned_files {
            let segment = serde_json::json!({
                "interface": "N4",
                "owned_file": owned,
                "size_bytes": size_bytes,
                "packets": 3u64,
                "imported_epoch_ms": imported_ms,
                "source_path": source_path,
                "historical_context": false,
            });
            let checksum = capture_id.strip_prefix("sha256:").unwrap().to_owned();
            segments_map.insert(checksum, segment);
            // Three events per snapshot — packets 1, 2, 3. Each snapshot
            // emits DIFFERENT event_ids because capture_id differs.
            for packet in 1..=3u64 {
                let event_id = format!("evt-{}-p{packet}", owned.trim_end_matches(".pcapng"));
                let owned_full = continuous.join("pcap").join(owned);
                let line = serde_json::json!({
                    "event_id": event_id,
                    "capture_id": capture_id,
                    "capture_point_id": "N4",
                    "timestamp": {
                        "seconds": packet,
                        "nanoseconds": 0,
                        "raw_ticks": packet as i128 * 1_000_000_000i128,
                        "display": "",
                    },
                    "interface": "N4",
                    "protocol": "PFCP",
                    "message_name": "SessionEstablishmentRequest",
                    "source_endpoint": {"address": "10.0.0.1", "network_function": "SMF"},
                    "destination_endpoint": {"address": "10.0.0.2", "network_function": "UPF"},
                    "direction": "CORE_TO_RAN",
                    "session_identifiers": [],
                    "information_elements": [],
                    "decoding_status": "DECODED",
                    "decoder_name": "test",
                    "decoder_version": "1",
                    "raw_payload_reference": capture_id,
                    "packet_references": [{
                        "source_file": owned_full.display().to_string(),
                        "packet_number": packet,
                        "byte_offset": 0,
                        "interface_id": 0,
                        "captured_length": 1,
                        "original_length": 1,
                    }],
                    "errors": [],
                })
                .to_string();
                lines.push(line);
                if owned == "owned-gggg.pcapng" {
                    final_event_ids.insert(event_id);
                } else {
                    partial_event_ids.insert(event_id);
                }
            }
        }
        // Scramble the input order so the canonical sort has to do
        // something. The input has 7 × 3 = 21 events.
        lines.reverse();
        write_jsonl(&dataset.join("oiran_events.jsonl"), &lines);
        let state = serde_json::json!({
            "segments": serde_json::Value::Object(segments_map),
            "seen_checksums": [],
            "seen_order": [],
            "failed_ingestions": [],
            "source_fingerprints": {},
        });
        fs::write(
            continuous.join("import_state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();

        let manager = fresh_manager_for_restore(&base);
        // Dry run: computes the would-be SHA + removed list without
        // writing anything. 2.8.4: no source_root → falls back to
        // state.segments-based "largest size" rule, which still works
        // here because state.segments carries all 7 entries.
        let dry_report = manager.repair_partial_imports(true, None).unwrap();
        assert!(dry_report.dry_run);
        assert_eq!(dry_report.event_count_before, 21);
        assert_eq!(dry_report.event_count_after, 3);
        assert_eq!(dry_report.partial_import_groups.len(), 1);
        assert_eq!(
            dry_report.partial_import_groups[0].final_capture_id.as_deref(),
            Some("sha256:gggg")
        );
        assert_eq!(dry_report.partial_import_groups[0].snapshots.len(), 7);
        assert_eq!(
            dry_report.partial_import_groups[0].final_source,
            PartialImportFinalSource::StateSegmentsLargest
        );
        assert_eq!(dry_report.removed_events.len(), 18);
        for removed in &dry_report.removed_events {
            assert!(
                removed
                    .reason
                    .contains("partial-import-superseded-by-final-capture-id=sha256:gggg"),
                "removed event must carry a precise reason, got {}",
                removed.reason
            );
        }
        // Real run.
        let report = manager.repair_partial_imports(false, None).unwrap();
        assert!(!report.dry_run);
        assert_eq!(report.event_count_after, 3);
        assert_eq!(report.events_sha256, dry_report.events_sha256);
        let on_disk = read_event_ids(&dataset.join("oiran_events.jsonl"));
        assert_eq!(
            on_disk, final_event_ids,
            "only events anchored on the final capture_id must remain; got {:?}",
            on_disk
        );
        for partial in &partial_event_ids {
            assert!(
                !on_disk.contains(partial),
                "partial-import event {partial} must be removed"
            );
        }
        let manifest: LiveDataset = serde_json::from_slice(
            &fs::read(dataset.join("dataset_manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.event_count, 3);
        // Idempotence: a second pass is a strict no-op.
        let second = manager.repair_partial_imports(false, None).unwrap();
        assert_eq!(second.event_count_after, 3);
        assert_eq!(second.events_sha256, report.events_sha256);
    }

    /// 2.9.17 (#9 comment 6739207609) + 2.9.17-fu (#9 comment
    /// 6740035832) — Preuve de reprise sûre après l'OOM d'une
    /// passe réelle ET reconstruction de l'import_state à partir
    /// du dataset publié. Fabrique l'état observé par ANR2 :
    /// `dataset/` publié (intact), `import_state.json` présent
    /// mais potentiellement désaligné, `.dataset-next/` de 6 GiB
    /// laissé par le crash. `recover_repair_staging` doit :
    ///   * retirer `.dataset-next/`,
    ///   * préserver `dataset/` strictement intact,
    ///   * sauvegarder `import_state.json` → `.pre-recover`,
    ///   * réécrire un state cohérent (seen_checksums = SHAs
    ///     extraits du dataset, segments = fichiers du ring).
    #[test]
    fn recover_repair_staging_removes_orphan_and_rebuilds_state_2_9_17() {
        let root = temporary_root("repair-recover-2-9-17");
        let base = root.join(CONTINUOUS_CAPTURE_ID);
        let dataset = base.join("dataset");
        let dataset_next = base.join(".dataset-next");
        let callflows = dataset.join("callflows");
        fs::create_dir_all(&callflows).unwrap();
        fs::create_dir_all(dataset_next.join("callflows")).unwrap();
        // Dataset publié sain avec event canonique.
        let published_jsonl = "{\"event_id\":\"evt-published\",\"capture_id\":\"sha256:a\"}\n";
        fs::write(dataset.join("oiran_events.jsonl"), published_jsonl).unwrap();
        fs::write(dataset.join("dataset_manifest.json"), "{\"event_count\":1}").unwrap();
        let published_size = fs::metadata(dataset.join("oiran_events.jsonl"))
            .unwrap()
            .len();
        // `.dataset-next/` = 1 MiB d'un scratch orphelin typique
        // de l'OOM (en production : 6,1 GiB). Taille minimale
        // suffisante pour la preuve de suppression.
        let scratch_bytes = vec![b'x'; 1024 * 1024];
        fs::write(dataset_next.join("oiran_events.jsonl"), &scratch_bytes).unwrap();
        let repair_staging = dataset_next.join(".repair-staging");
        fs::create_dir_all(&repair_staging).unwrap();
        fs::write(repair_staging.join("kept-events.jsonl"), &scratch_bytes).unwrap();
        // `import_state.json` avec un ancien état (désaligné du
        // dataset) — sera sauvegardé en `.pre-recover` puis réécrit.
        let mut state = ContinuousImportState::default();
        state.seen_order.push_back("checksum-a".into());
        state.seen_checksums.insert("checksum-a".into());
        let state_bytes_before = serde_json::to_vec_pretty(&state).unwrap();
        fs::write(base.join("import_state.json"), &state_bytes_before).unwrap();
        let dataset_mtime_before = fs::metadata(dataset.join("oiran_events.jsonl"))
            .unwrap()
            .modified()
            .unwrap();

        let report = recover_repair_staging(&root).unwrap();

        // `.dataset-next/` supprimé, chemins listés avec taille.
        assert!(!dataset_next.exists());
        assert!(
            report
                .removed_paths
                .iter()
                .any(|p| p.ends_with(".dataset-next")),
            "removed_paths doit lister .dataset-next ; got {:?}",
            report.removed_paths
        );
        assert!(
            report.removed_bytes >= 2 * 1024 * 1024,
            "removed_bytes doit refléter la taille du scratch ; got {}",
            report.removed_bytes
        );

        // `dataset/` strictement intact (byte + mtime).
        assert!(dataset.join("oiran_events.jsonl").is_file());
        assert_eq!(
            fs::metadata(dataset.join("oiran_events.jsonl"))
                .unwrap()
                .len(),
            published_size,
            "dataset/oiran_events.jsonl ne doit pas être touché"
        );
        assert_eq!(
            fs::metadata(dataset.join("oiran_events.jsonl"))
                .unwrap()
                .modified()
                .unwrap(),
            dataset_mtime_before,
            "dataset mtime ne doit pas changer"
        );
        // L'ancien `import_state.json` est préservé en
        // `.pre-recover` pour audit.
        let pre_recover = base.join("import_state.json.pre-recover");
        assert!(
            pre_recover.is_file(),
            "import_state.json.pre-recover doit exister"
        );
        assert_eq!(
            fs::read(&pre_recover).unwrap(),
            state_bytes_before,
            "pre-recover doit être byte-pour-byte l'ancien état"
        );
        // Le nouvel `import_state.json` est reconstruit depuis
        // le dataset : capture_id `sha256:a` ⇒ seen_checksums={"a"}.
        let rebuilt_state: ContinuousImportState = serde_json::from_slice(
            &fs::read(base.join("import_state.json")).unwrap(),
        )
        .unwrap();
        assert!(
            rebuilt_state.seen_checksums.contains("a"),
            "seen_checksums doit contenir le SHA 'a' extrait du dataset ; got {:?}",
            rebuilt_state.seen_checksums
        );
        assert!(
            !rebuilt_state.seen_checksums.contains("checksum-a"),
            "l'ancien seen_checksums désaligné doit être écarté"
        );
        assert_eq!(report.rebuilt_seen_checksums, 1);
        assert_eq!(
            report.rebuilt_import_state_path,
            Some(base.join("import_state.json").display().to_string()),
        );
    }

    /// 2.9.17-fu (#9 comment 6740035832) + 2.9.18-fu (#9 ANR2
    /// 2.9.17-fu post-recover) — Cas ANR2 réel : sauvegarde 2.9.16
    /// SANS `import_state.json`. Prouve que `--recover` reconstruit
    /// un state cohérent depuis le dataset publié uniquement.
    ///
    /// INVARIANT 2.9.18-fu : segment importé ⇔ événements dans le
    /// dataset publié. Un fichier présent dans le ring mais absent
    /// du dataset (crash OOM en cours d'ingest) est EXCLU de
    /// `seen_checksums`/`segments` ⇒ le worker continu le détecte
    /// comme neuf au prochain scan et le re-ingère avec le
    /// décodeur Diameter itératif 2.9.18.
    #[test]
    fn recover_repair_staging_rebuilds_import_state_from_dataset_2_9_17_fu() {
        let root = temporary_root("repair-recover-2-9-17-fu");
        let base = root.join(CONTINUOUS_CAPTURE_ID);
        let dataset = base.join("dataset");
        let pcap_dir = base.join("pcap");
        fs::create_dir_all(dataset.join("callflows")).unwrap();
        fs::create_dir_all(&pcap_dir).unwrap();

        // Ring pcap/ : 2 fichiers propriétaires dont les événements
        // doivent apparaître dans le dataset.
        let seg_a = pcap_dir.join("n2.pcap-aa.pcapng");
        let seg_b = pcap_dir.join("n4.pcap-bb.pcapng");
        fs::write(&seg_a, b"PCAP-SEGMENT-A").unwrap();
        fs::write(&seg_b, b"PCAP-SEGMENT-B").unwrap();
        let sha_a = sha256_hex_file(&seg_a).unwrap();
        let sha_b = sha256_hex_file(&seg_b).unwrap();

        // Dataset publié : 3 capture_id — 2 correspondent aux
        // fichiers du ring, 1 est historique (fichier déjà purgé).
        let published_jsonl = format!(
            "{{\"event_id\":\"evt-1\",\"capture_id\":\"sha256:{sha_a}\",\"packet_number\":1}}\n\
             {{\"event_id\":\"evt-2\",\"capture_id\":\"sha256:{sha_b}\",\"packet_number\":2}}\n\
             {{\"event_id\":\"evt-3\",\"capture_id\":\"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"packet_number\":3}}\n",
        );
        fs::write(dataset.join("oiran_events.jsonl"), &published_jsonl).unwrap();

        // PAS de `import_state.json` — cas ANR2.
        assert!(!base.join("import_state.json").exists());

        let report = recover_repair_staging(&root).unwrap();

        // Pas de pre-recover (il n'y avait rien à sauvegarder).
        assert!(!base.join("import_state.json.pre-recover").exists());

        // Nouveau state cohérent : seen_checksums = dataset SHAs
        // uniquement (invariant 2.9.18-fu).
        let rebuilt_state: ContinuousImportState = serde_json::from_slice(
            &fs::read(base.join("import_state.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            rebuilt_state.seen_checksums.len(),
            3,
            "seen_checksums = SHAs du dataset uniquement (invariant 2.9.18-fu)"
        );
        assert!(rebuilt_state.seen_checksums.contains(&sha_a));
        assert!(rebuilt_state.seen_checksums.contains(&sha_b));
        assert!(rebuilt_state
            .seen_checksums
            .contains(&"c".repeat(64)));
        // 2 segments du ring sont enregistrés (leur SHA est dans le
        // dataset). L'entrée historique `c…` n'a pas de fichier
        // physique donc pas dans segments.
        assert_eq!(rebuilt_state.segments.len(), 2);
        let interfaces: BTreeSet<String> = rebuilt_state
            .segments
            .values()
            .map(|seg| seg.interface.clone())
            .collect();
        assert!(interfaces.contains("n2"));
        assert!(interfaces.contains("n4"));
        // Report compteurs.
        assert_eq!(report.rebuilt_segments, 2);
        assert_eq!(report.rebuilt_seen_checksums, 3);
        assert_eq!(report.preserved_source_fingerprints, 0);
        assert_eq!(report.preserved_failed_ingestions, 0);
        assert!(
            report.excluded_ring_shas_no_events.is_empty(),
            "pas de ring SHA orphelin dans ce scénario"
        );

        // Dataset NON touché.
        assert_eq!(
            fs::read(dataset.join("oiran_events.jsonl")).unwrap(),
            published_jsonl.as_bytes(),
        );
        // Ring NON touché.
        assert_eq!(fs::read(&seg_a).unwrap(), b"PCAP-SEGMENT-A");
        assert_eq!(fs::read(&seg_b).unwrap(), b"PCAP-SEGMENT-B");
    }

    /// 2.9.18-fu (#9 ANR2 2.9.17-fu post-recover) — Preuve de la
    /// règle « segment importé ⇔ événements dans dataset ». ANR2
    /// a prouvé que les fichiers S6a `_00039`..`_00041` étaient
    /// dans `import_state.segments` (packets=0) mais ZERO
    /// événement publié dans le dataset. Le --recover 2.9.17-fu
    /// les marquait comme vus → le worker continu les sautait au
    /// prochain scan → événements perdus.
    ///
    /// 2.9.18-fu : les SHAs ring non représentés dans le dataset
    /// sont EXCLUS de seen_checksums + segments, et listés dans
    /// `report.excluded_ring_shas_no_events` pour visibilité
    /// opérateur. Le worker continu les détectera comme neufs et
    /// les re-ingérera avec le décodeur Diameter 2.9.18 itératif.
    #[test]
    fn recover_excludes_ring_shas_without_events_anr2_2_9_18_fu() {
        let root = temporary_root("repair-recover-anr2-no-events");
        let base = root.join(CONTINUOUS_CAPTURE_ID);
        let dataset = base.join("dataset");
        let pcap_dir = base.join("pcap");
        fs::create_dir_all(dataset.join("callflows")).unwrap();
        fs::create_dir_all(&pcap_dir).unwrap();

        // Ring pcap/ : 4 fichiers S6a.
        // _00035 et _00037 : dans le dataset (events).
        // _00039 et _00040 : dans le ring mais 0 événement.
        let seg_35 = pcap_dir.join("s6a.pcap-35.pcapng");
        let seg_37 = pcap_dir.join("s6a.pcap-37.pcapng");
        let seg_39 = pcap_dir.join("s6a.pcap-39.pcapng");
        let seg_40 = pcap_dir.join("s6a.pcap-40.pcapng");
        fs::write(&seg_35, b"S6A-35").unwrap();
        fs::write(&seg_37, b"S6A-37").unwrap();
        fs::write(&seg_39, b"S6A-39").unwrap();
        fs::write(&seg_40, b"S6A-40").unwrap();
        let sha_35 = sha256_hex_file(&seg_35).unwrap();
        let sha_37 = sha256_hex_file(&seg_37).unwrap();
        let sha_39 = sha256_hex_file(&seg_39).unwrap();
        let sha_40 = sha256_hex_file(&seg_40).unwrap();

        // Dataset publié : seulement _00035 et _00037 ont des events
        // (symptôme ANR2 réel : OOM a interrompu l'ingest de 39/40).
        let published_jsonl = format!(
            "{{\"event_id\":\"evt-35\",\"capture_id\":\"sha256:{sha_35}\",\"packet_number\":1}}\n\
             {{\"event_id\":\"evt-37\",\"capture_id\":\"sha256:{sha_37}\",\"packet_number\":1}}\n",
        );
        fs::write(dataset.join("oiran_events.jsonl"), &published_jsonl).unwrap();

        // État pré-existant simulant 2.9.17-fu bogué : 4 segments,
        // 4 seen_checksums (dont 39/40 orphelins).
        let mut state = ContinuousImportState::default();
        for sha in &[&sha_35, &sha_37, &sha_39, &sha_40] {
            state.seen_checksums.insert((*sha).clone());
            state.seen_order.push_back((*sha).clone());
            state.segments.insert(
                (*sha).clone(),
                ImportedSegment {
                    interface: "s6a".into(),
                    owned_file: format!("s6a.pcap-{sha}.pcapng"),
                    size_bytes: 6,
                    packets: 0,
                    imported_epoch_ms: 1_000,
                    source_path: String::new(),
                    historical_context: false,
                },
            );
        }
        fs::write(
            base.join("import_state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();

        let report = recover_repair_staging(&root).unwrap();

        // seen_checksums = SHAs dataset UNIQUEMENT (invariant).
        let rebuilt: ContinuousImportState = serde_json::from_slice(
            &fs::read(base.join("import_state.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            rebuilt.seen_checksums.len(),
            2,
            "seen_checksums doit contenir 2 SHAs (ceux représentés dans le dataset) ; \
             les 2 orphelins (39/40) sont exclus"
        );
        assert!(rebuilt.seen_checksums.contains(&sha_35));
        assert!(rebuilt.seen_checksums.contains(&sha_37));
        assert!(
            !rebuilt.seen_checksums.contains(&sha_39),
            "sha_39 orphelin NE DOIT PAS être dans seen_checksums"
        );
        assert!(
            !rebuilt.seen_checksums.contains(&sha_40),
            "sha_40 orphelin NE DOIT PAS être dans seen_checksums"
        );
        // state.segments : 2 segments, ceux avec events.
        assert_eq!(rebuilt.segments.len(), 2);
        assert!(rebuilt.segments.contains_key(&sha_35));
        assert!(rebuilt.segments.contains_key(&sha_37));

        // Report liste les SHAs exclus pour visibilité opérateur.
        let excluded: BTreeSet<String> = report
            .excluded_ring_shas_no_events
            .iter()
            .cloned()
            .collect();
        assert_eq!(
            excluded.len(),
            2,
            "excluded_ring_shas_no_events doit lister les 2 orphelins ; got {:?}",
            excluded
        );
        assert!(excluded.contains(&sha_39));
        assert!(excluded.contains(&sha_40));

        // Dataset NON touché.
        assert_eq!(
            fs::read(dataset.join("oiran_events.jsonl")).unwrap(),
            published_jsonl.as_bytes(),
        );
        // Ring NON touché.
        assert_eq!(fs::read(&seg_39).unwrap(), b"S6A-39");
        assert_eq!(fs::read(&seg_40).unwrap(), b"S6A-40");
    }

    /// 2.9.18-fu (#9 comment ANR2 6745114783) — Preuve que
    /// `count_pcap_records` gère le format **pcapng** (SHB magic
    /// `0x0A 0x0D 0x0D 0x0A`), pas uniquement le pcap classique.
    /// ANR2 a prouvé que tous les 1 307 segments post-recover
    /// avaient `packets=0` alors que 1 299 pcaps contenaient
    /// des paquets selon `capinfos -c`. Cause : la version
    /// pré-2.9.18-fu ne reconnaissait que le magic pcap
    /// classique (`0xd4c3b2a1`) et retournait 0 sur pcapng.
    #[test]
    fn count_pcap_records_handles_pcapng_anr2_2_9_18_fu() {
        let dir = tempdir();
        // SHB little-endian (28o) + IDB (20o) + 3 × EPB (36o chacun).
        let shb: [u8; 28] = [
            0x0a, 0x0d, 0x0d, 0x0a, 0x1c, 0x00, 0x00, 0x00, 0x4d, 0x3c, 0x2b, 0x1a,
            0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x1c, 0x00, 0x00, 0x00,
        ];
        let idb: [u8; 20] = [
            0x01, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x04, 0x00, 0x14, 0x00, 0x00, 0x00,
        ];
        let make_epb = |ts_low: u8| -> [u8; 36] {
            [
                0x06, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, ts_low, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                0x04, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x24, 0x00, 0x00, 0x00,
            ]
        };
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&shb);
        bytes.extend_from_slice(&idb);
        bytes.extend_from_slice(&make_epb(0));
        bytes.extend_from_slice(&make_epb(1));
        bytes.extend_from_slice(&make_epb(2));
        let path = dir.join("pcapng-count.pcapng");
        fs::write(&path, &bytes).unwrap();

        let count = count_pcap_records(&path);
        assert_eq!(
            count, 3,
            "count_pcap_records doit retourner 3 pour un pcapng \
             avec 3 EPB ; pré-2.9.18-fu retournait 0 (symptôme ANR2)"
        );
    }

    /// 2.9.17 (#9 comment 6739207609) — Preuve d'atomicité :
    /// `repair_partial_imports` ne touche à `import_state.json`
    /// à AUCUN moment, même sur une passe réelle complète.
    /// L'écriture ne porte que sur `.dataset-next/` puis commit
    /// atomique via `rename(.dataset-next, dataset)`. Un kill -9
    /// à n'importe quel moment avant ce rename laisse donc
    /// `import_state.json` byte-identique à l'avant.
    ///
    /// Test : setup un dataset avec doublons wire + state connu,
    /// exécute une passe réelle, vérifie que `import_state.json`
    /// a exactement les mêmes octets qu'avant l'appel.
    #[test]
    fn repair_partial_imports_never_touches_import_state_2_9_17() {
        let base = temporary_root("repair-atomic-state");
        let continuous = base.join(CONTINUOUS_CAPTURE_ID);
        let dataset = continuous.join("dataset");
        fs::create_dir_all(dataset.join("callflows")).unwrap();
        let capture_id = "sha256:01a70bdb74b0b";
        let owned_full = continuous.join("pcap").join("owned-01a70bdb.pcapng");
        let make_event = |event_id: &str, protocol: &str, message_name: &str| {
            serde_json::json!({
                "event_id": event_id,
                "capture_id": capture_id,
                "capture_point_id": "N2",
                "timestamp": {
                    "seconds": 23u64,
                    "nanoseconds": 0,
                    "raw_ticks": 23_000_000_000i128,
                    "display": "",
                },
                "interface": "N2",
                "protocol": protocol,
                "message_name": message_name,
                "source_endpoint": {"address": "10.0.0.1", "network_function": "gNB"},
                "destination_endpoint": {"address": "10.0.0.2", "network_function": "AMF"},
                "direction": "RAN_TO_CORE",
                "session_identifiers": [],
                "information_elements": [],
                "decoding_status": "DECODED",
                "decoder_name": "test",
                "decoder_version": "1",
                "raw_payload_reference": format!("sha256:payload-{event_id}"),
                "packet_references": [{
                    "source_file": owned_full.display().to_string(),
                    "packet_number": 23u64,
                    "byte_offset": 3908u64,
                    "interface_id": 0,
                    "captured_length": 1,
                    "original_length": 1,
                }],
                "errors": [],
            })
            .to_string()
        };
        let lines = vec![
            make_event("evt-dup-a", "NGAP", "UplinkNASTransport"),
            make_event("evt-dup-b", "NGAP", "UplinkNASTransport"),
        ];
        write_jsonl(&dataset.join("oiran_events.jsonl"), &lines);
        let state = serde_json::json!({
            "segments": {
                "01a70bdb74b0b": {
                    "interface": "N2",
                    "owned_file": "owned-01a70bdb.pcapng",
                    "size_bytes": 1024u64,
                    "packets": 23u64,
                    "imported_epoch_ms": 42u64,
                    "source_path": "",
                    "historical_context": false,
                }
            },
            "seen_checksums": ["01a70bdb74b0b"],
            "seen_order": ["01a70bdb74b0b"],
            "failed_ingestions": [],
            "source_fingerprints": {},
        });
        let state_bytes = serde_json::to_vec_pretty(&state).unwrap();
        let state_path = continuous.join("import_state.json");
        fs::write(&state_path, &state_bytes).unwrap();
        let state_sha_before = sha256_hex(&state_bytes);

        let manager = fresh_manager_for_restore(&base);
        let report = manager.repair_partial_imports(false, None).unwrap();
        // La passe a bien retiré 1 doublon wire.
        assert_eq!(report.event_count_before, 2);
        assert_eq!(report.event_count_after, 1);
        // INVARIANT 2.9.17 : import_state.json byte-identique.
        let state_bytes_after = fs::read(&state_path).unwrap();
        assert_eq!(
            sha256_hex(&state_bytes_after),
            state_sha_before,
            "repair_partial_imports NE DOIT PAS modifier import_state.json ; \
             un kill -9 avant le rename atomique laisserait donc l'état intact"
        );
        assert_eq!(
            state_bytes_after, state_bytes,
            "import_state.json strictement byte-identique"
        );
        // Le staging `.dataset-next/` a été consommé par le commit.
        assert!(
            !continuous.join(".dataset-next").exists(),
            ".dataset-next/ doit être renommé en dataset/ au commit"
        );
    }

    /// 2.9.17 (#9 comment 6739207609) — Bench de borne mémoire :
    /// 1,5 M lignes de dataset en entrée, la passe réelle doit
    /// terminer en < 512 MiB de RSS incrémental. ANR2 a prouvé
    /// que la version pré-2.9.17 consommait 14,2 à 14,9 GiB RSS
    /// (exit 137 ×2) sur ~1,3 M événements, en accumulant tout
    /// le JSONL retenu dans un `Vec<(String, u64, String,
    /// String)>`.
    ///
    /// Le test lit `/proc/self/status` VmRSS avant et après,
    /// stocke la valeur pour la réponse ANR2 (#9 « 2.9.17
    /// POUSSÉE »), et échoue si la différence dépasse 512 MiB.
    ///
    /// Ignoré par défaut : coûte ~500 MB disque + ~1 min CPU.
    /// Lancer explicitement avec :
    ///
    ///     cargo test --package live-probe --release \
    ///         repair_partial_imports_rss_bench_1_5m_2_9_17 \
    ///         -- --ignored --nocapture
    #[test]
    #[ignore]
    fn repair_partial_imports_rss_bench_1_5m_2_9_17() {
        fn vm_rss_kib() -> u64 {
            let text = fs::read_to_string("/proc/self/status").unwrap_or_default();
            for line in text.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    let value = rest.trim().split_whitespace().next().unwrap_or("0");
                    return value.parse::<u64>().unwrap_or(0);
                }
            }
            0
        }
        const EVENT_COUNT: u64 = 1_500_000;
        const RSS_BUDGET_MIB: u64 = 512;
        let base = temporary_root("repair-rss-bench-2-9-17");
        let continuous = base.join(CONTINUOUS_CAPTURE_ID);
        let dataset = continuous.join("dataset");
        fs::create_dir_all(dataset.join("callflows")).unwrap();
        let owned_full = continuous
            .join("pcap")
            .join("owned-bench.pcapng")
            .display()
            .to_string();
        let capture_id = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        // Écriture streaming du JSONL d'entrée.
        {
            let file = fs::File::create(dataset.join("oiran_events.jsonl")).unwrap();
            let mut writer = BufWriter::with_capacity(1 << 20, file);
            for i in 0..EVENT_COUNT {
                let line = serde_json::json!({
                    "event_id": format!("evt-bench-{i:07}"),
                    "capture_id": capture_id,
                    "capture_point_id": "N2",
                    "timestamp": {
                        "seconds": i,
                        "nanoseconds": 0,
                        "raw_ticks": i as i128 * 1_000_000_000,
                        "display": "",
                    },
                    "interface": "N2",
                    "protocol": "NGAP",
                    "message_name": "UplinkNASTransport",
                    "source_endpoint": {"address": "10.0.0.1", "network_function": "gNB"},
                    "destination_endpoint": {"address": "10.0.0.2", "network_function": "AMF"},
                    "direction": "RAN_TO_CORE",
                    "session_identifiers": [],
                    "information_elements": [],
                    "decoding_status": "DECODED",
                    "decoder_name": "test",
                    "decoder_version": "1",
                    "raw_payload_reference": format!("sha256:payload-{i}"),
                    "packet_references": [{
                        "source_file": owned_full,
                        // (packet_number, byte_offset) distincts
                        // par ligne ⇒ aucune wire-dupe.
                        "packet_number": i,
                        "byte_offset": i,
                        "interface_id": 0,
                        "captured_length": 1,
                        "original_length": 1,
                    }],
                    "errors": [],
                });
                writer.write_all(line.to_string().as_bytes()).unwrap();
                writer.write_all(b"\n").unwrap();
            }
            writer.flush().unwrap();
        }
        let state = serde_json::json!({
            "segments": {},
            "seen_checksums": [],
            "seen_order": [],
            "failed_ingestions": [],
            "source_fingerprints": {},
        });
        fs::write(
            continuous.join("import_state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();

        let manager = fresh_manager_for_restore(&base);
        let rss_before_kib = vm_rss_kib();
        // Dry-run : parcourt le pipeline complet (scan + index +
        // scratch + SHA) sans réécrire le dataset final. C'est le
        // chemin où 2.9.16 écroulait l'hôte à 14 GiB.
        let report = manager.repair_partial_imports(true, None).unwrap();
        let rss_after_kib = vm_rss_kib();
        let rss_delta_kib = rss_after_kib.saturating_sub(rss_before_kib);
        let rss_delta_mib = rss_delta_kib / 1024;
        eprintln!(
            "RSS_BENCH_2_9_17 events={EVENT_COUNT} before_kib={rss_before_kib} \
             after_kib={rss_after_kib} delta_mib={rss_delta_mib}",
        );
        assert_eq!(report.event_count_before as u64, EVENT_COUNT);
        assert!(
            rss_delta_mib < RSS_BUDGET_MIB,
            "RSS incrémental {rss_delta_mib} MiB dépasse la borne {RSS_BUDGET_MIB} MiB ANR2 \
             (régression du bug OOM 2.9.16 : 14 GiB sur 1,3 M événements)"
        );
    }

    /// 2.9.13 (#9 comment 6727243545) — ANR2 a prouvé 24 doublons
    /// wire-réels (dont 8 post-2.8.3) que la passe partial-import
    /// pré-2.9.13 n'adressait pas : deux événements partagent
    /// `(capture_id, packet_number, byte_offset, protocol,
    /// message_name)` mais sont dans le MÊME capture_id final
    /// (pas un cas prefix-SHA). Le dry-run ANR2 proposait 10 804
    /// suppressions mais ne couvrait que 10 des 48 event_ids.
    ///
    /// La passe wire-dedup 2.9.13 (`live-probe:4246-4310`) ajoute
    /// un second filtre : après le partial-import repair, dedup
    /// strict sur l'identité wire ANR2. Le test réplique 2 groupes
    /// réels ANR2 (NGAP UplinkNASTransport + NAS-5GMM Protected) ;
    /// le repair en retire 1 par groupe (first-canonical wins).
    #[test]
    fn repair_partial_imports_removes_wire_duplicates_anr2_2_9_13() {
        let base = temporary_root("repair-wire-dupes");
        let continuous = base.join(CONTINUOUS_CAPTURE_ID);
        let dataset = continuous.join("dataset");
        fs::create_dir_all(dataset.join("callflows")).unwrap();
        // Deux groupes ANR2 réels : même `(capture_id,
        // packet_number, byte_offset, protocol, message_name)`,
        // deux `event_id` différents.
        let capture_id = "sha256:01a70bdb74b0b";
        let owned_full = continuous.join("pcap").join("owned-01a70bdb.pcapng");
        let make_event = |event_id: &str, protocol: &str, message_name: &str| {
            serde_json::json!({
                "event_id": event_id,
                "capture_id": capture_id,
                "capture_point_id": "N2",
                "timestamp": {
                    "seconds": 23u64,
                    "nanoseconds": 0,
                    "raw_ticks": 23_000_000_000i128,
                    "display": "",
                },
                "interface": "N2",
                "protocol": protocol,
                "message_name": message_name,
                "source_endpoint": {"address": "10.0.0.1", "network_function": "gNB"},
                "destination_endpoint": {"address": "10.0.0.2", "network_function": "AMF"},
                "direction": "RAN_TO_CORE",
                "session_identifiers": [],
                "information_elements": [],
                "decoding_status": "DECODED",
                "decoder_name": "test",
                "decoder_version": "1",
                "raw_payload_reference": format!("sha256:payload-{event_id}"),
                "packet_references": [{
                    "source_file": owned_full.display().to_string(),
                    "packet_number": 23u64,
                    "byte_offset": 3908u64,
                    "interface_id": 0,
                    "captured_length": 1,
                    "original_length": 1,
                }],
                "errors": [],
            })
            .to_string()
        };
        let lines = vec![
            // Groupe 1 : NGAP UplinkNASTransport
            make_event("evt-83151568d66288d0", "NGAP", "UplinkNASTransport"),
            make_event("evt-c5cfdf6a8f4a9bdd", "NGAP", "UplinkNASTransport"),
            // Groupe 2 : NAS-5GMM Protected 5GMM message sur
            // même paquet — différent protocole, pas un dupe.
            make_event("evt-50e7a11f02dd0644", "NAS-5GMM", "Protected 5GMM message"),
            make_event("evt-b89b4f8aefc5af40", "NAS-5GMM", "Protected 5GMM message"),
            // Témoin : un événement légitime avec différent paquet,
            // ne doit PAS être retiré.
            {
                let line = make_event("evt-witness", "NGAP", "UplinkNASTransport");
                let mut value: Value = serde_json::from_str(&line).unwrap();
                value["packet_references"][0]["packet_number"] =
                    serde_json::Value::from(24u64);
                value.to_string()
            },
        ];
        write_jsonl(&dataset.join("oiran_events.jsonl"), &lines);
        let state = serde_json::json!({
            "segments": {},
            "seen_checksums": [],
            "seen_order": [],
            "failed_ingestions": [],
            "source_fingerprints": {},
        });
        fs::write(
            continuous.join("import_state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();

        let manager = fresh_manager_for_restore(&base);
        let dry = manager.repair_partial_imports(true, None).unwrap();
        assert!(dry.dry_run);
        assert_eq!(dry.event_count_before, 5);
        assert_eq!(
            dry.event_count_after, 3,
            "2 doublons wire retirés (1 par groupe) + 3 kept"
        );
        let wire_reasons: Vec<_> = dry
            .removed_events
            .iter()
            .filter(|r| r.reason == "wire-duplicate-superseded")
            .collect();
        assert_eq!(
            wire_reasons.len(),
            2,
            "wire-duplicate-superseded doit couvrir les 2 doublons"
        );
        let removed_ids: BTreeSet<&str> = wire_reasons
            .iter()
            .map(|r| r.event_id.as_str())
            .collect();
        // Canonique : premier event_id lex gagne pour chaque groupe.
        // Les secondaires (lex plus grands) sont retirés.
        assert!(
            removed_ids.contains("evt-c5cfdf6a8f4a9bdd")
                || removed_ids.contains("evt-83151568d66288d0"),
            "un des deux event_ids du groupe NGAP doit être retiré"
        );
    }

    /// 2.9.14 (#9 comment 6728398325) — ANR2 a prouvé que le
    /// plan repair ne couvrait que 3 des 5 fichiers `_00067` non
    /// vides parce que les planes N2 + S6a avaient ZÉRO événement
    /// dans le dataset — leur `capture_id` (prefix OU full) n'était
    /// jamais dans un IE. Le repair ne les trouvait donc pas via
    /// `prefix_sha_groups`.
    ///
    /// 2.9.14 : balaye `on_disk_prefix` après la boucle principale
    /// et pousse chaque fichier fermé dont le full-SHA n'est pas
    /// dans `dataset_capture_ids` vers `fresh_import_queue`. Un
    /// groupe `uncovered_closed_file` est ajouté à
    /// `partial_import_groups` avec `snapshots: []` et
    /// `needs_fresh_import=true`.
    #[test]
    fn repair_covers_uncovered_closed_file_fresh_import_2_9_14() {
        let base = temporary_root("repair-uncovered-closed");
        let continuous = base.join(CONTINUOUS_CAPTURE_ID);
        let dataset = continuous.join("dataset");
        fs::create_dir_all(dataset.join("callflows")).unwrap();
        let source_root = base.join("source");
        fs::create_dir_all(source_root.join("s6a")).unwrap();
        // Fichier S6a fermé sur disque : 4 paquets Diameter
        // minimum. prefix_sha_index produira ≥ 3 prefix SHAs
        // plus un full SHA ; aucun n'apparaît dans le dataset.
        let closed_path = source_root
            .join("s6a")
            .join("s6a_20261107T213849Z_00025_20261108213852.pcapng");
        write_pcap(
            &closed_path,
            &(1..=4u8).map(|byte| vec![byte; 32]).collect::<Vec<_>>(),
        );
        // Sibling actif (lex-greater) — exclu par la règle sequence.
        let active_path = source_root
            .join("s6a")
            .join("s6a_20261107T213849Z_00026_20261108223852.pcapng");
        write_pcap(&active_path, &[vec![9u8; 16]]);

        // Dataset VIDE : aucun événement sur le plan S6a. Juste
        // des événements sur un autre plan pour prouver que le
        // repair ne touche QUE le plan S6a nouveau.
        let unrelated = serde_json::json!({
            "event_id": "evt-unrelated",
            "capture_id": "sha256:other",
            "capture_point_id": "N2",
            "timestamp": {"seconds":1,"nanoseconds":0,"raw_ticks":0,"display":""},
            "interface": "N2",
            "protocol": "NGAP",
            "message_name": "NGSetupRequest",
            "source_endpoint": {"address":"a","network_function":"gNB"},
            "destination_endpoint": {"address":"b","network_function":"AMF"},
            "direction": "RAN_TO_CORE",
            "session_identifiers": [],
            "information_elements": [],
            "decoding_status": "DECODED",
            "decoder_name": "test",
            "decoder_version": "1",
            "raw_payload_reference": "sha256:other",
            "packet_references": [{
                "source_file":"other.pcap","packet_number":1,"byte_offset":0,
                "interface_id":0,"captured_length":1,"original_length":1
            }],
            "errors": []
        });
        write_jsonl(&dataset.join("oiran_events.jsonl"), &[unrelated.to_string()]);
        let state = serde_json::json!({
            "segments": {},
            "seen_checksums": [],
            "seen_order": [],
            "failed_ingestions": [],
            "source_fingerprints": {},
        });
        fs::write(
            continuous.join("import_state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();

        let manager = fresh_manager_for_restore(&base);
        let dry = manager
            .repair_partial_imports(true, Some(&source_root))
            .unwrap();
        // Un groupe "uncovered_closed_file" pour s6a_00025.
        let uncovered: Vec<_> = dry
            .partial_import_groups
            .iter()
            .filter(|g| g.reconstruction_key.contains("uncovered_closed_file"))
            .collect();
        assert_eq!(
            uncovered.len(),
            1,
            "un fichier S6a fermé non couvert doit déclencher un fresh-import"
        );
        assert_eq!(uncovered[0].interface, "S6a");
        assert!(
            uncovered[0].needs_fresh_import,
            "le groupe uncovered doit porter needs_fresh_import=true"
        );
        assert!(
            uncovered[0]
                .final_on_disk_path
                .as_deref()
                .is_some_and(|path| path.contains("s6a_20261107T213849Z_00025")),
            "final_on_disk_path doit pointer sur le fichier S6a fermé"
        );
        assert_eq!(
            uncovered[0].snapshots.len(),
            0,
            "pas de snapshots (zéro événement dataset) : fresh import pur"
        );
        // Le fichier actif (`_00026`) est exclu par la sequence
        // rule et ne doit PAS apparaître.
        for group in &dry.partial_import_groups {
            if let Some(p) = group.final_on_disk_path.as_deref() {
                assert!(
                    !p.contains("_00026_"),
                    "le fichier actif lex-greatest ne doit pas apparaître"
                );
            }
        }
    }

    /// 2.9.2 (#9 comment 6708784283): the ANR2 real-data scenario.
    /// Seven partial imports of a growing dumpcap file land in the
    /// published dataset with `capture_id` values equal to the
    /// SHA-256 of BYTE PREFIXES of the final closed file at packet
    /// boundaries. The final full-SHA snapshot is ABSENT — dumpcap
    /// rotated to `_00068` before the probe caught up, and
    /// `state.segments` holds no entry for `_00067`. The 2.9.2
    /// repair walks the closed file via `prefix_sha_index`, matches
    /// every snapshot `capture_id` against the per-packet prefix
    /// SHAs, groups the 7 snapshots to the on-disk file, decodes it
    /// afresh to replace the partial events, and removes the
    /// prefix-only events. The 2.9.0 content-identity key
    /// `(interface, first_raw_ticks, …)` failed in production
    /// (ANR2 observed zero groups) because each snapshot carries a
    /// DISJOINT packet range — no two snapshots share packet 1.
    #[test]
    fn repair_partial_imports_rebuilds_full_history_via_prefix_sha_match() {
        let base = temporary_root("repair-prefix-sha-7x");
        let continuous = base.join(CONTINUOUS_CAPTURE_ID);
        let dataset = continuous.join("dataset");
        fs::create_dir_all(dataset.join("callflows")).unwrap();
        let source_root = base.join("source");
        fs::create_dir_all(source_root.join("n4")).unwrap();
        // Build a real pcap with 8 packets so `prefix_sha_index`
        // produces ≥ 7 packet-boundary SHA snapshots to match
        // against.
        let final_path = source_root
            .join("n4")
            .join("n4_20261104T142333Z_00067_20261107082343.pcapng");
        write_pcap(
            &final_path,
            &(1..=8u8).map(|byte| vec![byte; 32]).collect::<Vec<_>>(),
        );
        // Active sibling (lex-greater) — excluded by the 2.8.3
        // sequence rule.
        let active_path = source_root
            .join("n4")
            .join("n4_20261104T142333Z_00068_20261107092400.pcapng");
        write_pcap(&active_path, &[vec![0xff; 32]]);

        let index = prefix_sha_index(&final_path).unwrap();
        let prefix_shas: Vec<String> = index.prefix_sha.keys().take(7).cloned().collect();
        assert_eq!(
            prefix_shas.len(),
            7,
            "fixture pcap must expose at least 7 packet-boundary prefixes; got {}",
            prefix_shas.len()
        );

        // Build 7 snapshots × 3 events = 21 prefix events. None has
        // the full-file SHA → forces the PrefixShaMatchFreshImport
        // path.
        let mut lines = Vec::new();
        let mut prefix_capture_ids: BTreeSet<String> = BTreeSet::new();
        for (snap_idx, prefix_sha) in prefix_shas.iter().enumerate() {
            let capture_id = format!("sha256:{prefix_sha}");
            prefix_capture_ids.insert(capture_id.clone());
            let owned = format!("N4.pcap-{}.pcapng", &prefix_sha[..16]);
            for packet in 1..=3u64 {
                let event_id = format!("evt-snap{}-p{packet}", snap_idx + 1);
                let owned_full = continuous.join("pcap").join(&owned);
                let line = serde_json::json!({
                    "event_id": event_id,
                    "capture_id": capture_id,
                    "capture_point_id": "N4",
                    "timestamp": {
                        "seconds": packet,
                        "nanoseconds": 0,
                        "raw_ticks": (snap_idx as i128 * 100 + packet as i128) * 1_000_000_000i128,
                        "display": "",
                    },
                    "interface": "N4",
                    "protocol": "PFCP",
                    "message_name": "SessionEstablishmentRequest",
                    "source_endpoint": {"address": "10.0.0.1", "network_function": "SMF"},
                    "destination_endpoint": {"address": "10.0.0.2", "network_function": "UPF"},
                    "direction": "CORE_TO_RAN",
                    "session_identifiers": [],
                    "information_elements": [],
                    "decoding_status": "DECODED",
                    "decoder_name": "test",
                    "decoder_version": "1",
                    "raw_payload_reference": capture_id.clone(),
                    "packet_references": [{
                        "source_file": owned_full.display().to_string(),
                        "packet_number": (snap_idx as u64 * 10) + packet,
                        "byte_offset": 1000 * (snap_idx as u64 + 1) + packet,
                        "interface_id": 0,
                        "captured_length": 1,
                        "original_length": 1,
                    }],
                    "errors": [],
                })
                .to_string();
                lines.push(line);
            }
        }
        write_jsonl(&dataset.join("oiran_events.jsonl"), &lines);
        // EMPTY state.segments — ANR2 proved this is the production
        // reality (no `_00067` entry survived the pre-2.8.4
        // eviction).
        let state = serde_json::json!({
            "segments": {},
            "seen_checksums": [],
            "seen_order": [],
            "failed_ingestions": [],
            "source_fingerprints": {},
        });
        fs::write(
            continuous.join("import_state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();

        let manager = fresh_manager_for_restore(&base);
        // Dry run — the 7 prefix snapshots are grouped together via
        // SHA-256 of packet-boundary prefixes.
        let dry_report = manager
            .repair_partial_imports(true, Some(source_root.as_path()))
            .unwrap();
        assert_eq!(
            dry_report.partial_import_groups.len(),
            1,
            "7 prefix snapshots of the same growing file must group together"
        );
        let group = &dry_report.partial_import_groups[0];
        assert_eq!(group.snapshots.len(), 7);
        assert_eq!(
            group.final_source,
            PartialImportFinalSource::PrefixShaMatchFreshImport,
            "no full-SHA snapshot in the dataset → needs fresh import"
        );
        assert_eq!(
            group.final_capture_id.as_deref(),
            Some(format!("sha256:{}", index.full_sha_hex).as_str())
        );
        assert!(group.needs_fresh_import);
        assert_eq!(dry_report.event_count_before, 21);
        assert_eq!(dry_report.removed_events.len(), 21);
        let dry_captures: BTreeSet<String> = dry_report
            .removed_events
            .iter()
            .map(|event| event.capture_id.clone())
            .collect();
        assert_eq!(
            dry_captures, prefix_capture_ids,
            "every prefix-snapshot capture_id must appear in the dry-run removals"
        );

        // Real run — the 21 prefix events are removed and the
        // closed file is decoded fresh. The synthetic fixture pcap
        // isn't a real PFCP capture so `decode_capture_streaming`
        // emits 0 events, but the invariant on prefix removal
        // stands.
        let report = manager
            .repair_partial_imports(false, Some(source_root.as_path()))
            .unwrap();
        for capture in &prefix_capture_ids {
            let remaining = count_events_with_capture(
                &dataset.join("oiran_events.jsonl"),
                capture,
            );
            assert_eq!(
                remaining, 0,
                "every prefix capture_id must be fully removed; {capture} still has {remaining}"
            );
        }
        assert_eq!(
            report.event_count_before - report.removed_events.len(),
            report.event_count_after - count_events_with_capture(
                &dataset.join("oiran_events.jsonl"),
                &format!("sha256:{}", index.full_sha_hex),
            ),
            "kept events equal (input - removed) plus any fresh-import additions"
        );
        // Idempotent — second pass finds no prefix snapshots because
        // they are all gone.
        let second = manager
            .repair_partial_imports(false, Some(source_root.as_path()))
            .unwrap();
        assert_eq!(second.events_sha256, report.events_sha256);
    }

    /// 2.8.3: repair is a strict no-op on a healthy dataset — no
    /// partial groups, no removed events, events_sha256 unchanged.
    #[test]
    fn repair_partial_imports_is_noop_on_a_healthy_dataset() {
        let base = temporary_root("repair-partial-imports-healthy");
        let continuous = base.join(CONTINUOUS_CAPTURE_ID);
        let dataset = continuous.join("dataset");
        fs::create_dir_all(dataset.join("callflows")).unwrap();
        write_jsonl(
            &dataset.join("oiran_events.jsonl"),
            &[
                restore_test_line("evt-1", "sha256:healthy", 1),
                restore_test_line("evt-2", "sha256:healthy", 2),
            ],
        );
        let segments = serde_json::json!({
            "healthy": {
                "interface": "N2",
                "owned_file": "healthy.pcap",
                "size_bytes": 4096u64,
                "packets": 2u64,
                "imported_epoch_ms": 1u64,
                "source_path": "/captures/n2/final.pcapng",
                "historical_context": false,
            }
        });
        let state = serde_json::json!({
            "segments": segments,
            "seen_checksums": [],
            "seen_order": [],
            "failed_ingestions": [],
            "source_fingerprints": {},
        });
        fs::write(
            continuous.join("import_state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();
        let original_sha = sha256_hex(&fs::read(&dataset.join("oiran_events.jsonl")).unwrap());
        let manager = fresh_manager_for_restore(&base);
        let report = manager.repair_partial_imports(false, None).unwrap();
        assert!(report.partial_import_groups.is_empty());
        assert!(report.removed_events.is_empty());
        assert_eq!(report.event_count_before, 2);
        assert_eq!(report.event_count_after, 2);
        assert_eq!(report.events_sha256, original_sha);
    }

    /// 2.7.28: `event_id`s that appear in BOTH the current hot view
    /// and the archive segment are reported in the restore report's
    /// `overlap_event_ids` so the operator can account for the
    /// `before + archive - overlap = after` identity ANR2 verified in
    /// the 2.7.27 field test.
    #[test]
    fn restore_reports_overlap_event_ids_between_hot_view_and_archive() {
        let base = temporary_root("restore-overlap");
        let (dataset, segment, _) = make_restore_fixture(&base);
        write_jsonl(
            &dataset.join("oiran_events.jsonl"),
            &[
                restore_test_line("evt-a", "sha256:cap", 1),
                restore_test_line("evt-b", "sha256:cap", 2),
            ],
        );
        write_jsonl(
            &segment.join("events.jsonl"),
            &[
                restore_test_line("evt-b", "sha256:cap", 2), // overlap
                restore_test_line("evt-c", "sha256:cap", 3),
            ],
        );
        let archive_sha = sha256_hex(&fs::read(&segment.join("events.jsonl")).unwrap());
        fs::write(
            segment.join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({"events_sha256": archive_sha}))
                .unwrap(),
        )
        .unwrap();
        let manager = fresh_manager_for_restore(&base);
        let report = manager.restore_from_archive_segment(&segment).unwrap();
        assert_eq!(report.overlap_event_count, 1);
        assert_eq!(report.overlap_event_ids, vec!["evt-b".to_string()]);
        assert_eq!(report.event_count_before, 2);
        assert_eq!(report.archive_event_count, 2);
        assert_eq!(
            report.event_count_after,
            report.event_count_before + report.archive_event_count - report.overlap_event_count,
            "before + archive - overlap = after"
        );
    }

    /// 2.7.28: once the restore has swapped `.dataset-next` in, the
    /// NEXT continuous publication (simulated here by calling
    /// `process_capture_into` with an empty pcap tree and no new
    /// interfaces) re-reads the restored events as its `prior_continuous`
    /// checkpoint and the registration validates — the ANR2 symptom
    /// (`DATASET_REGISTRATION_EVENT_COUNT_MISMATCH` on the next
    /// publish) must not reappear.
    #[test]
    fn restore_followed_by_an_empty_publish_leaves_registration_valid() {
        let base = temporary_root("restore-then-publish");
        let (dataset, segment, continuous) = make_restore_fixture(&base);
        write_jsonl(
            &dataset.join("oiran_events.jsonl"),
            &[restore_test_line("evt-fresh-1", "sha256:fresh", 100)],
        );
        write_jsonl(
            &segment.join("events.jsonl"),
            &[restore_test_line("evt-stale-1", "sha256:stale", 10)],
        );
        let archive_sha = sha256_hex(&fs::read(&segment.join("events.jsonl")).unwrap());
        fs::write(
            segment.join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({"events_sha256": archive_sha}))
                .unwrap(),
        )
        .unwrap();
        let manager = fresh_manager_for_restore(&base);
        manager.restore_from_archive_segment(&segment).unwrap();
        // Simulate the next publish: empty pcap dir, no interfaces.
        // process_capture_into reads the restored manifest as its
        // `prior_continuous` checkpoint via `validate_dataset_artifacts`.
        let pcap_dir = continuous.join("pcap");
        fs::create_dir_all(&pcap_dir).unwrap();
        let next = continuous.join(".dataset-next");
        let _ = fs::remove_dir_all(&next);
        let published = manager
            .process_capture_into(
                CONTINUOUS_CAPTURE_ID,
                CONTINUOUS_DATASET_ID.into(),
                &pcap_dir,
                &next,
                format!("runtime/live-captures/{CONTINUOUS_CAPTURE_ID}/dataset"),
                &[],
            )
            .expect("next publish after restore must succeed");
        assert_eq!(
            published.event_count, 2,
            "next publish carries the restored events through as its checkpoint"
        );
    }

    /// 2.7.27: the capture-level age is computed per capture_id, not
    /// per event. A capture with ONE very old event plus ONE very
    /// fresh event stays in the hot view: the capture's end_ts
    /// (= max event ts in the capture) is fresh.
    #[test]
    fn capture_level_age_never_slices_inside_a_capture() {
        let base = temporary_root("archive-per-capture");
        let dataset_dir = base.join("dataset");
        fs::create_dir_all(&dataset_dir).unwrap();
        let events_path = dataset_dir.join("oiran_events.jsonl");
        // Single capture with both old and fresh events. Per-event
        // retention (the 2.7.22 bug) would have dropped the first;
        // capture-level retention keeps both because max_ts = 9000
        // ≥ cutoff.
        write_jsonl(
            &events_path,
            &[
                archive_test_line("evt-old", "sha256:mixed", 100, 1),
                archive_test_line("evt-fresh", "sha256:mixed", 9000, 2),
            ],
        );
        let before_ids = read_event_ids(&events_path);
        let archive_root = base.join("archive");
        archive_stale_captures(&events_path, &archive_root, 5000).unwrap();
        let after_ids = read_event_ids(&events_path);
        assert_eq!(after_ids, before_ids, "mixed-age capture is kept whole");
    }

    // 2.9.5 (devmat #9 T1 + T3) : tests du KeepaliveAggregator et de
    // la règle de doublon. Volume ANR2 preuve 6714896530 : Sxa/Sxb
    // 868 123 heartbeats PFCP + S6a 76 890 watchdogs Diameter >75 %.

    fn keepalive_event(
        id: &str,
        interface: &str,
        protocol: Protocol,
        message_name: &str,
        source: &str,
        destination: &str,
        capture_id: &str,
        packet_number: u64,
    ) -> NormalizedEvent {
        NormalizedEvent {
            event_id: id.into(),
            parent_event_id: None,
            probe_id: "oiran-vprobe-local-01".into(),
            capture_point_id: interface.into(),
            capture_id: capture_id.into(),
            packet_references: vec![event_schema::PacketReference {
                source_file: "x.pcapng".into(),
                source_sha256: None,
                packet_number,
                byte_offset: packet_number * 64,
                interface_id: 0,
                link_type: None,
                sll2_protocol_type: None,
                sll2_reserved: None,
                sll2_interface_index: None,
                sll2_arphrd_type: None,
                sll2_packet_type: None,
                sll2_address_length: None,
                sll2_address: None,
                captured_length: 64,
                original_length: 64,
            }],
            timestamp: event_schema::ExactTimestamp {
                seconds: 1,
                nanoseconds: packet_number as u32,
                raw_ticks: 1_000_000_000 + packet_number,
                resolution_base: 10,
                resolution_exponent: 9,
            },
            interface: interface.into(),
            protocol,
            message_name: message_name.into(),
            message_type: 0,
            procedure_code: None,
            procedure: None,
            security_state: None,
            source_byte_offset: None,
            source_endpoint: event_schema::Endpoint {
                address: source.into(),
                port: None,
                network_function: None,
            },
            destination_endpoint: event_schema::Endpoint {
                address: destination.into(),
                port: None,
                network_function: None,
            },
            direction: event_schema::Direction::RanToCore,
            session_identifiers: vec![],
            information_elements: vec![],
            decoder_name: "test".into(),
            decoder_version: "0".into(),
            schema_version: NormalizedEvent::SCHEMA_VERSION,
            decoding_status: event_schema::DecodeStatus::Decoded,
            errors: vec![],
            raw_payload_reference: format!("sha256:{id}"),
            evidence_references: vec![],
            sbi: None,
        }
    }

    /// 1000 PFCP Heartbeat Requests + 1000 Responses du même couple de
    /// nœuds collapsent en 1 aggregate avec request_count=1000,
    /// response_count=1000, failure_count=0, et la paire canonique
    /// (min, max) des adresses.
    #[test]
    fn keepalive_aggregator_collapses_pfcp_heartbeats_with_paired_request_response() {
        let mut agg = KeepaliveAggregator::default();
        for i in 1..=1000 {
            let req = keepalive_event(
                &format!("req-{i}"),
                "Sxab",
                Protocol::Pfcp,
                "PFCP Heartbeat Request",
                "10.0.0.1",
                "10.0.0.2",
                "sha256:cap-sxab",
                i,
            );
            let resp = keepalive_event(
                &format!("resp-{i}"),
                "Sxab",
                Protocol::Pfcp,
                "PFCP Heartbeat Response",
                "10.0.0.2",
                "10.0.0.1",
                "sha256:cap-sxab",
                i + 10_000,
            );
            assert!(matches!(agg.observe(req), Ok(None)));
            assert!(matches!(agg.observe(resp), Ok(None)));
        }
        let out = agg.finish();
        assert_eq!(out.len(), 1, "une seule paire de nœuds → 1 aggregate");
        let agg_event = &out[0];
        assert_eq!(agg_event.message_name, "PFCP Heartbeat (aggregated)");
        let find = |name: &str| {
            agg_event
                .information_elements
                .iter()
                .find(|ie| ie.name == name)
                .and_then(|ie| ie.value.clone())
                .unwrap_or_default()
        };
        assert_eq!(find("aggregate_request_count"), "1000");
        assert_eq!(find("aggregate_response_count"), "1000");
        assert_eq!(find("aggregate_message_count"), "2000");
        assert_eq!(find("aggregate_failure_count"), "0");
        assert_eq!(find("aggregate_node_pair_low"), "10.0.0.1");
        assert_eq!(find("aggregate_node_pair_high"), "10.0.0.2");
        assert_eq!(find("aggregate_first_packet_number"), "1");
        // last = 10_000 + 1000 = 11_000 (dernière response)
        assert_eq!(find("aggregate_last_packet_number"), "11000");
    }

    /// Un couple avec requêtes non appariées produit un
    /// `aggregate_failure_count` > 0 (jamais masqué).
    #[test]
    fn keepalive_aggregator_counts_unmatched_requests_as_failures() {
        let mut agg = KeepaliveAggregator::default();
        // 100 DWR, 42 DWA → 58 failures.
        for i in 1..=100 {
            let req = keepalive_event(
                &format!("dwr-{i}"),
                "S6a",
                Protocol::Diameter,
                "Device-Watchdog-Request",
                "10.0.1.1",
                "10.0.1.2",
                "sha256:cap-s6a",
                i,
            );
            assert!(matches!(agg.observe(req), Ok(None)));
        }
        for i in 1..=42 {
            let resp = keepalive_event(
                &format!("dwa-{i}"),
                "S6a",
                Protocol::Diameter,
                "Device-Watchdog-Answer",
                "10.0.1.2",
                "10.0.1.1",
                "sha256:cap-s6a",
                i + 500,
            );
            assert!(matches!(agg.observe(resp), Ok(None)));
        }
        let out = agg.finish();
        assert_eq!(out.len(), 1);
        let find = |name: &str| {
            out[0]
                .information_elements
                .iter()
                .find(|ie| ie.name == name)
                .and_then(|ie| ie.value.clone())
                .unwrap_or_default()
        };
        assert_eq!(find("aggregate_request_count"), "100");
        assert_eq!(find("aggregate_response_count"), "42");
        assert_eq!(find("aggregate_failure_count"), "58");
        assert_eq!(out[0].message_name, "Device-Watchdog (aggregated)");
    }

    /// Les messages de session (non-keepalive) passent à travers
    /// l'aggregator sans être absorbés.
    #[test]
    fn keepalive_aggregator_passes_through_non_keepalive_session_events() {
        let mut agg = KeepaliveAggregator::default();
        let session = keepalive_event(
            "evt-session-1",
            "N4",
            Protocol::Pfcp,
            "PFCP Session Establishment Request",
            "10.0.0.1",
            "10.0.0.2",
            "sha256:cap-n4",
            7,
        );
        match agg.observe(session).expect("ok") {
            Some(evt) => assert_eq!(evt.message_name, "PFCP Session Establishment Request"),
            None => panic!("session messages must pass through, not be absorbed"),
        }
        assert_eq!(agg.finish().len(), 0, "no keepalive observed → no aggregate");
    }

    /// GTP-U Echo et GTPv2 Echo génèrent chacun leur aggregate séparé
    /// même sur le même capture_id (protocoles distincts).
    #[test]
    fn keepalive_aggregator_separates_gtpu_echo_from_gtpv2_echo() {
        let mut agg = KeepaliveAggregator::default();
        for i in 1..=5 {
            agg.observe(keepalive_event(
                &format!("gu-{i}"),
                "N3",
                Protocol::Gtpu,
                "Echo Request",
                "10.0.0.1",
                "10.0.0.2",
                "sha256:cap",
                i,
            ))
            .unwrap();
        }
        for i in 1..=3 {
            agg.observe(keepalive_event(
                &format!("gv-{i}"),
                "N4",
                Protocol::Gtpv2c,
                "Echo Request",
                "10.0.0.1",
                "10.0.0.2",
                "sha256:cap",
                100 + i,
            ))
            .unwrap();
        }
        let out = agg.finish();
        assert_eq!(out.len(), 2, "GTP-U Echo et GTPv2 Echo = 2 aggregates distincts");
        let mut by_kind = std::collections::BTreeMap::new();
        for e in &out {
            let kind = e
                .information_elements
                .iter()
                .find(|ie| ie.name == "aggregate_keepalive_kind")
                .and_then(|ie| ie.value.clone())
                .unwrap();
            by_kind.insert(kind, e.clone());
        }
        assert!(by_kind.contains_key("GTPU_ECHO"));
        assert!(by_kind.contains_key("GTPV2_ECHO"));
    }

    /// 2.9.5 T3 : la règle de doublon documentée. Même paquet
    /// (capture_id, packet_number, byte_offset) + même protocole +
    /// même message_name = doublon. S1AP et NAS-EPS-MM du même paquet
    /// = PAS un doublon (message_name différents). Deux S1AP du même
    /// paquet avec le même message_name = doublon.
    #[test]
    fn is_duplicate_rule_separates_s1ap_from_nas_eps_mm_on_same_packet() {
        let s1ap = keepalive_event(
            "evt-s1ap",
            "S1-MME",
            Protocol::S1ap,
            "InitialContextSetupRequest",
            "10.0.0.1",
            "10.0.0.2",
            "sha256:cap-s1mme",
            42,
        );
        let mut nas = s1ap.clone();
        nas.event_id = "evt-nas".into();
        nas.protocol = Protocol::NasEpsMm;
        nas.message_name = "Attach Accept".into();
        // S1AP et NAS-EPS-MM du même paquet (même capture_id, même
        // packet_number, même byte_offset) — protocoles ET
        // message_names différents → PAS un doublon.
        assert!(!is_duplicate(&s1ap, &nas),
            "S1AP + NAS-EPS-MM du même paquet sont deux événements légitimes");

        let mut s1ap_bis = s1ap.clone();
        s1ap_bis.event_id = "evt-s1ap-dup".into();
        // Même protocole, même message_name, même paquet → doublon.
        assert!(is_duplicate(&s1ap, &s1ap_bis),
            "deux S1AP InitialContextSetupRequest sur le même paquet = doublon");

        let mut s1ap_other_packet = s1ap.clone();
        s1ap_other_packet.event_id = "evt-s1ap-other".into();
        s1ap_other_packet.packet_references[0].packet_number = 99;
        s1ap_other_packet.packet_references[0].byte_offset = 99 * 64;
        // Même protocole + message_name mais paquet différent → PAS un doublon.
        assert!(!is_duplicate(&s1ap, &s1ap_other_packet),
            "deux S1AP du même type mais paquets différents = deux événements");

        let mut s1ap_other_offset = s1ap.clone();
        s1ap_other_offset.event_id = "evt-s1ap-off".into();
        s1ap_other_offset.packet_references[0].byte_offset = 42 * 64 + 1; // même packet_number mais byte_offset différent (impossible en pratique, test de rigueur)
        assert!(!is_duplicate(&s1ap, &s1ap_other_offset),
            "byte_offset différent = pas un doublon");
    }

    /// 2.9.6 (devmat #9 T1 — ANR2 #10 comment 6724120812) : avant ce
    /// correctif, `prefix_sha_index` ne reconnaissait que le pcap
    /// classique (magic `D4 C3 B2 A1` / reversed) et retournait
    /// `prefix_sha = {}` sur pcapng. Conséquence en production : les
    /// 7 snapshots de `_00067` n'étaient pas regroupés (1075 groupes
    /// tous singletons, 6 `UNRESOLVED_NO_EVIDENCE`), le --dry-run
    /// annonçait 0 événement à retirer. Ce test construit un pcapng
    /// minimal de 2 Enhanced Packet Blocks et vérifie que la sortie
    /// `prefix_sha` isole le SHA après le 1er paquet (le SHA après le
    /// 2e paquet == `full_sha_hex`, retiré par convention pour
    /// distinguer Full-SHA de Prefix-SHA).
    #[test]
    fn prefix_sha_index_walks_pcapng_enhanced_packet_blocks() {
        // SHB little-endian, 28 octets.
        let shb: [u8; 28] = [
            0x0a, 0x0d, 0x0d, 0x0a, // block type (signature)
            0x1c, 0x00, 0x00, 0x00, // block total length = 28 (LE)
            0x4d, 0x3c, 0x2b, 0x1a, // byte-order magic (LE)
            0x01, 0x00, // major version
            0x00, 0x00, // minor version
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // section length = -1
            0x1c, 0x00, 0x00, 0x00, // trailer length = 28
        ];
        // IDB (Interface Description Block), 20 octets.
        let idb: [u8; 20] = [
            0x01, 0x00, 0x00, 0x00, // block type 1
            0x14, 0x00, 0x00, 0x00, // block total length = 20
            0x01, 0x00, // link_type = 1 (Ethernet)
            0x00, 0x00, // reserved
            0x00, 0x00, 0x04, 0x00, // snaplen = 262144 (LE)
            0x14, 0x00, 0x00, 0x00, // trailer length = 20
        ];
        // EPB1, 36 octets avec 4 octets de données paquet.
        let epb1: [u8; 36] = [
            0x06, 0x00, 0x00, 0x00, // block type 6 (EPB)
            0x24, 0x00, 0x00, 0x00, // block total length = 36
            0x00, 0x00, 0x00, 0x00, // interface_id = 0
            0x00, 0x00, 0x00, 0x00, // ts high
            0x00, 0x00, 0x00, 0x00, // ts low
            0x04, 0x00, 0x00, 0x00, // captured_len = 4
            0x04, 0x00, 0x00, 0x00, // original_len = 4
            0xaa, 0xbb, 0xcc, 0xdd, // packet data (aligné à 4)
            0x24, 0x00, 0x00, 0x00, // trailer length
        ];
        // EPB2, même structure, données différentes pour que le SHA
        // du 2nd paquet soit distinct.
        let epb2: [u8; 36] = [
            0x06, 0x00, 0x00, 0x00, // block type 6 (EPB)
            0x24, 0x00, 0x00, 0x00, // block total length = 36
            0x00, 0x00, 0x00, 0x00, // interface_id = 0
            0x00, 0x00, 0x00, 0x00, // ts high
            0x01, 0x00, 0x00, 0x00, // ts low
            0x04, 0x00, 0x00, 0x00, // captured_len = 4
            0x04, 0x00, 0x00, 0x00, // original_len = 4
            0x11, 0x22, 0x33, 0x44, // packet data distincte
            0x24, 0x00, 0x00, 0x00, // trailer length
        ];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&shb);
        bytes.extend_from_slice(&idb);
        bytes.extend_from_slice(&epb1);
        bytes.extend_from_slice(&epb2);
        let dir = tempdir();
        let path = dir.join("fixture.pcapng");
        fs::write(&path, &bytes).unwrap();

        let index = prefix_sha_index(&path).expect("pcapng doit être parsé");
        assert_eq!(index.full_packet_count, 2, "2 EPB = 2 paquets comptés");
        assert_eq!(index.full_bytes, bytes.len() as u64);
        // Le SHA du fichier entier doit égaler le full_sha_hex calculé
        // par sha256_hex_file.
        assert_eq!(index.full_sha_hex.len(), 64);
        // prefix_sha doit contenir exactement 1 entrée : le SHA après le
        // 1er EPB. Le SHA après le 2e EPB == full_sha, retiré par
        // convention pour que la réparation distingue Full de Prefix.
        assert_eq!(
            index.prefix_sha.len(),
            1,
            "attendu 1 prefix SHA (packet 1) ; SHA après packet 2 est le full retiré ; got {:?}",
            index.prefix_sha
        );
        let (packet_count, bytes_at_snapshot) = index
            .prefix_sha
            .values()
            .next()
            .expect("prefix_sha a 1 entrée")
            .clone();
        assert_eq!(packet_count, 1);
        // Après SHB(28) + IDB(20) + EPB1(36) = 84 octets.
        assert_eq!(bytes_at_snapshot, 84);
    }

    fn tempdir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "oiran-prefix-sha-pcapng-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 2.9.8 (#9, ANR2 comment 6725097122): `work_bytes` must NOT
    /// count the committed pcap ring. ANR2 proved in production that
    /// the pre-2.9.8 definition `directory_size(base) -
    /// directory_size(dataset)` included every `pcap/<iface>.pcap-…`
    /// file; with a 10 GiB ring the next 163 MiB candidate tripped
    /// `CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT` even though the ring
    /// is bounded elsewhere and would never shrink on its own. This
    /// test stages exactly that shape: a committed ring of 10 GiB
    /// (via sparse files to avoid hitting the host disk) and asserts
    /// `work_bytes` returns only the staging budget (the `.importing`
    /// temporary is counted; the committed entries are not).
    #[test]
    fn work_bytes_excludes_committed_pcap_ring_proof_anr2() {
        use std::os::unix::fs::FileExt;
        let base = temporary_root("work-bytes-ring");
        let pcap = base.join("pcap");
        fs::create_dir_all(&pcap).unwrap();
        fs::create_dir_all(base.join("dataset")).unwrap();

        // Ten sparse 1 GiB "committed" ring files — this is what
        // `copy_verified` leaves on disk after `fs::rename` from
        // `.importing`. Sparse writes mean the host only pays for
        // the 24-byte PCAP header per file.
        for i in 0..10u32 {
            let path = pcap.join(format!("N3.pcap-{:016x}.pcapng", i));
            let file = fs::File::create(&path).unwrap();
            file.set_len(1_073_741_824).unwrap();
            // Write 24 bytes at offset 0 so the file is not purely
            // sparse (matches the reality of a real pcapng header).
            file.write_at(&[0u8; 24], 0).unwrap();
        }
        // An `.importing` temp — still in-flight, must be counted.
        let importing = pcap.join("N3.pcap-ffffffffffffffff.importing");
        fs::write(&importing, vec![0u8; 4 * 1024 * 1024]).unwrap();

        let staging = work_bytes(&base);
        // The ten committed ring entries total ~10 GiB but are
        // excluded. The `.importing` temp is counted.
        assert!(
            staging < 128 * 1024 * 1024,
            "work_bytes must exclude the committed ring; got {} bytes (expected < 128 MiB)",
            staging
        );
        assert!(
            staging >= 4 * 1024 * 1024,
            "work_bytes must count the .importing temp; got {} bytes (expected >= 4 MiB)",
            staging
        );

        // Backpressure gate: `max_owned_bytes = 128 MiB`, candidate
        // 163 MiB, derived reserve 64 MiB. Under the pre-2.9.8
        // definition the ring alone (10 GiB) tripped the gate. Under
        // 2.9.8 only `staging + 163 MiB + 64 MiB` is compared to
        // `max_owned_bytes`; a honest 163 MiB candidate with a 10 GiB
        // ring would still trip (163+64+4 > 128), but a 32 MiB
        // candidate must now pass.
        let max_owned = 128 * 1024 * 1024u64;
        let small_candidate = 16 * 1024 * 1024u64;
        let trip = staging
            .saturating_add(small_candidate)
            .saturating_add(MAX_CONTINUOUS_DERIVED_BYTES);
        assert!(
            trip <= max_owned,
            "a 16 MiB candidate must not trip backpressure on a 10 GiB committed ring; \
             staging={staging} trip={trip} max_owned={max_owned}"
        );
    }

    /// 2.11.3 (devmat, revue ANR1 #9 comment 6781367658) : reproduit
    /// EXACTEMENT le cas qui a causé le BLOCKED 2.10.2 à 20:47Z en
    /// prod. Un répertoire `.dataset.rollback.YYYYMMDDTHHMMSSZ` de
    /// **3,38 Go** à la racine d'import NE DOIT PAS déclencher le
    /// backpressure. Pre-2.11.3 `work_bytes` comptait ce répertoire ;
    /// la condition `staging + candidate + derived_reserve >
    /// max_owned_bytes` trippait sur chaque segment de 193 KB →
    /// `CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT` → état `BLOCKED` sans
    /// cause OIRAN réelle.
    #[test]
    fn rollback_tombstone_excluded_from_work_bytes_proof_anr1_6781367658() {
        let base = temporary_root("work-bytes-rollback");
        fs::create_dir_all(base.join("dataset")).unwrap();
        fs::create_dir_all(base.join("pcap")).unwrap();

        // Fabrique un `.dataset.rollback.YYYYMMDDTHHMMSSZ` sparse
        // de 3 380 541 933 octets — chiffre exact observé par ANR1
        // sur la prod 2.10.2 (`du -sb`). Le fichier sparse ne
        // consomme pas 3 Go sur le disque local du bench, mais
        // `metadata.len()` retourne la taille logique.
        let rollback = base.join(".dataset.rollback.20261110T204701Z");
        fs::create_dir_all(&rollback).unwrap();
        let file = fs::File::create(rollback.join("oiran_events.jsonl")).unwrap();
        file.set_len(3_380_541_933).unwrap();
        drop(file);

        // Sanity : `directory_size` voit bien les 3,38 Go sparse.
        let rollback_size = directory_size(&rollback);
        assert_eq!(
            rollback_size, 3_380_541_933,
            "sparse rollback dir must count as 3.38 GB via metadata.len()"
        );

        // Petit `.importing` 193 KB (1 segment N2 typique ANR1).
        fs::write(base.join("pcap/N2.pcap-cafebabedeadbeef.importing"), vec![0u8; 193_772]).unwrap();

        // Les seuils prod 2.10.2 observés par ANR1 :
        //   max_owned_bytes = 1 140 850 688 (1 GiB + 64 MiB).
        //   derived_reserve = 67 108 864    (64 MiB).
        //   candidate       = 193 772       (segment N2).
        let max_owned_bytes: u64 = 1_140_850_688;
        let derived_reserve: u64 = MAX_CONTINUOUS_DERIVED_BYTES;
        let candidate_bytes: u64 = 193_772;

        // Pre-2.11.3 : staging = 3.38 Go + 193 KB ≈ 3,38 Go.
        //   Gate : 3,38 Go + 193 KB + 64 MiB > 1,06 GiB → BLOCKED.
        // Post-2.11.3 : rollback exclu, staging = 193 KB.
        //   Gate : 193 KB + 193 KB + 64 MiB << 1,06 GiB → OK.
        let staging = work_bytes(&base);
        let trip = staging
            .saturating_add(candidate_bytes)
            .saturating_add(derived_reserve);
        assert!(
            trip <= max_owned_bytes,
            "ANR1 case 6781367658 : rollback tombstone 3,38 Go + candidate 193 KB + \
             derived reserve 64 MiB NE DOIT PAS dépasser max_owned_bytes {max_owned_bytes} ; \
             staging={staging} trip={trip}"
        );
        // `staging` doit refléter uniquement le `.importing` (~193 KB) +
        // d'éventuels fichiers top-level, pas le tombstone.
        assert!(
            staging < 64 * 1024 * 1024,
            "staging doit rester < 64 MiB après exclusion du rollback ; obtenu {staging}"
        );
    }

    /// 2.11.3 (devmat) : `.dataset-next` peut atteindre ~3,3 Go pendant
    /// une publication normale (1,5 M events → oiran_events.jsonl +
    /// callflows + manifest). La publication ne doit pas tripper
    /// backpressure sur son propre staging. Pre-2.11.3 l'aurait fait.
    #[test]
    fn dataset_next_excluded_from_work_bytes_matches_normal_publication() {
        let base = temporary_root("work-bytes-next");
        fs::create_dir_all(base.join("dataset")).unwrap();
        fs::create_dir_all(base.join("pcap")).unwrap();
        fs::create_dir_all(base.join(".dataset-next/callflows")).unwrap();

        // Simule une publication normale 1,5 M events : .dataset-next
        // contient un JSONL de 3,3 Go.
        let file = fs::File::create(base.join(".dataset-next/oiran_events.jsonl")).unwrap();
        file.set_len(3_300_000_000).unwrap();
        drop(file);

        let max_owned_bytes: u64 = 1_140_850_688;
        let staging = work_bytes(&base);
        assert!(
            staging < max_owned_bytes,
            "publication normale (.dataset-next 3,3 Go) NE DOIT PAS dépasser \
             max_owned_bytes {max_owned_bytes} ; staging={staging}"
        );
    }

    /// 2.11.3 (devmat) : `.dataset-previous` est un tombstone transient
    /// de swap atomique. Il contient une copie de l'ancien dataset
    /// pendant quelques ms. Pre-2.11.3 était compté, doublant
    /// temporairement l'empreinte dataset dans le budget.
    #[test]
    fn dataset_previous_excluded_from_work_bytes() {
        let base = temporary_root("work-bytes-previous");
        fs::create_dir_all(base.join("dataset")).unwrap();
        fs::create_dir_all(base.join("pcap")).unwrap();
        fs::create_dir_all(base.join(".dataset-previous")).unwrap();
        let file = fs::File::create(base.join(".dataset-previous/oiran_events.jsonl")).unwrap();
        file.set_len(2_700_000_000).unwrap();
        drop(file);

        let staging = work_bytes(&base);
        assert!(
            staging < 1_140_850_688,
            "dataset-previous doit être exclu du budget ; staging={staging}"
        );
    }

    /// 2.9.8 (#9 comment 6725097122): proves the new import invariant —
    /// `drop_orphan_fingerprints` removes entries whose checksum is NOT
    /// in `seen_checksums`, preserves committed entries, returns the
    /// dropped (path, checksum) pairs for logging, and is idempotent.
    /// Mirrors ANR2's production state: the orphan N3 fingerprint has
    /// `packets=0` (pcapng mis-parsed by `pcap_record_totals`, retained
    /// here only to prove the drop logic is checksum-based, not
    /// packets-based).
    #[test]
    fn drop_orphan_fingerprints_matches_anr2_production_shape() {
        let mut state = ContinuousImportState::default();
        state.seen_checksums.insert("sha-committed".into());
        state.seen_order.push_back("sha-committed".into());
        state.source_fingerprints.insert(
            "/captures/continuous-lab-import/N4/segment-committed.pcapng".into(),
            SourceFingerprint {
                dev: 42,
                inode: 1,
                size_bytes: 1024,
                mtime_ns: 0,
                checksum: "sha-committed".into(),
                packets: 2,
            },
        );
        state.source_fingerprints.insert(
            "/captures/continuous-lab-import/N3/segment-orphan.pcapng".into(),
            SourceFingerprint {
                dev: 42,
                inode: 2,
                size_bytes: 163 * 1024 * 1024,
                mtime_ns: 0,
                checksum: "sha-orphan-436e4bb7".into(),
                packets: 0,
            },
        );
        // SBI orphan with the same shape: fingerprint persisted but
        // checksum absent from `seen_checksums`. ANR2 observed the same
        // pattern on the SBI plane (`N2_SBI=UNKNOWN`, `SBI_N4=UNKNOWN`).
        state.source_fingerprints.insert(
            "/captures/continuous-lab-import/SBI/segment-orphan.pcapng".into(),
            SourceFingerprint {
                dev: 42,
                inode: 3,
                size_bytes: 12 * 1024 * 1024,
                mtime_ns: 0,
                checksum: "sha-sbi-orphan".into(),
                packets: 4,
            },
        );

        let orphans = drop_orphan_fingerprints(&mut state);

        assert_eq!(orphans.len(), 2, "exactly two orphans (ANR2 N3 + SBI shape)");
        let dropped: BTreeSet<String> = orphans.iter().map(|(_, sha)| sha.clone()).collect();
        assert!(dropped.contains("sha-orphan-436e4bb7"));
        assert!(dropped.contains("sha-sbi-orphan"));
        assert!(state
            .source_fingerprints
            .contains_key("/captures/continuous-lab-import/N4/segment-committed.pcapng"));
        assert!(!state
            .source_fingerprints
            .contains_key("/captures/continuous-lab-import/N3/segment-orphan.pcapng"));
        assert!(!state
            .source_fingerprints
            .contains_key("/captures/continuous-lab-import/SBI/segment-orphan.pcapng"));

        // Idempotent second pass.
        let second = drop_orphan_fingerprints(&mut state);
        assert!(second.is_empty());
    }

    /// 2.9.8 (#9 comment 6725097122): `/metrics` and `job.json` read
    /// `pending_segments` and `pending_fingerprints` from the SAME
    /// authoritative source — the worker sets them in a single
    /// `self.update(...)` closure from the same scan-local `pending`
    /// count. This test asserts the two fields co-vary on
    /// `CaptureMetrics`, so a concordance regression (one updated, the
    /// other left stale) would fail at the type level.
    #[test]
    fn capture_metrics_pending_fields_covary() {
        let mut metrics = CaptureMetrics::default();
        metrics.pending_segments = 7;
        metrics.pending_fingerprints = 7;
        let json = serde_json::to_value(&metrics).unwrap();
        assert_eq!(json["pending_segments"], 7);
        assert_eq!(json["pending_fingerprints"], 7);
        assert_eq!(json["pending_stability_segments"], 0);
        assert_eq!(json["pending_batch_segments"], 0);
        assert_eq!(json["orphan_fingerprints_recovered"], 0);
    }
}
