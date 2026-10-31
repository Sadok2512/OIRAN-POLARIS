//! Strictly owned, allowlisted live capture jobs for the OIRAN local vProbe.

use callflow_schema::{build_callflow, CallFlow, CorrelationEdge};
use capture_helper::{
    CaptureHelperClient, CaptureSpec, HelperState, InterfaceId, IpcRequest, MAX_CAPTURE_PLANES,
};
use correlation_engine::{correlate_cross_interface_evidence, correlate_discovered_tunnels};
use disk_safety::{assess, capture_budget, measure_path, CaptureBudget, Decision, Policy};
use event_schema::{
    sha256_hex, DecodeStatus, EvidenceReference, EvidenceState, InformationElement, NamedValue,
    NormalizedEvent, Protocol, Sha256Hasher,
};
use oiran_decode::{decode_capture_streaming, DecodeConfig, DecodeReport};
use serde::{Deserialize, Serialize};
use session_engine::{discover_sessions, load_path, reconstruct, Association, ReconstructionHints};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const VERSION: &str = "0.2.6";
/// Bounded read-chunk size for streaming file I/O; chosen so SHA-256 and pcap
/// record counting operate on ≤ 1 MiB in memory regardless of input file size.
const STREAM_CHUNK_BYTES: usize = 1 << 20;
const PROBE_ID: &str = "oiran-vprobe-local-01";
const MIN_CAPTURE_BYTES: u64 = 1024 * 1024;
const MAX_CONTINUOUS_EVENTS: usize = 50_000;
const MAX_N3_FLOW_AGGREGATES: usize = 4096;
const MAX_CONTINUOUS_DERIVED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SOURCE_CANDIDATES: usize = 512;
pub const DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_CONTINUOUS_SEEN: usize = 4096;
const ACTIVE_PACKET_WINDOW_MS: u64 = 60_000;
pub const CONTINUOUS_CAPTURE_ID: &str = "continuous-lab-import";
pub const CONTINUOUS_DATASET_ID: &str = "dataset-continuous-lab-import";
const HISTORICAL_N2_BOOTSTRAP_PATH: &str = "/var/lib/docker/volumes/oiran_lab_pcap/_data/n2/n2_20261026T121214Z_00001_20261026121214.pcapng";

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
}

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
/// The rule is: for each interface, drop the single newest candidate if
/// its mtime is more recent than `2 × stable_age`. Finalized files (older
/// than that window) are always eligible, even when they are the newest
/// for their interface — the next rotation simply did not happen yet.
pub fn finalized_candidates_only(
    mut candidates: Vec<FinalizationCandidate>,
    now: SystemTime,
    stable_age: Duration,
) -> Vec<FinalizationCandidate> {
    let safety_window = stable_age.saturating_mul(2);
    let mut newest_by_interface: BTreeMap<String, usize> = BTreeMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let is_newer = match newest_by_interface.get(&candidate.interface) {
            Some(&prev) => candidate.modified > candidates[prev].modified,
            None => true,
        };
        if is_newer {
            newest_by_interface.insert(candidate.interface.clone(), index);
        }
    }
    let active_indexes: BTreeSet<usize> = newest_by_interface
        .values()
        .copied()
        .filter(|index| {
            now.duration_since(candidates[*index].modified)
                .map(|age| age < safety_window)
                .unwrap_or(true)
        })
        .collect();
    let mut index = 0usize;
    candidates.retain(|_| {
        let keep = !active_indexes.contains(&index);
        index += 1;
        keep
    });
    candidates
}

/// Minimal shape consumed by `finalized_candidates_only`. Decoupled from
/// `SourceSegment` so the pure function can be unit-tested without reading
/// pcap bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizationCandidate {
    pub interface: String,
    pub modified: SystemTime,
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
}

impl CaptureManager {
    pub fn new(root: PathBuf, execution_enabled: bool) -> Result<Self, String> {
        let socket = std::env::var_os("OIRAN_CAPTURE_HELPER_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/run/oiran/capture-helper.sock"));
        let expected_uid = std::env::var("OIRAN_CAPTURE_HELPER_UID")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(107);
        Self::with_helper(
            root,
            execution_enabled,
            CaptureHelperClient::new(socket, expected_uid),
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
        )
    }

    pub fn with_helper_and_interface_root(
        root: PathBuf,
        execution_enabled: bool,
        helper: CaptureHelperClient,
        interface_root: PathBuf,
    ) -> Result<Self, String> {
        if !interface_root.is_absolute() {
            return Err("interface root must be absolute".into());
        }
        fs::create_dir_all(&root).map_err(display_error)?;
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
        let dataset = self.dataset(dataset_id)?;
        let dataset_root = if dataset.dataset_id.starts_with("derived-") {
            self.root
                .join("derived-datasets")
                .join(&dataset.dataset_id)
                .join("dataset")
        } else if dataset.dataset_id.starts_with("recovered-dataset-") {
            self.root
                .join("recovered-datasets")
                .join(&dataset.capture_id)
                .join("dataset")
        } else {
            self.root.join(&dataset.capture_id).join("dataset")
        };
        let path = dataset_root
            .join("callflows")
            .join(format!("{session_id}.json"));
        serde_json::from_slice(&fs::read(path).ok()?).ok()
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
            edges.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
            edges.dedup_by(|left, right| left.edge_id == right.edge_id);
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
        let recovered_dataset = self.dataset(CONTINUOUS_DATASET_ID);
        let mut observed = BTreeMap::<PathBuf, (u64, SystemTime)>::new();
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
                if native_owned_bytes > config.max_owned_bytes
                    || native_job_count > usize::from(config.max_segments)
                {
                    self.update(CONTINUOUS_CAPTURE_ID, |job| {
                        job.state = CaptureState::Blocked;
                        job.error = Some("CONTINUOUS_NATIVE_AGGREGATE_BUDGET".into());
                        job.stop_reason = Some("BOUNDED_STORAGE_FULL".into());
                        job.ended_epoch_ms = Some(epoch_ms());
                    })?;
                    return Ok(());
                }
                if terminal_native_captures.is_empty() {
                    match self.run_native_segment(config) {
                        Ok(capture_id) => terminal_native_captures.push(capture_id),
                        Err(error) => {
                            if error.contains("DISK_SAFETY") {
                                self.update(CONTINUOUS_CAPTURE_ID, |job| {
                                    job.state = CaptureState::Blocked;
                                    job.error = Some(error.clone());
                                    job.stop_reason = Some("DISK_SAFETY_POLICY".into());
                                    job.ended_epoch_ms = Some(epoch_ms());
                                })?;
                                return Ok(());
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
            let discovery = match source_segments(
                &config.source_root,
                config.stable_age,
                config.native_segment_seconds.is_some(),
                config.max_segment_bytes,
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
            let pending = candidates
                .iter()
                .filter(|candidate| !state.seen_checksums.contains(&candidate.checksum))
                .count() as u64;
            self.update(CONTINUOUS_CAPTURE_ID, |job| {
                job.metrics.pending_segments = pending
            })?;
            let mut pending_publication = std::mem::take(&mut bootstrap_pending);
            let mut changed = !pending_publication.is_empty();
            let prior_state = state.clone();
            let mut terminal_error = None;
            for candidate in candidates {
                if state.seen_checksums.contains(&candidate.checksum) {
                    continue;
                }
                let fingerprint = (candidate.size_bytes, candidate.modified);
                let stable_across_scans = observed.get(&candidate.path) == Some(&fingerprint);
                observed.insert(candidate.path.clone(), fingerprint);
                if config.native_segment_seconds.is_none() && !stable_across_scans {
                    continue;
                }
                if let Err(error) = decode_capture_streaming(
                    &DecodeConfig {
                        input: candidate.path.clone(),
                        capture_id: format!("sha256:{}", candidate.checksum),
                        interface: candidate.interface.clone(),
                        endpoints: endpoint_map(),
                    },
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
                while state.segments.len() >= usize::from(config.max_segments)
                    || directory_size(&base)
                        .saturating_add(candidate.size_bytes)
                        .saturating_add(MAX_CONTINUOUS_DERIVED_BYTES)
                        > config.max_owned_bytes
                {
                    let Some(oldest) = state
                        .segments
                        .iter()
                        .filter(|(_, item)| !item.historical_context)
                        .min_by_key(|(_, item)| item.imported_epoch_ms)
                        .map(|(checksum, item)| (checksum.clone(), item.clone()))
                    else {
                        break;
                    };
                    let owned = base.join("pcap").join(&oldest.1.owned_file);
                    if owned.is_file() {
                        fs::remove_file(&owned).map_err(display_error)?;
                    }
                    state.segments.remove(&oldest.0);
                }
                if state.segments.len() >= usize::from(config.max_segments)
                    || directory_size(&base)
                        .saturating_add(candidate.size_bytes)
                        .saturating_add(MAX_CONTINUOUS_DERIVED_BYTES)
                        > config.max_owned_bytes
                {
                    terminal_error = Some((
                        "CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT",
                        "BOUNDED_STORAGE_FULL",
                    ));
                    break;
                }
                let budget =
                    capture_budget(measure_path(&self.root), candidate.size_bytes, self.policy);
                if !budget.allowed {
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
            }
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
                self.update(CONTINUOUS_CAPTURE_ID, |job| {
                    job.state = CaptureState::Blocked;
                    job.error = Some(error.into());
                    job.stop_reason = Some(reason.into());
                    job.ended_epoch_ms = Some(epoch_ms());
                })?;
                return Ok(());
            }
            thread::sleep(config.scan_interval.min(Duration::from_secs(30)));
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

    fn process_continuous_capture(
        &self,
        base: &Path,
        interfaces: &[CaptureInterface],
        max_owned_bytes: u64,
    ) -> Result<LiveDataset, String> {
        let current = base.join("dataset");
        let next = base.join(".dataset-next");
        let previous = base.join(".dataset-previous");
        if previous.is_dir() && !current.is_dir() {
            fs::rename(&previous, &current).map_err(display_error)?;
        }
        if next.exists() {
            fs::remove_dir_all(&next).map_err(display_error)?;
        }
        if directory_size(base).saturating_add(MAX_CONTINUOUS_DERIVED_BYTES) > max_owned_bytes {
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
        if next_bytes > MAX_CONTINUOUS_DERIVED_BYTES {
            let _ = fs::remove_dir_all(&next);
            return Err("CONTINUOUS_DERIVED_OUTPUT_LIMIT".into());
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

    fn process_capture_into(
        &self,
        capture_id: &str,
        dataset_id: String,
        pcap_dir: &Path,
        dataset_dir: &Path,
        dataset_path: String,
        interfaces: &[CaptureInterface],
    ) -> Result<LiveDataset, String> {
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
                let mut individual_events = 0usize;
                let mut report = decode_capture_streaming(
                    &DecodeConfig {
                        input: path.clone(),
                        capture_id: capture_hash,
                        interface: interface.interface.clone(),
                        endpoints: endpoints.clone(),
                    },
                    |event| {
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
                if aggregate_n3 {
                    let aggregates = n3_aggregator.finish();
                    report.events = individual_events.saturating_add(aggregates.len());
                    for event in aggregates {
                        decoded_spool
                            .write_all(event.to_json().as_bytes())
                            .and_then(|_| decoded_spool.write_all(b"\n"))
                            .map_err(display_error)?;
                    }
                }
                let key = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("capture.pcap")
                    .to_string();
                checksums.insert(key.clone(), checksum);
                reports.insert(key, report);
            }
        }
        decoded_spool.flush().map_err(display_error)?;
        decoded_spool.get_ref().sync_all().map_err(display_error)?;
        drop(decoded_spool);
        if capture_id == CONTINUOUS_CAPTURE_ID {
            // Keep only IDs and offsets in memory. Normalized event JSON is
            // spooled on disk, so resident memory is independent of event body
            // size and of the number of events decoded from an input segment.
            let normalized_spool_path = dataset_dir.join(".normalized-events.spool");
            let normalized_spool_file = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&normalized_spool_path)
                .map_err(display_error)?;
            let mut normalized_writer = BufWriter::with_capacity(
                STREAM_CHUNK_BYTES,
                normalized_spool_file.try_clone().map_err(display_error)?,
            );
            let mut normalized_offset = 0u64;
            let mut indexed: BTreeMap<String, EventSpoolLocation> = BTreeMap::new();
            if let Some((prior_dir, _)) = &prior_continuous {
                let prior_events_file =
                    fs::File::open(prior_dir.join("oiran_events.jsonl")).map_err(display_error)?;
                let reader = BufReader::with_capacity(STREAM_CHUNK_BYTES, prior_events_file);
                index_event_stream(
                    reader,
                    &mut normalized_writer,
                    &mut normalized_offset,
                    &mut indexed,
                )?;
            }
            let decoded_reader = BufReader::with_capacity(
                STREAM_CHUNK_BYTES,
                fs::File::open(&decoded_spool_path).map_err(display_error)?,
            );
            index_event_stream(
                decoded_reader,
                &mut normalized_writer,
                &mut normalized_offset,
                &mut indexed,
            )?;
            normalized_writer.flush().map_err(display_error)?;
            normalized_writer
                .get_ref()
                .sync_all()
                .map_err(display_error)?;
            drop(normalized_writer);
            // Stream the output through BufWriter. We write to a tmp file next
            // to the destination, fsync, then atomic rename, matching the
            // existing `atomic_write` contract for bounded-memory callers.
            let tmp_path = events_path.with_extension("jsonl.tmp");
            {
                let tmp_file = fs::File::create(&tmp_path).map_err(display_error)?;
                let mut writer = BufWriter::with_capacity(STREAM_CHUNK_BYTES, tmp_file);
                let mut normalized_reader = normalized_spool_file;
                let mut line = Vec::new();
                for location in indexed.values() {
                    normalized_reader
                        .seek(SeekFrom::Start(location.offset))
                        .map_err(display_error)?;
                    line.resize(location.length as usize, 0);
                    normalized_reader
                        .read_exact(&mut line)
                        .map_err(display_error)?;
                    writer.write_all(&line).map_err(display_error)?;
                }
                writer.flush().map_err(display_error)?;
                writer.get_ref().sync_all().map_err(display_error)?;
            }
            fs::rename(&tmp_path, &events_path).map_err(display_error)?;
            fs::remove_file(&normalized_spool_path).map_err(display_error)?;
        } else {
            fs::rename(&decoded_spool_path, &events_path).map_err(display_error)?;
        }
        if decoded_spool_path.exists() {
            fs::remove_file(&decoded_spool_path).map_err(display_error)?;
        }
        let mut events = load_path(&events_path)?;
        // Materialise event-id set before taking a mutable borrow for
        // discover_sessions. The set is used later for the retained-event
        // provenance assertion. Taking owned Strings avoids holding an
        // immutable borrow of `events` across the `&mut events` call.
        let retained_event_ids: BTreeSet<String> =
            events.iter().map(|event| event.event_id.clone()).collect();
        let capture_job = self.get(capture_id);
        let capture_started_epoch_ms = capture_job.as_ref().and_then(|job| job.started_epoch_ms);
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
        let active_ue_ips = active_pdu_contexts
            .iter()
            .map(|context| context.ue_ip.clone())
            .collect::<Vec<_>>();
        let discovery = discover_sessions(&mut events);
        // Correlate over the complete retained evidence set before selecting
        // an individual session. Restricting correlation to the initial N2
        // session IDs made the exact N2→N4 edge impossible to discover and,
        // consequently, prevented the exact N4→N3 TEID edge from entering the
        // call flow even though all three observations were present.
        let mut global_edges = correlate_discovered_tunnels(&events, &discovery);
        global_edges.extend(correlate_cross_interface_evidence(&events));
        global_edges.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
        global_edges.dedup_by(|left, right| left.edge_id == right.edge_id);
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
            expand_session_evidence_ids(&mut ids, &global_edges);
            let selected = events
                .iter()
                .filter(|event| ids.contains(&event.event_id))
                .cloned()
                .collect::<Vec<_>>();
            let edges = global_edges
                .iter()
                .filter(|edge| {
                    ids.contains(&edge.source_event_id) && ids.contains(&edge.target_event_id)
                })
                .cloned()
                .collect::<Vec<_>>();
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
            let flow = build_callflow(&reconstruction, edges);
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
        for active in &active_pdu_contexts {
            let flow = runtime_pdu_callflow(&events, active);
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
                if !flow
                    .events
                    .iter()
                    .all(|event| retained_event_ids.contains(&event.event_id))
                {
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
        let dataset = LiveDataset {
            dataset_id,
            capture_id: capture_id.into(),
            path: dataset_path,
            event_count: events.len(),
            session_ids,
            decode_reports: reports,
            checksums,
            state: if events.is_empty() {
                "COMPLETED_EMPTY".into()
            } else if discovery.unmatched_event_ids.is_empty() {
                "COMPLETED".into()
            } else {
                "PARTIAL".into()
            },
            discovery: Some(discovery),
            capture_started_epoch_ms,
            last_packet_epoch_ms,
            fresh_packet_count,
            active_ue_ips,
            active_pdu_contexts,
        };
        atomic_write(
            &dataset_dir.join("dataset_manifest.json"),
            &serde_json::to_vec_pretty(&dataset).map_err(|error| error.to_string())?,
        )?;
        validate_dataset_artifacts(&dataset, dataset_dir)?;
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
    let events = load_path(&events_path)?;
    if events.len() != dataset.event_count {
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

fn interface_specs() -> Vec<CaptureInterface> {
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
}

fn source_segments(
    root: &Path,
    stable_age: Duration,
    native_only: bool,
    max_segment_bytes: u64,
) -> Result<SourceDiscovery, String> {
    let mut paths = Vec::new();
    collect_source_paths(root, 0, &mut paths)?;
    let now = SystemTime::now();
    let mut eligible: Vec<SourceCandidateMeta> = Vec::new();
    for path in paths {
        if native_only && !native_segment_source(root, &path) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(display_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() <= 24 {
            continue;
        }
        let Some(interface) = source_interface(root, &path) else {
            continue;
        };
        let modified = metadata.modified().map_err(display_error)?;
        if now.duration_since(modified).unwrap_or_default() < stable_age {
            continue;
        }
        eligible.push(SourceCandidateMeta {
            path,
            interface,
            size_bytes: metadata.len(),
            modified,
        });
    }
    eligible.sort_by(|left, right| {
        right
            .modified
            .cmp(&left.modified)
            .then_with(|| left.path.cmp(&right.path))
    });
    // Apply the "drop the still-live dumpcap target per interface" filter on
    // the cheap metadata projection BEFORE any file content is read. The
    // previous order (fs::read for every candidate, THEN filter) made the
    // worst-case transient RSS proportional to the candidate pool.
    let projections: Vec<FinalizationCandidate> = eligible
        .iter()
        .map(|candidate| FinalizationCandidate {
            interface: candidate.interface.clone(),
            modified: candidate.modified,
        })
        .collect();
    let kept = finalized_candidates_only(projections, now, stable_age);
    // Rebuild the kept subset positionally. We walk `eligible` and keep any
    // candidate whose (interface, modified) still appears in `kept`.
    let mut kept_lookup = kept
        .into_iter()
        .map(|p| (p.interface, p.modified))
        .collect::<Vec<_>>();
    let mut kept_meta: Vec<SourceCandidateMeta> = Vec::new();
    for candidate in eligible {
        if let Some(position) = kept_lookup
            .iter()
            .position(|(iface, m)| iface == &candidate.interface && *m == candidate.modified)
        {
            kept_lookup.swap_remove(position);
            kept_meta.push(candidate);
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
        if segments.len() >= MAX_SOURCE_CANDIDATES {
            continue;
        }
        let Ok(checksum) = sha256_hex_file(&candidate.path) else {
            continue;
        };
        let packets = count_pcap_records(&candidate.path);
        segments.push(SourceSegment {
            path: candidate.path,
            interface: candidate.interface,
            checksum,
            size_bytes: candidate.size_bytes,
            packets,
            modified: candidate.modified,
        });
    }
    segments.sort_by(|left, right| {
        right
            .modified
            .cmp(&left.modified)
            .then_with(|| left.checksum.cmp(&right.checksum))
    });
    rejected.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(SourceDiscovery { segments, rejected })
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
    while state.seen_order.len() > MAX_CONTINUOUS_SEEN {
        if let Some(oldest) = state.seen_order.pop_front() {
            state.seen_checksums.remove(&oldest);
        }
    }
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

#[derive(Clone, Copy, Debug)]
struct EventSpoolLocation {
    offset: u64,
    length: u64,
}

fn expand_session_evidence_ids(ids: &mut BTreeSet<String>, edges: &[CorrelationEdge]) {
    loop {
        let mut changed = false;
        for edge in edges {
            if ids.contains(&edge.source_event_id) {
                changed |= ids.insert(edge.target_event_id.clone());
            }
            if ids.contains(&edge.target_event_id) {
                changed |= ids.insert(edge.source_event_id.clone());
            }
        }
        if !changed {
            break;
        }
    }
}

fn index_event_stream<R: BufRead, W: Write>(
    mut reader: R,
    writer: &mut W,
    output_offset: &mut u64,
    indexed: &mut BTreeMap<String, EventSpoolLocation>,
) -> Result<(), String> {
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).map_err(display_error)? == 0 {
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        let mut value: serde_json::Value =
            serde_json::from_str(&line).map_err(|error| error.to_string())?;
        let id = continuous_observation_id(&value)?;
        value["event_id"] = serde_json::Value::String(id.clone());
        let serialized = serde_json::to_string(&value).map_err(|error| error.to_string())?;
        let bytes = serialized.as_bytes();
        let offset = *output_offset;
        writer.write_all(bytes).map_err(display_error)?;
        writer.write_all(b"\n").map_err(display_error)?;
        let length = (bytes.len() + 1) as u64;
        *output_offset = (*output_offset).saturating_add(length);
        indexed.insert(id, EventSpoolLocation { offset, length });
        // This is the same final retention policy as the previous post-pass
        // trim, but it never permits a transient one-million-line map.
        if indexed.len() > MAX_CONTINUOUS_EVENTS {
            if let Some(first) = indexed.keys().next().cloned() {
                indexed.remove(&first);
            }
        }
    }
    Ok(())
}

fn continuous_observation_id(value: &serde_json::Value) -> Result<String, String> {
    let stable_session_identifiers = value
        .get("session_identifiers")
        .and_then(serde_json::Value::as_array)
        .map(|identifiers| {
            identifiers
                .iter()
                .filter(|identifier| {
                    !identifier
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|name| name.ends_with("_event_id"))
                })
                .collect::<Vec<_>>()
        });
    let material = serde_json::to_vec(&serde_json::json!({
        "timestamp": value.get("timestamp"),
        "interface": value.get("interface"),
        "protocol": value.get("protocol"),
        "message_type": value.get("message_type"),
        "source_endpoint": value.get("source_endpoint"),
        "destination_endpoint": value.get("destination_endpoint"),
        "session_identifiers": stable_session_identifiers,
        "raw_payload_reference": value.get("raw_payload_reference"),
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

fn source_interface(root: &Path, path: &Path) -> Option<String> {
    path.strip_prefix(root)
        .ok()?
        .components()
        .find_map(|component| {
            let upper = component.as_os_str().to_str()?.to_ascii_uppercase();
            ["N2", "N3", "N4"]
                .into_iter()
                .find(|name| {
                    upper == *name
                        || upper.starts_with(&format!("{name}."))
                        || upper.starts_with(&format!("{name}_"))
                })
                .map(str::to_owned)
        })
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

fn count_pcap_records(path: &Path) -> u64 {
    pcap_record_totals(path).0
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
        };
        let edges = vec![
            edge("n2-n4", "n2-event", "n4-event"),
            edge("n4-n3", "n4-event", "n3-event"),
            edge("other", "other-a", "other-b"),
        ];
        let mut ids = BTreeSet::from(["n2-event".to_string()]);
        expand_session_evidence_ids(&mut ids, &edges);
        assert_eq!(
            ids,
            BTreeSet::from([
                "n2-event".to_string(),
                "n4-event".to_string(),
                "n3-event".to_string(),
            ])
        );
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
        let segments = source_segments(
            &root,
            Duration::ZERO,
            false,
            DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES,
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
        let manager = CaptureManager::new(root.clone(), false).unwrap();
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
        let manager = CaptureManager::new(root.clone(), false).unwrap();
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
        let rejected_size = fs::metadata(&rejected).unwrap().len();
        assert!(rejected_size > 100);
        assert!(fs::metadata(&accepted).unwrap().len() <= 100);
        thread::sleep(Duration::from_millis(500));
        let manager = CaptureManager::new(root.clone(), false).unwrap();
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
    /// filesystem is at or above the 85% utilisation threshold (disk-safety
    /// `StopNewCaptures` state). Tests that drive a real
    /// `start_continuous_import` therefore need the test host to be under
    /// that threshold; `TMPDIR` and `/tmp` sitting on a near-full `/` is a
    /// common operator laptop configuration (we saw 87% on this one). We
    /// skip-with-reason instead of silently timing out at the 30 s wait_for
    /// deadline, so the operator can distinguish an environmental skip from
    /// a code bug.
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
        let manager = CaptureManager::new(root.clone(), false).unwrap();
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

        let growing = source.join("N2/segment-0001.pcapng");
        let overlap = fs::read(&growing).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&growing)
            .unwrap()
            .write_all(&overlap)
            .unwrap();
        wait_for(|| {
            manager
                .get(CONTINUOUS_CAPTURE_ID)
                .is_some_and(|job| job.metrics.segments_ingested == 4)
        });
        assert_eq!(
            manager
                .get(CONTINUOUS_CAPTURE_ID)
                .unwrap()
                .metrics
                .decoded_events,
            first_event_count,
            "overlapping append snapshot must not duplicate prior events"
        );

        fs::copy(
            source.join("N2/segment-0001.pcapng"),
            source.join("N2/replayed-overlap.pcapng"),
        )
        .unwrap();
        thread::sleep(Duration::from_millis(600));
        assert_eq!(
            manager
                .get(CONTINUOUS_CAPTURE_ID)
                .unwrap()
                .metrics
                .segments_ingested,
            4
        );
        manager.stop(CONTINUOUS_CAPTURE_ID, "operator").unwrap();
        wait_for(|| {
            manager
                .get(CONTINUOUS_CAPTURE_ID)
                .is_some_and(|job| job.state == CaptureState::Completed)
        });
        drop(manager);

        let restarted = CaptureManager::new(root, false).unwrap();
        restarted.start_continuous_import(config).unwrap();
        wait_for(|| {
            restarted
                .get(CONTINUOUS_CAPTURE_ID)
                .is_some_and(|job| job.state == CaptureState::Capturing)
        });
        let recovered = restarted.get(CONTINUOUS_CAPTURE_ID).unwrap();
        assert_eq!(recovered.metrics.segments_ingested, 4);
        assert_eq!(recovered.session_ids, first.session_ids);
        restarted.stop(CONTINUOUS_CAPTURE_ID, "operator").unwrap();
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
        )
        .unwrap()
        .segments
        .is_empty());

        let root = temporary_root("continuous-quota");
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
        fs::copy(fixture.join("N2.pcapng"), source.join("N2/final-1.pcapng")).unwrap();
        fs::create_dir_all(source.join("N4")).unwrap();
        fs::copy(fixture.join("N4.pcapng"), source.join("N4/final-2.pcapng")).unwrap();
        thread::sleep(Duration::from_millis(250));
        let manager = CaptureManager::new(root, false).unwrap();
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
        assert_eq!(
            capture_files(&manager.root.join(CONTINUOUS_CAPTURE_ID).join("pcap")).len(),
            1
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
        let segments = source_segments(
            &source,
            Duration::ZERO,
            false,
            DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES,
        )
        .unwrap()
        .segments;
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].interface, "N2");
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
        let manager = CaptureManager::new(root, false).unwrap();
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

    #[test]
    fn continuous_checkpoint_keeps_five_sessions_across_restart_and_republish() {
        let root = temporary_root("continuous-five-session-checkpoint");
        let manager = CaptureManager::new(root.clone(), false).unwrap();
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
        let restarted = CaptureManager::new(root.clone(), false).unwrap();
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
        let manager = CaptureManager::new(root.clone(), false).unwrap();
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
        let manager = CaptureManager::new(root, false).unwrap();
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

            let expected = 11 + u64::from(rotation) * 3;
            wait_for(|| {
                manager
                    .get(CONTINUOUS_CAPTURE_ID)
                    .is_some_and(|job| job.metrics.segments_ingested == expected)
            });
            let dataset = manager.dataset(CONTINUOUS_DATASET_ID).unwrap();
            assert_eq!(dataset.active_pdu_contexts.len(), 3);
            assert_eq!(dataset.active_ue_ips.len(), 3);
            assert_eq!(
                capture_files(&manager.root.join(CONTINUOUS_CAPTURE_ID).join("pcap")).len(),
                8
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

    #[test]
    fn semantic_observation_id_survives_append_snapshot_capture_hash_changes() {
        let mut first = event_json(
            "first",
            "sha256:first",
            10_001,
            "GTP-U",
            "G-PDU",
            Some("10.46.0.4"),
        );
        let mut second = first.clone();
        second["capture_id"] = serde_json::Value::String("sha256:second".into());
        second["packet_references"][0]["source_file"] =
            serde_json::Value::String("rolled-N3.pcap".into());
        second["packet_references"][0]["packet_number"] = serde_json::Value::from(99);
        first["session_identifiers"] = serde_json::json!([
            {"name":"ran_ue_ngap_id","value":"4","pseudonymized":false},
            {"name":"parent_ngap_event_id","value":"evt-old","pseudonymized":false}
        ]);
        second["session_identifiers"] = serde_json::json!([
            {"name":"ran_ue_ngap_id","value":"4","pseudonymized":false},
            {"name":"parent_ngap_event_id","value":"evt-new","pseudonymized":false}
        ]);
        assert_eq!(
            continuous_observation_id(&first).unwrap(),
            continuous_observation_id(&second).unwrap()
        );
        first["timestamp"]["nanoseconds"] = serde_json::Value::from(2_000_000u64);
        assert_ne!(
            continuous_observation_id(&first).unwrap(),
            continuous_observation_id(&second).unwrap()
        );
    }

    #[test]
    fn persistent_seen_index_is_strictly_bounded() {
        let mut state = ContinuousImportState::default();
        for index in 0..(MAX_CONTINUOUS_SEEN + 17) {
            remember_checksum(&mut state, format!("checksum-{index:05}"));
        }
        assert_eq!(state.seen_checksums.len(), MAX_CONTINUOUS_SEEN);
        assert_eq!(state.seen_order.len(), MAX_CONTINUOUS_SEEN);
        assert!(!state.seen_checksums.contains("checksum-00000"));
        assert!(state.seen_checksums.contains("checksum-04112"));
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
        let manager = CaptureManager::new(root.clone(), false).unwrap();
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
        let manager = CaptureManager::new(temporary_root("interfaces"), false).unwrap();
        let interfaces = manager.interfaces();
        assert_eq!(interfaces.len(), 4);
        assert_eq!(
            interfaces
                .iter()
                .map(|item| item.interface.as_str())
                .collect::<Vec<_>>(),
            vec!["N2", "SBI", "N4", "N3"]
        );
        assert!(interfaces
            .iter()
            .all(|item| item.device.starts_with("br-oiran-")));
    }

    #[test]
    fn validation_rejects_custom_device_filter_and_unbounded_values() {
        let manager = CaptureManager::new(temporary_root("validation"), false).unwrap();
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
        let manager = CaptureManager::new(temporary_root("locked"), false).unwrap();
        assert!(manager
            .start(CaptureRequest::default(), "operator")
            .is_err());
        assert!(manager.list().is_empty());
    }

    #[test]
    fn stop_enforces_exact_owner_and_is_idempotent_after_completion() {
        let manager = CaptureManager::new(temporary_root("ownership"), false).unwrap();
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
        let manager = CaptureManager::new(root.clone(), false).unwrap();
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
        let manager = CaptureManager::new(root.clone(), false).unwrap();
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
        let manager = CaptureManager::new(root.clone(), false).unwrap();
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
        let manager = CaptureManager::new(root.clone(), false).unwrap();
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

        let recovered = CaptureManager::new(root, false).unwrap().get(id).unwrap();
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
        let manager = CaptureManager::new(root.clone(), false).unwrap();
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
        let manager = CaptureManager::new(root.clone(), false).unwrap();
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
        let manager = CaptureManager::new(root.clone(), false).unwrap();
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
        let manager = CaptureManager::new(root.clone(), false).unwrap();
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
        let manager = CaptureManager::new(root.clone(), false).unwrap();
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
        let manager = CaptureManager::new(root.clone(), false).unwrap();
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
        let recovered = CaptureManager::new(root, false).unwrap().get(id).unwrap();
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
        let manager = CaptureManager::new(root, false).unwrap();
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

        let manager = CaptureManager::new(root.clone(), false).unwrap();
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

    #[test]
    fn finalized_candidates_only_drops_the_still_live_dumpcap_target_per_interface() {
        let now = UNIX_EPOCH + Duration::from_secs(1_730_000_300);
        let stable_age = Duration::from_secs(10);
        let candidates = vec![
            // Finalized files per interface:
            FinalizationCandidate {
                interface: "N2".into(),
                modified: now - Duration::from_secs(120),
            },
            FinalizationCandidate {
                interface: "N3".into(),
                modified: now - Duration::from_secs(300),
            },
            // Still-live writer on N2 (newest, < 2 × stable_age ago):
            FinalizationCandidate {
                interface: "N2".into(),
                modified: now - Duration::from_secs(5),
            },
            // Still-live writer on N3 (newest, mtime inside the safety window):
            FinalizationCandidate {
                interface: "N3".into(),
                modified: now - Duration::from_secs(15),
            },
        ];
        let kept = finalized_candidates_only(candidates, now, stable_age);
        assert_eq!(kept.len(), 2);
        assert!(
            kept.iter()
                .all(|candidate| now.duration_since(candidate.modified).unwrap()
                    >= Duration::from_secs(60)),
            "the two newest-per-interface files were dropped as potentially active"
        );
    }

    #[test]
    fn finalized_candidates_only_keeps_the_single_file_when_safety_window_has_elapsed() {
        let now = UNIX_EPOCH + Duration::from_secs(2_000);
        let stable_age = Duration::from_secs(5);
        let old_enough = FinalizationCandidate {
            interface: "N2".into(),
            modified: now - Duration::from_secs(120),
        };
        // A single file older than 2 * stable_age is finalized — no newer
        // rotation observed, but mtime is well past the writer's cadence.
        let kept = finalized_candidates_only(vec![old_enough.clone()], now, stable_age);
        assert_eq!(kept, vec![old_enough]);
    }
}
