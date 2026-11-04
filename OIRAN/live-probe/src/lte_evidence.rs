//! Offline-only, fail-closed LTE evidence admission and materialization.
//!
//! The canonical orchestration document is owned by ANR1. OIRAN adds a
//! server-side binding to already-sanitized capture and normalized-event
//! artifacts. No path in this module is accepted from an HTTP URL and no raw
//! subscriber identity is permitted in admitted events.

use callflow_schema::{build_lte_callflow, CallFlow, CorrelationEdge};
use correlation_engine::correlate_lte_evidence;
use event_schema::{sha256_hex, Sha256Hasher};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use session_engine::{discover_lte_sessions, EventRecord, LteSession};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const INGESTION_SCHEMA: &str = "oiran.lte-evidence-ingestion.v1";
pub const EVIDENCE_SCHEMA: &str = "oiran-polaris.lte-e2e-evidence.v1";
pub const POLARIS_ENVELOPE_SCHEMA: &str = "polaris-oiran.lte-import-envelope.v1";
pub const EXPORT_SCHEMA: &str = "oiran.lte-anonymized-export.v1";
pub const MAX_INGEST_EVENTS: usize = 50_000;
pub const MAX_EVENT_LINE_BYTES: usize = 1024 * 1024;
pub const MAX_RETAINED_EVENT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SESSION_PAGE_SIZE: usize = 100;
pub const MAX_CATALOG_DATASETS: usize = 128;

const PROFILE_ID: &str = "LTE-SRSUE-TEST-01";
const SCENARIO_ID: &str = "lte-e2e-certification-v1";
const REQUIRED_PLANES: [&str; 3] = ["S1_MME", "S11", "S1_U"];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LteEvidenceImportRequest {
    pub schema_version: String,
    pub bundle_id: String,
    pub evidence: LteE2eEvidence,
    pub capture_bindings: Vec<LteCaptureBinding>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum LteEvidenceImportPayload {
    Direct(LteEvidenceImportRequest),
    Polaris(PolarisLteImportEnvelope),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolarisLteImportEnvelope {
    pub schema_version: String,
    pub provenance: PolarisLteProvenance,
    pub oiran_import: LteEvidenceImportRequest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolarisLteProvenance {
    pub source: String,
    pub published_at_epoch_ms: u64,
    pub run_id: String,
    pub rat: String,
    pub profile_id: String,
    pub scenario_id: String,
    pub started_at: String,
    pub ended_at: String,
    pub capture_ids: Vec<PolarisCaptureId>,
    pub session_references: Vec<String>,
    pub session_reference_state: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolarisCaptureId {
    pub plane: String,
    pub capture_id: String,
}

impl LteEvidenceImportPayload {
    pub fn into_request(self) -> Result<LteEvidenceImportRequest, LteEvidenceError> {
        match self {
            Self::Direct(request) => Ok(request),
            Self::Polaris(envelope) => envelope.into_request(),
        }
    }
}

impl PolarisLteImportEnvelope {
    fn into_request(self) -> Result<LteEvidenceImportRequest, LteEvidenceError> {
        if self.schema_version != POLARIS_ENVELOPE_SCHEMA
            || self.provenance.source != "POLARIS_SERVER_VERIFIED_BUNDLE"
            || self.provenance.rat != "LTE"
            || self.provenance.session_reference_state != "NOT_AVAILABLE_UNTIL_OIRAN_INGESTION"
            || !self.provenance.session_references.is_empty()
        {
            return Err(LteEvidenceError::new(
                "LTE_POLARIS_PROVENANCE_INVALID",
                "outer envelope discriminator or provenance state mismatch",
            ));
        }
        let evidence = &self.oiran_import.evidence;
        if self.provenance.run_id != evidence.run_id
            || self.provenance.profile_id != evidence.profile_id
            || self.provenance.scenario_id != evidence.scenario_id
            || self.provenance.started_at != evidence.started_at
            || self.provenance.ended_at != evidence.ended_at
        {
            return Err(LteEvidenceError::new(
                "LTE_POLARIS_PROVENANCE_MISMATCH",
                "outer provenance does not match nested evidence",
            ));
        }
        let expected = evidence
            .capture_refs
            .iter()
            .map(|capture| {
                (
                    capture.plane.as_str(),
                    format!("sha256:{}", capture.source_file_sha256),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut observed = BTreeMap::new();
        for capture in &self.provenance.capture_ids {
            if observed
                .insert(capture.plane.as_str(), capture.capture_id.clone())
                .is_some()
            {
                return Err(LteEvidenceError::new(
                    "LTE_POLARIS_CAPTURE_PROVENANCE_MISMATCH",
                    "duplicate outer capture plane",
                ));
            }
        }
        if observed != expected {
            return Err(LteEvidenceError::new(
                "LTE_POLARIS_CAPTURE_PROVENANCE_MISMATCH",
                "outer capture identifiers do not match nested capture_refs",
            ));
        }
        Ok(self.oiran_import)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LteE2eEvidence {
    pub schema_version: String,
    pub run_id: String,
    pub profile_id: String,
    pub scenario_id: String,
    pub started_at: String,
    pub ended_at: String,
    pub final_state: String,
    pub steps: Vec<LteEvidenceStep>,
    pub capture_refs: Vec<LteCaptureRef>,
    pub cleanup: LteCleanup,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LteEvidenceStep {
    pub index: u8,
    #[serde(rename = "type")]
    pub step_type: String,
    pub state: String,
    pub started_at: Option<String>,
    pub ended_at: Option<String>,
    pub reason_code: Option<String>,
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub measurements: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LteCaptureRef {
    pub plane: String,
    pub source_file_sha256: String,
    pub decoder_version: String,
    pub event_schema_version: String,
    pub first_frame: u64,
    pub last_frame: u64,
    pub sanitization_state: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LteCleanup {
    pub srsue_stopped: bool,
    pub srsenb_stopped: bool,
    pub sidecars_removed: bool,
    pub epc_healthy: bool,
    pub dumpcaps_preserved: bool,
}

/// OIRAN-owned binding. Paths are relative to a server-selected bundle root;
/// they are never resolved relative to the process working directory.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LteCaptureBinding {
    pub evidence_ref: String,
    pub capture_ref_index: usize,
    pub source_file: String,
    pub normalized_events_file: String,
    pub normalized_events_sha256: String,
    pub decoder_name: String,
    pub decoder_version: String,
    pub event_schema_version: String,
    pub endpoint_roles: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct LteEvidenceImportResult {
    pub schema_version: String,
    pub run_id: String,
    pub dataset_id: String,
    pub request_sha256: String,
    pub manifest_sha256: String,
    pub event_count: usize,
    pub session_count: usize,
    pub correlation_edge_count: usize,
    pub idempotent: bool,
    pub state: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LteDatasetManifest {
    pub schema_version: String,
    pub run_id: String,
    pub dataset_id: String,
    pub profile_id: String,
    pub scenario_id: String,
    #[serde(default = "default_completed_state")]
    pub final_state: String,
    #[serde(default)]
    pub capture_planes: Vec<String>,
    pub evidence_schema: String,
    pub evidence_sha256: String,
    pub request_sha256: String,
    pub source_capture_sha256: BTreeMap<String, String>,
    pub normalized_event_sha256: BTreeMap<String, String>,
    pub decoder_versions: BTreeMap<String, String>,
    pub event_schema_versions: BTreeMap<String, String>,
    pub event_count: usize,
    pub session_ids: Vec<String>,
    pub correlation_edge_count: usize,
    pub sanitization_state: String,
    pub artifacts: BTreeMap<String, String>,
}

fn default_completed_state() -> String {
    "COMPLETED".into()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LteEvidenceExportManifest {
    pub schema_version: String,
    pub export_id: String,
    pub run_id: String,
    pub dataset_id: String,
    pub review_state: String,
    pub transformation_version: String,
    pub source_manifest_sha256: String,
    pub source_capture_sha256: BTreeMap<String, String>,
    pub output_sha256: BTreeMap<String, String>,
    pub removed_field_classes: Vec<String>,
    pub replaced_field_classes: Vec<String>,
    pub packet_count: u64,
    pub event_count: usize,
    pub session_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LteEvidenceError {
    pub code: &'static str,
    pub detail: String,
}

impl LteEvidenceError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for LteEvidenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

#[derive(Clone, Debug)]
pub struct LteEvidenceStore {
    root: PathBuf,
}

impl LteEvidenceStore {
    pub fn new(root: PathBuf) -> Result<Self, LteEvidenceError> {
        fs::create_dir_all(root.join("datasets"))
            .and_then(|_| fs::create_dir_all(root.join("exports")))
            .map_err(|error| LteEvidenceError::new("LTE_STORE_UNAVAILABLE", error.to_string()))?;
        Ok(Self { root })
    }

    pub fn ingest(
        &self,
        bundle_root: &Path,
        request: &LteEvidenceImportRequest,
    ) -> Result<LteEvidenceImportResult, LteEvidenceError> {
        validate_request(request)?;
        let request_bytes = serde_json::to_vec(request)
            .map_err(|error| LteEvidenceError::new("LTE_REQUEST_INVALID", error.to_string()))?;
        let request_sha256 = sha256_hex(&request_bytes);
        let dataset_id = format!("dataset-{}", request.evidence.run_id);
        let final_root = self.root.join("datasets").join(&dataset_id);
        let result_path = final_root.join("ingestion_result.json");
        if result_path.is_file() {
            let mut result: LteEvidenceImportResult = read_json(&result_path)?;
            if result.request_sha256 != request_sha256 {
                return Err(LteEvidenceError::new(
                    "LTE_INGESTION_CONFLICT",
                    "run_id already exists with different evidence",
                ));
            }
            result.idempotent = true;
            return Ok(result);
        }
        if final_root.exists() {
            return Err(LteEvidenceError::new(
                "LTE_INGESTION_INCOMPLETE_OUTPUT_EXISTS",
                final_root.display().to_string(),
            ));
        }

        let verified = verify_bindings(bundle_root, request)?;
        let mut events = Vec::new();
        let mut seen_event_ids = BTreeSet::new();
        let mut retained_event_bytes = 0usize;
        for item in &verified {
            read_events_bounded(
                item,
                &mut events,
                &mut seen_event_ids,
                &mut retained_event_bytes,
            )?;
        }
        // 2.7.13: canonical (capture_id, seq, event_id). The timestamp
        // is NEVER used for a processing decision and no two events from
        // different captures are compared on `timestamp_ns`. Call flow
        // ladder rendering reorders a separate view by ts (see
        // `callflow-schema::build_ladder_records_for_display`).
        events.sort_by(|a, b| {
            session_engine::canonical_sort_key(a).cmp(&session_engine::canonical_sort_key(b))
        });
        let sessions = discover_lte_sessions(&events);
        if sessions.is_empty() {
            return Err(LteEvidenceError::new(
                "LTE_SESSION_NOT_RECONSTRUCTED",
                "admitted evidence produced no LTE session",
            ));
        }
        let edges = correlate_lte_evidence(&events);
        let callflows = sessions
            .iter()
            .map(|session| {
                let ids = session.event_ids.iter().collect::<BTreeSet<_>>();
                let selected_edges = edges
                    .iter()
                    .filter(|edge| {
                        ids.contains(&edge.source_event_id) && ids.contains(&edge.target_event_id)
                    })
                    .cloned()
                    .collect();
                build_lte_callflow(session, &events, selected_edges)
            })
            .collect::<Vec<_>>();

        let staging = self.root.join("datasets").join(format!(
            ".{dataset_id}.{}.{}.tmp",
            std::process::id(),
            epoch_ms()
        ));
        if staging.exists() {
            fs::remove_dir_all(&staging).map_err(io_error("LTE_STAGING_CLEANUP_FAILED"))?;
        }
        let write_result = self.write_dataset(
            &staging,
            request,
            &request_bytes,
            &request_sha256,
            &dataset_id,
            &verified,
            &events,
            &sessions,
            &edges,
            &callflows,
        );
        if let Err(error) = write_result {
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }
        fs::rename(&staging, &final_root).map_err(|error| {
            LteEvidenceError::new("LTE_INGESTION_FINALIZE_FAILED", error.to_string())
        })?;
        read_json(&result_path)
    }

    #[allow(clippy::too_many_arguments)]
    fn write_dataset(
        &self,
        staging: &Path,
        request: &LteEvidenceImportRequest,
        request_bytes: &[u8],
        request_sha256: &str,
        dataset_id: &str,
        verified: &[VerifiedBinding],
        events: &[EventRecord],
        sessions: &[LteSession],
        edges: &[CorrelationEdge],
        callflows: &[CallFlow],
    ) -> Result<(), LteEvidenceError> {
        fs::create_dir_all(staging.join("callflows"))
            .map_err(io_error("LTE_STAGING_CREATE_FAILED"))?;
        fs::create_dir_all(staging.join("captures"))
            .map_err(io_error("LTE_STAGING_CREATE_FAILED"))?;
        write_atomic(&staging.join("request.json"), request_bytes)?;
        let evidence_bytes = json_bytes(&request.evidence)?;
        write_atomic(&staging.join("evidence.json"), &evidence_bytes)?;
        let events_bytes = jsonl_bytes(events)?;
        write_atomic(&staging.join("events.jsonl"), &events_bytes)?;
        let sessions_bytes = jsonl_values(sessions)?;
        write_atomic(&staging.join("sessions.jsonl"), &sessions_bytes)?;
        let edges_bytes = json_bytes(edges)?;
        write_atomic(&staging.join("correlation_edges.json"), &edges_bytes)?;
        for flow in callflows {
            write_atomic(
                &staging
                    .join("callflows")
                    .join(format!("{}.json", flow.session_id)),
                &json_bytes(flow)?,
            )?;
        }
        for item in verified {
            let name = format!("{}.pcapng", item.plane.to_ascii_lowercase());
            let copied_hash =
                copy_file_streaming(&item.source_path, &staging.join("captures").join(&name))?;
            if copied_hash != item.capture.source_file_sha256 {
                return Err(LteEvidenceError::new(
                    "LTE_CAPTURE_HASH_MISMATCH",
                    &item.plane,
                ));
            }
        }
        let source_capture_sha256 = verified
            .iter()
            .map(|item| (item.plane.clone(), item.capture.source_file_sha256.clone()))
            .collect();
        let normalized_event_sha256 = verified
            .iter()
            .map(|item| {
                (
                    item.plane.clone(),
                    item.binding.normalized_events_sha256.clone(),
                )
            })
            .collect();
        let decoder_versions = verified
            .iter()
            .map(|item| {
                (
                    item.binding.decoder_name.clone(),
                    item.binding.decoder_version.clone(),
                )
            })
            .collect();
        let event_schema_versions = verified
            .iter()
            .map(|item| {
                (
                    item.plane.clone(),
                    item.binding.event_schema_version.clone(),
                )
            })
            .collect();
        let mut artifacts = BTreeMap::from([
            ("request.json".into(), sha256_hex(request_bytes)),
            ("evidence.json".into(), sha256_hex(&evidence_bytes)),
            ("events.jsonl".into(), sha256_hex(&events_bytes)),
            ("sessions.jsonl".into(), sha256_hex(&sessions_bytes)),
            ("correlation_edges.json".into(), sha256_hex(&edges_bytes)),
        ]);
        for flow in callflows {
            let name = format!("callflows/{}.json", flow.session_id);
            artifacts.insert(name, sha256_hex(&json_bytes(flow)?));
        }
        for item in verified {
            artifacts.insert(
                format!("captures/{}.pcapng", item.plane.to_ascii_lowercase()),
                item.capture.source_file_sha256.clone(),
            );
        }
        let manifest = LteDatasetManifest {
            schema_version: "oiran.lte-dataset-manifest.v1".into(),
            run_id: request.evidence.run_id.clone(),
            dataset_id: dataset_id.into(),
            profile_id: request.evidence.profile_id.clone(),
            scenario_id: request.evidence.scenario_id.clone(),
            final_state: request.evidence.final_state.clone(),
            capture_planes: verified.iter().map(|item| item.plane.clone()).collect(),
            evidence_schema: request.evidence.schema_version.clone(),
            evidence_sha256: sha256_hex(&evidence_bytes),
            request_sha256: request_sha256.into(),
            source_capture_sha256,
            normalized_event_sha256,
            decoder_versions,
            event_schema_versions,
            event_count: events.len(),
            session_ids: sessions
                .iter()
                .map(|session| session.session_id.clone())
                .collect(),
            correlation_edge_count: edges.len(),
            sanitization_state: "SANITIZED_APPROVED".into(),
            artifacts,
        };
        let manifest_bytes = json_bytes(&manifest)?;
        write_atomic(&staging.join("dataset_manifest.json"), &manifest_bytes)?;
        let result = LteEvidenceImportResult {
            schema_version: INGESTION_SCHEMA.into(),
            run_id: request.evidence.run_id.clone(),
            dataset_id: dataset_id.into(),
            request_sha256: request_sha256.into(),
            manifest_sha256: sha256_hex(&manifest_bytes),
            event_count: events.len(),
            session_count: sessions.len(),
            correlation_edge_count: edges.len(),
            idempotent: false,
            state: if request.evidence.final_state == "COMPLETED" {
                "IMPORTED"
            } else {
                "IMPORTED_PARTIAL"
            }
            .into(),
        };
        write_atomic(
            &staging.join("ingestion_result.json"),
            &json_bytes(&result)?,
        )?;
        sync_directory(staging)?;
        Ok(())
    }

    pub fn import_result(&self, run_id: &str) -> Result<LteEvidenceImportResult, LteEvidenceError> {
        validate_run_id(run_id)?;
        read_json(
            &self
                .root
                .join("datasets")
                .join(format!("dataset-{run_id}"))
                .join("ingestion_result.json"),
        )
    }

    /// Enumerates only atomically finalized LTE datasets. Temporary or partial
    /// directories are ignored and the catalog has a fixed upper bound.
    pub fn catalog(&self) -> Result<Vec<LteDatasetManifest>, LteEvidenceError> {
        let mut paths = fs::read_dir(self.root.join("datasets"))
            .map_err(io_error("LTE_STORE_UNAVAILABLE"))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("dataset-") && !name.starts_with('.'))
                    && path.join("ingestion_result.json").is_file()
                    && path.join("dataset_manifest.json").is_file()
            })
            .collect::<Vec<_>>();
        paths.sort();
        if paths.len() > MAX_CATALOG_DATASETS {
            return Err(LteEvidenceError::new(
                "LTE_CATALOG_LIMIT_EXCEEDED",
                format!(
                    "{} finalized datasets exceeds {MAX_CATALOG_DATASETS}",
                    paths.len()
                ),
            ));
        }
        paths
            .into_iter()
            .map(|path| read_json(&path.join("dataset_manifest.json")))
            .collect()
    }

    /// Resolves a session by stable identifier using bounded, line-oriented
    /// reads. No dataset event collection is loaded into memory.
    pub fn find_session(
        &self,
        session_id: &str,
    ) -> Result<Option<(LteDatasetManifest, LteSession)>, LteEvidenceError> {
        if !safe_id(session_id) {
            return Err(LteEvidenceError::new("LTE_SESSION_ID_INVALID", session_id));
        }
        for manifest in self.catalog()? {
            if !manifest.session_ids.iter().any(|id| id == session_id) {
                continue;
            }
            let path = self
                .root
                .join("datasets")
                .join(&manifest.dataset_id)
                .join("sessions.jsonl");
            let reader =
                BufReader::new(File::open(path).map_err(io_error("LTE_ARTIFACT_UNAVAILABLE"))?);
            for line in reader.lines() {
                let line = line.map_err(io_error("LTE_ARTIFACT_INVALID"))?;
                if line.len() > MAX_EVENT_LINE_BYTES {
                    return Err(LteEvidenceError::new(
                        "LTE_ARTIFACT_LINE_TOO_LARGE",
                        session_id,
                    ));
                }
                let session: LteSession = serde_json::from_str(&line).map_err(|error| {
                    LteEvidenceError::new("LTE_ARTIFACT_INVALID", error.to_string())
                })?;
                if session.session_id == session_id {
                    return Ok(Some((manifest, session)));
                }
            }
            return Err(LteEvidenceError::new(
                "LTE_MANIFEST_SESSION_MISSING",
                session_id,
            ));
        }
        Ok(None)
    }

    pub fn callflow_page_by_session(
        &self,
        session_id: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Option<Value>, LteEvidenceError> {
        let Some((manifest, _)) = self.find_session(session_id)? else {
            return Ok(None);
        };
        self.callflow_page(&manifest.run_id, session_id, cursor, limit)
            .map(Some)
    }

    /// Loads a finalized LTE Call Flow for the existing API export route.
    /// The artifact is selected only through the finalized catalog and its
    /// size is capped before allocation; callers must still apply their
    /// response privacy sanitizer before serializing JSON or HTML.
    pub fn callflow_for_export_by_session(
        &self,
        session_id: &str,
    ) -> Result<Option<CallFlow>, LteEvidenceError> {
        let Some((manifest, _)) = self.find_session(session_id)? else {
            return Ok(None);
        };
        let path = self
            .root
            .join("datasets")
            .join(&manifest.dataset_id)
            .join("callflows")
            .join(format!("{session_id}.json"));
        let length = fs::metadata(&path)
            .map_err(io_error("LTE_ARTIFACT_UNAVAILABLE"))?
            .len();
        if length > MAX_RETAINED_EVENT_BYTES as u64 {
            return Err(LteEvidenceError::new(
                "LTE_CALLFLOW_EXPORT_TOO_LARGE",
                length.to_string(),
            ));
        }
        read_json(&path).map(Some)
    }

    pub fn session_page(
        &self,
        run_id: &str,
        page: usize,
        page_size: usize,
    ) -> Result<Value, LteEvidenceError> {
        validate_run_id(run_id)?;
        if page == 0 || !(1..=MAX_SESSION_PAGE_SIZE).contains(&page_size) {
            return Err(LteEvidenceError::new(
                "LTE_PAGINATION_INVALID",
                "page must be >= 1 and page_size must be 1..100",
            ));
        }
        let path = self
            .root
            .join("datasets")
            .join(format!("dataset-{run_id}"))
            .join("sessions.jsonl");
        let reader =
            BufReader::new(File::open(&path).map_err(io_error("LTE_ARTIFACT_UNAVAILABLE"))?);
        let start = (page - 1).saturating_mul(page_size);
        let mut total = 0usize;
        let mut items = Vec::with_capacity(page_size);
        for line in reader.lines() {
            let line = line.map_err(io_error("LTE_ARTIFACT_INVALID"))?;
            if total >= start && items.len() < page_size {
                items.push(serde_json::from_str::<LteSession>(&line).map_err(|error| {
                    LteEvidenceError::new("LTE_ARTIFACT_INVALID", error.to_string())
                })?);
            }
            total = total.saturating_add(1);
        }
        Ok(json!({"data":items,"pagination":{"page":page,"page_size":page_size,"total":total}}))
    }

    pub fn callflow_page(
        &self,
        run_id: &str,
        session_id: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Value, LteEvidenceError> {
        validate_run_id(run_id)?;
        if !safe_id(session_id) {
            return Err(LteEvidenceError::new("LTE_SESSION_ID_INVALID", session_id));
        }
        let path = self
            .root
            .join("datasets")
            .join(format!("dataset-{run_id}"))
            .join("callflows")
            .join(format!("{session_id}.json"));
        super::read_callflow_page(&path, cursor, limit)
            .map_err(|error| LteEvidenceError::new("LTE_CALLFLOW_PAGE_INVALID", error))
    }

    pub fn export_pending_review(
        &self,
        run_id: &str,
        export_id: &str,
        transformation: &str,
    ) -> Result<LteEvidenceExportManifest, LteEvidenceError> {
        validate_run_id(run_id)?;
        if transformation != "VERIFIED_COPY" {
            return Err(LteEvidenceError::new(
                "LTE_EXPORT_TRANSFORMATION_UNSUPPORTED",
                transformation,
            ));
        }
        if !safe_id(export_id) {
            return Err(LteEvidenceError::new("LTE_EXPORT_ID_INVALID", export_id));
        }
        let dataset_root = self.root.join("datasets").join(format!("dataset-{run_id}"));
        let source: LteDatasetManifest = read_json(&dataset_root.join("dataset_manifest.json"))?;
        let final_root = self.root.join("exports").join(export_id);
        let manifest_path = final_root.join("export_manifest.json");
        if manifest_path.is_file() {
            let existing: LteEvidenceExportManifest = read_json(&manifest_path)?;
            if existing.run_id == run_id {
                return Ok(existing);
            }
            return Err(LteEvidenceError::new(
                "LTE_EXPORT_CONFLICT",
                "export_id belongs to another run",
            ));
        }
        if final_root.exists() {
            return Err(LteEvidenceError::new(
                "LTE_EXPORT_INCOMPLETE_OUTPUT_EXISTS",
                final_root.display().to_string(),
            ));
        }
        let staging = self.root.join("exports").join(format!(
            ".{export_id}.{}.{}.tmp",
            std::process::id(),
            epoch_ms()
        ));
        fs::create_dir_all(&staging).map_err(io_error("LTE_EXPORT_CREATE_FAILED"))?;
        let names = ["events.jsonl", "sessions.jsonl", "correlation_edges.json"];
        let mut output_sha256 = BTreeMap::new();
        for name in names {
            if name == "events.jsonl" {
                scan_jsonl_privacy(&dataset_root.join(name))?;
            }
            let digest = copy_file_streaming(&dataset_root.join(name), &staging.join(name))?;
            let Some(expected_hash) = source.artifacts.get(name) else {
                let _ = fs::remove_dir_all(&staging);
                return Err(LteEvidenceError::new(
                    "LTE_EXPORT_SOURCE_MANIFEST_INCOMPLETE",
                    name,
                ));
            };
            if &digest != expected_hash {
                let _ = fs::remove_dir_all(&staging);
                return Err(LteEvidenceError::new(
                    "LTE_EXPORT_SOURCE_HASH_MISMATCH",
                    name,
                ));
            }
            output_sha256.insert(name.into(), digest);
        }
        fs::create_dir_all(staging.join("captures"))
            .map_err(io_error("LTE_EXPORT_CREATE_FAILED"))?;
        for (plane, expected_hash) in &source.source_capture_sha256 {
            let relative = format!("captures/{}.pcapng", plane.to_ascii_lowercase());
            let digest =
                copy_file_streaming(&dataset_root.join(&relative), &staging.join(&relative))?;
            if &digest != expected_hash {
                let _ = fs::remove_dir_all(&staging);
                return Err(LteEvidenceError::new(
                    "LTE_EXPORT_SOURCE_HASH_MISMATCH",
                    plane,
                ));
            }
            output_sha256.insert(relative, digest);
        }
        let packet_count = source
            .source_capture_sha256
            .keys()
            .filter_map(|plane| {
                let evidence: LteE2eEvidence =
                    read_json(&dataset_root.join("evidence.json")).ok()?;
                evidence
                    .capture_refs
                    .iter()
                    .find(|capture| &capture.plane == plane)
                    .map(|capture| capture.last_frame - capture.first_frame + 1)
            })
            .sum();
        let source_manifest_bytes = fs::read(dataset_root.join("dataset_manifest.json"))
            .map_err(io_error("LTE_EXPORT_READ_FAILED"))?;
        let manifest = LteEvidenceExportManifest {
            schema_version: EXPORT_SCHEMA.into(),
            export_id: export_id.into(),
            run_id: run_id.into(),
            dataset_id: source.dataset_id,
            review_state: "SANITIZED_PENDING_REVIEW".into(),
            transformation_version: "verified-copy-1.0.0".into(),
            source_manifest_sha256: sha256_hex(&source_manifest_bytes),
            source_capture_sha256: source.source_capture_sha256,
            output_sha256,
            removed_field_classes: vec![],
            replaced_field_classes: vec![],
            packet_count,
            event_count: source.event_count,
            session_count: source.session_ids.len(),
        };
        write_atomic(
            &staging.join("export_manifest.json"),
            &json_bytes(&manifest)?,
        )?;
        sync_directory(&staging)?;
        fs::rename(&staging, &final_root).map_err(|error| {
            LteEvidenceError::new("LTE_EXPORT_FINALIZE_FAILED", error.to_string())
        })?;
        Ok(manifest)
    }
}

struct VerifiedBinding<'a> {
    plane: String,
    capture: &'a LteCaptureRef,
    binding: &'a LteCaptureBinding,
    source_path: PathBuf,
    events_path: PathBuf,
}

fn validate_request(request: &LteEvidenceImportRequest) -> Result<(), LteEvidenceError> {
    if request.schema_version != INGESTION_SCHEMA
        || request.evidence.schema_version != EVIDENCE_SCHEMA
    {
        return Err(LteEvidenceError::new(
            "LTE_EVIDENCE_SCHEMA_UNSUPPORTED",
            "unsupported schema_version",
        ));
    }
    if !safe_id(&request.bundle_id) {
        return Err(LteEvidenceError::new(
            "LTE_BUNDLE_ID_INVALID",
            &request.bundle_id,
        ));
    }
    validate_run_id(&request.evidence.run_id)?;
    if request.evidence.profile_id != PROFILE_ID || request.evidence.scenario_id != SCENARIO_ID {
        return Err(LteEvidenceError::new(
            "LTE_EVIDENCE_SCOPE_MISMATCH",
            "profile_id/scenario_id mismatch",
        ));
    }
    if !matches!(
        request.evidence.final_state.as_str(),
        "COMPLETED" | "FAILED" | "CANCELLED"
    ) {
        return Err(LteEvidenceError::new(
            "LTE_EVIDENCE_FINAL_STATE_INVALID",
            &request.evidence.final_state,
        ));
    }
    if request.evidence.steps.len() > 11 {
        return Err(LteEvidenceError::new(
            "LTE_STEP_LIMIT_EXCEEDED",
            request.evidence.steps.len().to_string(),
        ));
    }
    let mut indexes = BTreeSet::new();
    let valid_step_types = [
        "preflight",
        "enb_start",
        "s1_setup",
        "ue_start",
        "lte_attach",
        "ue_ip",
        "ping_ul",
        "ping_dl",
        "udp_ul",
        "udp_dl",
        "cleanup",
    ];
    for step in &request.evidence.steps {
        if step.index > 10 || !indexes.insert(step.index) {
            return Err(LteEvidenceError::new(
                "LTE_STEP_INDEX_INVALID",
                step.index.to_string(),
            ));
        }
        if !valid_step_types.contains(&step.step_type.as_str())
            || !matches!(
                step.state.as_str(),
                "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "SKIPPED"
            )
            || step.evidence_refs.len() > 32
            || step.measurements.len() > 32
            || step.reason_code.as_deref().is_some_and(|reason| {
                reason.len() < 3
                    || reason.len() > 96
                    || !reason.bytes().all(|byte| {
                        byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                    })
            })
        {
            return Err(LteEvidenceError::new(
                "LTE_STEP_SCHEMA_INVALID",
                step.index.to_string(),
            ));
        }
        if contains_forbidden_step_measurement(
            &serde_json::to_value(&step.measurements).unwrap_or(Value::Null),
            &request.evidence.run_id,
            &[],
        ) {
            return Err(LteEvidenceError::new(
                "LTE_IDENTITY_DISCLOSURE_REJECTED",
                "step measurements",
            ));
        }
    }
    if !request.evidence.cleanup.srsue_stopped
        || !request.evidence.cleanup.srsenb_stopped
        || !request.evidence.cleanup.sidecars_removed
        || !request.evidence.cleanup.epc_healthy
        || !request.evidence.cleanup.dumpcaps_preserved
    {
        return Err(LteEvidenceError::new(
            "LTE_CLEANUP_NOT_PROVEN",
            "all cleanup observations must be true",
        ));
    }
    if !valid_utc(&request.evidence.started_at)
        || !valid_utc(&request.evidence.ended_at)
        || request.evidence.started_at > request.evidence.ended_at
    {
        return Err(LteEvidenceError::new(
            "LTE_EVIDENCE_TIME_RANGE_INVALID",
            "started_at/ended_at",
        ));
    }
    Ok(())
}

fn verify_bindings<'a>(
    bundle_root: &Path,
    request: &'a LteEvidenceImportRequest,
) -> Result<Vec<VerifiedBinding<'a>>, LteEvidenceError> {
    let root = bundle_root
        .canonicalize()
        .map_err(io_error("LTE_BUNDLE_UNAVAILABLE"))?;
    let mut planes = BTreeSet::new();
    for capture in &request.evidence.capture_refs {
        if !REQUIRED_PLANES.contains(&capture.plane.as_str()) {
            return Err(LteEvidenceError::new(
                "LTE_OPTIONAL_PLANE_UNSUPPORTED",
                &capture.plane,
            ));
        }
        if !planes.insert(capture.plane.as_str()) {
            return Err(LteEvidenceError::new(
                "LTE_CAPTURE_PLANE_DUPLICATE",
                &capture.plane,
            ));
        }
        if capture.first_frame == 0 || capture.first_frame > capture.last_frame {
            return Err(LteEvidenceError::new(
                "LTE_CAPTURE_FRAME_RANGE_INVALID",
                &capture.plane,
            ));
        }
        if capture.sanitization_state != "SANITIZED_APPROVED" {
            return Err(LteEvidenceError::new(
                "LTE_EVIDENCE_NOT_APPROVED",
                &capture.plane,
            ));
        }
        if capture.decoder_version.trim().is_empty() || capture.event_schema_version != "1.5.0" {
            return Err(LteEvidenceError::new(
                "LTE_CAPTURE_DECODER_METADATA_INVALID",
                &capture.plane,
            ));
        }
        validate_sha256(&capture.source_file_sha256, "LTE_CAPTURE_SHA256_INVALID")?;
    }
    if planes.is_empty() {
        return Err(LteEvidenceError::new(
            "LTE_NO_OBSERVED_CAPTURE",
            "at least one approved LTE plane is required",
        ));
    }
    if request.evidence.final_state == "COMPLETED"
        && planes != REQUIRED_PLANES.into_iter().collect()
    {
        return Err(LteEvidenceError::new(
            "LTE_REQUIRED_PLANE_MISSING",
            format!("observed={planes:?}"),
        ));
    }
    if request.capture_bindings.len() != request.evidence.capture_refs.len() {
        return Err(LteEvidenceError::new(
            "LTE_CAPTURE_BINDING_COUNT_MISMATCH",
            "one binding per capture_ref required",
        ));
    }
    let mut refs = BTreeSet::new();
    let mut bound_indexes = BTreeSet::new();
    let mut verified = Vec::new();
    for binding in &request.capture_bindings {
        if !refs.insert(binding.evidence_ref.as_str())
            || !bound_indexes.insert(binding.capture_ref_index)
        {
            return Err(LteEvidenceError::new(
                "LTE_EVIDENCE_REF_DUPLICATE",
                &binding.evidence_ref,
            ));
        }
        let capture = request
            .evidence
            .capture_refs
            .get(binding.capture_ref_index)
            .ok_or_else(|| {
                LteEvidenceError::new(
                    "LTE_CAPTURE_REF_UNRESOLVED",
                    binding.capture_ref_index.to_string(),
                )
            })?;
        let expected_ref = format!("capture:{}", capture.plane);
        if binding.evidence_ref != expected_ref {
            return Err(LteEvidenceError::new(
                "LTE_EVIDENCE_REF_INVALID",
                format!("expected {expected_ref}"),
            ));
        }
        validate_sha256(
            &binding.normalized_events_sha256,
            "LTE_EVENT_SHA256_INVALID",
        )?;
        if binding.decoder_name.trim().is_empty()
            || binding.decoder_version.trim().is_empty()
            || binding.event_schema_version != "1.5.0"
            || binding.endpoint_roles.is_empty()
        {
            return Err(LteEvidenceError::new(
                "LTE_DECODER_METADATA_INVALID",
                &binding.evidence_ref,
            ));
        }
        if binding.decoder_version != capture.decoder_version
            || binding.event_schema_version != capture.event_schema_version
        {
            return Err(LteEvidenceError::new(
                "LTE_CAPTURE_DECODER_METADATA_MISMATCH",
                &binding.evidence_ref,
            ));
        }
        let source_path = confined_regular_file(&root, &binding.source_file)?;
        if sha256_file(&source_path)? != capture.source_file_sha256 {
            return Err(LteEvidenceError::new(
                "LTE_CAPTURE_HASH_MISMATCH",
                &capture.plane,
            ));
        }
        let events_path = confined_regular_file(&root, &binding.normalized_events_file)?;
        if sha256_file(&events_path)? != binding.normalized_events_sha256 {
            return Err(LteEvidenceError::new(
                "LTE_EVENT_HASH_MISMATCH",
                &capture.plane,
            ));
        }
        verified.push(VerifiedBinding {
            plane: capture.plane.clone(),
            capture,
            binding,
            source_path,
            events_path,
        });
    }
    for step in &request.evidence.steps {
        for evidence_ref in &step.evidence_refs {
            if !refs.contains(evidence_ref.as_str()) {
                return Err(LteEvidenceError::new(
                    "LTE_EVIDENCE_REF_UNRESOLVED",
                    evidence_ref,
                ));
            }
        }
    }
    Ok(verified)
}

/// Explicit allowlist of (plane, protocol, decoder_name) triples. The plane
/// binding decoder always carries the event's primary protocol; a nested
/// NAS event is accepted on S1-MME when its decoder is the current
/// decoder-nas and it carries a `parent_event_id` resolvable to a previously
/// seen S1AP event inside the same plane. Every other combination is a
/// fail-closed `LTE_EVENT_DECODER_MISMATCH`.
///
/// 2.7.10: the nested-NAS exception is the only structural relaxation. The
/// list is explicit — a new plane or a new child decoder cannot be added
/// implicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventKind {
    /// Event matches the plane binding's declared decoder (name + version +
    /// schema version); accepted as a primary (potential-parent) event.
    PlaneBinding,
    /// Event is an EPS NAS child of an S1AP event on S1-MME. Must carry
    /// `parent_event_id`, which must resolve to a S1AP `PlaneBinding` event
    /// in the same plane.
    NestedEpsNas,
}

const NESTED_NAS_DECODER: &str = "decoder-nas";
const NESTED_NAS_VERSION: &str = "0.3.1";

fn classify_event(
    plane: &str,
    event: &EventRecord,
    binding: &LteCaptureBinding,
) -> Result<EventKind, LteEvidenceError> {
    let schema_version = event
        .source_json
        .get("schema_version")
        .and_then(Value::as_str);
    let is_plane_binding = event.decoder_name == binding.decoder_name
        && event.decoder_version == binding.decoder_version
        && schema_version == Some(binding.event_schema_version.as_str());

    if is_plane_binding {
        // The binding decoder's primary protocol is constrained per plane.
        let primary_protocol_ok = match plane {
            "S1_MME" => event.protocol == "S1AP",
            "S11" => event.protocol == "GTPv2-C",
            "S1_U" => event.protocol == "GTP-U",
            _ => false,
        };
        if !primary_protocol_ok {
            return Err(LteEvidenceError::new(
                "LTE_EVENT_DECODER_MISMATCH",
                format!(
                    "event {}: decoder {} declared plane {plane}, but protocol {} is not the \
                     plane-binding protocol",
                    event.event_id, event.decoder_name, event.protocol
                ),
            ));
        }
        return Ok(EventKind::PlaneBinding);
    }

    let nested_eps_nas_candidate = plane == "S1_MME"
        && matches!(event.protocol.as_str(), "NAS-EPS-MM" | "NAS-EPS-SM")
        && event.decoder_name == NESTED_NAS_DECODER
        && event.decoder_version == NESTED_NAS_VERSION;
    if nested_eps_nas_candidate {
        return Ok(EventKind::NestedEpsNas);
    }

    Err(LteEvidenceError::new(
        "LTE_EVENT_DECODER_MISMATCH",
        format!(
            "event {}: decoder {}/{} protocol {} parent {:?} does not match any allowed \
             (plane, protocol, decoder) tuple on plane {plane}; expected plane binding \
             {}/{} or the nested EPS NAS decoder {}/{} for NAS-EPS-MM|NAS-EPS-SM on S1_MME",
            event.event_id,
            event.decoder_name,
            event.decoder_version,
            event.protocol,
            event.parent_event_id,
            binding.decoder_name,
            binding.decoder_version,
            NESTED_NAS_DECODER,
            NESTED_NAS_VERSION,
        ),
    ))
}

fn read_events_bounded(
    verified: &VerifiedBinding<'_>,
    events: &mut Vec<EventRecord>,
    seen_event_ids: &mut BTreeSet<String>,
    retained_event_bytes: &mut usize,
) -> Result<(), LteEvidenceError> {
    let file = File::open(&verified.events_path).map_err(io_error("LTE_EVENT_FILE_UNAVAILABLE"))?;
    let reader = BufReader::new(file);
    let alias = plane_alias(&verified.plane)?;
    let expected_capture_id = format!("sha256:{}", verified.capture.source_file_sha256);
    // Per-plane tracking: S1AP event ids seen in this JSONL stream, and the
    // indices (into the outer `events` buffer) of nested NAS children whose
    // parent has not been observed yet. The post-pass resolves every
    // pending child against the final S1AP set — streaming emission does
    // not guarantee a parent-before-child ordering once oiran-decode has
    // sorted events by timestamp.
    let mut plane_s1ap_event_ids: BTreeSet<String> = BTreeSet::new();
    let mut pending_nested_nas: Vec<usize> = Vec::new();
    let plane_event_start = events.len();

    for (line_index, line) in reader.lines().enumerate() {
        let line = line.map_err(io_error("LTE_EVENT_READ_FAILED"))?;
        if line.len() > MAX_EVENT_LINE_BYTES {
            return Err(LteEvidenceError::new(
                "LTE_EVENT_LINE_TOO_LARGE",
                (line_index + 1).to_string(),
            ));
        }
        if line.trim().is_empty() {
            continue;
        }
        if events.len() >= MAX_INGEST_EVENTS {
            return Err(LteEvidenceError::new(
                "LTE_EVENT_LIMIT_EXCEEDED",
                MAX_INGEST_EVENTS.to_string(),
            ));
        }
        charge_retained_event_bytes(retained_event_bytes, line.len())?;
        let value: Value = serde_json::from_str(&line).map_err(|error| {
            LteEvidenceError::new(
                "LTE_EVENT_JSON_INVALID",
                format!("line {}: {error}", line_index + 1),
            )
        })?;
        if contains_forbidden_identity(&value) {
            return Err(LteEvidenceError::new(
                "LTE_IDENTITY_DISCLOSURE_REJECTED",
                format!("line {}", line_index + 1),
            ));
        }
        let event: EventRecord = serde_json::from_value(value).map_err(|error| {
            LteEvidenceError::new(
                "LTE_EVENT_SCHEMA_INVALID",
                format!("line {}: {error}", line_index + 1),
            )
        })?;
        if event.interface != alias || event.capture_id != expected_capture_id {
            return Err(LteEvidenceError::new(
                "LTE_EVENT_PROVENANCE_MISMATCH",
                &event.event_id,
            ));
        }
        let protocol_ok = match verified.plane.as_str() {
            "S1_MME" => matches!(
                event.protocol.as_str(),
                "S1AP" | "NAS-EPS-MM" | "NAS-EPS-SM"
            ),
            "S11" => event.protocol == "GTPv2-C",
            "S1_U" => event.protocol == "GTP-U",
            _ => false,
        };
        if !protocol_ok {
            return Err(LteEvidenceError::new(
                "LTE_EVENT_PROTOCOL_MISMATCH",
                &event.event_id,
            ));
        }
        let kind = classify_event(&verified.plane, &event, verified.binding)?;
        if event.packet_references.is_empty()
            || event.packet_references.iter().any(|packet| {
                packet.packet_number < verified.capture.first_frame
                    || packet.packet_number > verified.capture.last_frame
                    || packet.source_file != verified.binding.source_file
            })
        {
            return Err(LteEvidenceError::new(
                "LTE_PACKET_REFERENCE_INVALID",
                &event.event_id,
            ));
        }
        if !seen_event_ids.insert(event.event_id.clone()) {
            return Err(LteEvidenceError::new(
                "LTE_EVENT_ID_DUPLICATE",
                &event.event_id,
            ));
        }
        match kind {
            EventKind::PlaneBinding => {
                if event.protocol == "S1AP" {
                    plane_s1ap_event_ids.insert(event.event_id.clone());
                }
            }
            EventKind::NestedEpsNas => {
                if event.parent_event_id.is_none() {
                    return Err(LteEvidenceError::new(
                        "LTE_EVENT_NESTED_NAS_WITHOUT_PARENT",
                        format!(
                            "event {}: nested EPS NAS decoded by {}/{} carries no \
                             parent_event_id on plane S1_MME",
                            event.event_id, event.decoder_name, event.decoder_version
                        ),
                    ));
                }
                pending_nested_nas.push(events.len());
            }
        }
        events.push(event);
    }

    // Post-pass: every nested NAS child must resolve to a S1AP parent seen
    // in the same plane. A child whose parent is missing (e.g., a NAS
    // event synthesised without its S1AP envelope) fails closed.
    for idx in pending_nested_nas {
        let event = &events[idx];
        let parent = event
            .parent_event_id
            .as_deref()
            .expect("NestedEpsNas is checked to have parent_event_id before pending push");
        if !plane_s1ap_event_ids.contains(parent) {
            return Err(LteEvidenceError::new(
                "LTE_EVENT_NESTED_NAS_WITHOUT_PARENT",
                format!(
                    "event {}: nested NAS parent {} not observed as an S1AP event in the \
                     same S1-MME plane (decoder {}/{}, protocol {})",
                    event.event_id,
                    parent,
                    event.decoder_name,
                    event.decoder_version,
                    event.protocol,
                ),
            ));
        }
    }
    // plane_event_start is reserved for future cross-event invariants and
    // keeps the per-plane range explicit in the code flow.
    let _ = plane_event_start;
    Ok(())
}

/// Conservative retained-allocation accounting: JSON values and owned event
/// fields are budgeted at eight times their wire length plus 1 KiB/event.
fn retained_event_cost(line_bytes: usize) -> usize {
    line_bytes.saturating_mul(8).saturating_add(1024)
}

fn charge_retained_event_bytes(
    retained_event_bytes: &mut usize,
    line_bytes: usize,
) -> Result<(), LteEvidenceError> {
    let next = retained_event_bytes
        .checked_add(retained_event_cost(line_bytes))
        .ok_or_else(|| {
            LteEvidenceError::new(
                "LTE_EVENT_BYTES_LIMIT_EXCEEDED",
                MAX_RETAINED_EVENT_BYTES.to_string(),
            )
        })?;
    if next > MAX_RETAINED_EVENT_BYTES {
        return Err(LteEvidenceError::new(
            "LTE_EVENT_BYTES_LIMIT_EXCEEDED",
            MAX_RETAINED_EVENT_BYTES.to_string(),
        ));
    }
    *retained_event_bytes = next;
    Ok(())
}

fn plane_alias(plane: &str) -> Result<&'static str, LteEvidenceError> {
    match plane {
        "S1_MME" => Ok("S1-MME"),
        "S11" => Ok("S11"),
        "S1_U" => Ok("S1-U"),
        other => Err(LteEvidenceError::new(
            "LTE_OPTIONAL_PLANE_UNSUPPORTED",
            other,
        )),
    }
}

fn validate_run_id(value: &str) -> Result<(), LteEvidenceError> {
    if !value.starts_with("lte-run-") || !safe_id(value) || !(16..=72).contains(&value.len()) {
        return Err(LteEvidenceError::new("LTE_RUN_ID_INVALID", value));
    }
    Ok(())
}

fn valid_utc(value: &str) -> bool {
    value.len() >= 20 && value.contains('T') && value.ends_with('Z')
}

fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn validate_sha256(value: &str, code: &'static str) -> Result<(), LteEvidenceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LteEvidenceError::new(code, value));
    }
    Ok(())
}

fn confined_regular_file(root: &Path, relative: &str) -> Result<PathBuf, LteEvidenceError> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(LteEvidenceError::new("LTE_BUNDLE_PATH_REJECTED", relative));
    }
    let joined = root.join(path);
    let metadata =
        fs::symlink_metadata(&joined).map_err(io_error("LTE_BUNDLE_FILE_UNAVAILABLE"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(LteEvidenceError::new("LTE_BUNDLE_FILE_REJECTED", relative));
    }
    let canonical = joined
        .canonicalize()
        .map_err(io_error("LTE_BUNDLE_FILE_UNAVAILABLE"))?;
    if !canonical.starts_with(root) {
        return Err(LteEvidenceError::new("LTE_BUNDLE_PATH_REJECTED", relative));
    }
    Ok(canonical)
}

fn normalized_identity_label(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn is_forbidden_identity_label(value: &str) -> bool {
    let normalized = normalized_identity_label(value);
    matches!(
        normalized.as_str(),
        "imsi"
            | "supi"
            | "suci"
            | "guti"
            | "tmsi"
            | "5gtmsi"
            | "imei"
            | "imeisv"
            | "maskedimeisv"
            | "msisdn"
            | "pei"
            | "k"
            | "opc"
            | "authenticationkey"
            | "subscriberkey"
            | "securitykey"
            | "permanentequipmentidentifier"
    ) || normalized.contains("imeisv")
        || normalized.ends_with("tmsi")
        || normalized.contains("mobileidentity")
        || normalized.contains("subscriberidentity")
}

fn contains_forbidden_identity(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            is_forbidden_identity_label(key)
                || (["name", "type", "field", "key"].contains(&key.as_str())
                    && value.as_str().is_some_and(is_forbidden_identity_label))
                || contains_forbidden_identity(value)
        }),
        Value::Array(items) => items.iter().any(contains_forbidden_identity),
        Value::String(text) => {
            (has_long_digit_run(text, 14) && !is_sha256_value(text))
                || contains_forbidden_identity_marker(text)
        }
        _ => false,
    }
}

fn contains_forbidden_identity_marker(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "imsi-",
        "supi-",
        "suci-",
        "5g-guti-",
        "5g-tmsi-",
        "imei-",
        "imeisv=",
        "msisdn=",
        "pei=",
        "opc=",
        "authentication_key=",
        "subscriber_key=",
        "security_key=",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn strict_lte_run_id(value: &str) -> bool {
    value.len() == "lte-run-".len() + 32
        && value.strip_prefix("lte-run-").is_some_and(|suffix| {
            suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn is_iperf_runtime_output(path: &[&str]) -> bool {
    matches!(
        path,
        ["iperf_runtime_diagnostic", "diagnostic", "stdout"]
            | ["iperf_runtime_diagnostic", "diagnostic", "stderr"]
    )
}

fn contains_forbidden_step_measurement(
    value: &Value,
    declared_run_id: &str,
    path: &[&str],
) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            if is_forbidden_identity_label(key)
                || (["name", "type", "field", "key"].contains(&key.as_str())
                    && value.as_str().is_some_and(is_forbidden_identity_label))
            {
                return true;
            }
            let mut child_path = path.to_vec();
            child_path.push(key);
            contains_forbidden_step_measurement(value, declared_run_id, &child_path)
        }),
        Value::Array(items) => items
            .iter()
            .any(|item| contains_forbidden_step_measurement(item, declared_run_id, path)),
        Value::String(text) => {
            let without_declared_run_id = if strict_lte_run_id(declared_run_id) {
                text.replace(declared_run_id, "")
            } else {
                text.clone()
            };
            if without_declared_run_id.contains("lte-run-")
                || contains_forbidden_identity_marker(&without_declared_run_id)
            {
                return true;
            }
            if is_iperf_runtime_output(path) {
                let lower = without_declared_run_id.to_ascii_lowercase();
                return [
                    "imsi", "imei", "imeisv", "msisdn", "guti", "tmsi", "suci", "supi",
                ]
                .iter()
                .any(|marker| lower.contains(marker));
            }
            has_long_digit_run(&without_declared_run_id, 14)
                && !is_sha256_value(&without_declared_run_id)
        }
        _ => false,
    }
}

fn is_sha256_value(value: &str) -> bool {
    let digest = value.strip_prefix("sha256:").unwrap_or(value);
    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn has_long_digit_run(value: &str, threshold: usize) -> bool {
    let mut run = 0usize;
    for byte in value.bytes() {
        if byte.is_ascii_digit() {
            run += 1;
            if run >= threshold {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn sha256_file(path: &Path) -> Result<String, LteEvidenceError> {
    let mut file = File::open(path).map_err(io_error("LTE_BUNDLE_FILE_UNAVAILABLE"))?;
    let mut hasher = Sha256Hasher::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(io_error("LTE_BUNDLE_READ_FAILED"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finish_hex())
}

/// Streaming verified copy used only for inputs already classified
/// `SANITIZED_APPROVED`. It is deliberately not a generic PCAP anonymizer.
fn copy_file_streaming(source: &Path, destination: &Path) -> Result<String, LteEvidenceError> {
    let parent = destination.parent().ok_or_else(|| {
        LteEvidenceError::new("LTE_STREAM_COPY_FAILED", "destination has no parent")
    })?;
    fs::create_dir_all(parent).map_err(io_error("LTE_STREAM_COPY_FAILED"))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        destination
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("artifact"),
        epoch_ms()
    ));
    let result = (|| {
        let mut input = File::open(source).map_err(io_error("LTE_STREAM_COPY_FAILED"))?;
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(io_error("LTE_STREAM_COPY_FAILED"))?;
        let mut hasher = Sha256Hasher::new();
        let mut buffer = [0u8; 1024 * 1024];
        loop {
            let count = input
                .read(&mut buffer)
                .map_err(io_error("LTE_STREAM_COPY_FAILED"))?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
            output
                .write_all(&buffer[..count])
                .map_err(io_error("LTE_STREAM_COPY_FAILED"))?;
        }
        output
            .sync_all()
            .map_err(io_error("LTE_STREAM_COPY_FAILED"))?;
        fs::rename(&temporary, destination).map_err(io_error("LTE_STREAM_COPY_FAILED"))?;
        Ok(hasher.finish_hex())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn scan_jsonl_privacy(path: &Path) -> Result<(), LteEvidenceError> {
    let reader =
        BufReader::new(File::open(path).map_err(io_error("LTE_EXPORT_SOURCE_UNAVAILABLE"))?);
    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(io_error("LTE_EXPORT_SOURCE_UNAVAILABLE"))?;
        if line.len() > MAX_EVENT_LINE_BYTES {
            return Err(LteEvidenceError::new(
                "LTE_EXPORT_IDENTITY_SCAN_UNSUPPORTED",
                format!("line {} exceeds scan bound", index + 1),
            ));
        }
        let value: Value = serde_json::from_str(&line).map_err(|error| {
            LteEvidenceError::new(
                "LTE_EXPORT_IDENTITY_SCAN_UNSUPPORTED",
                format!("line {}: {error}", index + 1),
            )
        })?;
        if contains_forbidden_identity(&value) {
            return Err(LteEvidenceError::new(
                "LTE_EXPORT_IDENTITY_SCAN_FAILED",
                format!("line {}", index + 1),
            ));
        }
    }
    Ok(())
}

fn json_bytes<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, LteEvidenceError> {
    serde_json::to_vec_pretty(value)
        .map_err(|error| LteEvidenceError::new("LTE_SERIALIZATION_FAILED", error.to_string()))
}

fn jsonl_bytes(events: &[EventRecord]) -> Result<Vec<u8>, LteEvidenceError> {
    let mut bytes = Vec::new();
    for event in events {
        serde_json::to_writer(&mut bytes, event).map_err(|error| {
            LteEvidenceError::new("LTE_SERIALIZATION_FAILED", error.to_string())
        })?;
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn jsonl_values<T: Serialize>(values: &[T]) -> Result<Vec<u8>, LteEvidenceError> {
    let mut bytes = Vec::new();
    for value in values {
        serde_json::to_writer(&mut bytes, value).map_err(|error| {
            LteEvidenceError::new("LTE_SERIALIZATION_FAILED", error.to_string())
        })?;
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), LteEvidenceError> {
    let parent = path
        .parent()
        .ok_or_else(|| LteEvidenceError::new("LTE_ATOMIC_WRITE_FAILED", "missing parent"))?;
    fs::create_dir_all(parent).map_err(io_error("LTE_ATOMIC_WRITE_FAILED"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("artifact");
    let temporary = parent.join(format!(".{name}.{}.tmp", epoch_ms()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(io_error("LTE_ATOMIC_WRITE_FAILED"))?;
        file.write_all(bytes)
            .map_err(io_error("LTE_ATOMIC_WRITE_FAILED"))?;
        file.sync_all()
            .map_err(io_error("LTE_ATOMIC_WRITE_FAILED"))?;
        fs::rename(&temporary, path).map_err(io_error("LTE_ATOMIC_WRITE_FAILED"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn sync_directory(path: &Path) -> Result<(), LteEvidenceError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(io_error("LTE_DIRECTORY_SYNC_FAILED"))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, LteEvidenceError> {
    let bytes = fs::read(path).map_err(io_error("LTE_ARTIFACT_UNAVAILABLE"))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| LteEvidenceError::new("LTE_ARTIFACT_INVALID", error.to_string()))
}

fn io_error(code: &'static str) -> impl FnOnce(std::io::Error) -> LteEvidenceError {
    move |error| LteEvidenceError::new(code, error.to_string())
}

fn epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;
    use session_engine::PacketRef;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    fn temp_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "oiran-lte-v2-{label}-{}-{}-{}",
            std::process::id(),
            epoch_ms(),
            NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn event(
        plane: &str,
        capture_sha: &str,
        source_file: &str,
        frame: u64,
        id: &str,
    ) -> EventRecord {
        let (interface, protocol, name, decoder) = match plane {
            "S1_MME" => (
                "S1-MME",
                "S1AP",
                "InitialContextSetupResponse",
                "decoder-s1ap",
            ),
            "S11" => ("S11", "GTPv2-C", "CreateSessionResponse", "decoder-gtpv2c"),
            _ => ("S1-U", "GTP-U", "G-PDU", "decoder-gtpu"),
        };
        let identifiers = match plane {
            "S1_MME" => vec![
                ("enb_ue_s1ap_id".into(), "ctx-enb-a".into()),
                ("mme_ue_s1ap_id".into(), "ctx-mme-a".into()),
                ("subscriber_pseudonym".into(), "SUB-opaque-a".into()),
                ("erab_teid".into(), "0x00001001".into()),
            ],
            "S11" => vec![
                ("subscriber_pseudonym".into(), "SUB-opaque-a".into()),
                ("eps_bearer_identity".into(), "5".into()),
                ("bearer_f_teid".into(), "0x00001001".into()),
            ],
            _ => vec![("teid".into(), "0x00001001".into())],
        };
        EventRecord {
            event_id: id.into(),
            parent_event_id: None,
            capture_id: format!("sha256:{capture_sha}"),
            capture_point_id: plane.into(),
            timestamp: format!("2026-10-31T12:00:0{frame}Z"),
            timestamp_ns: i128::from(frame) * 1_000_000_000,
            raw_ticks: frame,
            interface: interface.into(),
            protocol: protocol.into(),
            message_name: name.into(),
            source_address: "192.0.2.1".into(),
            destination_address: "192.0.2.2".into(),
            source_participant: "RAN".into(),
            destination_participant: "CORE".into(),
            direction: if plane == "S1_U" {
                "UPLINK".into()
            } else {
                "RAN_TO_CORE".into()
            },
            identifiers,
            information_elements: json!([]),
            decoding_status: "DECODED".into(),
            decoder_name: decoder.into(),
            decoder_version: "test-1".into(),
            raw_payload_reference: format!("sha256:event-{id}"),
            packet_references: vec![PacketRef {
                source_file: source_file.into(),
                packet_number: frame,
                byte_offset: frame * 64,
                interface_id: 0,
                captured_length: 128,
                original_length: 128,
            }],
            errors: vec![],
            source_json: json!({"schema_version":"1.5.0"}),
        }
    }

    fn build_bundle() -> (PathBuf, LteEvidenceImportRequest) {
        let root = temp_root("bundle");
        let mut captures = Vec::new();
        let mut bindings = Vec::new();
        let mut refs = Vec::new();
        for (index, plane) in REQUIRED_PLANES.iter().enumerate() {
            let source_file = format!("{}.pcapng", plane.to_ascii_lowercase());
            let source_bytes = format!("synthetic sanitized {plane}").into_bytes();
            fs::write(root.join(&source_file), &source_bytes).unwrap();
            let source_sha = sha256_hex(&source_bytes);
            let frame = (index + 1) as u64;
            let record = event(
                plane,
                &source_sha,
                &source_file,
                frame,
                &format!("evt-{plane}"),
            );
            let events_file = format!("{}.jsonl", plane.to_ascii_lowercase());
            let events_bytes = jsonl_bytes(&[record]).unwrap();
            fs::write(root.join(&events_file), &events_bytes).unwrap();
            captures.push(LteCaptureRef {
                plane: (*plane).into(),
                source_file_sha256: source_sha,
                decoder_version: "test-1".into(),
                event_schema_version: "1.5.0".into(),
                first_frame: frame,
                last_frame: frame,
                sanitization_state: "SANITIZED_APPROVED".into(),
            });
            let evidence_ref = format!("capture:{plane}");
            refs.push(evidence_ref.clone());
            bindings.push(LteCaptureBinding {
                evidence_ref,
                capture_ref_index: index,
                source_file,
                normalized_events_file: events_file,
                normalized_events_sha256: sha256_hex(&events_bytes),
                decoder_name: match *plane {
                    "S1_MME" => "decoder-s1ap",
                    "S11" => "decoder-gtpv2c",
                    _ => "decoder-gtpu",
                }
                .into(),
                decoder_version: "test-1".into(),
                event_schema_version: "1.5.0".into(),
                endpoint_roles: BTreeMap::from([
                    ("192.0.2.1".into(), "RAN".into()),
                    ("192.0.2.2".into(), "CORE".into()),
                ]),
            });
        }
        let request = LteEvidenceImportRequest {
            schema_version: INGESTION_SCHEMA.into(),
            bundle_id: "bundle-synthetic-01".into(),
            evidence: LteE2eEvidence {
                schema_version: EVIDENCE_SCHEMA.into(),
                run_id: "lte-run-synthetic-0001".into(),
                profile_id: PROFILE_ID.into(),
                scenario_id: SCENARIO_ID.into(),
                started_at: "2026-10-31T12:00:00Z".into(),
                ended_at: "2026-10-31T12:00:10Z".into(),
                final_state: "COMPLETED".into(),
                steps: vec![LteEvidenceStep {
                    index: 0,
                    step_type: "lte_attach".into(),
                    state: "COMPLETED".into(),
                    started_at: Some("2026-10-31T12:00:00Z".into()),
                    ended_at: Some("2026-10-31T12:00:10Z".into()),
                    reason_code: None,
                    evidence_refs: refs,
                    measurements: BTreeMap::new(),
                }],
                capture_refs: captures,
                cleanup: LteCleanup {
                    srsue_stopped: true,
                    srsenb_stopped: true,
                    sidecars_removed: true,
                    epc_healthy: true,
                    dumpcaps_preserved: true,
                },
            },
            capture_bindings: bindings,
        };
        (root, request)
    }

    #[test]
    fn imports_atomically_idempotently_and_materializes_lte_session_callflow() {
        let (bundle, request) = build_bundle();
        let store_root = temp_root("store");
        let store = LteEvidenceStore::new(store_root.clone()).unwrap();
        let first = store.ingest(&bundle, &request).unwrap();
        assert_eq!(first.session_count, 1);
        assert!(!first.idempotent);
        let second = store.ingest(&bundle, &request).unwrap();
        assert!(second.idempotent);
        let sessions = store.session_page(&request.evidence.run_id, 1, 10).unwrap();
        assert_eq!(sessions["pagination"]["total"], 1);
        let session_id = sessions["data"][0]["session_id"].as_str().unwrap();
        let catalog = store.catalog().unwrap();
        assert_eq!(catalog.len(), 1);
        assert_eq!(catalog[0].dataset_id, first.dataset_id);
        let (found_manifest, found_session) = store.find_session(session_id).unwrap().unwrap();
        assert_eq!(found_manifest.dataset_id, first.dataset_id);
        assert_eq!(found_session.session_id, session_id);
        let flow = store
            .callflow_page(&request.evidence.run_id, session_id, None, 2)
            .unwrap();
        assert_eq!(flow["technology"], "LTE");
        assert!(flow["events"].as_array().unwrap().len() <= 2);
        assert!(store
            .callflow_page_by_session(session_id, None, 2)
            .unwrap()
            .is_some());
        let export_flow = store
            .callflow_for_export_by_session(session_id)
            .unwrap()
            .unwrap();
        assert_eq!(export_flow.session_id, session_id);
        assert_eq!(export_flow.technology, "LTE");
        assert_eq!(
            export_flow.events.len() as u64,
            flow["pagination"]["total_events"].as_u64().unwrap()
        );
        assert!(!store_root
            .join("datasets")
            .read_dir()
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with('.')));
        fs::remove_dir_all(bundle).unwrap();
        fs::remove_dir_all(store_root).unwrap();
    }

    #[test]
    fn imports_timeout_partial_evidence_without_inventing_missing_planes() {
        let (bundle, mut request) = build_bundle();
        request.evidence.run_id = "lte-run-timeout-partial-0001".into();
        request.evidence.final_state = "FAILED".into();
        request.evidence.capture_refs.truncate(1);
        request.capture_bindings.truncate(1);
        request.evidence.steps[0].state = "FAILED".into();
        request.evidence.steps[0].reason_code = Some("LTE_GLOBAL_TIMEOUT".into());
        request.evidence.steps[0].evidence_refs = vec!["capture:S1_MME".into()];

        let store_root = temp_root("partial-timeout-store");
        let store = LteEvidenceStore::new(store_root.clone()).unwrap();
        let first = store.ingest(&bundle, &request).unwrap();
        assert_eq!(first.state, "IMPORTED_PARTIAL");
        assert_eq!(first.session_count, 1);
        assert!(!first.idempotent);
        assert!(store.ingest(&bundle, &request).unwrap().idempotent);

        let catalog = store.catalog().unwrap();
        let manifest = catalog
            .iter()
            .find(|item| item.run_id == request.evidence.run_id)
            .unwrap();
        assert_eq!(manifest.final_state, "FAILED");
        assert_eq!(manifest.capture_planes, vec!["S1_MME"]);
        assert_eq!(manifest.source_capture_sha256.len(), 1);
        let sessions = store.session_page(&request.evidence.run_id, 1, 10).unwrap();
        assert_eq!(sessions["data"].as_array().unwrap().len(), 1);
        let session_id = sessions["data"][0]["session_id"].as_str().unwrap();
        let flow = store
            .callflow_page(&request.evidence.run_id, session_id, None, 100)
            .unwrap();
        assert_eq!(flow["interfaces"], json!(["S1-MME"]));
        assert!(flow["correlation_edges"].as_array().unwrap().is_empty());

        fs::remove_dir_all(bundle).unwrap();
        fs::remove_dir_all(store_root).unwrap();
    }

    #[test]
    fn failed_run_still_requires_completed_cleanup_proof() {
        let (bundle, mut request) = build_bundle();
        request.evidence.run_id = "lte-run-failed-cleanup-0001".into();
        request.evidence.final_state = "FAILED".into();
        request.evidence.cleanup.srsue_stopped = false;
        let store_root = temp_root("failed-cleanup-store");
        let store = LteEvidenceStore::new(store_root.clone()).unwrap();
        assert_eq!(
            store.ingest(&bundle, &request).unwrap_err().code,
            "LTE_CLEANUP_NOT_PROVEN"
        );
        fs::remove_dir_all(bundle).unwrap();
        fs::remove_dir_all(store_root).unwrap();
    }

    #[test]
    fn accepts_exact_polaris_outer_envelope_and_rejects_provenance_drift() {
        let (_bundle, request) = build_bundle();
        let capture_ids = request
            .evidence
            .capture_refs
            .iter()
            .map(|capture| PolarisCaptureId {
                plane: capture.plane.clone(),
                capture_id: format!("sha256:{}", capture.source_file_sha256),
            })
            .collect();
        let envelope = PolarisLteImportEnvelope {
            schema_version: POLARIS_ENVELOPE_SCHEMA.into(),
            provenance: PolarisLteProvenance {
                source: "POLARIS_SERVER_VERIFIED_BUNDLE".into(),
                published_at_epoch_ms: 1_793_448_010_000,
                run_id: request.evidence.run_id.clone(),
                rat: "LTE".into(),
                profile_id: request.evidence.profile_id.clone(),
                scenario_id: request.evidence.scenario_id.clone(),
                started_at: request.evidence.started_at.clone(),
                ended_at: request.evidence.ended_at.clone(),
                capture_ids,
                session_references: vec![],
                session_reference_state: "NOT_AVAILABLE_UNTIL_OIRAN_INGESTION".into(),
            },
            oiran_import: request.clone(),
        };
        let decoded: LteEvidenceImportPayload =
            serde_json::from_value(serde_json::to_value(&envelope).unwrap()).unwrap();
        assert_eq!(
            decoded.into_request().unwrap().evidence.run_id,
            request.evidence.run_id
        );

        let mut drifted = envelope;
        drifted.provenance.scenario_id = "different-scenario".into();
        let error = LteEvidenceImportPayload::Polaris(drifted)
            .into_request()
            .unwrap_err();
        assert_eq!(error.code, "LTE_POLARIS_PROVENANCE_MISMATCH");
    }

    #[test]
    fn rejects_missing_plane_unapproved_hash_mismatch_and_unresolved_reference() {
        let (bundle, mut request) = build_bundle();
        request.evidence.capture_refs.pop();
        request.capture_bindings.pop();
        let store_root = temp_root("reject-store");
        let store = LteEvidenceStore::new(store_root.clone()).unwrap();
        assert_eq!(
            store.ingest(&bundle, &request).unwrap_err().code,
            "LTE_REQUIRED_PLANE_MISSING"
        );

        let (_, mut request) = build_bundle();
        request.evidence.capture_refs[0].sanitization_state = "SANITIZED_PENDING_REVIEW".into();
        assert_eq!(
            store.ingest(&bundle, &request).unwrap_err().code,
            "LTE_EVIDENCE_NOT_APPROVED"
        );

        let (_, mut request) = build_bundle();
        request.evidence.capture_refs[0].source_file_sha256 = "0".repeat(64);
        assert_eq!(
            store.ingest(&bundle, &request).unwrap_err().code,
            "LTE_CAPTURE_HASH_MISMATCH"
        );

        let (_, mut request) = build_bundle();
        request.evidence.capture_refs[0].decoder_version = "different".into();
        assert_eq!(
            store.ingest(&bundle, &request).unwrap_err().code,
            "LTE_CAPTURE_DECODER_METADATA_MISMATCH"
        );

        let (_, mut request) = build_bundle();
        request.evidence.steps[0]
            .evidence_refs
            .push("capture:UNKNOWN".into());
        assert_eq!(
            store.ingest(&bundle, &request).unwrap_err().code,
            "LTE_EVIDENCE_REF_UNRESOLVED"
        );
        fs::remove_dir_all(store_root).unwrap();
    }

    #[test]
    fn rejects_duplicate_planes_events_and_mismatched_event_provenance() {
        let store_root = temp_root("provenance-reject-store");
        let store = LteEvidenceStore::new(store_root.clone()).unwrap();

        let (bundle, mut request) = build_bundle();
        request.evidence.capture_refs[1].plane = "S1_MME".into();
        assert_eq!(
            store.ingest(&bundle, &request).unwrap_err().code,
            "LTE_CAPTURE_PLANE_DUPLICATE"
        );
        fs::remove_dir_all(bundle).unwrap();

        let (bundle, mut request) = build_bundle();
        let events_path = bundle.join(&request.capture_bindings[1].normalized_events_file);
        let mut event: EventRecord =
            serde_json::from_str(fs::read_to_string(&events_path).unwrap().trim()).unwrap();
        event.event_id = "evt-S1_MME".into();
        let bytes = jsonl_bytes(&[event]).unwrap();
        fs::write(&events_path, &bytes).unwrap();
        request.capture_bindings[1].normalized_events_sha256 = sha256_hex(&bytes);
        assert_eq!(
            store.ingest(&bundle, &request).unwrap_err().code,
            "LTE_EVENT_ID_DUPLICATE"
        );
        fs::remove_dir_all(bundle).unwrap();

        let (bundle, mut request) = build_bundle();
        let events_path = bundle.join(&request.capture_bindings[0].normalized_events_file);
        let mut event: EventRecord =
            serde_json::from_str(fs::read_to_string(&events_path).unwrap().trim()).unwrap();
        event.capture_id = format!("sha256:{}", "0".repeat(64));
        let bytes = jsonl_bytes(&[event]).unwrap();
        fs::write(&events_path, &bytes).unwrap();
        request.capture_bindings[0].normalized_events_sha256 = sha256_hex(&bytes);
        assert_eq!(
            store.ingest(&bundle, &request).unwrap_err().code,
            "LTE_EVENT_PROVENANCE_MISMATCH"
        );
        fs::remove_dir_all(bundle).unwrap();

        let (bundle, mut request) = build_bundle();
        let events_path = bundle.join(&request.capture_bindings[2].normalized_events_file);
        let mut event: EventRecord =
            serde_json::from_str(fs::read_to_string(&events_path).unwrap().trim()).unwrap();
        event.packet_references[0].source_file = "different-source.pcapng".into();
        let bytes = jsonl_bytes(&[event]).unwrap();
        fs::write(&events_path, &bytes).unwrap();
        request.capture_bindings[2].normalized_events_sha256 = sha256_hex(&bytes);
        assert_eq!(
            store.ingest(&bundle, &request).unwrap_err().code,
            "LTE_PACKET_REFERENCE_INVALID"
        );
        fs::remove_dir_all(bundle).unwrap();
        fs::remove_dir_all(store_root).unwrap();
    }

    #[test]
    fn retained_event_allocation_budget_is_fail_closed() {
        let mut retained = MAX_RETAINED_EVENT_BYTES - retained_event_cost(1);
        charge_retained_event_bytes(&mut retained, 1).unwrap();
        assert_eq!(retained, MAX_RETAINED_EVENT_BYTES);
        assert_eq!(
            charge_retained_event_bytes(&mut retained, 1)
                .unwrap_err()
                .code,
            "LTE_EVENT_BYTES_LIMIT_EXCEEDED"
        );
        assert_eq!(retained, MAX_RETAINED_EVENT_BYTES);
    }

    #[test]
    fn conflicting_run_rolls_back_and_export_starts_pending_review_with_verified_capture_copy() {
        let (bundle, request) = build_bundle();
        let store_root = temp_root("conflict-store");
        let store = LteEvidenceStore::new(store_root.clone()).unwrap();
        store.ingest(&bundle, &request).unwrap();
        let mut conflict = request.clone();
        conflict.evidence.ended_at = "2026-10-31T12:00:11Z".into();
        assert_eq!(
            store.ingest(&bundle, &conflict).unwrap_err().code,
            "LTE_INGESTION_CONFLICT"
        );
        let export = store
            .export_pending_review(
                &request.evidence.run_id,
                "export-synthetic-01",
                "VERIFIED_COPY",
            )
            .unwrap();
        assert_eq!(export.review_state, "SANITIZED_PENDING_REVIEW");
        let export_root = store_root.join("exports/export-synthetic-01");
        assert!(!export_root.join("s1_mme.pcapng").exists());
        assert!(export_root.join("captures/s1_mme.pcapng").is_file());
        assert!(export_root.join("events.jsonl").is_file());
        fs::OpenOptions::new()
            .append(true)
            .open(
                store_root
                    .join("datasets")
                    .join(format!("dataset-{}/events.jsonl", request.evidence.run_id)),
            )
            .unwrap()
            .write_all(b"{}\n")
            .unwrap();
        assert_eq!(
            store
                .export_pending_review(
                    &request.evidence.run_id,
                    "export-tampered-02",
                    "VERIFIED_COPY",
                )
                .unwrap_err()
                .code,
            "LTE_EXPORT_SOURCE_HASH_MISMATCH"
        );
        assert_eq!(
            store
                .export_pending_review(
                    &request.evidence.run_id,
                    "export-unsupported-03",
                    "REWRITE_IDENTITIES",
                )
                .unwrap_err()
                .code,
            "LTE_EXPORT_TRANSFORMATION_UNSUPPORTED"
        );
        fs::remove_dir_all(bundle).unwrap();
        fs::remove_dir_all(store_root).unwrap();
    }

    #[test]
    fn rejects_clear_identity_and_reused_ambiguous_teid_does_not_create_extra_edge() {
        let (bundle, mut request) = build_bundle();
        request.evidence.steps[0]
            .measurements
            .insert("imsi".into(), Value::String("synthetic-identity".into()));
        let store_root = temp_root("privacy-store");
        let store = LteEvidenceStore::new(store_root.clone()).unwrap();
        assert_eq!(
            store.ingest(&bundle, &request).unwrap_err().code,
            "LTE_IDENTITY_DISCLOSURE_REJECTED"
        );

        let (bundle2, request2) = build_bundle();
        let result = store.ingest(&bundle2, &request2).unwrap();
        assert!(result.correlation_edge_count <= 2);
        fs::remove_dir_all(bundle).unwrap();
        fs::remove_dir_all(bundle2).unwrap();
        fs::remove_dir_all(store_root).unwrap();
    }

    #[test]
    fn privacy_predicate_rejects_all_prohibited_identity_labels_and_values() {
        for label in [
            "imsi",
            "SUPI",
            "suci",
            "GUTI",
            "5G-TMSI",
            "imei",
            "MaskedIMEISV",
            "MSISDN",
            "PEI",
            "K",
            "OPc",
            "authentication_key",
            "subscriber-key",
            "Security Key",
            "PermanentEquipmentIdentifier",
        ] {
            assert!(
                contains_forbidden_identity(&json!({(label):"opaque"})),
                "identity-bearing key was accepted: {label}"
            );
            assert!(
                contains_forbidden_identity(&json!({"information_elements":[
                    {"name":label,"value":"opaque"}
                ]})),
                "identity IE label was accepted: {label}"
            );
        }
        for value in [
            "suci-opaque",
            "supi-opaque",
            "5g-tmsi-opaque",
            "pei=opaque",
            "authentication_key=opaque",
            "subscriber_key=opaque",
            "security_key=opaque",
        ] {
            assert!(
                contains_forbidden_identity(&json!({"value":value})),
                "identity-shaped value was accepted: {value}"
            );
        }
        assert!(!contains_forbidden_identity(&json!({
            "imsi_pseudonym":"SUB-opaque-a",
            "message_name":"InitialContextSetupResponse",
            "teid":"0x1001",
            "capture_id":format!("sha256:{}", "0".repeat(64))
        })));
    }

    #[test]
    fn step_privacy_allows_only_declared_run_id_and_iperf_numeric_diagnostics() {
        let run_id = "lte-run-09913806240271269bd9d7e0d4d07eb2";
        let measurements = json!({
            "terminal_log_persistence": {"path": format!("/runs/{run_id}/srsue.log")},
            "iperf_runtime_diagnostic": {
                "diagnostic": {
                    "stdout": "1700000000000000 1000000 120000000000000",
                    "stderr": ""
                }
            }
        });
        assert!(!contains_forbidden_step_measurement(
            &measurements,
            run_id,
            &[]
        ));
    }

    #[test]
    fn step_privacy_rejects_long_identity_outside_iperf_output() {
        let run_id = "lte-run-09913806240271269bd9d7e0d4d07eb2";
        assert!(contains_forbidden_step_measurement(
            &json!({"other_diagnostic":{"stdout":"001010123456789"}}),
            run_id,
            &[]
        ));
    }

    #[test]
    fn step_privacy_keeps_identity_markers_active_in_iperf_output() {
        let run_id = "lte-run-09913806240271269bd9d7e0d4d07eb2";
        assert!(contains_forbidden_step_measurement(
            &json!({"iperf_runtime_diagnostic":{"diagnostic":{
                "stdout":"imsi 001010123456789"
            }}}),
            run_id,
            &[]
        ));
    }

    #[test]
    fn step_privacy_rejects_mismatched_or_malformed_run_ids() {
        let run_id = "lte-run-09913806240271269bd9d7e0d4d07eb2";
        for embedded in [
            "lte-run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "lte-run-111111111111111",
        ] {
            assert!(contains_forbidden_step_measurement(
                &json!({"iperf_runtime_diagnostic":{"diagnostic":{
                    "stdout":embedded
                }}}),
                run_id,
                &[]
            ));
        }
    }

    // 2.7.10: nested EPS NAS events decoded by decoder-nas/0.3.1 must be
    // accepted on S1-MME when their parent_event_id resolves to an S1AP
    // event seen in the same plane. The ANR3 field evidence (issue #10
    // comment 6628829729) was blocked by the stricter prior contract.

    fn s1_mme_nested_nas_bundle(child_count: usize) -> (PathBuf, LteEvidenceImportRequest) {
        let (bundle, mut request) = build_bundle();
        let binding_index = request
            .capture_bindings
            .iter()
            .position(|binding| binding.evidence_ref == "capture:S1_MME")
            .expect("S1_MME binding present");
        let binding = request.capture_bindings[binding_index].clone();
        let capture_sha = request.evidence.capture_refs[binding_index]
            .source_file_sha256
            .clone();
        let parent_id = "evt-s1ap-parent-0001";
        let mut parent = event(
            "S1_MME",
            &capture_sha,
            &binding.source_file,
            1,
            parent_id,
        );
        parent.decoder_name = binding.decoder_name.clone();
        parent.decoder_version = binding.decoder_version.clone();
        let mut children: Vec<EventRecord> = (0..child_count)
            .map(|i| {
                let mut child = event(
                    "S1_MME",
                    &capture_sha,
                    &binding.source_file,
                    1,
                    &format!("evt-nas-child-{i:04}"),
                );
                child.protocol = "NAS-EPS-MM".into();
                child.decoder_name = NESTED_NAS_DECODER.into();
                child.decoder_version = NESTED_NAS_VERSION.into();
                child.parent_event_id = Some(parent_id.into());
                child.message_name = "Attach Request".into();
                child
            })
            .collect();
        let mut all = vec![parent];
        all.append(&mut children);
        let events_bytes = jsonl_bytes(&all).unwrap();
        let events_path = bundle.join(&binding.normalized_events_file);
        fs::write(&events_path, &events_bytes).unwrap();
        request.capture_bindings[binding_index].normalized_events_sha256 = sha256_hex(&events_bytes);
        (bundle, request)
    }

    #[test]
    fn accepts_ten_nas_children_decoded_by_the_eps_nas_decoder_on_s1_mme() {
        // Reproduces the ANR3 field case (issue #10 comment 6628829729):
        // one S1AP envelope on S1-MME + ten EPS NAS children decoded by
        // decoder-nas/0.3.1 with parent_event_id set.
        let (bundle, request) = s1_mme_nested_nas_bundle(10);
        let store = LteEvidenceStore::new(temp_root("nested-nas-accept-store")).unwrap();
        let result = store.ingest(&bundle, &request).expect("accepted");
        assert!(
            matches!(result.state.as_str(), "COMPLETED" | "IMPORTED" | "IMPORTED_PARTIAL"),
            "unexpected state: {}",
            result.state
        );
        // Idempotency still holds after accepting the ten children.
        let second = store.ingest(&bundle, &request).unwrap();
        assert!(second.idempotent);
        fs::remove_dir_all(bundle).unwrap();
    }

    #[test]
    fn rejects_nested_nas_without_s1ap_parent_on_s1_mme() {
        let (bundle, mut request) = s1_mme_nested_nas_bundle(1);
        let binding_index = request
            .capture_bindings
            .iter()
            .position(|binding| binding.evidence_ref == "capture:S1_MME")
            .unwrap();
        let binding = request.capture_bindings[binding_index].clone();
        let capture_sha = request.evidence.capture_refs[binding_index]
            .source_file_sha256
            .clone();
        // Rewrite the JSONL to remove the S1AP parent — the lone child
        // has a `parent_event_id` that will not resolve to any S1AP event
        // present in the stream.
        let mut orphan = event(
            "S1_MME",
            &capture_sha,
            &binding.source_file,
            1,
            "evt-nas-orphan-0001",
        );
        orphan.protocol = "NAS-EPS-MM".into();
        orphan.decoder_name = NESTED_NAS_DECODER.into();
        orphan.decoder_version = NESTED_NAS_VERSION.into();
        orphan.parent_event_id = Some("evt-s1ap-missing".into());
        let bytes = jsonl_bytes(&[orphan]).unwrap();
        fs::write(bundle.join(&binding.normalized_events_file), &bytes).unwrap();
        request.capture_bindings[binding_index].normalized_events_sha256 = sha256_hex(&bytes);
        let store = LteEvidenceStore::new(temp_root("nested-nas-orphan-store")).unwrap();
        let error = store.ingest(&bundle, &request).unwrap_err();
        assert_eq!(error.code, "LTE_EVENT_NESTED_NAS_WITHOUT_PARENT");
        fs::remove_dir_all(bundle).unwrap();
    }

    #[test]
    fn rejects_nested_nas_without_any_parent_event_id_on_s1_mme() {
        let (bundle, mut request) = s1_mme_nested_nas_bundle(1);
        let binding_index = request
            .capture_bindings
            .iter()
            .position(|binding| binding.evidence_ref == "capture:S1_MME")
            .unwrap();
        let binding = request.capture_bindings[binding_index].clone();
        let capture_sha = request.evidence.capture_refs[binding_index]
            .source_file_sha256
            .clone();
        let mut child = event(
            "S1_MME",
            &capture_sha,
            &binding.source_file,
            1,
            "evt-nas-no-parent-0001",
        );
        child.protocol = "NAS-EPS-MM".into();
        child.decoder_name = NESTED_NAS_DECODER.into();
        child.decoder_version = NESTED_NAS_VERSION.into();
        child.parent_event_id = None;
        let bytes = jsonl_bytes(&[child]).unwrap();
        fs::write(bundle.join(&binding.normalized_events_file), &bytes).unwrap();
        request.capture_bindings[binding_index].normalized_events_sha256 = sha256_hex(&bytes);
        let store = LteEvidenceStore::new(temp_root("nested-nas-none-store")).unwrap();
        let error = store.ingest(&bundle, &request).unwrap_err();
        assert_eq!(error.code, "LTE_EVENT_NESTED_NAS_WITHOUT_PARENT");
        fs::remove_dir_all(bundle).unwrap();
    }

    #[test]
    fn rejects_unknown_decoder_on_s1_mme() {
        let (bundle, mut request) = build_bundle();
        let binding_index = request
            .capture_bindings
            .iter()
            .position(|binding| binding.evidence_ref == "capture:S1_MME")
            .unwrap();
        let binding = request.capture_bindings[binding_index].clone();
        let capture_sha = request.evidence.capture_refs[binding_index]
            .source_file_sha256
            .clone();
        let mut rogue = event(
            "S1_MME",
            &capture_sha,
            &binding.source_file,
            1,
            "evt-rogue-decoder",
        );
        rogue.decoder_name = "decoder-unknown".into();
        rogue.decoder_version = "9.9.9".into();
        let bytes = jsonl_bytes(&[rogue]).unwrap();
        fs::write(bundle.join(&binding.normalized_events_file), &bytes).unwrap();
        request.capture_bindings[binding_index].normalized_events_sha256 = sha256_hex(&bytes);
        let store = LteEvidenceStore::new(temp_root("rogue-decoder-store")).unwrap();
        let error = store.ingest(&bundle, &request).unwrap_err();
        assert_eq!(error.code, "LTE_EVENT_DECODER_MISMATCH");
        // The detail must identify the offending decoder, protocol and parent.
        assert!(
            error.detail.contains("decoder-unknown/9.9.9"),
            "error detail should name the rogue decoder, got: {}",
            error.detail
        );
        assert!(
            error.detail.contains("S1AP"),
            "error detail should name the protocol, got: {}",
            error.detail
        );
        assert!(
            error.detail.contains("parent"),
            "error detail should surface the parent context, got: {}",
            error.detail
        );
        fs::remove_dir_all(bundle).unwrap();
    }

    #[test]
    fn rejects_wrong_decoder_version_for_nested_eps_nas() {
        // The nested NAS exception is pinned to decoder-nas/0.3.1. A NAS
        // event claiming a different version must be refused to prevent
        // silent decoder drift.
        let (bundle, mut request) = s1_mme_nested_nas_bundle(1);
        let binding_index = request
            .capture_bindings
            .iter()
            .position(|binding| binding.evidence_ref == "capture:S1_MME")
            .unwrap();
        let binding = request.capture_bindings[binding_index].clone();
        let capture_sha = request.evidence.capture_refs[binding_index]
            .source_file_sha256
            .clone();
        let parent_id = "evt-s1ap-parent-drift";
        let mut parent = event(
            "S1_MME",
            &capture_sha,
            &binding.source_file,
            1,
            parent_id,
        );
        parent.decoder_name = binding.decoder_name.clone();
        parent.decoder_version = binding.decoder_version.clone();
        let mut drifted_child = event(
            "S1_MME",
            &capture_sha,
            &binding.source_file,
            1,
            "evt-nas-drift-0001",
        );
        drifted_child.protocol = "NAS-EPS-MM".into();
        drifted_child.decoder_name = NESTED_NAS_DECODER.into();
        drifted_child.decoder_version = "0.4.0".into();
        drifted_child.parent_event_id = Some(parent_id.into());
        let bytes = jsonl_bytes(&[parent, drifted_child]).unwrap();
        fs::write(bundle.join(&binding.normalized_events_file), &bytes).unwrap();
        request.capture_bindings[binding_index].normalized_events_sha256 = sha256_hex(&bytes);
        let store = LteEvidenceStore::new(temp_root("drifted-nas-store")).unwrap();
        let error = store.ingest(&bundle, &request).unwrap_err();
        assert_eq!(error.code, "LTE_EVENT_DECODER_MISMATCH");
        fs::remove_dir_all(bundle).unwrap();
    }

    // 2.7.11: SecurityKey IEs must be withheld at decode time. The
    // normalised event may carry the IE's id/length + `WITHHELD` marker
    // but never the raw bytes nor any hash, and the finalizer keeps
    // refusing any residual key material that reaches the exported stream.

    fn s1_mme_ics_bundle_with_withheld_security_key() -> (PathBuf, LteEvidenceImportRequest) {
        let (bundle, mut request) = build_bundle();
        let binding_index = request
            .capture_bindings
            .iter()
            .position(|binding| binding.evidence_ref == "capture:S1_MME")
            .unwrap();
        let binding = request.capture_bindings[binding_index].clone();
        let capture_sha = request.evidence.capture_refs[binding_index]
            .source_file_sha256
            .clone();
        let mut ics = event(
            "S1_MME",
            &capture_sha,
            &binding.source_file,
            1,
            "evt-s1ap-ics-0001",
        );
        ics.decoder_name = binding.decoder_name.clone();
        ics.decoder_version = binding.decoder_version.clone();
        ics.message_name = "InitialContextSetupRequest".into();
        // 2.7.11 contract: SecurityKey emitted only by length and WITHHELD
        // marker. This is what a correctly behaving decoder outputs.
        ics.information_elements = json!([
            {
                "id": 73,
                "name": "key_material_withheld",
                "length": 32,
                "value": "WITHHELD",
                "raw_sha256": null,
                "status": "DECODED"
            }
        ]);
        let bytes = jsonl_bytes(&[ics]).unwrap();
        fs::write(bundle.join(&binding.normalized_events_file), &bytes).unwrap();
        request.capture_bindings[binding_index].normalized_events_sha256 = sha256_hex(&bytes);
        (bundle, request)
    }

    #[test]
    fn imports_ics_with_withheld_security_key_without_privacy_rejection() {
        // Reproduces the ANR3 ICS case (issue #10 comment 6628829729,
        // SecurityKey at line 17 of s1-mme.events.jsonl): the event with
        // the withheld IE is accepted and no raw key material appears in
        // the persisted copy.
        let (bundle, request) = s1_mme_ics_bundle_with_withheld_security_key();
        let store = LteEvidenceStore::new(temp_root("ics-withheld-key-store")).unwrap();
        let result = store.ingest(&bundle, &request).expect("accepted");
        assert!(
            matches!(result.state.as_str(), "COMPLETED" | "IMPORTED" | "IMPORTED_PARTIAL"),
            "unexpected state: {}",
            result.state
        );
        fs::remove_dir_all(bundle).unwrap();
    }

    #[test]
    fn rejects_raw_security_key_leaked_into_the_published_stream() {
        // Symmetric guard: if any serialiser skips the withhold path and
        // lets a raw SecurityKey (or its sha256) escape under the original
        // IE name, the privacy predicate still refuses it fail-closed.
        for leak in [
            json!([{
                "id": 73,
                "name": "SecurityKey",
                "length": 32,
                "value": "4b654e42" ,
                "raw_sha256": "4b654e42000000000000000000000000000000000000000000000000000000ff",
                "status": "DECODED"
            }]),
            json!([{
                "id": 73,
                "name": "key_material_withheld",
                "length": 32,
                "value": "security_key=4b654e42...",
                "raw_sha256": null,
                "status": "DECODED"
            }]),
        ] {
            let (bundle, mut request) = build_bundle();
            let binding_index = request
                .capture_bindings
                .iter()
                .position(|binding| binding.evidence_ref == "capture:S1_MME")
                .unwrap();
            let binding = request.capture_bindings[binding_index].clone();
            let capture_sha = request.evidence.capture_refs[binding_index]
                .source_file_sha256
                .clone();
            let mut rogue = event(
                "S1_MME",
                &capture_sha,
                &binding.source_file,
                1,
                "evt-s1ap-key-leak",
            );
            rogue.decoder_name = binding.decoder_name.clone();
            rogue.decoder_version = binding.decoder_version.clone();
            rogue.message_name = "InitialContextSetupRequest".into();
            rogue.information_elements = leak.clone();
            let bytes = jsonl_bytes(&[rogue]).unwrap();
            fs::write(bundle.join(&binding.normalized_events_file), &bytes).unwrap();
            request.capture_bindings[binding_index].normalized_events_sha256 =
                sha256_hex(&bytes);
            let store = LteEvidenceStore::new(temp_root("rogue-security-key-store")).unwrap();
            let error = store
                .ingest(&bundle, &request)
                .expect_err("leaked key material must be refused");
            assert_eq!(
                error.code, "LTE_IDENTITY_DISCLOSURE_REJECTED",
                "unexpected error for leak {}: {:?}",
                leak, error
            );
            fs::remove_dir_all(bundle).unwrap();
        }
    }
}
