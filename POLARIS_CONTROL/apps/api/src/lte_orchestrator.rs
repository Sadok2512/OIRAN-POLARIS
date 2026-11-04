use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub const EVIDENCE_SCHEMA: &str = "oiran-polaris.lte-e2e-evidence.v1";
pub const PROFILE_ID: &str = "LTE-SRSUE-TEST-01";
pub const SCENARIO_ID: &str = "lte-e2e-certification-v1";
pub const MAX_RUN_MS: u64 = 300_000;
pub const OIRAN_INGESTION_SCHEMA: &str = "oiran.lte-evidence-ingestion.v1";
pub const CAPTURE_RELEASE_SCHEMA: &str = "polaris.oiran-lte-capture-release.v1";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunState {
    Idle,
    EnbStarting,
    S1Ready,
    UeStarting,
    Attached,
    IpReady,
    TrafficRunning,
    Stopping,
    Clean,
}

impl RunState {
    pub fn terminal(self) -> bool {
        self == Self::Clean
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunOutcome {
    Completed,
    Failed,
    Cancelled,
    RecoveryBlocked,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StepState {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct Observation {
    pub sequence: u64,
    pub observed_at: String,
    pub source_kind: String,
    pub source_sha256: String,
    pub validity: String,
    pub sanitization_state: String,
    pub measurements: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct StepEvidence {
    pub index: u8,
    #[serde(rename = "type")]
    pub kind: String,
    pub state: StepState,
    pub started_at: Option<String>,
    pub ended_at: Option<String>,
    pub reason_code: Option<String>,
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub measurements: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct CaptureRef {
    pub plane: String,
    pub source_file_sha256: String,
    pub first_frame: u64,
    pub last_frame: u64,
    pub decoder_version: String,
    #[serde(alias = "schema_version")]
    pub event_schema_version: String,
    pub sanitization_state: String,
}

/// Capture proof supplied by the trusted OIRAN finalization boundary.  It is
/// deliberately richer than the public capture_ref: provenance is validated
/// here and only the OIRAN 2.7.1 allowlisted fields are emitted.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ObservedCaptureProof {
    pub capture_ref: CaptureRef,
    pub observed_at: String,
    pub provenance: String,
    pub rat: String,
    #[serde(default)]
    pub session_refs: Vec<String>,
    pub source_file: String,
    pub normalized_events_file: String,
    pub normalized_events_sha256: String,
    pub decoder_name: String,
    pub endpoint_roles: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEnvelopeInput {
    pub bundle_id: String,
    pub capture_proofs: Vec<ObservedCaptureProof>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEnvelopeRequest {
    pub bundle_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceFinalizeRequest {
    pub release_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct AuthorizedCaptureRelease {
    interface: String,
    proof: ObservedCaptureProof,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct AuthorizedEvidenceRelease {
    schema_version: String,
    release_id: String,
    run_id: String,
    profile_id: String,
    scenario_id: String,
    rat: String,
    run_started_at: String,
    run_ended_at: String,
    final_state: String,
    authorization_state: String,
    captures: Vec<AuthorizedCaptureRelease>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ObservedEvidenceManifest {
    schema_version: String,
    run_id: String,
    profile_id: String,
    scenario_id: String,
    capture_proofs: Vec<ObservedCaptureProof>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct OiranCaptureBinding {
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

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct CanonicalLteEvidence {
    pub schema_version: String,
    pub run_id: String,
    pub profile_id: String,
    pub scenario_id: String,
    pub started_at: String,
    pub ended_at: String,
    pub final_state: String,
    pub steps: Vec<StepEvidence>,
    pub capture_refs: Vec<CaptureRef>,
    pub cleanup: CleanupEvidence,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct OiranEvidenceEnvelope {
    pub schema_version: String,
    pub bundle_id: String,
    pub evidence: CanonicalLteEvidence,
    pub capture_bindings: Vec<OiranCaptureBinding>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub struct CleanupEvidence {
    pub srsue_stopped: bool,
    pub srsenb_stopped: bool,
    pub sidecars_removed: bool,
    pub epc_healthy: bool,
    pub dumpcaps_preserved: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct RunRecord {
    pub schema_version: String,
    pub run_id: String,
    pub grant_id: String,
    pub profile_id: String,
    pub scenario_id: String,
    pub state: RunState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intended_state: Option<RunState>,
    pub outcome: Option<RunOutcome>,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub created_at_epoch_ms: u64,
    pub hard_deadline_epoch_ms: u64,
    pub cancel_requested: bool,
    pub cleanup_required: bool,
    pub operation_id: Option<String>,
    pub idempotency_key_sha256: String,
    pub steps: Vec<StepEvidence>,
    pub observations: Vec<Observation>,
    pub capture_refs: Vec<CaptureRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_bundle_id: Option<String>,
    pub cleanup: CleanupEvidence,
}

impl RunRecord {
    pub fn public_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "profile_id": self.profile_id,
            "scenario_id": self.scenario_id,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "deadline_at_epoch_ms": self.hard_deadline_epoch_ms,
            "evidence_url": format!("/api/v1/lte/runs/{}", self.run_id),
            "state": self.state,
            "intended_state": self.intended_state,
            "final_state": self.outcome,
            "cancel_requested": self.cancel_requested,
            "cleanup_required": self.cleanup_required,
            "steps": self.steps,
            "capture_refs": self.capture_refs,
            "evidence_bundle_id": self.evidence_bundle_id,
            "cleanup": self.cleanup,
        })
    }
}

#[derive(Deserialize, Serialize)]
struct StoreDocument {
    schema_version: u8,
    checksum_sha256: String,
    runs: Vec<RunRecord>,
}

#[derive(Clone, Debug)]
pub struct RunStore {
    path: PathBuf,
    runs: Vec<RunRecord>,
}

impl RunStore {
    pub fn load(path: PathBuf) -> Result<Self, String> {
        let mut store = match fs::read(&path) {
            Ok(bytes) => {
                let document: StoreDocument =
                    serde_json::from_slice(&bytes).map_err(|_| "LTE_RUN_STORE_INVALID")?;
                if document.schema_version != 2
                    || checksum(&document.runs)? != document.checksum_sha256
                {
                    return Err("LTE_RUN_STORE_CHECKSUM_INVALID".into());
                }
                Self {
                    path,
                    runs: document.runs,
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Self { path, runs: vec![] }
            }
            Err(_) => return Err("LTE_RUN_STORE_UNREADABLE".into()),
        };
        let mut changed = false;
        for run in &mut store.runs {
            if !run.state.terminal() {
                run.state = RunState::Stopping;
                run.outcome = Some(RunOutcome::RecoveryBlocked);
                run.cancel_requested = true;
                run.cleanup_required = true;
                run.operation_id = Some(format!("recovery-cleanup-{}", run.run_id));
                run.intended_state = Some(RunState::Stopping);
                changed = true;
            }
        }
        if changed {
            store.persist()?;
        }
        Ok(store)
    }

    pub fn records(&self) -> &[RunRecord] {
        &self.runs
    }

    pub fn create(
        &mut self,
        run_id: String,
        grant_id: String,
        now_ms: u64,
        grant_expiry_ms: u64,
        idempotency_key: &str,
    ) -> Result<(RunRecord, bool), String> {
        let key = hash(idempotency_key.as_bytes());
        if let Some(existing) = self
            .runs
            .iter()
            .find(|run| run.idempotency_key_sha256 == key)
        {
            return Ok((existing.clone(), true));
        }
        if self.runs.iter().any(|run| !run.state.terminal()) {
            return Err("LTE_RUN_ALREADY_ACTIVE".into());
        }
        let hard_deadline_epoch_ms = grant_expiry_ms.min(now_ms.saturating_add(MAX_RUN_MS));
        let run = RunRecord {
            schema_version: EVIDENCE_SCHEMA.into(),
            run_id,
            grant_id,
            profile_id: PROFILE_ID.into(),
            scenario_id: SCENARIO_ID.into(),
            state: RunState::Idle,
            intended_state: None,
            outcome: None,
            started_at: timestamp(now_ms),
            ended_at: None,
            created_at_epoch_ms: now_ms,
            hard_deadline_epoch_ms,
            cancel_requested: false,
            cleanup_required: false,
            operation_id: None,
            idempotency_key_sha256: key,
            steps: canonical_steps(),
            observations: vec![],
            capture_refs: vec![],
            evidence_bundle_id: None,
            cleanup: CleanupEvidence::default(),
        };
        self.runs.push(run.clone());
        self.persist()?;
        Ok((run, false))
    }

    pub fn get(&self, run_id: &str) -> Option<&RunRecord> {
        self.runs.iter().find(|run| run.run_id == run_id)
    }

    pub fn request_cancel(&mut self, run_id: &str) -> Result<RunRecord, String> {
        let run = self.run_mut(run_id)?;
        run.cancel_requested = true;
        if !run.state.terminal() {
            run.cleanup_required = true;
        }
        let result = run.clone();
        self.persist()?;
        Ok(result)
    }

    pub fn intent(
        &mut self,
        run_id: &str,
        state: RunState,
        operation_id: String,
        step: usize,
        now_ms: u64,
    ) -> Result<(), String> {
        let run = self.run_mut(run_id)?;
        run.intended_state = Some(state);
        run.operation_id = Some(operation_id);
        run.cleanup_required = state == RunState::Stopping;
        let item = run.steps.get_mut(step).ok_or("LTE_RUN_STEP_INVALID")?;
        item.state = StepState::Running;
        item.started_at.get_or_insert_with(|| timestamp(now_ms));
        self.persist()
    }

    pub fn advance(&mut self, run_id: &str, state: RunState) -> Result<(), String> {
        let run = self.run_mut(run_id)?;
        if run.intended_state.as_ref() != Some(&state) {
            return Err("LTE_RUN_STATE_PROOF_MISSING".into());
        }
        run.state = state;
        run.intended_state = None;
        run.operation_id = None;
        self.persist()
    }

    pub fn observe(
        &mut self,
        run_id: &str,
        step: usize,
        observation: Observation,
        now_ms: u64,
    ) -> Result<(), String> {
        let run = self.run_mut(run_id)?;
        if run.observations.len() >= 128 {
            return Err("LTE_EVIDENCE_LIMIT_REACHED".into());
        }
        let source_kind = observation.source_kind.clone();
        let measurements = observation.measurements.clone();
        run.observations.push(observation);
        let item = run.steps.get_mut(step).ok_or("LTE_RUN_STEP_INVALID")?;
        if let Some(values) = item.measurements.as_object_mut() {
            values.insert(source_kind, measurements);
        }
        item.state = StepState::Completed;
        item.ended_at = Some(timestamp(now_ms));
        self.persist()
    }

    pub fn record_step_diagnostic(
        &mut self,
        run_id: &str,
        step: usize,
        observation: Observation,
    ) -> Result<(), String> {
        let run = self.run_mut(run_id)?;
        if run.observations.len() >= 128 {
            return Err("LTE_EVIDENCE_LIMIT_REACHED".into());
        }
        let source_kind = observation.source_kind.clone();
        let measurements = observation.measurements.clone();
        run.observations.push(observation);
        let item = run.steps.get_mut(step).ok_or("LTE_RUN_STEP_INVALID")?;
        item.measurements
            .as_object_mut()
            .ok_or("LTE_EVIDENCE_STEP_MEASUREMENTS_INVALID")?
            .insert(source_kind, measurements);
        self.persist()
    }

    pub fn fail_step(
        &mut self,
        run_id: &str,
        step: usize,
        reason: &str,
        now_ms: u64,
    ) -> Result<(), String> {
        let run = self.run_mut(run_id)?;
        let item = run.steps.get_mut(step).ok_or("LTE_RUN_STEP_INVALID")?;
        item.state = StepState::Failed;
        item.reason_code = Some(reason.into());
        item.ended_at = Some(timestamp(now_ms));
        run.state = RunState::Stopping;
        run.outcome = Some(RunOutcome::Failed);
        run.cleanup_required = true;
        run.operation_id = None;
        run.intended_state = None;
        self.persist()
    }

    pub fn fail_active_step(
        &mut self,
        run_id: &str,
        reason: &str,
        now_ms: u64,
    ) -> Result<(), String> {
        let run = self.run_mut(run_id)?;
        if let Some(item) = run
            .steps
            .iter_mut()
            .find(|item| item.state == StepState::Running)
        {
            item.state = StepState::Failed;
            item.reason_code = Some(reason.into());
            item.ended_at = Some(timestamp(now_ms));
        }
        run.state = RunState::Stopping;
        run.outcome = Some(RunOutcome::Failed);
        run.cleanup_required = true;
        run.operation_id = None;
        run.intended_state = None;
        self.persist()
    }

    pub fn finalize(
        &mut self,
        run_id: &str,
        outcome: RunOutcome,
        cleanup: CleanupEvidence,
        now_ms: u64,
    ) -> Result<(), String> {
        let clean = cleanup.srsue_stopped
            && cleanup.srsenb_stopped
            && cleanup.sidecars_removed
            && cleanup.epc_healthy
            && cleanup.dumpcaps_preserved;
        let run = self.run_mut(run_id)?;
        run.cleanup = cleanup;
        run.ended_at = Some(timestamp(now_ms));
        run.operation_id = None;
        run.intended_state = None;
        if clean {
            run.state = RunState::Clean;
            run.outcome = Some(outcome);
            run.cleanup_required = false;
        } else {
            run.state = RunState::Stopping;
            run.outcome = Some(RunOutcome::RecoveryBlocked);
            run.cleanup_required = true;
        }
        self.persist()
    }

    pub fn publish_capture_refs(
        &mut self,
        run_id: &str,
        bundle_id: &str,
        refs: Vec<CaptureRef>,
    ) -> Result<bool, String> {
        validate_capture_refs(&refs)?;
        if !safe_id(bundle_id) {
            return Err("LTE_EVIDENCE_BUNDLE_ID_INVALID".into());
        }
        let run = self.run_mut(run_id)?;
        if run.state != RunState::Clean
            || !matches!(
                run.outcome,
                Some(RunOutcome::Completed | RunOutcome::Failed | RunOutcome::Cancelled)
            )
        {
            return Err("LTE_EVIDENCE_RUN_NOT_ADMISSIBLE".into());
        }
        if run.outcome == Some(RunOutcome::Completed) && !capture_refs_complete(&refs) {
            return Err("LTE_EVIDENCE_REQUIRED_PLANE_MISSING".into());
        }
        if let Some(existing) = &run.evidence_bundle_id {
            return if existing == bundle_id && run.capture_refs == refs {
                Ok(true)
            } else {
                Err("LTE_EVIDENCE_PUBLICATION_CONFLICT".into())
            };
        }
        run.capture_refs = refs;
        run.evidence_bundle_id = Some(bundle_id.into());
        for (step, plane) in [
            (2_usize, "S1_MME"),
            (4, "S1_MME"),
            (8, "S1_U"),
            (9, "S1_U"),
            (10, "S11"),
        ] {
            let reference = format!("capture:{plane}");
            if let Some(item) = run.steps.get_mut(step) {
                if !item.evidence_refs.contains(&reference) {
                    item.evidence_refs.push(reference);
                }
            }
        }
        self.persist()?;
        Ok(false)
    }

    fn run_mut(&mut self, id: &str) -> Result<&mut RunRecord, String> {
        self.runs
            .iter_mut()
            .find(|run| run.run_id == id)
            .ok_or_else(|| "LTE_RUN_NOT_FOUND".into())
    }
    fn persist(&self) -> Result<(), String> {
        let doc = StoreDocument {
            schema_version: 2,
            checksum_sha256: checksum(&self.runs)?,
            runs: self.runs.clone(),
        };
        atomic_write_0600(
            &self.path,
            &serde_json::to_vec_pretty(&doc).map_err(|_| "LTE_RUN_STORE_WRITE_FAILED")?,
        )
    }
}

pub fn validate_capture_refs(refs: &[CaptureRef]) -> Result<(), String> {
    // A failed/cancelled run may legitimately have only the planes observed
    // before cleanup. Empty, duplicate, unsupported or unapproved evidence is
    // still rejected; a successful run separately requires all three planes.
    let supported = ["S1_MME", "S11", "S1_U"];
    if refs.is_empty() {
        return Err("LTE_EVIDENCE_NO_OBSERVED_CAPTURE".into());
    }
    let mut planes = BTreeSet::new();
    for reference in refs {
        if !supported.contains(&reference.plane.as_str()) {
            return Err("LTE_EVIDENCE_PLANE_UNSUPPORTED".into());
        }
        if !planes.insert(reference.plane.as_str()) {
            return Err("LTE_EVIDENCE_PLANE_DUPLICATE".into());
        }
        if reference.source_file_sha256.len() != 64
            || !reference
                .source_file_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || reference.first_frame == 0
            || reference.first_frame > reference.last_frame
            || reference.decoder_version.trim().is_empty()
            || reference.event_schema_version.trim().is_empty()
        {
            return Err("LTE_EVIDENCE_CAPTURE_REF_INVALID".into());
        }
        if reference.sanitization_state != "SANITIZED_APPROVED" {
            return Err("LTE_EVIDENCE_NOT_APPROVED".into());
        }
    }
    Ok(())
}

fn capture_refs_complete(refs: &[CaptureRef]) -> bool {
    let planes = refs
        .iter()
        .map(|reference| reference.plane.as_str())
        .collect::<BTreeSet<_>>();
    ["S1_MME", "S11", "S1_U"]
        .into_iter()
        .all(|plane| planes.contains(plane))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_relative_file(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn safe_id(value: &str) -> bool {
    (3..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "LTE_EVIDENCE_FILE_UNAVAILABLE")?;
    if !metadata.file_type().is_file() {
        return Err("LTE_EVIDENCE_FILE_UNSAFE".into());
    }
    let mut file = fs::File::open(path).map_err(|_| "LTE_EVIDENCE_FILE_UNAVAILABLE")?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| "LTE_EVIDENCE_FILE_READ_FAILED")?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn confined_regular_file(bundle: &Path, relative: &str) -> Result<PathBuf, String> {
    if !safe_relative_file(relative) {
        return Err("LTE_EVIDENCE_BUNDLE_PATH_REJECTED".into());
    }
    let candidate = bundle.join(relative);
    let metadata = fs::symlink_metadata(&candidate).map_err(|_| "LTE_EVIDENCE_FILE_UNAVAILABLE")?;
    if !metadata.file_type().is_file() {
        return Err("LTE_EVIDENCE_FILE_UNSAFE".into());
    }
    let canonical = candidate
        .canonicalize()
        .map_err(|_| "LTE_EVIDENCE_FILE_UNAVAILABLE")?;
    if !canonical.starts_with(bundle) {
        return Err("LTE_EVIDENCE_BUNDLE_PATH_REJECTED".into());
    }
    Ok(canonical)
}

fn run_outcome_name(outcome: Option<RunOutcome>) -> Option<&'static str> {
    match outcome {
        Some(RunOutcome::Completed) => Some("COMPLETED"),
        Some(RunOutcome::Failed) => Some("FAILED"),
        Some(RunOutcome::Cancelled) => Some("CANCELLED"),
        _ => None,
    }
}

fn privacy_safe_value(value: &serde_json::Value) -> bool {
    const FORBIDDEN: [&str; 10] = [
        "imsi",
        "suci",
        "guti",
        "tmsi",
        "imei",
        "imeisv",
        "msisdn",
        "opc",
        "subscriber_id",
        "subscriber_identity",
    ];
    // 0.29.16: single lock-down exception for the privacy contract agreed
    // with OIRAN 2.7.7. A field whose JSON key is literally
    // `subscriber_pseudonym` is accepted ONLY when its value matches the
    // HMAC output format `psn-` + 32 lowercase hex characters. An object
    // whose `name` field equals `subscriber_pseudonym` or
    // `identity_pseudonym` (OIRAN NamedValue / InformationElement shape)
    // must likewise carry a `value` field matching the same regex. Every
    // other blacklist rule stays in force.
    fn is_valid_psn(text: &str) -> bool {
        if text.len() != 36 {
            return false;
        }
        let Some(suffix) = text.strip_prefix("psn-") else {
            return false;
        };
        suffix.len() == 32
            && suffix
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    }
    const PSEUDONYM_NAMES: [&str; 2] = ["subscriber_pseudonym", "identity_pseudonym"];
    match value {
        serde_json::Value::Object(map) => {
            // NamedValue / InformationElement shape: when `name` labels this
            // record as a pseudonym, the sibling `value` must match the
            // locked format or the whole record is rejected.
            if let Some(name_str) = map.get("name").and_then(serde_json::Value::as_str) {
                if PSEUDONYM_NAMES.contains(&name_str) {
                    let Some(serde_json::Value::String(v)) = map.get("value") else {
                        return false;
                    };
                    if !is_valid_psn(v) {
                        return false;
                    }
                }
            }
            map.iter().all(|(key, value)| {
                let lower = key.to_ascii_lowercase();
                if PSEUDONYM_NAMES.contains(&lower.as_str()) {
                    // Direct `{"subscriber_pseudonym": "psn-..."}` or
                    // `{"identity_pseudonym": "psn-..."}` shape: the value
                    // must be a string matching the regex. No recursion
                    // beyond that, since the string carries no nested
                    // material.
                    return matches!(value, serde_json::Value::String(v) if is_valid_psn(v));
                }
                !FORBIDDEN.iter().any(|needle| lower.contains(needle))
                    && !matches!(lower.as_str(), "k" | "key" | "op" | "authentication_key")
                    && privacy_safe_value(value)
            })
        }
        serde_json::Value::Array(values) => values.iter().all(privacy_safe_value),
        serde_json::Value::String(value) => {
            let value = value.to_ascii_lowercase();
            let compact = value
                .chars()
                .filter(|character| character.is_ascii_hexdigit())
                .count();
            let decimal_identity = value.chars().all(|character| character.is_ascii_digit())
                && (14..=16).contains(&value.len());
            let secret_hex = compact == value.len() && value.len() == 32;
            !FORBIDDEN.iter().any(|needle| value.contains(needle))
                && !decimal_identity
                && !secret_hex
        }
        serde_json::Value::Number(value) => {
            let value = value.to_string();
            !(value.chars().all(|character| character.is_ascii_digit())
                && (14..=16).contains(&value.len()))
        }
        _ => true,
    }
}

fn scan_normalized_events(path: &Path) -> Result<(), String> {
    let file = fs::File::open(path).map_err(|_| "LTE_EVIDENCE_FILE_UNAVAILABLE")?;
    let mut total = 0_u64;
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|_| "LTE_EVIDENCE_FILE_READ_FAILED")?;
        total = total.saturating_add(line.len() as u64);
        if total > 64 * 1024 * 1024 {
            return Err("LTE_EVIDENCE_EVENTS_TOO_LARGE".into());
        }
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(&line).map_err(|_| "LTE_EVIDENCE_EVENTS_INVALID")?;
        if !privacy_safe_value(&value) {
            return Err("LTE_EVIDENCE_PRIVACY_REJECTED".into());
        }
    }
    Ok(())
}

fn copy_verified_file(source: &Path, destination: &Path) -> Result<(), String> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|_| "LTE_EVIDENCE_BUNDLE_WRITE_FAILED")?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|_| "LTE_EVIDENCE_BUNDLE_WRITE_FAILED")?;
    }
    let mut input = fs::File::open(source).map_err(|_| "LTE_EVIDENCE_FILE_UNAVAILABLE")?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .map_err(|_| "LTE_EVIDENCE_BUNDLE_WRITE_FAILED")?;
    std::io::copy(&mut input, &mut output).map_err(|_| "LTE_EVIDENCE_BUNDLE_WRITE_FAILED")?;
    output
        .sync_all()
        .map_err(|_| "LTE_EVIDENCE_BUNDLE_WRITE_FAILED".to_string())
}

fn existing_finalized_bundle(
    bundle_root: &Path,
    bundle_id: &str,
    expected_manifest: &[u8],
    run: &RunRecord,
) -> Result<Option<EvidenceEnvelopeInput>, String> {
    let bundle = bundle_root.join(bundle_id);
    if !bundle.exists() {
        return Ok(None);
    }
    let existing = fs::read(bundle.join("polaris-evidence-proof.json"))
        .map_err(|_| "LTE_EVIDENCE_FINALIZATION_CONFLICT")?;
    if existing != expected_manifest {
        return Err("LTE_EVIDENCE_FINALIZATION_CONFLICT".into());
    }
    load_observed_evidence_bundle(
        bundle_root,
        EvidenceEnvelopeRequest {
            bundle_id: bundle_id.into(),
        },
        run,
    )
    .map(Some)
}

/// Convert a server-owned, explicitly approved sanitized capture release into
/// the immutable bundle consumed by the existing POLARIS -> OIRAN contract.
/// The HTTP caller controls only an opaque release id; paths, hashes and proof
/// metadata are re-read and verified below.
pub fn finalize_authorized_evidence_release(
    release_root: &Path,
    bundle_root: &Path,
    request: EvidenceFinalizeRequest,
    run: &RunRecord,
) -> Result<EvidenceEnvelopeInput, String> {
    if !safe_id(&request.release_id) {
        return Err("LTE_EVIDENCE_RELEASE_ID_INVALID".into());
    }
    let canonical_release_root = release_root
        .canonicalize()
        .map_err(|_| "LTE_EVIDENCE_RELEASE_ROOT_UNAVAILABLE")?;
    let release_dir = canonical_release_root.join(&request.release_id);
    let canonical_release_dir = release_dir
        .canonicalize()
        .map_err(|_| "LTE_EVIDENCE_RELEASE_UNAVAILABLE")?;
    if !canonical_release_dir.starts_with(&canonical_release_root) {
        return Err("LTE_EVIDENCE_RELEASE_PATH_REJECTED".into());
    }
    let release_path = canonical_release_dir.join("oiran-lte-capture-release.json");
    let metadata = fs::symlink_metadata(&release_path)
        .map_err(|_| "LTE_EVIDENCE_RELEASE_MANIFEST_UNAVAILABLE")?;
    if !metadata.file_type().is_file() || metadata.len() > 1024 * 1024 {
        return Err("LTE_EVIDENCE_RELEASE_MANIFEST_UNSAFE".into());
    }
    let release: AuthorizedEvidenceRelease = serde_json::from_slice(
        &fs::read(&release_path).map_err(|_| "LTE_EVIDENCE_RELEASE_MANIFEST_UNAVAILABLE")?,
    )
    .map_err(|_| "LTE_EVIDENCE_RELEASE_MANIFEST_INVALID")?;
    let ended_at = run
        .ended_at
        .as_deref()
        .ok_or("LTE_EVIDENCE_RUN_NOT_ADMISSIBLE")?;
    if release.schema_version != CAPTURE_RELEASE_SCHEMA
        || release.release_id != request.release_id
        || release.run_id != run.run_id
        || release.profile_id != run.profile_id
        || release.scenario_id != run.scenario_id
        || release.rat != "LTE"
        || release.run_started_at != run.started_at
        || release.run_ended_at != ended_at
        || Some(release.final_state.as_str()) != run_outcome_name(run.outcome)
    {
        return Err("LTE_EVIDENCE_RELEASE_SCOPE_MISMATCH".into());
    }
    if release.authorization_state != "SANITIZED_APPROVED" {
        return Err("LTE_EVIDENCE_RELEASE_NOT_APPROVED".into());
    }
    if run.state != RunState::Clean || run.cleanup_required {
        return Err("LTE_EVIDENCE_RUN_NOT_ADMISSIBLE".into());
    }
    let release_json =
        serde_json::to_value(&release).map_err(|_| "LTE_EVIDENCE_RELEASE_MANIFEST_INVALID")?;
    if !privacy_safe_value(&release_json) {
        return Err("LTE_EVIDENCE_PRIVACY_REJECTED".into());
    }

    let mut proofs = Vec::with_capacity(release.captures.len());
    let mut files = BTreeSet::new();
    for capture in release.captures {
        if capture.interface != capture.proof.capture_ref.plane {
            return Err("LTE_EVIDENCE_INTERFACE_MISMATCH".into());
        }
        for relative in [
            capture.proof.source_file.as_str(),
            capture.proof.normalized_events_file.as_str(),
        ] {
            if !files.insert(relative.to_string()) {
                return Err("LTE_EVIDENCE_FILE_DUPLICATE".into());
            }
        }
        let source = confined_regular_file(&canonical_release_dir, &capture.proof.source_file)?;
        let events = confined_regular_file(
            &canonical_release_dir,
            &capture.proof.normalized_events_file,
        )?;
        if sha256_file(&source)? != capture.proof.capture_ref.source_file_sha256
            || sha256_file(&events)? != capture.proof.normalized_events_sha256
        {
            return Err("LTE_EVIDENCE_FILE_HASH_MISMATCH".into());
        }
        scan_normalized_events(&events)?;
        proofs.push(capture.proof);
    }
    validate_capture_refs(
        &proofs
            .iter()
            .map(|proof| proof.capture_ref.clone())
            .collect::<Vec<_>>(),
    )?;
    if run.outcome == Some(RunOutcome::Completed)
        && !capture_refs_complete(
            &proofs
                .iter()
                .map(|proof| proof.capture_ref.clone())
                .collect::<Vec<_>>(),
        )
    {
        return Err("LTE_EVIDENCE_REQUIRED_PLANE_MISSING".into());
    }

    fs::create_dir_all(bundle_root).map_err(|_| "LTE_EVIDENCE_BUNDLE_ROOT_UNAVAILABLE")?;
    fs::set_permissions(bundle_root, fs::Permissions::from_mode(0o700))
        .map_err(|_| "LTE_EVIDENCE_BUNDLE_ROOT_UNAVAILABLE")?;
    let canonical_bundle_root = bundle_root
        .canonicalize()
        .map_err(|_| "LTE_EVIDENCE_BUNDLE_ROOT_UNAVAILABLE")?;
    let bundle_digest = hash(format!("{}:{}", run.run_id, request.release_id).as_bytes());
    let bundle_id = format!("lte-bundle-{bundle_digest}");
    let observed = ObservedEvidenceManifest {
        schema_version: "polaris.oiran-observed-capture-proof.v1".into(),
        run_id: run.run_id.clone(),
        profile_id: run.profile_id.clone(),
        scenario_id: run.scenario_id.clone(),
        capture_proofs: proofs.clone(),
    };
    let manifest_bytes =
        serde_json::to_vec_pretty(&observed).map_err(|_| "LTE_EVIDENCE_MANIFEST_INVALID")?;
    if let Some(existing) =
        existing_finalized_bundle(&canonical_bundle_root, &bundle_id, &manifest_bytes, run)?
    {
        return Ok(existing);
    }

    let staging =
        canonical_bundle_root.join(format!(".{bundle_id}.staging-{}", std::process::id()));
    if staging.exists() {
        return Err("LTE_EVIDENCE_FINALIZATION_BUSY".into());
    }
    fs::create_dir(&staging).map_err(|_| "LTE_EVIDENCE_BUNDLE_WRITE_FAILED")?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))
        .map_err(|_| "LTE_EVIDENCE_BUNDLE_WRITE_FAILED")?;
    let result = (|| {
        for proof in &proofs {
            let source = confined_regular_file(&canonical_release_dir, &proof.source_file)?;
            let events =
                confined_regular_file(&canonical_release_dir, &proof.normalized_events_file)?;
            copy_verified_file(&source, &staging.join(&proof.source_file))?;
            copy_verified_file(&events, &staging.join(&proof.normalized_events_file))?;
        }
        atomic_write_0600(
            &staging.join("polaris-evidence-proof.json"),
            &manifest_bytes,
        )?;
        fs::File::open(&staging)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "LTE_EVIDENCE_BUNDLE_WRITE_FAILED")?;
        fs::rename(&staging, canonical_bundle_root.join(&bundle_id))
            .map_err(|_| "LTE_EVIDENCE_FINALIZATION_CONFLICT")?;
        fs::File::open(&canonical_bundle_root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "LTE_EVIDENCE_BUNDLE_WRITE_FAILED")?;
        load_observed_evidence_bundle(
            &canonical_bundle_root,
            EvidenceEnvelopeRequest {
                bundle_id: bundle_id.clone(),
            },
            run,
        )
    })();
    if result.is_err() && staging.exists() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

/// Load a proof set staged by the OIRAN capture finalizer. The HTTP caller
/// supplies only a bundle id; hashes and capture metadata come from a private,
/// server-owned manifest and are re-measured against the staged files.
pub fn load_observed_evidence_bundle(
    root: &Path,
    request: EvidenceEnvelopeRequest,
    run: &RunRecord,
) -> Result<EvidenceEnvelopeInput, String> {
    if !safe_id(&request.bundle_id) {
        return Err("LTE_EVIDENCE_BUNDLE_ID_INVALID".into());
    }
    let canonical_root = root
        .canonicalize()
        .map_err(|_| "LTE_EVIDENCE_BUNDLE_ROOT_UNAVAILABLE")?;
    let bundle = canonical_root.join(&request.bundle_id);
    let canonical_bundle = bundle
        .canonicalize()
        .map_err(|_| "LTE_EVIDENCE_BUNDLE_UNAVAILABLE")?;
    if !canonical_bundle.starts_with(&canonical_root) {
        return Err("LTE_EVIDENCE_BUNDLE_PATH_REJECTED".into());
    }
    let manifest_path = canonical_bundle.join("polaris-evidence-proof.json");
    let metadata =
        fs::symlink_metadata(&manifest_path).map_err(|_| "LTE_EVIDENCE_MANIFEST_UNAVAILABLE")?;
    if !metadata.file_type().is_file() || metadata.len() > 1024 * 1024 {
        return Err("LTE_EVIDENCE_MANIFEST_UNSAFE".into());
    }
    let manifest: ObservedEvidenceManifest = serde_json::from_slice(
        &fs::read(&manifest_path).map_err(|_| "LTE_EVIDENCE_MANIFEST_UNAVAILABLE")?,
    )
    .map_err(|_| "LTE_EVIDENCE_MANIFEST_INVALID")?;
    if manifest.schema_version != "polaris.oiran-observed-capture-proof.v1" {
        return Err("LTE_EVIDENCE_MANIFEST_SCHEMA_UNSUPPORTED".into());
    }
    if manifest.run_id != run.run_id
        || manifest.profile_id != run.profile_id
        || manifest.scenario_id != run.scenario_id
    {
        return Err("LTE_EVIDENCE_MANIFEST_SCOPE_MISMATCH".into());
    }
    for proof in &manifest.capture_proofs {
        if !safe_relative_file(&proof.source_file)
            || !safe_relative_file(&proof.normalized_events_file)
        {
            return Err("LTE_EVIDENCE_BUNDLE_PATH_REJECTED".into());
        }
        let source = confined_regular_file(&canonical_bundle, &proof.source_file)?;
        let events = confined_regular_file(&canonical_bundle, &proof.normalized_events_file)?;
        if sha256_file(&source)? != proof.capture_ref.source_file_sha256
            || sha256_file(&events)? != proof.normalized_events_sha256
        {
            return Err("LTE_EVIDENCE_FILE_HASH_MISMATCH".into());
        }
    }
    Ok(EvidenceEnvelopeInput {
        bundle_id: request.bundle_id,
        capture_proofs: manifest.capture_proofs,
    })
}

/// Build the OIRAN wrapper from a terminal, clean run and independently
/// observed, sanitized capture proofs. Failed/cancelled runs retain only the
/// planes actually observed; no capture reference is synthesized from state
/// or timestamps and only completed runs may claim a complete proof set.
pub fn build_oiran_evidence_envelope(
    run: &RunRecord,
    input: EvidenceEnvelopeInput,
) -> Result<OiranEvidenceEnvelope, String> {
    if run.state != RunState::Clean
        || !matches!(
            run.outcome,
            Some(RunOutcome::Completed | RunOutcome::Failed | RunOutcome::Cancelled)
        )
        || run.cleanup_required
        || run.ended_at.as_deref().map_or(true, str::is_empty)
        || !run.cleanup.srsue_stopped
        || !run.cleanup.srsenb_stopped
        || !run.cleanup.sidecars_removed
        || !run.cleanup.epc_healthy
        || !run.cleanup.dumpcaps_preserved
    {
        return Err("LTE_EVIDENCE_RUN_NOT_ADMISSIBLE".into());
    }
    if !safe_id(&input.bundle_id) {
        return Err("LTE_EVIDENCE_BUNDLE_ID_INVALID".into());
    }

    let capture_refs = input
        .capture_proofs
        .iter()
        .map(|proof| proof.capture_ref.clone())
        .collect::<Vec<_>>();
    validate_capture_refs(&capture_refs)?;
    if run.outcome == Some(RunOutcome::Completed) && !capture_refs_complete(&capture_refs) {
        return Err("LTE_EVIDENCE_REQUIRED_PLANE_MISSING".into());
    }

    let mut capture_bindings = Vec::with_capacity(input.capture_proofs.len());
    let mut provenance = serde_json::Map::new();
    let mut session_refs = BTreeSet::new();
    for (index, proof) in input.capture_proofs.iter().enumerate() {
        if proof.provenance != "OIRAN_SANITIZED_CAPTURE_MANIFEST"
            || proof.rat != "LTE"
            || !proof.observed_at.ends_with('Z')
            || proof.observed_at.len() < 20
            || !safe_relative_file(&proof.source_file)
            || !safe_relative_file(&proof.normalized_events_file)
            || !valid_sha256(&proof.normalized_events_sha256)
            || proof.decoder_name.trim().is_empty()
            || proof.capture_ref.event_schema_version != "1.5.0"
            || proof.endpoint_roles.is_empty()
        {
            return Err("LTE_EVIDENCE_PROVENANCE_INVALID".into());
        }
        for session_ref in &proof.session_refs {
            if !session_ref.starts_with("lte-session-") || !safe_id(session_ref) {
                return Err("LTE_EVIDENCE_SESSION_REF_INVALID".into());
            }
            session_refs.insert(session_ref.clone());
        }
        let evidence_ref = format!("capture:{}", proof.capture_ref.plane);
        provenance.insert(
            evidence_ref.clone(),
            serde_json::json!({
                "observed_at": proof.observed_at,
                "provenance": proof.provenance,
                "rat": proof.rat,
                "source_file_sha256": proof.capture_ref.source_file_sha256,
                "normalized_events_sha256": proof.normalized_events_sha256,
            }),
        );
        capture_bindings.push(OiranCaptureBinding {
            evidence_ref,
            capture_ref_index: index,
            source_file: proof.source_file.clone(),
            normalized_events_file: proof.normalized_events_file.clone(),
            normalized_events_sha256: proof.normalized_events_sha256.clone(),
            decoder_name: proof.decoder_name.clone(),
            decoder_version: proof.capture_ref.decoder_version.clone(),
            event_schema_version: proof.capture_ref.event_schema_version.clone(),
            endpoint_roles: proof.endpoint_roles.clone(),
        });
    }

    let available_planes = capture_refs
        .iter()
        .map(|reference| reference.plane.as_str())
        .collect::<BTreeSet<_>>();
    let mut steps = run.steps.clone();
    for (step_index, plane) in [
        (2_usize, "S1_MME"),
        (4, "S1_MME"),
        (8, "S1_U"),
        (9, "S1_U"),
        (10, "S11"),
    ] {
        if !available_planes.contains(plane) {
            continue;
        }
        if let Some(step) = steps.get_mut(step_index) {
            let evidence_ref = format!("capture:{plane}");
            if !step.evidence_refs.contains(&evidence_ref) {
                step.evidence_refs.push(evidence_ref);
            }
        }
    }
    let metadata = serde_json::json!({
        "rat": "LTE",
        "capture_provenance": provenance,
        "session_refs": session_refs.into_iter().collect::<Vec<_>>(),
    });
    let measurements = metadata
        .as_object()
        .cloned()
        .ok_or_else(|| "LTE_EVIDENCE_PROVENANCE_INVALID".to_string())?;
    if let Some(preflight) = steps.first_mut() {
        let current = preflight
            .measurements
            .as_object_mut()
            .ok_or_else(|| "LTE_EVIDENCE_STEP_MEASUREMENTS_INVALID".to_string())?;
        current.extend(measurements);
    }
    let valid_refs = capture_bindings
        .iter()
        .map(|binding| binding.evidence_ref.as_str())
        .collect::<BTreeSet<_>>();
    if steps
        .iter()
        .flat_map(|step| &step.evidence_refs)
        .any(|reference| {
            reference.starts_with("capture:") && !valid_refs.contains(reference.as_str())
        })
    {
        return Err("LTE_EVIDENCE_REF_UNRESOLVED".into());
    }

    Ok(OiranEvidenceEnvelope {
        schema_version: OIRAN_INGESTION_SCHEMA.into(),
        bundle_id: input.bundle_id,
        evidence: CanonicalLteEvidence {
            schema_version: EVIDENCE_SCHEMA.into(),
            run_id: run.run_id.clone(),
            profile_id: run.profile_id.clone(),
            scenario_id: run.scenario_id.clone(),
            started_at: run.started_at.clone(),
            ended_at: run.ended_at.clone().unwrap_or_default(),
            final_state: match run.outcome {
                Some(RunOutcome::Completed) => "COMPLETED",
                Some(RunOutcome::Failed) => "FAILED",
                Some(RunOutcome::Cancelled) => "CANCELLED",
                _ => return Err("LTE_EVIDENCE_RUN_NOT_ADMISSIBLE".into()),
            }
            .into(),
            steps,
            capture_refs,
            cleanup: run.cleanup.clone(),
        },
        capture_bindings,
    })
}

fn canonical_steps() -> Vec<StepEvidence> {
    [
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
    ]
    .into_iter()
    .enumerate()
    .map(|(index, kind)| StepEvidence {
        index: index as u8,
        kind: kind.into(),
        state: StepState::Pending,
        started_at: None,
        ended_at: None,
        reason_code: None,
        evidence_refs: vec![],
        measurements: serde_json::json!({}),
    })
    .collect()
}

fn checksum(runs: &[RunRecord]) -> Result<String, String> {
    serde_json::to_vec(runs)
        .map(|bytes| hash(&bytes))
        .map_err(|_| "LTE_RUN_STORE_WRITE_FAILED".into())
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(crate) fn timestamp(ms: u64) -> String {
    format!("{}.{:03}Z", unix_date_time(ms / 1000), ms % 1000)
}
fn unix_date_time(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let sod = seconds % 86_400;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}
fn atomic_write_0600(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| "LTE_RUN_STORE_WRITE_FAILED")?;
    }
    let tmp = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|_| "LTE_RUN_STORE_WRITE_FAILED")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "LTE_RUN_STORE_WRITE_FAILED")?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
        .map_err(|_| "LTE_RUN_STORE_WRITE_FAILED")?;
    fs::rename(&tmp, path).map_err(|_| "LTE_RUN_STORE_WRITE_FAILED")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(1);

    fn path(name: &str) -> PathBuf {
        let fixture_id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "polaris-lte-run-{name}-{}-{fixture_id}",
            std::process::id()
        ))
    }

    #[test]
    fn fixture_paths_are_unique_for_same_named_parallel_tests() {
        let first = path("envelope");
        let second = path("envelope");
        assert_ne!(first, second);
        assert_eq!(first.parent(), Some(std::env::temp_dir().as_path()));
        assert_eq!(second.parent(), Some(std::env::temp_dir().as_path()));
    }

    #[test]
    fn route_diagnostic_persists_before_a_failed_step() {
        let p = path("route-diagnostic");
        let mut store = RunStore::load(p.clone()).unwrap();
        let run_id = "lte-run-route-diagnostic-12345678";
        store
            .create(run_id.into(), "grant-test".into(), 1, 999_999, "idem")
            .unwrap();
        store
            .record_step_diagnostic(
                run_id,
                6,
                Observation {
                    sequence: 6,
                    observed_at: timestamp(2),
                    source_kind: "route_probe".into(),
                    source_sha256: "a".repeat(64),
                    validity: "VALID".into(),
                    sanitization_state: "SANITIZED".into(),
                    measurements: serde_json::json!({
                        "diagnostic":{"exit_code":2,"stdout":"","stderr":"Network is unreachable"},
                        "error_code":"LTE_UL_ROUTE_PROBE_FAILED"
                    }),
                },
            )
            .unwrap();
        store
            .fail_step(run_id, 6, "LTE_UL_ROUTE_PROBE_FAILED", 3)
            .unwrap();
        let run = store.get(run_id).unwrap();
        assert_eq!(run.steps[6].reason_code.as_deref(), Some("LTE_UL_ROUTE_PROBE_FAILED"));
        assert_eq!(run.steps[6].measurements["route_probe"]["diagnostic"]["exit_code"], 2);
        let _ = fs::remove_file(p);
    }
    #[test]
    fn ping_diagnostic_persists_before_failure_and_cleanup() {
        let p = path("ping-diagnostic"); let mut store = RunStore::load(p.clone()).unwrap(); let run_id = "lte-run-ping-diagnostic-12345678";
        store.create(run_id.into(), "grant-test".into(), 1, 999_999, "idem").unwrap();
        store.record_step_diagnostic(run_id, 6, Observation { sequence: 6, observed_at: timestamp(2), source_kind: "ping_runtime_diagnostic".into(), source_sha256: "b".repeat(64), validity: "VALID".into(), sanitization_state: "SANITIZED".into(), measurements: serde_json::json!({"evidence":{"ping":{"exit_code":1},"ue_link":{"exit_code":0},"ue_routes":{"exit_code":0},"srsue_log_tail":{"exit_code":0},"srsenb_log_tail":{"exit_code":0}},"error_code":"LTE_PING_FAILED"}) }).unwrap();
        store.fail_step(run_id, 6, "LTE_PING_FAILED", 3).unwrap(); let run = store.get(run_id).unwrap(); assert!(run.cleanup_required);
        for key in ["ping", "ue_link", "ue_routes", "srsue_log_tail", "srsenb_log_tail"] { assert!(run.steps[6].measurements["ping_runtime_diagnostic"]["evidence"].get(key).is_some(), "missing {key}"); }
        let _ = fs::remove_file(p);
    }

    #[test]
    fn iperf_diagnostic_persists_before_failure_and_cleanup() {
        let p = path("iperf-diagnostic");
        let mut store = RunStore::load(p.clone()).unwrap();
        let run_id = "lte-run-iperf-diagnostic-12345678";
        store
            .create(run_id.into(), "grant-test".into(), 1, 999_999, "idem")
            .unwrap();
        store
            .record_step_diagnostic(
                run_id,
                8,
                Observation {
                    sequence: 8,
                    observed_at: timestamp(2),
                    source_kind: "iperf_runtime_diagnostic".into(),
                    source_sha256: "c".repeat(64),
                    validity: "VALID".into(),
                    sanitization_state: "SANITIZED".into(),
                    measurements: serde_json::json!({
                        "diagnostic": {
                            "exit_code": 1,
                            "stdout": "unable to create a new stream",
                            "stderr": "Read-only file system"
                        },
                        "error_code": "LTE_TRAFFIC_COMMAND_FAILED"
                    }),
                },
            )
            .unwrap();
        store
            .fail_step(run_id, 8, "LTE_TRAFFIC_COMMAND_FAILED", 3)
            .unwrap();
        let run = store.get(run_id).unwrap();
        assert!(run.cleanup_required);
        assert_eq!(
            run.steps[8].measurements["iperf_runtime_diagnostic"]["diagnostic"]
                ["exit_code"],
            1
        );
        assert_eq!(
            run.steps[8].measurements["iperf_runtime_diagnostic"]["diagnostic"]["stderr"],
            "Read-only file system"
        );
        let _ = fs::remove_file(p);
    }

    fn capture(plane: &str) -> CaptureRef {
        CaptureRef {
            plane: plane.into(),
            source_file_sha256: "a".repeat(64),
            first_frame: 1,
            last_frame: 2,
            decoder_version: "test".into(),
            event_schema_version: "1.5.0".into(),
            sanitization_state: "SANITIZED_APPROVED".into(),
        }
    }
    fn capture_proof(plane: &str) -> ObservedCaptureProof {
        let mut endpoint_roles = BTreeMap::new();
        endpoint_roles.insert("192.0.2.1".into(), "SOURCE".into());
        endpoint_roles.insert("192.0.2.2".into(), "DESTINATION".into());
        ObservedCaptureProof {
            capture_ref: capture(plane),
            observed_at: "2026-11-01T09:00:00Z".into(),
            provenance: "OIRAN_SANITIZED_CAPTURE_MANIFEST".into(),
            rat: "LTE".into(),
            session_refs: vec!["lte-session-pseudonym-01".into()],
            source_file: format!("{}.pcapng", plane.to_ascii_lowercase()),
            normalized_events_file: format!("{}.events.jsonl", plane.to_ascii_lowercase()),
            normalized_events_sha256: "b".repeat(64),
            decoder_name: format!("decoder-{}", plane.to_ascii_lowercase()),
            endpoint_roles,
        }
    }
    fn completed_run(name: &str) -> RunRecord {
        terminal_run(name, RunOutcome::Completed)
    }
    fn terminal_run(name: &str, outcome: RunOutcome) -> RunRecord {
        let p = path(name);
        let _ = fs::remove_file(&p);
        let mut store = RunStore::load(p.clone()).unwrap();
        let run_id = format!("lte-run-{name}-12345678");
        store
            .create(
                run_id.clone(),
                "grant-test".into(),
                1,
                999_999,
                "idempotency-key-test",
            )
            .unwrap();
        store
            .finalize(
                &run_id,
                outcome,
                CleanupEvidence {
                    srsue_stopped: true,
                    srsenb_stopped: true,
                    sidecars_removed: true,
                    epc_healthy: true,
                    dumpcaps_preserved: true,
                },
                2,
            )
            .unwrap();
        let run = store.get(&run_id).unwrap().clone();
        let _ = fs::remove_file(p);
        run
    }
    #[test]
    fn oiran_wrapper_is_exact_and_derived_only_from_approved_observations() {
        let run = completed_run("envelope");
        let envelope = build_oiran_evidence_envelope(
            &run,
            EvidenceEnvelopeInput {
                bundle_id: "bundle-lte-approved-01".into(),
                capture_proofs: vec![
                    capture_proof("S1_MME"),
                    capture_proof("S11"),
                    capture_proof("S1_U"),
                ],
            },
        )
        .unwrap();
        assert_eq!(envelope.schema_version, OIRAN_INGESTION_SCHEMA);
        assert_eq!(envelope.evidence.schema_version, EVIDENCE_SCHEMA);
        assert_eq!(envelope.evidence.final_state, "COMPLETED");
        assert_eq!(envelope.evidence.capture_refs.len(), 3);
        for (index, binding) in envelope.capture_bindings.iter().enumerate() {
            assert_eq!(binding.capture_ref_index, index);
            assert_eq!(
                binding.decoder_version,
                envelope.evidence.capture_refs[index].decoder_version
            );
            assert_eq!(binding.event_schema_version, "1.5.0");
        }
        let json = serde_json::to_value(envelope).unwrap();
        assert!(json.get("rat").is_none());
        assert!(json["evidence"].get("grant_id").is_none());
        assert_eq!(json["evidence"]["steps"][0]["measurements"]["rat"], "LTE");
    }
    #[test]
    fn oiran_wrapper_fails_closed_for_unproved_or_inadmissible_evidence() {
        let good = || EvidenceEnvelopeInput {
            bundle_id: "bundle-lte-approved-02".into(),
            capture_proofs: vec![
                capture_proof("S1_MME"),
                capture_proof("S11"),
                capture_proof("S1_U"),
            ],
        };
        let run = completed_run("negative-clean");
        let mut missing = good();
        missing.capture_proofs.pop();
        assert_eq!(
            build_oiran_evidence_envelope(&run, missing).unwrap_err(),
            "LTE_EVIDENCE_REQUIRED_PLANE_MISSING"
        );
        let mut raw = good();
        raw.capture_proofs[0].capture_ref.sanitization_state = "RAW".into();
        assert_eq!(
            build_oiran_evidence_envelope(&run, raw).unwrap_err(),
            "LTE_EVIDENCE_NOT_APPROVED"
        );
        let mut five_g = good();
        five_g.capture_proofs[0].capture_ref.plane = "N2".into();
        assert_eq!(
            build_oiran_evidence_envelope(&run, five_g).unwrap_err(),
            "LTE_EVIDENCE_PLANE_UNSUPPORTED"
        );
        let mut identity = good();
        identity.capture_proofs[0].session_refs = vec!["001010000000001".into()];
        assert_eq!(
            build_oiran_evidence_envelope(&run, identity).unwrap_err(),
            "LTE_EVIDENCE_SESSION_REF_INVALID"
        );
    }
    #[test]
    fn terminal_failed_and_cancelled_runs_publish_only_observed_planes() {
        for (name, outcome, final_state) in [
            ("timeout-proof", RunOutcome::Failed, "FAILED"),
            ("cancelled-proof", RunOutcome::Cancelled, "CANCELLED"),
        ] {
            let run = terminal_run(name, outcome);
            let envelope = build_oiran_evidence_envelope(
                &run,
                EvidenceEnvelopeInput {
                    bundle_id: format!("bundle-{name}"),
                    capture_proofs: vec![capture_proof("S1_MME")],
                },
            )
            .unwrap();
            assert_eq!(envelope.evidence.final_state, final_state);
            assert_eq!(envelope.evidence.capture_refs.len(), 1);
            assert_eq!(envelope.evidence.capture_refs[0].plane, "S1_MME");
        }
    }

    #[test]
    fn completed_run_still_requires_all_three_planes() {
        let run = completed_run("complete-needs-three");
        assert_eq!(
            build_oiran_evidence_envelope(
                &run,
                EvidenceEnvelopeInput {
                    bundle_id: "bundle-complete-needs-three".into(),
                    capture_proofs: vec![capture_proof("S1_MME")],
                },
            )
            .unwrap_err(),
            "LTE_EVIDENCE_REQUIRED_PLANE_MISSING"
        );
    }
    #[test]
    fn staged_bundle_is_rehashed_and_operator_metadata_cannot_bypass_it() {
        let root = path("observed-bundle-root");
        let _ = fs::remove_dir_all(&root);
        let bundle_id = "bundle-server-observed-01";
        let bundle = root.join(bundle_id);
        fs::create_dir_all(&bundle).unwrap();
        let mut proofs = Vec::new();
        for plane in ["S1_MME", "S11", "S1_U"] {
            let source_file = format!("{plane}.pcapng");
            let events_file = format!("{plane}.events.jsonl");
            let source = format!("sanitized-{plane}").into_bytes();
            let events = format!("{{\"plane\":\"{plane}\"}}\n").into_bytes();
            fs::write(bundle.join(&source_file), &source).unwrap();
            fs::write(bundle.join(&events_file), &events).unwrap();
            let mut proof = capture_proof(plane);
            proof.source_file = source_file;
            proof.normalized_events_file = events_file;
            proof.capture_ref.source_file_sha256 = format!("{:x}", Sha256::digest(&source));
            proof.normalized_events_sha256 = format!("{:x}", Sha256::digest(&events));
            proofs.push(proof);
        }
        let manifest = ObservedEvidenceManifest {
            schema_version: "polaris.oiran-observed-capture-proof.v1".into(),
            run_id: "lte-run-envelope-12345678".into(),
            profile_id: PROFILE_ID.into(),
            scenario_id: SCENARIO_ID.into(),
            capture_proofs: proofs,
        };
        fs::write(
            bundle.join("polaris-evidence-proof.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let request = EvidenceEnvelopeRequest {
            bundle_id: bundle_id.into(),
        };
        let run = completed_run("envelope");
        assert_eq!(
            load_observed_evidence_bundle(&root, request.clone(), &run)
                .unwrap()
                .capture_proofs
                .len(),
            3
        );
        fs::write(bundle.join("S11.pcapng"), b"post-approval mutation").unwrap();
        assert_eq!(
            load_observed_evidence_bundle(&root, request.clone(), &run).unwrap_err(),
            "LTE_EVIDENCE_FILE_HASH_MISMATCH"
        );
        fs::write(bundle.join("S11.pcapng"), b"sanitized-S11").unwrap();
        let another_run = completed_run("different");
        assert_eq!(
            load_observed_evidence_bundle(&root, request, &another_run).unwrap_err(),
            "LTE_EVIDENCE_MANIFEST_SCOPE_MISMATCH"
        );
        assert_eq!(
            load_observed_evidence_bundle(
                &root,
                EvidenceEnvelopeRequest {
                    bundle_id: "../escape".into()
                },
                &run,
            )
            .unwrap_err(),
            "LTE_EVIDENCE_BUNDLE_ID_INVALID"
        );
        let _ = fs::remove_dir_all(root);
    }

    fn write_authorized_release(root: &Path, release_id: &str, run: &RunRecord, planes: &[&str]) {
        let release_dir = root.join(release_id);
        fs::create_dir_all(&release_dir).unwrap();
        let captures = planes
            .iter()
            .map(|plane| {
                let source_file = format!("{plane}.pcapng");
                let events_file = format!("{plane}.events.jsonl");
                let source = format!("synthetic-sanitized-{plane}").into_bytes();
                let events = format!("{{\"plane\":\"{plane}\",\"teid\":42}}\n").into_bytes();
                fs::write(release_dir.join(&source_file), &source).unwrap();
                fs::write(release_dir.join(&events_file), &events).unwrap();
                let mut proof = capture_proof(plane);
                proof.source_file = source_file;
                proof.normalized_events_file = events_file;
                proof.capture_ref.source_file_sha256 = format!("{:x}", Sha256::digest(&source));
                proof.normalized_events_sha256 = format!("{:x}", Sha256::digest(&events));
                AuthorizedCaptureRelease {
                    interface: (*plane).into(),
                    proof,
                }
            })
            .collect();
        let release = AuthorizedEvidenceRelease {
            schema_version: CAPTURE_RELEASE_SCHEMA.into(),
            release_id: release_id.into(),
            run_id: run.run_id.clone(),
            profile_id: run.profile_id.clone(),
            scenario_id: run.scenario_id.clone(),
            rat: "LTE".into(),
            run_started_at: run.started_at.clone(),
            run_ended_at: run.ended_at.clone().unwrap(),
            final_state: run_outcome_name(run.outcome).unwrap().into(),
            authorization_state: "SANITIZED_APPROVED".into(),
            captures,
        };
        fs::write(
            release_dir.join("oiran-lte-capture-release.json"),
            serde_json::to_vec_pretty(&release).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn real_finalizer_builds_an_immutable_complete_bundle_and_is_idempotent() {
        let fixture = path("real-finalizer-complete");
        let release_root = fixture.join("releases");
        let bundle_root = fixture.join("bundles");
        fs::create_dir_all(&release_root).unwrap();
        let run = completed_run("real-finalizer-complete");
        let release_id = "release-complete-01";
        write_authorized_release(&release_root, release_id, &run, &["S1_MME", "S11", "S1_U"]);
        let request = EvidenceFinalizeRequest {
            release_id: release_id.into(),
        };
        let first = finalize_authorized_evidence_release(
            &release_root,
            &bundle_root,
            request.clone(),
            &run,
        )
        .unwrap();
        let second =
            finalize_authorized_evidence_release(&release_root, &bundle_root, request, &run)
                .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.capture_proofs.len(), 3);
        assert!(bundle_root
            .join(&first.bundle_id)
            .join("polaris-evidence-proof.json")
            .is_file());
        let _ = fs::remove_dir_all(fixture);
    }

    #[test]
    fn real_finalizer_preserves_failed_and_cancelled_partial_evidence() {
        for (name, outcome) in [
            ("real-finalizer-failed", RunOutcome::Failed),
            ("real-finalizer-cancelled", RunOutcome::Cancelled),
        ] {
            let fixture = path(name);
            let release_root = fixture.join("releases");
            let bundle_root = fixture.join("bundles");
            fs::create_dir_all(&release_root).unwrap();
            let run = terminal_run(name, outcome);
            let release_id = format!("release-{name}");
            write_authorized_release(&release_root, &release_id, &run, &["S1_MME"]);
            let input = finalize_authorized_evidence_release(
                &release_root,
                &bundle_root,
                EvidenceFinalizeRequest { release_id },
                &run,
            )
            .unwrap();
            let envelope = build_oiran_evidence_envelope(&run, input).unwrap();
            assert_eq!(envelope.evidence.capture_refs.len(), 1);
            assert_eq!(envelope.evidence.capture_refs[0].plane, "S1_MME");
            let _ = fs::remove_dir_all(fixture);
        }
    }

    #[test]
    fn privacy_contract_subscriber_pseudonym_accepts_only_psn_32_hex() {
        // 0.29.16 contract with OIRAN 2.7.7. A key literally named
        // `subscriber_pseudonym` (or `identity_pseudonym`) is accepted only
        // when its value matches ^psn-[0-9a-f]{32}$.
        let valid_psn = "psn-0123456789abcdef0123456789abcdef";
        assert!(privacy_safe_value(&serde_json::json!({
            "subscriber_pseudonym": valid_psn
        })));
        assert!(privacy_safe_value(&serde_json::json!({
            "identity_pseudonym": valid_psn
        })));
        // Shorter hex tail — rejected.
        assert!(!privacy_safe_value(&serde_json::json!({
            "subscriber_pseudonym": "psn-0123456789abcdef"
        })));
        // Longer hex tail — rejected.
        assert!(!privacy_safe_value(&serde_json::json!({
            "subscriber_pseudonym": "psn-0123456789abcdef0123456789abcdef00"
        })));
        // Uppercase hex — rejected.
        assert!(!privacy_safe_value(&serde_json::json!({
            "subscriber_pseudonym": "psn-0123456789ABCDEF0123456789ABCDEF"
        })));
        // Decimal IMSI stuffed under the pseudonym name — rejected.
        assert!(!privacy_safe_value(&serde_json::json!({
            "subscriber_pseudonym": "001011234567890"
        })));
        // Forbidden key name — still rejected.
        assert!(!privacy_safe_value(&serde_json::json!({
            "imsi": "REDACTED"
        })));
        // Bare 32-hex secret under an unrelated key — still rejected.
        assert!(!privacy_safe_value(&serde_json::json!({
            "material": "00112233445566778899aabbccddeeff"
        })));
        // NamedValue / InformationElement shape: `name == subscriber_pseudonym`
        // forces the sibling `value` to match the psn regex.
        assert!(privacy_safe_value(&serde_json::json!({
            "name": "subscriber_pseudonym",
            "value": valid_psn,
            "pseudonymized": true
        })));
        assert!(!privacy_safe_value(&serde_json::json!({
            "name": "subscriber_pseudonym",
            "value": "001011234567890",
            "pseudonymized": true
        })));
        // Same rule on `identity_pseudonym` InformationElement entries.
        assert!(privacy_safe_value(&serde_json::json!({
            "name": "identity_pseudonym",
            "value": valid_psn
        })));
        assert!(!privacy_safe_value(&serde_json::json!({
            "name": "identity_pseudonym",
            "value": "psn-0123456789ABCDEF0123456789ABCDEF"
        })));
    }

    #[test]
    fn real_finalizer_rejects_empty_privacy_leaks_hash_drift_and_conflicts() {
        assert!(!privacy_safe_value(&serde_json::json!({
            "id": "0".repeat(15)
        })));
        assert!(!privacy_safe_value(&serde_json::json!({
            "k": "00112233445566778899aabbccddeeff"
        })));
        let fixture = path("real-finalizer-negative");
        let release_root = fixture.join("releases");
        let bundle_root = fixture.join("bundles");
        fs::create_dir_all(&release_root).unwrap();
        let failed = terminal_run("real-finalizer-empty", RunOutcome::Failed);
        write_authorized_release(&release_root, "release-empty", &failed, &[]);
        assert_eq!(
            finalize_authorized_evidence_release(
                &release_root,
                &bundle_root,
                EvidenceFinalizeRequest {
                    release_id: "release-empty".into()
                },
                &failed,
            )
            .unwrap_err(),
            "LTE_EVIDENCE_NO_OBSERVED_CAPTURE"
        );

        let completed = completed_run("real-finalizer-negative");
        let release_id = "release-negative";
        write_authorized_release(
            &release_root,
            release_id,
            &completed,
            &["S1_MME", "S11", "S1_U"],
        );
        let release_dir = release_root.join(release_id);
        fs::write(
            release_dir.join("S11.events.jsonl"),
            b"{\"imsi\":\"REDACTED\"}\n",
        )
        .unwrap();
        assert_eq!(
            finalize_authorized_evidence_release(
                &release_root,
                &bundle_root,
                EvidenceFinalizeRequest {
                    release_id: release_id.into()
                },
                &completed,
            )
            .unwrap_err(),
            "LTE_EVIDENCE_FILE_HASH_MISMATCH"
        );
        let privacy_id = "release-privacy";
        write_authorized_release(
            &release_root,
            privacy_id,
            &completed,
            &["S1_MME", "S11", "S1_U"],
        );
        let privacy_dir = release_root.join(privacy_id);
        let leaked = b"{\"imsi\":\"REDACTED\"}\n";
        fs::write(privacy_dir.join("S11.events.jsonl"), leaked).unwrap();
        let mut privacy_release: AuthorizedEvidenceRelease = serde_json::from_slice(
            &fs::read(privacy_dir.join("oiran-lte-capture-release.json")).unwrap(),
        )
        .unwrap();
        privacy_release.captures[1].proof.normalized_events_sha256 =
            format!("{:x}", Sha256::digest(leaked));
        fs::write(
            privacy_dir.join("oiran-lte-capture-release.json"),
            serde_json::to_vec_pretty(&privacy_release).unwrap(),
        )
        .unwrap();
        assert_eq!(
            finalize_authorized_evidence_release(
                &release_root,
                &bundle_root,
                EvidenceFinalizeRequest {
                    release_id: privacy_id.into()
                },
                &completed,
            )
            .unwrap_err(),
            "LTE_EVIDENCE_PRIVACY_REJECTED"
        );
        write_authorized_release(
            &release_root,
            release_id,
            &completed,
            &["S1_MME", "S11", "S1_U"],
        );
        let request = EvidenceFinalizeRequest {
            release_id: release_id.into(),
        };
        let finalized = finalize_authorized_evidence_release(
            &release_root,
            &bundle_root,
            request.clone(),
            &completed,
        )
        .unwrap();
        let mut release: AuthorizedEvidenceRelease = serde_json::from_slice(
            &fs::read(release_dir.join("oiran-lte-capture-release.json")).unwrap(),
        )
        .unwrap();
        release.captures[0].proof.capture_ref.last_frame = 99;
        fs::write(
            release_dir.join("oiran-lte-capture-release.json"),
            serde_json::to_vec_pretty(&release).unwrap(),
        )
        .unwrap();
        assert_eq!(
            finalize_authorized_evidence_release(&release_root, &bundle_root, request, &completed,)
                .unwrap_err(),
            "LTE_EVIDENCE_FINALIZATION_CONFLICT"
        );
        assert!(bundle_root.join(finalized.bundle_id).is_dir());
        let _ = fs::remove_dir_all(fixture);
    }

    #[test]
    fn capture_publication_is_persistently_idempotent_and_rejects_drift() {
        let p = path("capture-publication");
        let _ = fs::remove_file(&p);
        let mut store = RunStore::load(p.clone()).unwrap();
        store
            .create(
                "lte-run-publication".into(),
                "grant-publication".into(),
                1,
                999_999,
                "publication-key",
            )
            .unwrap();
        let refs = vec![capture("S1_MME"), capture("S11"), capture("S1_U")];
        assert_eq!(
            store
                .publish_capture_refs("lte-run-publication", "bundle-publication-01", refs.clone(),)
                .unwrap_err(),
            "LTE_EVIDENCE_RUN_NOT_ADMISSIBLE"
        );
        store
            .finalize(
                "lte-run-publication",
                RunOutcome::Completed,
                CleanupEvidence {
                    srsue_stopped: true,
                    srsenb_stopped: true,
                    sidecars_removed: true,
                    epc_healthy: true,
                    dumpcaps_preserved: true,
                },
                2,
            )
            .unwrap();
        assert!(!store
            .publish_capture_refs("lte-run-publication", "bundle-publication-01", refs.clone())
            .unwrap());
        assert!(store
            .publish_capture_refs("lte-run-publication", "bundle-publication-01", refs.clone())
            .unwrap());
        assert_eq!(
            store
                .publish_capture_refs("lte-run-publication", "bundle-publication-02", refs)
                .unwrap_err(),
            "LTE_EVIDENCE_PUBLICATION_CONFLICT"
        );
        drop(store);
        let store = RunStore::load(p.clone()).unwrap();
        assert_eq!(
            store
                .get("lte-run-publication")
                .unwrap()
                .evidence_bundle_id
                .as_deref(),
            Some("bundle-publication-01")
        );
        let _ = fs::remove_file(p);
    }
    #[test]
    fn timeout_cleanup_keeps_observed_capture_refs_publishable_after_reload() {
        let p = path("timeout-publication");
        let _ = fs::remove_file(&p);
        let run_id = "lte-run-timeout-publication";
        let mut store = RunStore::load(p.clone()).unwrap();
        store
            .create(
                run_id.into(),
                "grant-timeout-publication".into(),
                1,
                999_999,
                "timeout-publication-key",
            )
            .unwrap();
        store
            .fail_active_step(run_id, "LTE_GLOBAL_TIMEOUT", 2)
            .unwrap();
        store
            .finalize(
                run_id,
                RunOutcome::Failed,
                CleanupEvidence {
                    srsue_stopped: true,
                    srsenb_stopped: true,
                    sidecars_removed: true,
                    epc_healthy: true,
                    dumpcaps_preserved: true,
                },
                3,
            )
            .unwrap();
        assert!(!store
            .publish_capture_refs(
                run_id,
                "bundle-timeout-publication",
                vec![capture("S1_MME")]
            )
            .unwrap());
        drop(store);
        let store = RunStore::load(p.clone()).unwrap();
        let run = store.get(run_id).unwrap();
        assert_eq!(run.outcome, Some(RunOutcome::Failed));
        assert_eq!(run.capture_refs.len(), 1);
        assert_eq!(
            run.evidence_bundle_id.as_deref(),
            Some("bundle-timeout-publication")
        );
        let _ = fs::remove_file(p);
    }
    #[test]
    fn persistent_lease_and_idempotency() {
        let p = path("lease");
        let _ = fs::remove_file(&p);
        let mut s = RunStore::load(p.clone()).unwrap();
        let (a, replayed) = s
            .create(
                "lte-run-12345678".into(),
                "g".into(),
                1,
                999999,
                "key-12345678",
            )
            .unwrap();
        assert!(!replayed);
        let (b, replayed) = s
            .create(
                "lte-run-other123".into(),
                "g".into(),
                2,
                999999,
                "key-12345678",
            )
            .unwrap();
        assert!(replayed);
        assert_eq!(a.run_id, b.run_id);
        assert_eq!(
            s.create(
                "lte-run-other123".into(),
                "g".into(),
                2,
                999999,
                "other-key"
            )
            .unwrap_err(),
            "LTE_RUN_ALREADY_ACTIVE"
        );
        let _ = fs::remove_file(p);
    }
    #[test]
    fn restart_moves_nonterminal_to_recovery_cleanup() {
        let p = path("recover");
        let _ = fs::remove_file(&p);
        {
            let mut s = RunStore::load(p.clone()).unwrap();
            s.create(
                "lte-run-12345678".into(),
                "g".into(),
                1,
                999999,
                "key-12345678",
            )
            .unwrap();
            s.intent(
                "lte-run-12345678",
                RunState::TrafficRunning,
                "op".into(),
                8,
                2,
            )
            .unwrap();
        }
        let s = RunStore::load(p.clone()).unwrap();
        let r = s.get("lte-run-12345678").unwrap();
        assert_eq!(r.state, RunState::Stopping);
        assert_eq!(r.outcome, Some(RunOutcome::RecoveryBlocked));
        assert!(r.cancel_requested && r.cleanup_required);
        let _ = fs::remove_file(p);
    }
    #[test]
    fn intent_never_publishes_state_before_observation_and_advance() {
        let p = path("proof-before-state");
        let _ = fs::remove_file(&p);
        let mut store = RunStore::load(p.clone()).unwrap();
        store
            .create(
                "lte-run-12345678".into(),
                "g".into(),
                1,
                999999,
                "key-12345678",
            )
            .unwrap();
        store
            .intent("lte-run-12345678", RunState::S1Ready, "s1-op".into(), 2, 2)
            .unwrap();
        assert_eq!(store.get("lte-run-12345678").unwrap().state, RunState::Idle);
        assert_eq!(
            store.get("lte-run-12345678").unwrap().intended_state,
            Some(RunState::S1Ready)
        );
        store
            .observe(
                "lte-run-12345678",
                2,
                Observation {
                    sequence: 2,
                    observed_at: "test".into(),
                    source_kind: "synthetic_sctp".into(),
                    source_sha256: "a".repeat(64),
                    validity: "VALID".into(),
                    sanitization_state: "SYNTHETIC_NO_IDENTITY".into(),
                    measurements: serde_json::json!({"connected":true}),
                },
                3,
            )
            .unwrap();
        assert_eq!(store.get("lte-run-12345678").unwrap().state, RunState::Idle);
        store
            .advance("lte-run-12345678", RunState::S1Ready)
            .unwrap();
        assert_eq!(
            store.get("lte-run-12345678").unwrap().state,
            RunState::S1Ready
        );
        assert_eq!(store.get("lte-run-12345678").unwrap().intended_state, None);
        let _ = fs::remove_file(p);
    }
    #[test]
    fn clean_requires_every_observation() {
        let p = path("clean");
        let _ = fs::remove_file(&p);
        let mut s = RunStore::load(p.clone()).unwrap();
        s.create(
            "lte-run-12345678".into(),
            "g".into(),
            1,
            999999,
            "key-12345678",
        )
        .unwrap();
        s.finalize(
            "lte-run-12345678",
            RunOutcome::Completed,
            CleanupEvidence {
                srsue_stopped: true,
                srsenb_stopped: true,
                sidecars_removed: true,
                epc_healthy: true,
                dumpcaps_preserved: false,
            },
            2,
        )
        .unwrap();
        assert_eq!(s.get("lte-run-12345678").unwrap().state, RunState::Stopping);
        let _ = fs::remove_file(p);
    }
    #[test]
    fn capture_refs_require_nonempty_unique_approved_observed_planes() {
        let good = vec![capture("S1_MME"), capture("S11"), capture("S1_U")];
        assert!(validate_capture_refs(&good).is_ok());
        let mut bad = good.clone();
        bad[2].sanitization_state = "RAW_PROTECTED".into();
        assert_eq!(
            validate_capture_refs(&bad).unwrap_err(),
            "LTE_EVIDENCE_NOT_APPROVED"
        );
        assert!(validate_capture_refs(&good[..2]).is_ok());
        assert_eq!(
            validate_capture_refs(&[]).unwrap_err(),
            "LTE_EVIDENCE_NO_OBSERVED_CAPTURE"
        );
        let mut unsupported = good;
        unsupported.push(capture("N2"));
        assert_eq!(
            validate_capture_refs(&unsupported).unwrap_err(),
            "LTE_EVIDENCE_PLANE_UNSUPPORTED"
        );
    }
    #[test]
    fn checksum_corruption_fails_closed() {
        let p = path("corrupt");
        let _ = fs::remove_file(&p);
        let mut s = RunStore::load(p.clone()).unwrap();
        s.create(
            "lte-run-12345678".into(),
            "g".into(),
            1,
            999999,
            "key-12345678",
        )
        .unwrap();
        let mut text = fs::read_to_string(&p).unwrap();
        text = text.replace("LTE-SRSUE-TEST-01", "LTE-TAMPERED-TEST");
        fs::write(&p, text).unwrap();
        assert_eq!(
            RunStore::load(p.clone()).unwrap_err(),
            "LTE_RUN_STORE_CHECKSUM_INVALID"
        );
        let _ = fs::remove_file(p);
    }
    #[test]
    fn deadline_is_clipped_to_grant_or_five_minutes() {
        let p = path("deadline");
        let _ = fs::remove_file(&p);
        let mut s = RunStore::load(p.clone()).unwrap();
        let (a, _) = s
            .create(
                "lte-run-12345678".into(),
                "g".into(),
                1_000,
                999_999,
                "key-12345678",
            )
            .unwrap();
        assert_eq!(a.hard_deadline_epoch_ms, 301_000);
        let _ = fs::remove_file(p);
    }
    #[test]
    fn cancellation_is_durable_and_cleanup_remains_required() {
        let p = path("cancel");
        let _ = fs::remove_file(&p);
        let mut s = RunStore::load(p.clone()).unwrap();
        s.create(
            "lte-run-12345678".into(),
            "g".into(),
            1,
            999999,
            "key-12345678",
        )
        .unwrap();
        s.request_cancel("lte-run-12345678").unwrap();
        drop(s);
        let s = RunStore::load(p.clone()).unwrap();
        let r = s.get("lte-run-12345678").unwrap();
        assert!(r.cancel_requested && r.cleanup_required);
        assert_eq!(r.state, RunState::Stopping);
        let _ = fs::remove_file(p);
    }
    #[test]
    fn global_timeout_marks_the_active_step_failed_and_requires_cleanup() {
        let p = path("global-timeout");
        let _ = fs::remove_file(&p);
        let mut store = RunStore::load(p.clone()).unwrap();
        store
            .create(
                "lte-run-timeout-test".into(),
                "grant-timeout".into(),
                1,
                999_999,
                "timeout-key-1",
            )
            .unwrap();
        store
            .intent(
                "lte-run-timeout-test",
                RunState::S1Ready,
                "wait-s1".into(),
                2,
                2,
            )
            .unwrap();
        store
            .fail_active_step("lte-run-timeout-test", "LTE_GLOBAL_TIMEOUT", 3)
            .unwrap();
        let run = store.get("lte-run-timeout-test").unwrap();
        assert_eq!(run.state, RunState::Stopping);
        assert_eq!(run.outcome, Some(RunOutcome::Failed));
        assert!(run.cleanup_required);
        assert_eq!(
            run.steps[2].reason_code.as_deref(),
            Some("LTE_GLOBAL_TIMEOUT")
        );
        let _ = fs::remove_file(p);
    }
    #[test]
    fn successful_cleanup_releases_lease() {
        let p = path("success");
        let _ = fs::remove_file(&p);
        let mut s = RunStore::load(p.clone()).unwrap();
        s.create(
            "lte-run-12345678".into(),
            "g".into(),
            1,
            999999,
            "key-12345678",
        )
        .unwrap();
        s.finalize(
            "lte-run-12345678",
            RunOutcome::Completed,
            CleanupEvidence {
                srsue_stopped: true,
                srsenb_stopped: true,
                sidecars_removed: true,
                epc_healthy: true,
                dumpcaps_preserved: true,
            },
            2,
        )
        .unwrap();
        assert_eq!(s.get("lte-run-12345678").unwrap().state, RunState::Clean);
        assert!(s
            .create(
                "lte-run-87654321".into(),
                "g2".into(),
                3,
                999999,
                "key-87654321"
            )
            .is_ok());
        let _ = fs::remove_file(p);
    }
    #[test]
    fn frame_bounds_and_duplicate_planes_fail_closed() {
        let mut refs = vec![capture("S1_MME"), capture("S11"), capture("S1_U")];
        refs[0].first_frame = 3;
        refs[0].last_frame = 2;
        assert_eq!(
            validate_capture_refs(&refs).unwrap_err(),
            "LTE_EVIDENCE_CAPTURE_REF_INVALID"
        );
        let refs = vec![
            capture("S1_MME"),
            capture("S11"),
            capture("S1_U"),
            capture("S11"),
        ];
        assert_eq!(
            validate_capture_refs(&refs).unwrap_err(),
            "LTE_EVIDENCE_PLANE_DUPLICATE"
        );
    }
}
