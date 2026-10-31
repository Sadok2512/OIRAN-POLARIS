use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub const EVIDENCE_SCHEMA: &str = "oiran-polaris.lte-e2e-evidence.v1";
pub const PROFILE_ID: &str = "LTE-SRSUE-TEST-01";
pub const SCENARIO_ID: &str = "lte-e2e-certification-v1";
pub const MAX_RUN_MS: u64 = 300_000;

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
    pub schema_version: String,
    pub sanitization_state: String,
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
            "final_state": self.outcome,
            "cancel_requested": self.cancel_requested,
            "cleanup_required": self.cleanup_required,
            "steps": self.steps,
            "capture_refs": self.capture_refs,
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
        run.state = state;
        run.operation_id = Some(operation_id);
        run.cleanup_required = state == RunState::Stopping;
        let item = run.steps.get_mut(step).ok_or("LTE_RUN_STEP_INVALID")?;
        item.state = StepState::Running;
        item.started_at.get_or_insert_with(|| timestamp(now_ms));
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
        run.observations.push(observation);
        let item = run.steps.get_mut(step).ok_or("LTE_RUN_STEP_INVALID")?;
        item.state = StepState::Completed;
        item.ended_at = Some(timestamp(now_ms));
        run.operation_id = None;
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

    pub fn set_capture_refs(&mut self, run_id: &str, refs: Vec<CaptureRef>) -> Result<(), String> {
        validate_capture_refs(&refs)?;
        let run = self.run_mut(run_id)?;
        run.capture_refs = refs;
        for (step, plane) in [(2_usize,"S1_MME"),(4,"S1_MME"),(8,"S1_U"),(9,"S1_U"),(10,"S11")] {
            let reference = format!("capture:{plane}");
            if let Some(item) = run.steps.get_mut(step) {
                if !item.evidence_refs.contains(&reference) { item.evidence_refs.push(reference); }
            }
        }
        self.persist()
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
    let supported = ["S1_MME", "S11", "S1_U", "S5_C", "S5_U"];
    let required = ["S1_MME", "S11", "S1_U"];
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
                .all(|b| b.is_ascii_hexdigit())
            || reference.first_frame == 0
            || reference.first_frame > reference.last_frame
        {
            return Err("LTE_EVIDENCE_CAPTURE_REF_INVALID".into());
        }
        if reference.sanitization_state != "SANITIZED_APPROVED" {
            return Err("LTE_EVIDENCE_NOT_APPROVED".into());
        }
    }
    if required.iter().any(|plane| !planes.contains(plane)) {
        return Err("LTE_EVIDENCE_REQUIRED_PLANE_MISSING".into());
    }
    Ok(())
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
    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("polaris-lte-run-{name}-{}", std::process::id()))
    }
    fn capture(plane: &str) -> CaptureRef {
        CaptureRef {
            plane: plane.into(),
            source_file_sha256: "a".repeat(64),
            first_frame: 1,
            last_frame: 2,
            decoder_version: "test".into(),
            schema_version: "v1".into(),
            sanitization_state: "SANITIZED_APPROVED".into(),
        }
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
    fn capture_refs_require_unique_approved_mandatory_planes() {
        let good = vec![capture("S1_MME"), capture("S11"), capture("S1_U")];
        assert!(validate_capture_refs(&good).is_ok());
        let mut bad = good.clone();
        bad[2].sanitization_state = "RAW_PROTECTED".into();
        assert_eq!(
            validate_capture_refs(&bad).unwrap_err(),
            "LTE_EVIDENCE_NOT_APPROVED"
        );
        assert_eq!(
            validate_capture_refs(&good[..2]).unwrap_err(),
            "LTE_EVIDENCE_REQUIRED_PLANE_MISSING"
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
