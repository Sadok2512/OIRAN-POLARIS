use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub const PROFILE_ID: &str = "LTE-SRSUE-TEST-01";
pub const SCENARIO_ID: &str = "lte-e2e-certification-v1";
pub const SCENARIO_SHA256: &str =
    "13a8e488839b7542e3ae967b681b139870ad070b5438bb314ca28707134be67d";
pub const MAX_DURATION_SECONDS: u32 = 300;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct LteProfileRecord {
    pub schema_version: String,
    pub profile_id: String,
    pub revision: u32,
    pub owner: String,
    pub enabled: bool,
    pub configuration_sha256: String,
    pub compose_project: String,
    pub enb_service: String,
    pub ue_service: String,
    pub max_running_ues: u32,
}

#[derive(Clone, Debug)]
pub struct ProfileRegistry {
    path: PathBuf,
    profile: LteProfileRecord,
}

impl ProfileRegistry {
    pub fn load_or_seed(path: PathBuf, configuration_sha256: String) -> Result<Self, String> {
        let expected = LteProfileRecord {
            schema_version: "polaris.lte-profile.v1".into(),
            profile_id: PROFILE_ID.into(),
            revision: 1,
            owner: "POLARIS_CONTROLLER".into(),
            enabled: false,
            configuration_sha256,
            compose_project: "oiran-lab".into(),
            enb_service: "srsenb".into(),
            ue_service: "srsue".into(),
            max_running_ues: 1,
        };
        let mut registry = match fs::read(&path) {
            Ok(bytes) => {
                let mut stored: LteProfileRecord =
                    serde_json::from_slice(&bytes).map_err(|_| "LTE_PROFILE_REGISTRY_INVALID")?;
                if stored.profile_id != PROFILE_ID
                    || stored.owner != "POLARIS_CONTROLLER"
                    || stored.compose_project != "oiran-lab"
                    || stored.enb_service != "srsenb"
                    || stored.ue_service != "srsue"
                    || stored.max_running_ues != 1
                {
                    return Err("LTE_PROFILE_REGISTRY_OWNERSHIP_CONFLICT".into());
                }
                stored.configuration_sha256 = expected.configuration_sha256;
                Self {
                    path,
                    profile: stored,
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self {
                path,
                profile: expected,
            },
            Err(_) => return Err("LTE_PROFILE_REGISTRY_UNREADABLE".into()),
        };
        registry.persist()?;
        Ok(registry)
    }

    pub fn profile(&self) -> &LteProfileRecord {
        &self.profile
    }

    pub fn set_enabled(&mut self, enabled: bool) -> Result<LteProfileRecord, String> {
        self.profile.enabled = enabled;
        self.persist()?;
        Ok(self.profile.clone())
    }

    fn persist(&mut self) -> Result<(), String> {
        atomic_write_0600(
            &self.path,
            &serde_json::to_vec_pretty(&self.profile)
                .map_err(|_| "LTE_PROFILE_REGISTRY_WRITE_FAILED")?,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct GrantTarget {
    pub kind: String,
    pub profile_id: String,
    pub profile_revision: u32,
    pub configuration_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct GrantScenario {
    pub scenario_id: String,
    pub scenario_revision: u32,
    pub scenario_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PingBounds {
    pub max_packets_per_direction: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct UdpBounds {
    pub max_rate_bps_per_direction: u64,
    pub max_duration_seconds_per_direction: u32,
    pub max_payload_bytes: u32,
    pub max_parallel_streams: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct GrantConstraints {
    pub max_ues: u32,
    pub allowed_actions: Vec<String>,
    pub ping: PingBounds,
    pub udp: UdpBounds,
    pub hard_deadline_behavior: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct GrantRequestV2 {
    pub schema_version: String,
    pub target: GrantTarget,
    pub scenario: GrantScenario,
    pub duration_seconds: u32,
    pub constraints: GrantConstraints,
    pub execution_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GrantState {
    Issued,
    Consumed,
    Revoked,
    Expired,
    RevokedRestart,
    RecoveryOnly,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct GrantRecord {
    pub schema_version: String,
    pub grant_id: String,
    pub state: GrantState,
    pub target: GrantTarget,
    pub scenario: GrantScenario,
    pub duration_seconds: u32,
    pub constraints: GrantConstraints,
    pub issued_at_epoch_ms: u64,
    pub expires_at_epoch_ms: u64,
    pub role: String,
    #[serde(default)]
    pub issuer_subject_sha256: String,
    pub nonce_sha256: String,
    pub request_sha256: String,
    pub idempotency_key_sha256: String,
    pub use_count: u8,
    pub run_id: Option<String>,
    #[serde(default)]
    pub run_request_sha256: Option<String>,
    #[serde(default)]
    pub run_idempotency_key_sha256: Option<String>,
    #[serde(default)]
    pub run_state: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RunRequest {
    pub grant_id: String,
    pub profile_id: String,
    pub profile_revision: u32,
    pub configuration_sha256: String,
    pub scenario_id: String,
    pub scenario_revision: u32,
    pub scenario_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RunRecord {
    pub run_id: String,
    pub grant_id: String,
    pub profile_id: String,
    pub state: String,
    pub deadline_at_epoch_ms: u64,
    pub evidence_url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoreDocument {
    schema_version: u32,
    checksum_sha256: String,
    grants: Vec<GrantRecord>,
}

#[derive(Clone, Debug)]
pub struct GrantStore {
    path: PathBuf,
    grants: Vec<GrantRecord>,
}

impl GrantRequestV2 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != "polaris.live-grant.v2" {
            return Err("LIVE_GRANT_SCHEMA_INVALID");
        }
        if self.target.kind != "srsran_lte_profile"
            || self.target.profile_id != PROFILE_ID
            || self.target.profile_revision != 1
        {
            return Err("LTE_PROFILE_NOT_FOUND");
        }
        if self.scenario.scenario_id != SCENARIO_ID
            || self.scenario.scenario_revision != 1
            || self.scenario.scenario_sha256 != SCENARIO_SHA256
        {
            return Err("LTE_SCENARIO_NOT_ALLOWLISTED");
        }
        if self.duration_seconds == 0 || self.duration_seconds > MAX_DURATION_SECONDS {
            return Err("LIVE_GRANT_DURATION_INVALID");
        }
        if !is_sha256(&self.target.configuration_sha256)
            || !is_sha256(&self.scenario.scenario_sha256)
        {
            return Err("LIVE_GRANT_HASH_INVALID");
        }
        if self.execution_nonce.len() < 43
            || !self
                .execution_nonce
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err("LIVE_GRANT_NONCE_INVALID");
        }
        let allowed = [
            "s1_setup",
            "lte_attach",
            "ping_ul",
            "ping_dl",
            "udp_ul",
            "udp_dl",
            "cleanup",
        ];
        if self.constraints.max_ues != 1
            || self.constraints.allowed_actions.is_empty()
            || self
                .constraints
                .allowed_actions
                .iter()
                .any(|action| !allowed.contains(&action.as_str()))
            || !self
                .constraints
                .allowed_actions
                .iter()
                .any(|action| action == "cleanup")
            || self.constraints.ping.max_packets_per_direction > 5
            || self.constraints.udp.max_rate_bps_per_direction > 1_000_000
            || self.constraints.udp.max_duration_seconds_per_direction > 30
            || self.constraints.udp.max_payload_bytes > 1_200
            || self.constraints.udp.max_parallel_streams != 1
            || self.constraints.hard_deadline_behavior != "STOP_TRAFFIC_AND_CLEANUP"
        {
            return Err("LTE_CONSTRAINT_OUT_OF_RANGE");
        }
        Ok(())
    }
}

impl GrantRecord {
    pub fn public_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema_version": self.schema_version,
            "grant_id": self.grant_id,
            "state": self.state,
            "target": self.target,
            "scenario_id": self.scenario.scenario_id,
            "issued_at_epoch_ms": self.issued_at_epoch_ms,
            "expires_at_epoch_ms": self.expires_at_epoch_ms,
            "duration_seconds": self.duration_seconds,
            "constraints": self.constraints,
            "use_count": self.use_count,
            "run_id": self.run_id,
        })
    }
}

impl GrantStore {
    pub fn load(path: PathBuf) -> Result<Self, String> {
        let mut store = match fs::read(&path) {
            Ok(bytes) => {
                let document: StoreDocument =
                    serde_json::from_slice(&bytes).map_err(|_| "LTE_GRANT_STORE_INVALID")?;
                if document.schema_version != 2
                    || checksum(&document.grants)? != document.checksum_sha256
                {
                    return Err("LTE_GRANT_STORE_CHECKSUM_INVALID".into());
                }
                Self {
                    path,
                    grants: document.grants,
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self {
                path,
                grants: Vec::new(),
            },
            Err(_) => return Err("LTE_GRANT_STORE_UNREADABLE".into()),
        };
        let mut changed = false;
        for grant in &mut store.grants {
            match grant.state {
                GrantState::Issued => {
                    grant.state = GrantState::RevokedRestart;
                    changed = true;
                }
                GrantState::Consumed => {
                    grant.state = GrantState::RecoveryOnly;
                    changed = true;
                }
                _ => {}
            }
        }
        if changed {
            store.persist()?;
        }
        Ok(store)
    }

    pub fn records(&self) -> &[GrantRecord] {
        &self.grants
    }

    pub fn create(
        &mut self,
        request: GrantRequestV2,
        grant_id: String,
        now_ms: u64,
        role: &str,
        issuer_subject: &str,
        idempotency_key: &str,
    ) -> Result<(GrantRecord, bool), String> {
        request.validate().map_err(str::to_string)?;
        validate_idempotency_key(idempotency_key)?;
        let request_sha256 = hash_json(&request)?;
        let key_hash = hash_bytes(idempotency_key.as_bytes());
        if let Some(existing) = self
            .grants
            .iter()
            .find(|grant| grant.idempotency_key_sha256 == key_hash)
        {
            return if existing.request_sha256 == request_sha256 {
                Ok((existing.clone(), true))
            } else {
                Err("IDEMPOTENCY_KEY_CONFLICT".into())
            };
        }
        let record = GrantRecord {
            schema_version: request.schema_version,
            grant_id,
            state: GrantState::Issued,
            target: request.target,
            scenario: request.scenario,
            duration_seconds: request.duration_seconds,
            constraints: request.constraints,
            issued_at_epoch_ms: now_ms,
            expires_at_epoch_ms: now_ms.saturating_add(u64::from(request.duration_seconds) * 1_000),
            role: role.to_string(),
            issuer_subject_sha256: hash_bytes(issuer_subject.as_bytes()),
            nonce_sha256: hash_bytes(request.execution_nonce.as_bytes()),
            request_sha256,
            idempotency_key_sha256: key_hash,
            use_count: 0,
            run_id: None,
            run_request_sha256: None,
            run_idempotency_key_sha256: None,
            run_state: None,
        };
        self.grants.push(record.clone());
        self.persist()?;
        Ok((record, false))
    }

    pub fn consume(
        &mut self,
        request: &RunRequest,
        nonce: &str,
        idempotency_key: &str,
        run_id: String,
        now_ms: u64,
        role: &str,
        issuer_subject: &str,
    ) -> Result<RunRecord, String> {
        validate_idempotency_key(idempotency_key)?;
        let run_request_sha256 = hash_json(request)?;
        let run_key_sha256 = hash_bytes(idempotency_key.as_bytes());
        let grant = self
            .grants
            .iter_mut()
            .find(|grant| grant.grant_id == request.grant_id)
            .ok_or("LIVE_GRANT_NOT_FOUND")?;
        if now_ms >= grant.expires_at_epoch_ms {
            grant.state = GrantState::Expired;
            self.persist()?;
            return Err("LIVE_GRANT_INACTIVE".into());
        }
        if grant.role != role
            || grant.issuer_subject_sha256 != hash_bytes(issuer_subject.as_bytes())
        {
            return Err("GRANT_SUBJECT_CHANGED".into());
        }
        if grant.run_idempotency_key_sha256.as_deref() == Some(run_key_sha256.as_str()) {
            if grant.run_request_sha256.as_deref() != Some(run_request_sha256.as_str()) {
                return Err("IDEMPOTENCY_KEY_CONFLICT".into());
            }
            let existing_run_id = grant.run_id.clone().ok_or("LTE_GRANT_STORE_INVALID")?;
            return Ok(RunRecord {
                run_id: existing_run_id.clone(),
                grant_id: grant.grant_id.clone(),
                profile_id: request.profile_id.clone(),
                state: "PREFLIGHT".into(),
                deadline_at_epoch_ms: grant.expires_at_epoch_ms,
                evidence_url: format!("/api/v1/lte/runs/{existing_run_id}"),
            });
        }
        if grant.state != GrantState::Issued {
            return Err("LIVE_GRANT_REPLAYED".into());
        }
        if hash_bytes(nonce.as_bytes()) != grant.nonce_sha256 {
            return Err("LIVE_GRANT_NONCE_INVALID".into());
        }
        if request.profile_id != grant.target.profile_id
            || request.profile_revision != grant.target.profile_revision
            || request.configuration_sha256 != grant.target.configuration_sha256
            || request.scenario_id != grant.scenario.scenario_id
            || request.scenario_revision != grant.scenario.scenario_revision
            || request.scenario_sha256 != grant.scenario.scenario_sha256
        {
            return Err("GRANT_SUBJECT_CHANGED".into());
        }
        grant.state = GrantState::Consumed;
        grant.use_count = 1;
        grant.run_id = Some(run_id.clone());
        grant.run_request_sha256 = Some(run_request_sha256);
        grant.run_idempotency_key_sha256 = Some(run_key_sha256);
        grant.run_state = Some("PREFLIGHT".into());
        let result = RunRecord {
            run_id: run_id.clone(),
            grant_id: grant.grant_id.clone(),
            profile_id: request.profile_id.clone(),
            state: "PREFLIGHT".into(),
            deadline_at_epoch_ms: grant.expires_at_epoch_ms,
            evidence_url: format!("/api/v1/lte/runs/{run_id}"),
        };
        self.persist()?;
        Ok(result)
    }

    pub fn revoke(&mut self, grant_id: &str) -> Result<GrantRecord, String> {
        let grant = self
            .grants
            .iter_mut()
            .find(|grant| grant.grant_id == grant_id)
            .ok_or("LIVE_GRANT_NOT_FOUND")?;
        grant.state = GrantState::Revoked;
        let result = grant.clone();
        self.persist()?;
        Ok(result)
    }

    pub fn set_run_state(&mut self, run_id: &str, state: &str) -> Result<(), String> {
        let grant = self
            .grants
            .iter_mut()
            .find(|grant| grant.run_id.as_deref() == Some(run_id))
            .ok_or("LTE_RUN_NOT_FOUND")?;
        grant.run_state = Some(state.to_string());
        self.persist()
    }

    fn persist(&self) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|_| "LTE_GRANT_STORE_WRITE_FAILED")?;
        }
        let document = StoreDocument {
            schema_version: 2,
            checksum_sha256: checksum(&self.grants)?,
            grants: self.grants.clone(),
        };
        atomic_write_0600(&self.path, &serde_json::to_vec_pretty(&document).unwrap())
    }
}

fn atomic_write_0600(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err("LTE_GRANT_STORE_INSECURE".into());
        }
    }
    let parent = path.parent().ok_or("LTE_GRANT_STORE_WRITE_FAILED")?;
    fs::create_dir_all(parent).map_err(|_| "LTE_GRANT_STORE_WRITE_FAILED")?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("lte-store"),
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|_| "LTE_GRANT_STORE_WRITE_FAILED")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "LTE_GRANT_STORE_WRITE_FAILED")?;
    fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))
        .map_err(|_| "LTE_GRANT_STORE_WRITE_FAILED")?;
    fs::rename(&temp, path).map_err(|_| "LTE_GRANT_STORE_WRITE_FAILED")?;
    if let Some(parent) = path.parent() {
        let directory = fs::File::open(parent).map_err(|_| "LTE_GRANT_STORE_WRITE_FAILED")?;
        directory
            .sync_all()
            .map_err(|_| "LTE_GRANT_STORE_WRITE_FAILED")?;
    }
    Ok(())
}

fn validate_idempotency_key(value: &str) -> Result<(), String> {
    if (8..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Ok(())
    } else {
        Err("IDEMPOTENCY_KEY_INVALID".into())
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn hash_json<T: Serialize + ?Sized>(value: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|_| "LIVE_GRANT_SERIALIZATION_FAILED")?;
    Ok(hash_bytes(&bytes))
}

fn checksum(grants: &[GrantRecord]) -> Result<String, String> {
    hash_json(grants)
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn request() -> GrantRequestV2 {
        GrantRequestV2 {
            schema_version: "polaris.live-grant.v2".into(),
            target: GrantTarget {
                kind: "srsran_lte_profile".into(),
                profile_id: PROFILE_ID.into(),
                profile_revision: 1,
                configuration_sha256: "a".repeat(64),
            },
            scenario: GrantScenario {
                scenario_id: SCENARIO_ID.into(),
                scenario_revision: 1,
                scenario_sha256: SCENARIO_SHA256.into(),
            },
            duration_seconds: 300,
            constraints: GrantConstraints {
                max_ues: 1,
                allowed_actions: vec!["s1_setup".into(), "cleanup".into()],
                ping: PingBounds {
                    max_packets_per_direction: 5,
                },
                udp: UdpBounds {
                    max_rate_bps_per_direction: 1_000_000,
                    max_duration_seconds_per_direction: 30,
                    max_payload_bytes: 1_200,
                    max_parallel_streams: 1,
                },
                hard_deadline_behavior: "STOP_TRAFFIC_AND_CLEANUP".into(),
            },
            execution_nonce: "n".repeat(43),
        }
    }

    fn path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "polaris-lte-grants-{label}-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn grant_is_persistent_0600_and_nonce_is_never_plaintext() {
        let path = path("persistent");
        let mut store = GrantStore::load(path.clone()).unwrap();
        store
            .create(
                request(),
                "grant-1".into(),
                100,
                "operator",
                "session-a",
                "request-123",
            )
            .unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&"n".repeat(43)));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let recovered = GrantStore::load(path.clone()).unwrap();
        assert_eq!(recovered.records()[0].state, GrantState::RevokedRestart);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn one_time_consumption_and_subject_binding_are_enforced() {
        let path = path("consume");
        let mut store = GrantStore::load(path.clone()).unwrap();
        store
            .create(
                request(),
                "grant-1".into(),
                100,
                "operator",
                "session-a",
                "request-123",
            )
            .unwrap();
        let run = RunRequest {
            grant_id: "grant-1".into(),
            profile_id: PROFILE_ID.into(),
            profile_revision: 1,
            configuration_sha256: "a".repeat(64),
            scenario_id: SCENARIO_ID.into(),
            scenario_revision: 1,
            scenario_sha256: SCENARIO_SHA256.into(),
        };
        assert!(store
            .consume(
                &run,
                &"n".repeat(43),
                "run-request-1",
                "lte-run-1".into(),
                101,
                "operator",
                "session-a"
            )
            .is_ok());
        assert_eq!(
            store
                .consume(
                    &run,
                    &"n".repeat(43),
                    "run-request-1",
                    "lte-run-ignored".into(),
                    102,
                    "operator",
                    "session-a"
                )
                .unwrap()
                .run_id,
            "lte-run-1"
        );
        assert_eq!(
            store
                .consume(
                    &run,
                    &"n".repeat(43),
                    "run-request-2",
                    "lte-run-2".into(),
                    102,
                    "operator",
                    "session-a"
                )
                .unwrap_err(),
            "LIVE_GRANT_REPLAYED"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn idempotency_key_conflict_and_bounds_fail_closed() {
        let path = path("bounds");
        let mut store = GrantStore::load(path.clone()).unwrap();
        let first = store
            .create(
                request(),
                "grant-1".into(),
                100,
                "operator",
                "session-a",
                "request-123",
            )
            .unwrap();
        assert!(!first.1);
        assert!(
            store
                .create(
                    request(),
                    "grant-2".into(),
                    101,
                    "operator",
                    "session-a",
                    "request-123"
                )
                .unwrap()
                .1
        );
        let mut changed = request();
        changed.duration_seconds = 200;
        assert_eq!(
            store
                .create(
                    changed,
                    "grant-3".into(),
                    101,
                    "operator",
                    "session-a",
                    "request-123"
                )
                .unwrap_err(),
            "IDEMPOTENCY_KEY_CONFLICT"
        );
        let mut unsafe_request = request();
        unsafe_request.constraints.udp.max_rate_bps_per_direction = 1_000_001;
        assert_eq!(
            unsafe_request.validate(),
            Err("LTE_CONSTRAINT_OUT_OF_RANGE")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn consumption_rejects_another_session_or_role() {
        let path = path("subject-binding");
        let mut store = GrantStore::load(path.clone()).unwrap();
        store
            .create(
                request(),
                "grant-1".into(),
                100,
                "operator",
                "session-a",
                "request-123",
            )
            .unwrap();
        let run = RunRequest {
            grant_id: "grant-1".into(),
            profile_id: PROFILE_ID.into(),
            profile_revision: 1,
            configuration_sha256: "a".repeat(64),
            scenario_id: SCENARIO_ID.into(),
            scenario_revision: 1,
            scenario_sha256: SCENARIO_SHA256.into(),
        };
        assert_eq!(
            store
                .consume(
                    &run,
                    &"n".repeat(43),
                    "run-request-1",
                    "lte-run-1".into(),
                    101,
                    "operator",
                    "session-b"
                )
                .unwrap_err(),
            "GRANT_SUBJECT_CHANGED"
        );
        assert_eq!(
            store
                .consume(
                    &run,
                    &"n".repeat(43),
                    "run-request-2",
                    "lte-run-2".into(),
                    101,
                    "administrator",
                    "session-a"
                )
                .unwrap_err(),
            "GRANT_SUBJECT_CHANGED"
        );
        assert_eq!(store.records()[0].state, GrantState::Issued);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn expired_revoked_and_wrong_nonce_grants_fail_closed() {
        let path = path("inactive");
        let run = RunRequest {
            grant_id: "grant-1".into(),
            profile_id: PROFILE_ID.into(),
            profile_revision: 1,
            configuration_sha256: "a".repeat(64),
            scenario_id: SCENARIO_ID.into(),
            scenario_revision: 1,
            scenario_sha256: SCENARIO_SHA256.into(),
        };
        let mut store = GrantStore::load(path.clone()).unwrap();
        store
            .create(
                request(),
                "grant-1".into(),
                100,
                "operator",
                "session-a",
                "request-123",
            )
            .unwrap();
        assert_eq!(
            store
                .consume(
                    &run,
                    &"x".repeat(43),
                    "run-request-1",
                    "lte-run-1".into(),
                    101,
                    "operator",
                    "session-a"
                )
                .unwrap_err(),
            "LIVE_GRANT_NONCE_INVALID"
        );
        store.revoke("grant-1").unwrap();
        assert_eq!(
            store
                .consume(
                    &run,
                    &"n".repeat(43),
                    "run-request-2",
                    "lte-run-2".into(),
                    102,
                    "operator",
                    "session-a"
                )
                .unwrap_err(),
            "LIVE_GRANT_REPLAYED"
        );

        let mut expired_request = request();
        expired_request.duration_seconds = 1;
        store
            .create(
                expired_request,
                "grant-2".into(),
                100,
                "operator",
                "session-a",
                "request-456",
            )
            .unwrap();
        let mut expired_run = run;
        expired_run.grant_id = "grant-2".into();
        assert_eq!(
            store
                .consume(
                    &expired_run,
                    &"n".repeat(43),
                    "run-request-3",
                    "lte-run-3".into(),
                    1_100,
                    "operator",
                    "session-a"
                )
                .unwrap_err(),
            "LIVE_GRANT_INACTIVE"
        );
        assert_eq!(store.records()[1].state, GrantState::Expired);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn profile_registry_is_persistent_private_and_rejects_ownership_drift() {
        let path = path("profile");
        let registry = ProfileRegistry::load_or_seed(path.clone(), "a".repeat(64)).unwrap();
        assert_eq!(registry.profile().profile_id, PROFILE_ID);
        assert!(!registry.profile().enabled);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["ue_service"] = serde_json::json!("open5gs-amf");
        atomic_write_0600(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            ProfileRegistry::load_or_seed(path.clone(), "a".repeat(64)).unwrap_err(),
            "LTE_PROFILE_REGISTRY_OWNERSHIP_CONFLICT"
        );
        let _ = fs::remove_file(path);
    }
}
