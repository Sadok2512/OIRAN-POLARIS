mod cpu_safety;
mod scenario_definitions;
mod ue_profiles;

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Extension, Path as AxumPath, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use cpu_safety::{CpuSafetyEvidence, CpuSafetyMonitor, ScenarioResourceBudget};
use rand_core::{OsRng, RngCore};
use safety_guard::{evaluate, measure, Policy};
use scenario_definitions::{
    estimate_duration_ms, resolve_steps, ResolvedStep, ScenarioCatalog, ScenarioDefinition,
    ScenarioDefinitionStore, ScenarioMutation, EXPORT_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use simulator_controller::MultiUeController;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tower_http::{
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
};
use ue_profiles::{BulkProfileInput, ManagedUeProfile, ProfileMutationInput, ProfileStore};
use ueransim_adapter::{
    LiveLaunchSpec, ProvisionedProfileEvidence, ProvisioningBinding, UeObservation, UeProfileSpec,
};

pub use ue_profiles::UeProfileRegistry;

pub const VERSION: &str = "0.14.0";
const LIVE_TEST_ID: &str = "POLARIS-LIVE-001";
const LIVE_APPROVAL_PATH: &str = "/run/polaris-control/POLARIS-LIVE-001.approved";
const LIVE_RESULT_PATH: &str = "/root/POLARIS_CONTROL/live-tests/POLARIS-LIVE-001-result.json";
static LIVE_RUNNING: AtomicBool = AtomicBool::new(false);
static LIVE_APPROVAL_CONSUMED: AtomicBool = AtomicBool::new(false);
static LIVE_RECORD: OnceLock<Mutex<Option<Value>>> = OnceLock::new();
const UE_INVENTORY_OBSERVATION_TTL_SECONDS: u64 = 10;
const UE_CONTROL_AUTHORIZATION_SECONDS: u64 = 5 * 60;
const UE01_TRANSFER_ATTESTATION_PATH: &str =
    "/var/lib/polaris-control/ue-01-ownership-transfer.json";

#[derive(Clone)]
pub struct AppState {
    pub storage_path: PathBuf,
    pub static_dir: PathBuf,
    users_path: PathBuf,
    sessions: Arc<Mutex<BTreeMap<String, SessionRecord>>>,
    audit_path: PathBuf,
    job_state_path: PathBuf,
    ue_job_state_path: PathBuf,
    cpu_decision_path: PathBuf,
    cpu_decision_lock: Arc<Mutex<()>>,
    latest_cpu_decision: Arc<Mutex<Option<CpuSafetyEvidence>>>,
    configuration_path: PathBuf,
    profile_store: ProfileStore,
    profile_registry: Arc<Mutex<UeProfileRegistry>>,
    scenario_definition_store: ScenarioDefinitionStore,
    scenario_catalog: Arc<Mutex<ScenarioCatalog>>,
    definition_live_enabled: bool,
    definition_jobs: Arc<Mutex<BTreeMap<String, DefinitionJobControl>>>,
    policy_path: PathBuf,
    policy_enabled: Arc<AtomicBool>,
    execution_mode: String,
    additional_ue_live_enabled: bool,
    ue01_controller_owned: bool,
    ue_runtime: Arc<dyn UeRuntime>,
    resource_override: Option<Result<(), String>>,
    cpu_safety: Arc<Mutex<CpuSafetyMonitor>>,
    runtime: Arc<Mutex<ControlRuntime>>,
    multi_ue: Arc<Mutex<MultiUeController>>,
    configuration: Arc<Mutex<DesiredConfiguration>>,
    ue_operations: Arc<Mutex<()>>,
    ue_inventory_running: Arc<AtomicBool>,
    ue_inventory_last_observed_epoch_s: Arc<AtomicU64>,
    ue_inventory_cache_version: Arc<AtomicU64>,
    shared_ue_cache: Arc<Mutex<Option<UeObservation>>>,
    ue_reconciliation_running: Arc<AtomicBool>,
    ue_reconciliation: Arc<Mutex<UeReconciliation>>,
    startup_reconcile: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Ue01OwnershipTransferAttestation {
    schema_version: u8,
    ue_id: String,
    state: String,
    legacy_container_name: String,
    legacy_container_id: String,
    legacy_compose_project: String,
    legacy_compose_service: String,
    legacy_compose_sha256: String,
    profile_sha256: String,
    ownership_id: String,
}

#[derive(Clone, Debug)]
struct Ue01OwnershipTransferEvidence {
    legacy_container_present: bool,
    legacy_container_running: bool,
    legacy_container_id: Option<String>,
    compose_sha256: String,
    profile_sha256: String,
    ownership_id: String,
}

fn validate_ue01_ownership_transfer(
    transfer: &Ue01OwnershipTransferAttestation,
    evidence: &Ue01OwnershipTransferEvidence,
) -> Result<(), String> {
    if transfer.schema_version != 1
        || transfer.ue_id != "UE-01"
        || transfer.state != "CONTROLLER_OWNED"
        || transfer.legacy_container_name != "oiran-lab-ueransim-ue-1"
        || transfer.legacy_compose_project != "oiran-lab"
        || transfer.legacy_compose_service != "ueransim-ue"
    {
        return Err("UE01_TRANSFER_ATTESTATION_INVALID".into());
    }
    if transfer.legacy_container_id.len() != 64
        || !transfer
            .legacy_container_id
            .chars()
            .all(|value| value.is_ascii_hexdigit())
        || transfer.legacy_compose_sha256.len() != 64
        || transfer.profile_sha256.len() != 64
        || transfer.ownership_id.len() != 64
    {
        return Err("UE01_TRANSFER_ATTESTATION_INVALID".into());
    }
    if evidence.legacy_container_present || evidence.legacy_container_running {
        return Err("UE01_LEGACY_OWNER_STILL_PRESENT".into());
    }
    if evidence
        .legacy_container_id
        .as_deref()
        .is_some_and(|id| id != transfer.legacy_container_id)
    {
        return Err("UE01_LEGACY_OWNER_ID_MISMATCH".into());
    }
    if evidence.compose_sha256 != transfer.legacy_compose_sha256
        || evidence.profile_sha256 != transfer.profile_sha256
        || evidence.ownership_id != transfer.ownership_id
    {
        return Err("UE01_TRANSFER_EVIDENCE_MISMATCH".into());
    }
    Ok(())
}

fn controller_owns_ue(state: &AppState, ue_id: &str) -> bool {
    ueransim_adapter::is_approved_controller_ue(ue_id)
        && (ue_id != "UE-01" || state.ue01_controller_owned)
}

fn compose_disables_legacy_ue01(document: &str) -> bool {
    let mut in_service = false;
    let mut marker = false;
    let mut profiles_disable_normal_5g = false;
    for line in document.lines() {
        if line == "  ueransim-ue:" {
            in_service = true;
            continue;
        }
        if in_service
            && line.starts_with("  ")
            && !line.starts_with("    ")
            && line.trim_end().ends_with(':')
        {
            break;
        }
        if in_service {
            marker |= line.contains("POLARIS_UE01_OWNERSHIP_TRANSFERRED");
            if line.trim_start().starts_with("profiles:") {
                profiles_disable_normal_5g = !line.contains("\"5g\"") && !line.contains("'5g'");
            }
        }
    }
    marker && profiles_disable_normal_5g
}

fn disable_legacy_ue01_service(document: &str) -> Result<String, String> {
    if document.contains("POLARIS_UE01_OWNERSHIP_TRANSFERRED") {
        return Ok(document.to_string());
    }
    let mut output = Vec::new();
    let mut in_service = false;
    let mut replaced = false;
    for line in document.lines() {
        if line == "  ueransim-ue:" {
            in_service = true;
            output.push(line.to_string());
            continue;
        }
        if in_service
            && line.starts_with("  ")
            && !line.starts_with("    ")
            && line.trim_end().ends_with(':')
        {
            in_service = false;
        }
        if in_service && line.trim() == "profiles: [\"5g\"]" {
            output.push("    # POLARIS_UE01_OWNERSHIP_TRANSFERRED".into());
            output.push("    profiles: [\"polaris-ue01-legacy-disabled\"]".into());
            replaced = true;
        } else {
            output.push(line.to_string());
        }
    }
    if !replaced {
        return Err("UE01_COMPOSE_PROFILE_NOT_RECOGNIZED".into());
    }
    let mut result = output.join("\n");
    if document.ends_with('\n') {
        result.push('\n');
    }
    Ok(result)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct DesiredConfiguration {
    ue_count: usize,
    gnb_count: usize,
    updated_at_epoch_s: u64,
    updated_by: String,
}

impl Default for DesiredConfiguration {
    fn default() -> Self {
        Self {
            ue_count: 1,
            gnb_count: 1,
            updated_at_epoch_s: 0,
            updated_by: "SYSTEM_DEFAULT".into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct UeReconciliation {
    operation_id: Option<String>,
    desired_count: usize,
    state: String,
    started_at_epoch_s: Option<u64>,
    completed_at_epoch_s: Option<u64>,
    started: Vec<String>,
    stopped: Vec<String>,
    failures: Vec<(String, String)>,
}

impl Default for UeReconciliation {
    fn default() -> Self {
        Self {
            operation_id: None,
            desired_count: 1,
            state: "IDLE".into(),
            started_at_epoch_s: None,
            completed_at_epoch_s: None,
            started: Vec::new(),
            stopped: Vec::new(),
            failures: Vec::new(),
        }
    }
}

struct ControlRuntime {
    active: Option<OwnedScenarioJob>,
    history: Vec<Value>,
}

#[derive(Clone)]
struct DefinitionJobControl {
    cancel: Arc<AtomicBool>,
    started_ues: Arc<Mutex<BTreeSet<String>>>,
}

struct OwnedScenarioJob {
    job_id: String,
    started_at: u64,
    started_at_epoch_ms: u64,
    ended_at: Option<u64>,
    ended_at_epoch_ms: Option<u64>,
    state: String,
    child: Option<Child>,
    process_id: Option<u32>,
    packets_requested: u64,
    packets_sent: Option<u64>,
    packets_received: Option<u64>,
    bytes_sent: Option<u64>,
    bytes_received: Option<u64>,
    terminal_result: Option<String>,
    target_ue_id: String,
    target_ue_pseudonym: String,
    tun_interface: Option<String>,
}

const TRAFFIC_PACKET_COUNT: u64 = 5;
const TRAFFIC_PACKET_BYTES: u64 = 64;
const TRAFFIC_EXECUTION_COMMAND: &str = "for i in 1 2 3 4 5; do printf '%-64s' \"POLARIS-CONTROL-V2.1:${i}\" > /dev/udp/10.46.0.1/49001 || exit 70; /usr/bin/sleep 1; done";

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedTrafficTarget {
    ue_id: String,
    pseudonym: String,
    namespace_pid: u32,
    tun_interface: String,
    ue_ip: String,
}

trait UeRuntime: Send + Sync {
    fn verify_provisioning(
        &self,
        profiles: &[UeProfileSpec],
    ) -> Result<BTreeMap<String, String>, String>;
    fn approve_launch(
        &self,
        profile: &UeProfileSpec,
        profile_sha256: &str,
    ) -> Result<LiveLaunchSpec, String>;
    fn launch(&self, spec: &LiveLaunchSpec) -> Result<String, UeLaunchFailure>;
    fn discover(&self, spec: &LiveLaunchSpec) -> Result<Option<String>, String>;
    fn observe_owned(&self, spec: &LiveLaunchSpec, handle: &str) -> Result<UeObservation, String>;
    fn observe_shared(&self) -> Result<UeObservation, String>;
    fn owns(&self, spec: &LiveLaunchSpec, handle: &str) -> bool;
    fn stop(&self, spec: &LiveLaunchSpec, handle: &str) -> Result<(), String>;
    fn establish_pdu(
        &self,
        job: &simulator_controller::UeJob,
        profile: &UeProfileSpec,
        timeout_seconds: u64,
        cancel: &AtomicBool,
    ) -> Result<(), String> {
        let _ = (job, profile, timeout_seconds, cancel);
        Err("PDU_RUNTIME_COMMAND_UNSUPPORTED".into())
    }
    fn release_pdu(
        &self,
        job: &simulator_controller::UeJob,
        timeout_seconds: u64,
        cancel: &AtomicBool,
    ) -> Result<(), String> {
        let _ = (job, timeout_seconds, cancel);
        Err("PDU_RUNTIME_COMMAND_UNSUPPORTED".into())
    }
    fn resolve_traffic_target(
        &self,
        job: &simulator_controller::UeJob,
        destination: &str,
    ) -> Result<VerifiedTrafficTarget, String> {
        let _ = (job, destination);
        Err("TRAFFIC_TARGET_RESOLUTION_UNSUPPORTED".into())
    }
    fn execute_bounded_udp(&self, target: &VerifiedTrafficTarget) -> Result<(), String> {
        let status = Command::new("/usr/bin/nsenter")
            .args([
                "--target",
                &target.namespace_pid.to_string(),
                "--net",
                "--",
                "/usr/bin/bash",
                "-lc",
                TRAFFIC_EXECUTION_COMMAND,
            ])
            .status()
            .map_err(|_| "TRAFFIC_PROCESS_SPAWN_FAILED".to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err(format!(
                "TRAFFIC_PROCESS_EXIT_{}",
                status.code().unwrap_or(-1)
            ))
        }
    }
    fn execute_iperf_ul(&self, target: &VerifiedTrafficTarget, bytes: u64) -> Result<u64, String> {
        let output = Command::new("/usr/bin/nsenter")
            .args([
                "--target",
                &target.namespace_pid.to_string(),
                "--net",
                "--",
                "/usr/bin/iperf3",
                "-c",
                "10.46.0.1",
                "-n",
                &bytes.to_string(),
                "--connect-timeout",
                "5000",
                "-J",
            ])
            .output()
            .map_err(|_| "IPERF3_PROCESS_SPAWN_FAILED".to_string())?;
        if !output.status.success() {
            return Err("IPERF3_UL_FAILED".into());
        }
        let report: Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| "IPERF3_REPORT_INVALID".to_string())?;
        report
            .pointer("/end/sum_sent/bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| "IPERF3_BYTES_NOT_MEASURED".into())
    }
    fn deregister_switch_off(&self, job: &simulator_controller::UeJob) -> Result<(), String> {
        let _ = job;
        Err("UE_DEREGISTER_COMMAND_UNSUPPORTED".into())
    }
}

#[derive(Debug)]
struct UeLaunchFailure {
    error: String,
    process_handle: Option<String>,
}

impl UeLaunchFailure {
    fn before_launch(error: String) -> Self {
        Self {
            error,
            process_handle: None,
        }
    }

    fn after_launch(error: String, process_handle: String) -> Self {
        Self {
            error,
            process_handle: Some(process_handle),
        }
    }
}

struct DockerUeRuntime {
    ownership_id: Option<String>,
}

impl DockerUeRuntime {
    const ATTESTATION_PATH: &'static str =
        "/var/lib/polaris-control/ue-provisioning-attestation.json";

    fn output(args: &[String]) -> Result<String, String> {
        let output = Command::new("/usr/bin/timeout")
            .args(["--signal=TERM", "--kill-after=1s", "10s", "/usr/bin/docker"])
            .args(args)
            .output()
            .map_err(|_| "DOCKER_COMMAND_FAILED".to_string())?;
        if !output.status.success() {
            return Err("DOCKER_COMMAND_FAILED".into());
        }
        String::from_utf8(output.stdout).map_err(|_| "DOCKER_OUTPUT_INVALID".into())
    }

    fn container_id(handle: &str) -> Option<&str> {
        let id = handle.strip_prefix("container:")?;
        (id.len() == 64 && id.chars().all(|value| value.is_ascii_hexdigit())).then_some(id)
    }

    fn inspect_fields(target: &str) -> Result<Vec<String>, String> {
        let output = Self::output(&[
            "inspect".into(),
            "--format".into(),
            "{{.Id}}|{{.State.Status}}|{{.Image}}|{{index .Config.Labels \"polaris.control.owner\"}}|{{index .Config.Labels \"polaris.control.ue-id\"}}|{{index .Config.Labels \"polaris.control.profile\"}}|{{index .Config.Labels \"polaris.control.ownership-id\"}}|{{index .Config.Labels \"polaris.control.profile-sha256\"}}|{{index .Config.Labels \"polaris.control.script-sha256\"}}|{{.HostConfig.NetworkMode}}|{{json .Config.Entrypoint}}|{{json .Config.Cmd}}|{{.Config.User}}|{{json .HostConfig.CapAdd}}|{{json .HostConfig.CapDrop}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.SecurityOpt}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.Memory}}|{{.HostConfig.RestartPolicy.Name}}|{{json .Mounts}}|{{json .HostConfig.Tmpfs}}|{{json .HostConfig.Devices}}|{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{json .NetworkSettings.Networks}}".into(),
            target.into(),
        ])?;
        Ok(output.trim().split('|').map(str::to_string).collect())
    }

    fn valid_digest(value: &str) -> bool {
        value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
    }

    fn ue01_transfer_is_active(ownership_id: Option<&str>) -> Result<bool, String> {
        #[cfg(unix)]
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let path = Path::new(UE01_TRANSFER_ATTESTATION_PATH);
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err("UE01_TRANSFER_ATTESTATION_UNREADABLE".into()),
        };
        if !metadata.file_type().is_file()
            || metadata.len() > 16_384
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("UE01_TRANSFER_ATTESTATION_UNSAFE".into());
        }
        let ownership_id = ownership_id
            .filter(|value| Self::valid_digest(value))
            .ok_or("LIVE_UE_OWNERSHIP_ID_REQUIRED")?;
        let transfer: Ue01OwnershipTransferAttestation = serde_json::from_slice(
            &fs::read(path).map_err(|_| "UE01_TRANSFER_ATTESTATION_UNREADABLE")?,
        )
        .map_err(|_| "UE01_TRANSFER_ATTESTATION_INVALID")?;
        let compose_path = Path::new("/root/POLARIS/compose/docker-compose.oiran-lab.yml");
        let compose = fs::read(compose_path).map_err(|_| "UE01_COMPOSE_UNREADABLE")?;
        if !compose_disables_legacy_ue01(&String::from_utf8_lossy(&compose)) {
            return Err("UE01_COMPOSE_TRANSFER_MARKER_MISSING".into());
        }
        let profile = fs::read(Path::new(ueransim_adapter::LIVE_PROFILE_ROOT).join("ue-01.yaml"))
            .map_err(|_| "UE01_PROFILE_UNREADABLE")?;
        let legacy = Self::output(&[
            "ps".into(),
            "--all".into(),
            "--filter".into(),
            "name=oiran-lab-ueransim-ue-1".into(),
            "--format".into(),
            "{{.ID}}|{{.Names}}".into(),
        ])?;
        let legacy_id = legacy.lines().find_map(|line| {
            let (id, name) = line.trim().split_once('|')?;
            (name == "oiran-lab-ueransim-ue-1").then_some(id)
        });
        let evidence = Ue01OwnershipTransferEvidence {
            legacy_container_present: legacy_id.is_some(),
            legacy_container_running: false,
            legacy_container_id: None,
            compose_sha256: Self::hash_bytes(&compose)?,
            profile_sha256: Self::hash_bytes(&profile)?,
            ownership_id: ownership_id.into(),
        };
        validate_ue01_ownership_transfer(&transfer, &evidence)?;
        Ok(true)
    }

    fn hash_bytes(bytes: &[u8]) -> Result<String, String> {
        let mut child = Command::new("/usr/bin/timeout")
            .args([
                "--signal=TERM",
                "--kill-after=1s",
                "5s",
                "/usr/bin/sha256sum",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "PROVISIONING_DIGEST_FAILED".to_string())?;
        child
            .stdin
            .take()
            .ok_or("PROVISIONING_DIGEST_FAILED")?
            .write_all(bytes)
            .map_err(|_| "PROVISIONING_DIGEST_FAILED".to_string())?;
        let output = child
            .wait_with_output()
            .map_err(|_| "PROVISIONING_DIGEST_FAILED".to_string())?;
        if !output.status.success() {
            return Err("PROVISIONING_DIGEST_FAILED".into());
        }
        let digest = String::from_utf8(output.stdout)
            .map_err(|_| "PROVISIONING_DIGEST_FAILED".to_string())?
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
        Self::valid_digest(&digest)
            .then_some(digest)
            .ok_or_else(|| "PROVISIONING_DIGEST_FAILED".into())
    }

    fn profile_path(ue_id: &str, basename: &str) -> Result<PathBuf, String> {
        let expected = ue_id
            .strip_prefix("UE-")
            .map(|suffix| format!("ue-{suffix}.yaml"));
        if !ueransim_adapter::is_approved_controller_ue(ue_id)
            || expected.as_deref() != Some(basename)
        {
            return Err("PROVISIONING_PROFILE_PATH_NOT_ALLOWLISTED".into());
        }
        Ok(Path::new(ueransim_adapter::LIVE_PROFILE_ROOT).join(basename))
    }

    fn yaml_value(value: &str) -> String {
        value
            .split('#')
            .next()
            .unwrap_or_default()
            .trim()
            .trim_matches(|ch| matches!(ch, '\'' | '"'))
            .to_string()
    }

    fn top_level_scalar(document: &str, key: &str) -> Option<String> {
        let values = document
            .lines()
            .filter_map(|line| {
                (!line.starts_with(char::is_whitespace))
                    .then(|| line.split_once(':'))
                    .flatten()
                    .filter(|(candidate, _)| candidate.trim() == key)
                    .map(|(_, value)| Self::yaml_value(value))
                    .filter(|value| !value.is_empty())
            })
            .collect::<Vec<_>>();
        (values.len() == 1).then(|| values[0].clone())
    }

    fn split_yaml_fields(value: &str) -> Vec<&str> {
        let mut fields = Vec::new();
        let (mut depth, mut quoted, mut start) = (0_u8, None, 0_usize);
        for (index, ch) in value.char_indices() {
            match ch {
                '\'' | '"' if quoted == Some(ch) => quoted = None,
                '\'' | '"' if quoted.is_none() => quoted = Some(ch),
                '{' | '[' if quoted.is_none() => depth = depth.saturating_add(1),
                '}' | ']' if quoted.is_none() => depth = depth.saturating_sub(1),
                ',' if quoted.is_none() && depth == 0 => {
                    fields.push(value[start..index].trim());
                    start = index + 1;
                }
                _ => {}
            }
        }
        fields.push(value[start..].trim());
        fields
    }

    fn inline_yaml_map(value: &str) -> Option<BTreeMap<String, String>> {
        let inner = value.trim().strip_prefix('{')?.strip_suffix('}')?;
        let mut result = BTreeMap::new();
        for field in Self::split_yaml_fields(inner) {
            let (key, value) = field.split_once(':')?;
            if result
                .insert(key.trim().to_string(), value.trim().to_string())
                .is_some()
            {
                return None;
            }
        }
        Some(result)
    }

    fn slice_map(value: &str) -> Option<(u8, Option<String>)> {
        let map = Self::inline_yaml_map(value)?;
        let sst = Self::yaml_value(map.get("sst")?).parse().ok()?;
        let sd = map.get("sd").map(|value| {
            Self::yaml_value(value)
                .trim_start_matches("0x")
                .trim_start_matches("0X")
                .to_ascii_uppercase()
        });
        Some((sst, sd))
    }

    fn sequence_inline_maps(document: &str, key: &str) -> Option<Vec<BTreeMap<String, String>>> {
        let lines = document.lines().collect::<Vec<_>>();
        let starts = lines
            .iter()
            .enumerate()
            .filter_map(|(index, line)| {
                (!line.starts_with(char::is_whitespace)
                    && line
                        .split_once(':')
                        .is_some_and(|(candidate, _)| candidate.trim() == key))
                .then_some(index)
            })
            .collect::<Vec<_>>();
        if starts.len() != 1 {
            return None;
        }
        let start = starts[0];
        let inline = lines[start].split_once(':')?.1.trim();
        if !inline.is_empty() {
            let inner = inline.strip_prefix('[')?.strip_suffix(']')?;
            let values = Self::split_yaml_fields(inner)
                .into_iter()
                .map(Self::inline_yaml_map)
                .collect::<Option<Vec<_>>>()?;
            return (!values.is_empty()).then_some(values);
        }
        let mut values = Vec::new();
        let mut current = None::<BTreeMap<String, String>>;
        for line in lines.iter().skip(start + 1) {
            if !line.trim().is_empty() && !line.starts_with(char::is_whitespace) {
                break;
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(value) = trimmed.strip_prefix('-') {
                if let Some(previous) = current.take() {
                    values.push(previous);
                }
                let value = value.trim();
                current = if value.starts_with('{') {
                    Some(Self::inline_yaml_map(value)?)
                } else {
                    let (field, value) = value.split_once(':')?;
                    Some(BTreeMap::from([(
                        field.trim().to_string(),
                        value.trim().to_string(),
                    )]))
                };
            } else if let Some(fields) = current.as_mut() {
                let (field, value) = trimmed.split_once(':')?;
                if fields
                    .insert(field.trim().to_string(), value.trim().to_string())
                    .is_some()
                {
                    return None;
                }
            }
        }
        if let Some(last) = current {
            values.push(last);
        }
        (!values.is_empty()).then_some(values)
    }

    fn profile_network(document: &str) -> Option<(String, u8, Option<String>)> {
        let configured = Self::sequence_inline_maps(document, "configured-nssai")?;
        let defaults = Self::sequence_inline_maps(document, "default-nssai")?;
        let sessions = Self::sequence_inline_maps(document, "sessions")?;
        if configured.len() != 1 || defaults.len() != 1 || sessions.len() != 1 {
            return None;
        }
        let configured_slice = Self::slice_map(&format!(
            "{{sst: {}, sd: {}}}",
            configured[0].get("sst")?,
            configured[0].get("sd")?
        ))?;
        let default_slice = Self::slice_map(&format!(
            "{{sst: {}, sd: {}}}",
            defaults[0].get("sst")?,
            defaults[0].get("sd")?
        ))?;
        let session_slice = Self::slice_map(sessions[0].get("slice")?)?;
        if configured_slice != default_slice || default_slice != session_slice {
            return None;
        }
        let dnn = Self::yaml_value(sessions[0].get("apn").or_else(|| sessions[0].get("dnn"))?);
        Some((dnn, session_slice.0, session_slice.1))
    }

    fn profile_evidence(profile: &UeProfileSpec) -> Result<ProvisionedProfileEvidence, String> {
        #[cfg(unix)]
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let path = Self::profile_path(&profile.ue_id, &profile.profile_name)?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| "PROVISIONING_PROFILE_UNREADABLE".to_string())?;
        if !metadata.file_type().is_file() || metadata.len() > 65_536 {
            return Err("PROVISIONING_PROFILE_UNSAFE".into());
        }
        let bytes = fs::read(&path).map_err(|_| "PROVISIONING_PROFILE_UNREADABLE".to_string())?;
        let document =
            std::str::from_utf8(&bytes).map_err(|_| "PROVISIONING_PROFILE_INVALID".to_string())?;
        let identity =
            Self::top_level_scalar(document, "supi").ok_or("PROVISIONING_PROFILE_INVALID")?;
        let identity_digest = Self::hash_bytes(identity.as_bytes())?;
        let profile_digest = Self::hash_bytes(&bytes)?;
        let (dnn, sst, sd) =
            Self::profile_network(document).ok_or("PROVISIONING_PROFILE_INVALID")?;
        Ok(ProvisionedProfileEvidence {
            ue_id: profile.ue_id.clone(),
            profile_basename: profile.profile_name.clone(),
            profile_sha256: profile_digest,
            subscriber_identity_sha256: identity_digest,
            plmn_mcc: Self::top_level_scalar(document, "mcc")
                .ok_or("PROVISIONING_PROFILE_INVALID")?,
            plmn_mnc: Self::top_level_scalar(document, "mnc")
                .ok_or("PROVISIONING_PROFILE_INVALID")?,
            dnn,
            sst,
            sd,
            owner_uid: metadata.uid(),
            mode: metadata.permissions().mode() & 0o777,
        })
    }

    fn script_digest() -> Result<String, String> {
        #[cfg(unix)]
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let path = Path::new(ueransim_adapter::LIVE_START_SCRIPT);
        let metadata =
            fs::symlink_metadata(path).map_err(|_| "LIVE_START_SCRIPT_UNREADABLE".to_string())?;
        if !metadata.file_type().is_file()
            || metadata.len() > 65_536
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err("LIVE_START_SCRIPT_UNSAFE".into());
        }
        Self::hash_bytes(&fs::read(path).map_err(|_| "LIVE_START_SCRIPT_UNREADABLE".to_string())?)
    }

    fn json_array_equals(field: Option<&String>, expected: &[&str]) -> bool {
        field
            .and_then(|value| serde_json::from_str::<Vec<String>>(value).ok())
            .is_some_and(|actual| actual == expected)
    }

    fn envelope_matches(fields: &[String], spec: &LiveLaunchSpec) -> bool {
        let mounts_ok = fields
            .get(21)
            .and_then(|value| serde_json::from_str::<Vec<Value>>(value).ok())
            .is_some_and(|mounts| {
                let required_binds = [
                    (
                        Path::new(ueransim_adapter::LIVE_PROFILE_ROOT)
                            .join(&spec.profile_basename)
                            .display()
                            .to_string(),
                        "/run/secrets/ue.yaml",
                    ),
                    (
                        ueransim_adapter::LIVE_START_SCRIPT.to_string(),
                        "/usr/local/bin/start-ueransim-ue",
                    ),
                ];
                let binds_ok = required_binds.iter().all(|(source, destination)| {
                    mounts.iter().any(|mount| {
                        mount["Type"] == "bind"
                            && mount["Source"] == *source
                            && mount["Destination"] == *destination
                            && mount["RW"] == false
                    })
                }) && mounts
                    .iter()
                    .filter(|mount| mount["Type"] == "bind")
                    .count()
                    == 2;
                let expected_tmpfs = ["/tmp", "/etc/iproute2"];
                let fixture_tmpfs_ok = expected_tmpfs.iter().all(|destination| {
                    mounts.iter().any(|mount| {
                        mount["Type"] == "tmpfs"
                            && mount["Source"] == ""
                            && mount["Destination"] == *destination
                            && mount["RW"] == true
                    })
                }) && mounts
                    .iter()
                    .filter(|mount| mount["Type"] == "tmpfs")
                    .count()
                    == 2;
                binds_ok && (mounts.len() == 2 || (mounts.len() == 4 && fixture_tmpfs_ok))
            });
        let tmpfs_ok = fields
            .get(22)
            .and_then(|value| serde_json::from_str::<BTreeMap<String, String>>(value).ok())
            .is_some_and(|tmpfs| {
                tmpfs.len() == 2
                    && tmpfs.get("/tmp").map(String::as_str) == Some("size=64m")
                    && tmpfs.get("/etc/iproute2").map(String::as_str) == Some("size=1m")
            });
        let device_ok = fields
            .get(23)
            .and_then(|value| serde_json::from_str::<Vec<Value>>(value).ok())
            .is_some_and(|devices| {
                devices.len() == 1
                    && devices[0]["PathOnHost"] == "/dev/net/tun"
                    && devices[0]["PathInContainer"] == "/dev/net/tun"
                    && devices[0]["CgroupPermissions"] == "rwm"
            });
        let networks_ok = fields
            .get(27)
            .and_then(|value| serde_json::from_str::<BTreeMap<String, Value>>(value).ok())
            .is_some_and(|networks| {
                networks.len() == 1 && networks.contains_key(ueransim_adapter::LIVE_DOCKER_NETWORK)
            });
        fields.first().is_some_and(|id| id.len() == 64)
            && fields.get(2) == Some(&spec.image_id)
            && fields
                .get(3)
                .is_some_and(|value| value == "polaris-control")
            && fields.get(4) == Some(&spec.ue_id)
            && fields.get(5) == Some(&spec.profile_basename)
            && fields.get(6) == Some(&spec.owner_id)
            && fields.get(7) == Some(&spec.profile_sha256)
            && fields.get(8) == Some(&spec.script_sha256)
            && fields
                .get(9)
                .is_some_and(|value| value == ueransim_adapter::LIVE_DOCKER_NETWORK)
            && Self::json_array_equals(fields.get(10), &["/usr/local/bin/start-ueransim-ue"])
            && Self::json_array_equals(fields.get(11), &["/run/secrets/ue.yaml"])
            && fields.get(12).is_some_and(|value| value == "0:0")
            && fields
                .get(13)
                .and_then(|value| serde_json::from_str::<Vec<String>>(value).ok())
                .is_some_and(|capabilities| {
                    capabilities.len() == 1
                        && capabilities[0]
                            .strip_prefix("CAP_")
                            .unwrap_or(&capabilities[0])
                            == "NET_ADMIN"
                })
            && Self::json_array_equals(fields.get(14), &["ALL"])
            && fields.get(15).is_some_and(|value| value == "true")
            && Self::json_array_equals(fields.get(16), &["no-new-privileges:true"])
            && fields.get(17).is_some_and(|value| value == "128")
            && fields.get(18).is_some_and(|value| value == "750000000")
            && fields.get(19).is_some_and(|value| value == "536870912")
            && fields.get(20).is_some_and(|value| value == "no")
            && fields.get(24).is_some_and(|value| value == "false")
            && fields.get(25).is_some_and(String::is_empty)
            && fields
                .get(26)
                .is_some_and(|value| matches!(value.as_str(), "" | "private"))
            && mounts_ok
            && tmpfs_ok
            && device_ok
            && networks_ok
    }

    fn observation_commands(target: &str, node_name: &str) -> [Vec<String>; 3] {
        [
            vec![
                "exec".into(),
                target.into(),
                "nr-cli".into(),
                node_name.into(),
                "-e".into(),
                "status".into(),
            ],
            vec![
                "exec".into(),
                target.into(),
                "nr-cli".into(),
                node_name.into(),
                "-e".into(),
                "ps-list".into(),
            ],
            vec![
                "exec".into(),
                target.into(),
                "ip".into(),
                "-o".into(),
                "-4".into(),
                "addr".into(),
                "show".into(),
            ],
        ]
    }

    fn ue_cli_node(target: &str) -> Result<String, String> {
        let nodes = Self::output(&Self::node_list_command(target))?;
        let mut names = nodes.lines().map(str::trim).filter(|line| !line.is_empty());
        let node_name = names.next().ok_or("UE_CLI_NODE_NOT_OBSERVED")?;
        if names.next().is_some() {
            return Err("UE_CLI_NODE_AMBIGUOUS".into());
        }
        Ok(node_name.into())
    }

    fn execute_ue_cli(target: &str, command: String) -> Result<(), String> {
        let node_name = Self::ue_cli_node(target)?;
        Self::output(&[
            "exec".into(),
            target.into(),
            "nr-cli".into(),
            node_name,
            "-e".into(),
            command,
        ])
        .map(|_| ())
    }

    fn pdu_establish_command(profile: &UeProfileSpec) -> String {
        let mut command = format!(
            "ps-establish IPv4 --dnn {} --sst {}",
            profile.dnn, profile.sst
        );
        if let Some(sd) = profile.sd.as_deref() {
            command.push_str(" --sd ");
            command.push_str(sd);
        }
        command
    }

    fn wait_for_owned_pdu(
        &self,
        spec: &LiveLaunchSpec,
        handle: &str,
        expected: &str,
        timeout_seconds: u64,
        cancel: &AtomicBool,
    ) -> Result<(), String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_seconds);
        loop {
            if cancel.load(Ordering::SeqCst) {
                return Err("SCENARIO_STOP_REQUESTED".into());
            }
            let observed = self.observe_owned(spec, handle)?;
            if observed.pdu_session_state == expected {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!("PDU_STATE_{expected}_NOT_OBSERVED"));
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }

    fn node_list_command(target: &str) -> Vec<String> {
        vec![
            "exec".into(),
            target.into(),
            "nr-cli".into(),
            "--dump".into(),
        ]
    }

    fn observe_target(target: &str) -> Result<UeObservation, String> {
        let fields = Self::inspect_fields(target)?;
        let process_state = fields.get(1).map(String::as_str).unwrap_or("unknown");
        if process_state != "running" {
            return Ok(ueransim_adapter::observe_ueransim(process_state, "", ""));
        }
        let node_name = Self::ue_cli_node(target)?;
        let commands = Self::observation_commands(target, &node_name);
        let status = Self::output(&commands[0])?;
        let sessions = Self::output(&commands[1])?;
        let tunnels = Self::output(&commands[2])?;
        let current = format!("{status}\n---PDU---\n{sessions}");
        Ok(ueransim_adapter::observe_ueransim(
            process_state,
            &current,
            &tunnels,
        ))
    }

    fn namespace_pid(target: &str) -> Result<u32, String> {
        let output = Self::output(&[
            "inspect".into(),
            "--format".into(),
            "{{.State.Pid}}".into(),
            target.into(),
        ])?;
        output
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|pid| *pid > 1)
            .ok_or_else(|| "UE_NAMESPACE_UNAVAILABLE".into())
    }

    fn tunnel_interface(target: &str, ue_ip: &str) -> Result<String, String> {
        let addresses = Self::output(&[
            "exec".into(),
            target.into(),
            "ip".into(),
            "-j".into(),
            "-4".into(),
            "addr".into(),
            "show".into(),
        ])?;
        verified_tun_from_ip_json(&addresses, ue_ip)
    }

    fn verify_route(
        target: &str,
        destination: &str,
        tun_interface: &str,
        ue_ip: &str,
    ) -> Result<(), String> {
        if destination != "10.46.0.1" {
            return Err("TRAFFIC_DESTINATION_NOT_ALLOWLISTED".into());
        }
        let route = Self::output(&[
            "exec".into(),
            target.into(),
            "ip".into(),
            "route".into(),
            "get".into(),
            destination.into(),
        ])?;
        verified_route_uses_tun(&route, destination, tun_interface, ue_ip)
    }

    fn existing_launch(spec: &LiveLaunchSpec) -> Result<Option<String>, String> {
        let Ok(fields) = Self::inspect_fields(&spec.container_name) else {
            return Ok(None);
        };
        if !Self::envelope_matches(&fields, spec) {
            return Err("LIVE_UE_EXISTING_CONTAINER_ENVELOPE_MISMATCH".into());
        }
        let id = fields.first().ok_or("LIVE_UE_INSPECT_INVALID")?;
        let status = fields.get(1).ok_or("LIVE_UE_INSPECT_INVALID")?;
        if !matches!(status.as_str(), "created" | "exited" | "running") {
            return Err("LIVE_UE_EXISTING_CONTAINER_STATE_UNSAFE".into());
        }
        if status != "running" && Self::output(&["start".into(), id.clone()]).is_err() {
            return Err("LIVE_UE_RESTART_FAILED".into());
        }
        Ok(Some(format!("container:{id}")))
    }

    fn discover_launch(spec: &LiveLaunchSpec) -> Result<Option<String>, String> {
        let Ok(fields) = Self::inspect_fields(&spec.container_name) else {
            return Ok(None);
        };
        if !Self::envelope_matches(&fields, spec) {
            return Err("LIVE_UE_EXISTING_CONTAINER_ENVELOPE_MISMATCH".into());
        }
        let id = fields.first().ok_or("LIVE_UE_INSPECT_INVALID")?;
        let status = fields.get(1).ok_or("LIVE_UE_INSPECT_INVALID")?;
        if !matches!(
            status.as_str(),
            "created" | "exited" | "running" | "paused" | "restarting"
        ) {
            return Err("LIVE_UE_EXISTING_CONTAINER_STATE_UNSAFE".into());
        }
        Ok(Some(format!("container:{id}")))
    }
}

impl UeRuntime for DockerUeRuntime {
    fn verify_provisioning(
        &self,
        profiles: &[UeProfileSpec],
    ) -> Result<BTreeMap<String, String>, String> {
        #[cfg(unix)]
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = fs::symlink_metadata(Self::ATTESTATION_PATH)
            .map_err(|_| "PROVISIONING_ATTESTATION_UNREADABLE".to_string())?;
        if !metadata.file_type().is_file()
            || metadata.len() > 65_536
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("PROVISIONING_ATTESTATION_UNSAFE".into());
        }
        let bindings: Vec<ProvisioningBinding> = serde_json::from_slice(
            &fs::read(Self::ATTESTATION_PATH)
                .map_err(|_| "PROVISIONING_ATTESTATION_UNREADABLE".to_string())?,
        )
        .map_err(|_| "PROVISIONING_ATTESTATION_INVALID".to_string())?;
        let evidence = profiles
            .iter()
            .filter(|profile| profile.configured)
            .map(Self::profile_evidence)
            .collect::<Result<Vec<_>, _>>()?;
        ueransim_adapter::validate_provisioning_bindings(profiles, &evidence, &bindings)?;
        Ok(evidence
            .into_iter()
            .map(|item| (item.ue_id, item.profile_sha256))
            .collect())
    }

    fn approve_launch(
        &self,
        profile: &UeProfileSpec,
        profile_sha256: &str,
    ) -> Result<LiveLaunchSpec, String> {
        let ownership_id = self
            .ownership_id
            .as_deref()
            .filter(|value| Self::valid_digest(value))
            .ok_or("LIVE_UE_OWNERSHIP_ID_REQUIRED")?;
        let current = self.verify_provisioning(std::slice::from_ref(profile))?;
        if current.get(&profile.ue_id).map(String::as_str) != Some(profile_sha256) {
            return Err("PROVISIONING_PROFILE_CHANGED".into());
        }
        let image_id = Self::output(&[
            "inspect".into(),
            "--format".into(),
            "{{.Image}}".into(),
            "oiran-lab-ueransim-gnb-1".into(),
        ])?;
        ueransim_adapter::live_launch_spec(
            profile,
            Path::new(ueransim_adapter::LIVE_PROFILE_ROOT),
            image_id.trim(),
            Path::new(ueransim_adapter::LIVE_START_SCRIPT),
            ownership_id,
            profile_sha256,
            &Self::script_digest()?,
        )
    }

    fn launch(&self, spec: &LiveLaunchSpec) -> Result<String, UeLaunchFailure> {
        if let Some(handle) =
            Self::existing_launch(&spec).map_err(UeLaunchFailure::before_launch)?
        {
            return Ok(handle);
        }
        let id = Self::output(&spec.docker_args).map_err(UeLaunchFailure::before_launch)?;
        let id = id.trim();
        if id.len() != 64 || !id.chars().all(|value| value.is_ascii_hexdigit()) {
            return Err(UeLaunchFailure::before_launch(
                "LIVE_UE_CONTAINER_ID_INVALID".into(),
            ));
        }
        let handle = format!("container:{id}");
        let fields = Self::inspect_fields(id)
            .map_err(|error| UeLaunchFailure::after_launch(error, handle.clone()))?;
        if !Self::envelope_matches(&fields, &spec) {
            let stopped =
                Self::output(&["stop".into(), "--time".into(), "10".into(), id.into()]).is_ok();
            return Err(if stopped {
                UeLaunchFailure::before_launch("LIVE_UE_RUNTIME_ENVELOPE_MISMATCH".into())
            } else {
                UeLaunchFailure::after_launch("LIVE_UE_RUNTIME_ENVELOPE_MISMATCH".into(), handle)
            });
        }
        Ok(handle)
    }

    fn discover(&self, spec: &LiveLaunchSpec) -> Result<Option<String>, String> {
        Self::discover_launch(spec)
    }

    fn observe_owned(&self, spec: &LiveLaunchSpec, handle: &str) -> Result<UeObservation, String> {
        if !self.owns(spec, handle) {
            return Err("LIVE_UE_OWNERSHIP_NOT_PROVEN".into());
        }
        Self::observe_target(Self::container_id(handle).ok_or("INVALID_PROCESS_HANDLE")?)
    }

    fn observe_shared(&self) -> Result<UeObservation, String> {
        Self::observe_target("oiran-lab-ueransim-ue-1")
    }

    fn owns(&self, spec: &LiveLaunchSpec, handle: &str) -> bool {
        let Some(id) = Self::container_id(handle) else {
            return false;
        };
        let Ok(fields) = Self::inspect_fields(id) else {
            return false;
        };
        fields.first().is_some_and(|value| value == id) && Self::envelope_matches(&fields, spec)
    }

    fn stop(&self, spec: &LiveLaunchSpec, handle: &str) -> Result<(), String> {
        if !self.owns(spec, handle) {
            return Err("LIVE_UE_OWNERSHIP_NOT_PROVEN".into());
        }
        let id = Self::container_id(handle).ok_or("INVALID_PROCESS_HANDLE")?;
        let fields = Self::inspect_fields(id)?;
        if fields
            .get(1)
            .is_some_and(|state| matches!(state.as_str(), "exited" | "created"))
        {
            return Ok(());
        }
        Self::output(&["stop".into(), "--time".into(), "10".into(), id.into()]).map(|_| ())
    }

    fn establish_pdu(
        &self,
        job: &simulator_controller::UeJob,
        profile: &UeProfileSpec,
        timeout_seconds: u64,
        cancel: &AtomicBool,
    ) -> Result<(), String> {
        let handle = job.process_handle.as_deref().ok_or("UE_NOT_STARTED")?;
        let spec = job
            .approved_runtime
            .as_ref()
            .ok_or("LIVE_RUNTIME_APPROVAL_MISSING")?;
        if !self.owns(spec, handle) {
            return Err("LIVE_UE_OWNERSHIP_NOT_PROVEN".into());
        }
        if self.observe_owned(spec, handle)?.pdu_session_state == "ACTIVE" {
            return Ok(());
        }
        let target = Self::container_id(handle).ok_or("INVALID_PROCESS_HANDLE")?;
        Self::execute_ue_cli(target, Self::pdu_establish_command(profile))?;
        self.wait_for_owned_pdu(spec, handle, "ACTIVE", timeout_seconds, cancel)
    }

    fn release_pdu(
        &self,
        job: &simulator_controller::UeJob,
        timeout_seconds: u64,
        cancel: &AtomicBool,
    ) -> Result<(), String> {
        let handle = job.process_handle.as_deref().ok_or("UE_NOT_STARTED")?;
        let spec = job
            .approved_runtime
            .as_ref()
            .ok_or("LIVE_RUNTIME_APPROVAL_MISSING")?;
        if !self.owns(spec, handle) {
            return Err("LIVE_UE_OWNERSHIP_NOT_PROVEN".into());
        }
        if self.observe_owned(spec, handle)?.pdu_session_state == "INACTIVE" {
            return Ok(());
        }
        let target = Self::container_id(handle).ok_or("INVALID_PROCESS_HANDLE")?;
        Self::execute_ue_cli(target, "ps-release-all".into())?;
        self.wait_for_owned_pdu(spec, handle, "INACTIVE", timeout_seconds, cancel)
    }

    fn deregister_switch_off(&self, job: &simulator_controller::UeJob) -> Result<(), String> {
        let handle = job.process_handle.as_deref().ok_or("UE_NOT_STARTED")?;
        let spec = job
            .approved_runtime
            .as_ref()
            .ok_or("LIVE_RUNTIME_APPROVAL_MISSING")?;
        if !self.owns(spec, handle) {
            return Err("LIVE_UE_OWNERSHIP_NOT_PROVEN".into());
        }
        let target = Self::container_id(handle).ok_or("INVALID_PROCESS_HANDLE")?;
        Self::execute_ue_cli(target, "deregister switch-off".into())
    }

    fn resolve_traffic_target(
        &self,
        job: &simulator_controller::UeJob,
        destination: &str,
    ) -> Result<VerifiedTrafficTarget, String> {
        if !job.controller_owned || !ueransim_adapter::is_approved_controller_ue(&job.ue_id) {
            return Err("SHARED_UE_TRAFFIC_TARGET_FORBIDDEN".into());
        }
        if job.process_state != "RUNNING"
            || job.registration_state != "REGISTERED"
            || job.pdu_session_state != "ACTIVE"
        {
            return Err("UE_TRAFFIC_PREREQUISITES_NOT_MET".into());
        }
        let ue_ip = job
            .ue_ip
            .as_deref()
            .filter(|value| value.starts_with("10.46."))
            .ok_or("UE_IP_NOT_VERIFIED")?;
        let handle = job
            .process_handle
            .as_deref()
            .ok_or("UE_PROCESS_NOT_OWNED")?;
        let spec = job
            .approved_runtime
            .as_ref()
            .ok_or("UE_RUNTIME_APPROVAL_MISSING")?;
        if !self.owns(spec, handle) {
            return Err("UE_PROCESS_NOT_OWNED".into());
        }
        let observed = self.observe_owned(spec, handle)?;
        if observed.process_state != "RUNNING"
            || observed.registration_state != "REGISTERED"
            || observed.pdu_session_state != "ACTIVE"
            || observed.ue_ip.as_deref() != Some(ue_ip)
        {
            return Err("UE_RUNTIME_STATE_CHANGED".into());
        }
        let container_id = Self::container_id(handle).ok_or("INVALID_PROCESS_HANDLE")?;
        let namespace_pid = Self::namespace_pid(container_id)?;
        let tun_interface = Self::tunnel_interface(container_id, ue_ip)?;
        Self::verify_route(container_id, destination, &tun_interface, ue_ip)?;
        Ok(VerifiedTrafficTarget {
            ue_id: job.ue_id.clone(),
            pseudonym: job.pseudonym.clone(),
            namespace_pid,
            tun_interface,
            ue_ip: ue_ip.into(),
        })
    }
}

fn valid_tun_interface(value: &str) -> bool {
    value
        .strip_prefix("uesimtun")
        .is_some_and(|suffix| !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit()))
}

fn verified_tun_from_ip_json(document: &str, expected_ip: &str) -> Result<String, String> {
    let interfaces: Vec<Value> =
        serde_json::from_str(document).map_err(|_| "UE_TUN_INVENTORY_INVALID".to_string())?;
    let matches = interfaces
        .iter()
        .filter_map(|interface| {
            let name = interface.get("ifname")?.as_str()?;
            let has_ip = interface
                .get("addr_info")?
                .as_array()?
                .iter()
                .any(|address| {
                    address.get("family").and_then(Value::as_str) == Some("inet")
                        && address.get("local").and_then(Value::as_str) == Some(expected_ip)
                });
            (valid_tun_interface(name) && has_ip).then(|| name.to_string())
        })
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        Ok(matches[0].clone())
    } else {
        Err("UE_TUN_INTERFACE_NOT_UNIQUE".into())
    }
}

fn verified_route_uses_tun(
    route: &str,
    destination: &str,
    tun_interface: &str,
    ue_ip: &str,
) -> Result<(), String> {
    if !valid_tun_interface(tun_interface) {
        return Err("UE_TUN_INTERFACE_INVALID".into());
    }
    let fields = route.split_whitespace().collect::<Vec<_>>();
    let field_after = |key: &str| {
        fields
            .iter()
            .position(|field| *field == key)
            .and_then(|index| fields.get(index + 1).copied())
    };
    if fields.first().copied() == Some(destination)
        && field_after("dev") == Some(tun_interface)
        && field_after("src") == Some(ue_ip)
    {
        Ok(())
    } else {
        Err("UE_ROUTE_NOT_BOUND_TO_TUN".into())
    }
}

pub fn verify_open5gs_profile_binding(
    profile: &UeProfileSpec,
    profile_bytes: &[u8],
    record: &Value,
) -> Result<ProvisioningBinding, String> {
    let document = std::str::from_utf8(profile_bytes)
        .map_err(|_| "PROVISIONING_PROFILE_INVALID".to_string())?;
    let supi = DockerUeRuntime::top_level_scalar(document, "supi")
        .ok_or("PROVISIONING_PROFILE_INVALID")?;
    let imsi = supi.strip_prefix("imsi-").unwrap_or(&supi);
    if record.get("imsi").and_then(Value::as_str) != Some(imsi) {
        return Err("OPEN5GS_IDENTITY_MISMATCH".into());
    }
    let security = record
        .get("security")
        .and_then(Value::as_object)
        .ok_or("OPEN5GS_AUTH_MATERIAL_MISSING")?;
    let exact_hex = |profile_key: &str, record_keys: &[&str]| -> Result<(), String> {
        let profile_value = DockerUeRuntime::top_level_scalar(document, profile_key)
            .ok_or("PROVISIONING_PROFILE_INVALID")?;
        let record_value = record_keys
            .iter()
            .find_map(|key| security.get(*key).and_then(Value::as_str))
            .ok_or("OPEN5GS_AUTH_MATERIAL_MISSING")?;
        if profile_value.eq_ignore_ascii_case(record_value) {
            Ok(())
        } else {
            Err("OPEN5GS_AUTH_MATERIAL_MISMATCH".into())
        }
    };
    exact_hex("key", &["k", "key"])?;
    exact_hex("op", &["opc"])?;
    exact_hex("amf", &["amf"])?;
    if !DockerUeRuntime::top_level_scalar(document, "opType")
        .is_some_and(|value| value.eq_ignore_ascii_case("OPC"))
    {
        return Err("PROVISIONING_PROFILE_INVALID".into());
    }
    let (dnn, sst, sd) =
        DockerUeRuntime::profile_network(document).ok_or("PROVISIONING_PROFILE_INVALID")?;
    let normalize_sd = |value: &Value| -> Option<String> {
        if let Some(value) = value.as_str() {
            return Some(
                value
                    .trim_start_matches("0x")
                    .trim_start_matches("0X")
                    .to_ascii_uppercase(),
            );
        }
        value.as_u64().map(|value| format!("{value:06X}"))
    };
    let network_match = record
        .get("slice")
        .and_then(Value::as_array)
        .is_some_and(|slices| {
            slices.iter().any(|slice| {
                let record_sst = slice.get("sst").and_then(|value| {
                    value
                        .as_u64()
                        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
                });
                let record_sd = slice.get("sd").and_then(&normalize_sd);
                let dnn_match =
                    slice
                        .get("session")
                        .and_then(Value::as_array)
                        .is_some_and(|sessions| {
                            sessions.iter().any(|session| {
                                session
                                    .get("name")
                                    .or_else(|| session.get("dnn"))
                                    .and_then(Value::as_str)
                                    == Some(dnn.as_str())
                            })
                        });
                record_sst == Some(u64::from(sst)) && record_sd == sd && dnn_match
            })
        });
    if !network_match
        || DockerUeRuntime::top_level_scalar(document, "mcc").as_deref()
            != Some(profile.plmn_mcc.as_str())
        || DockerUeRuntime::top_level_scalar(document, "mnc").as_deref()
            != Some(profile.plmn_mnc.as_str())
        || dnn != profile.dnn
        || sst != profile.sst
        || sd != profile.sd
    {
        return Err("OPEN5GS_NETWORK_MISMATCH".into());
    }
    let authoritative_record =
        serde_json::to_vec(record).map_err(|_| "OPEN5GS_RECORD_INVALID".to_string())?;
    Ok(ProvisioningBinding {
        ue_id: profile.ue_id.clone(),
        profile_basename: profile.profile_name.clone(),
        profile_sha256: DockerUeRuntime::hash_bytes(profile_bytes)?,
        subscriber_identity_sha256: DockerUeRuntime::hash_bytes(supi.as_bytes())?,
        authority: "OPEN5GS".into(),
        authoritative_record_sha256: DockerUeRuntime::hash_bytes(&authoritative_record)?,
    })
}

#[derive(Clone)]
struct SessionRecord {
    username: String,
    role: String,
    csrf_token: String,
    expires_at: u64,
    certified_validation_until: Option<u64>,
    certified_scenario_type: Option<String>,
    certified_target_ue_id: Option<String>,
    ue_control_authorized_until: Option<u64>,
    ue_control_authorized_ids: BTreeSet<String>,
}

#[derive(Clone)]
struct EffectiveIdentity {
    role: String,
    username: Option<String>,
    session_id: Option<String>,
    csrf_valid: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub username: String,
    pub role: String,
    pub password_hash: String,
    pub enabled: bool,
}

#[derive(Default, Serialize, Deserialize)]
pub struct UserDatabase {
    pub users: Vec<UserRecord>,
}

impl AppState {
    pub fn from_env() -> Result<Self, String> {
        let policy_path: PathBuf = std::env::var("POLARIS_POLICY_PATH")
            .unwrap_or_else(|_| "/var/lib/polaris-control/scenario-policy.json".into())
            .into();
        let policy_enabled = fs::read_to_string(&policy_path)
            .ok()
            .and_then(|value| serde_json::from_str::<Value>(&value).ok())
            .and_then(|value| value["enabled"].as_bool())
            .unwrap_or(true);
        let job_state_path: PathBuf = std::env::var("POLARIS_JOB_STATE_PATH")
            .unwrap_or_else(|_| "/var/lib/polaris-control/jobs.json".into())
            .into();
        let stored = fs::read_to_string(&job_state_path)
            .ok()
            .and_then(|value| serde_json::from_str::<Value>(&value).ok());
        let runtime = recover_runtime(stored);
        let ue_job_state_path: PathBuf = std::env::var("POLARIS_UE_JOB_STATE_PATH")
            .unwrap_or_else(|_| "/var/lib/polaris-control/ue-jobs.json".into())
            .into();
        let configuration_path: PathBuf = std::env::var("POLARIS_CONFIGURATION_PATH")
            .unwrap_or_else(|_| "/var/lib/polaris-control/configuration.json".into())
            .into();
        let configuration = match fs::read_to_string(&configuration_path) {
            Ok(value) => serde_json::from_str::<DesiredConfiguration>(&value)
                .map_err(|_| "CONFIGURATION_REGISTRY_INVALID".to_string())?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                DesiredConfiguration::default()
            }
            Err(_) => return Err("CONFIGURATION_REGISTRY_UNREADABLE".into()),
        };
        validate_configuration(configuration.ue_count, configuration.gnb_count)?;
        let ownership_id = std::env::var("POLARIS_UE_OWNERSHIP_ID").ok();
        let ue01_controller_owned =
            DockerUeRuntime::ue01_transfer_is_active(ownership_id.as_deref())?;
        let ue_runtime: Arc<dyn UeRuntime> = Arc::new(DockerUeRuntime { ownership_id });
        let profile_store = ProfileStore::with_gnbs(
            std::env::var("POLARIS_UE_PROFILE_REGISTRY_PATH")
                .unwrap_or_else(|_| "/var/lib/polaris-control/ue-profile-registry.json".into())
                .into(),
            std::env::var("POLARIS_UE_PROFILE_ROOT")
                .unwrap_or_else(|_| ueransim_adapter::LIVE_PROFILE_ROOT.into())
                .into(),
            ueransim_adapter::load_gnb_registry_from_env()?,
        )
        .with_subscriber_plan(
            std::env::var("POLARIS_SUBSCRIBER_PLAN_PATH")
                .unwrap_or_else(|_| ue_profiles::DEFAULT_SUBSCRIBER_PLAN_PATH.into())
                .into(),
        );
        let scenario_definition_store = ScenarioDefinitionStore::new(
            std::env::var("POLARIS_SCENARIO_CATALOG_PATH")
                .unwrap_or_else(|_| "/var/lib/polaris-control/scenario-definitions.json".into())
                .into(),
        );
        let scenario_catalog = scenario_definition_store.load()?;
        let fallback_profiles = ueransim_adapter::planned_profiles()
            .into_iter()
            .take(configuration.ue_count)
            .map(|mut profile| {
                profile.configured = true;
                profile
            })
            .collect();
        let mut profile_registry = profile_store.load_or_bootstrap(fallback_profiles)?;
        let mut profiles = profile_registry
            .profiles
            .iter()
            .map(|record| record.profile.clone())
            .collect::<Vec<_>>();
        if let Ok(verified) = ue_runtime.verify_provisioning(&profiles) {
            for profile in profiles.iter_mut().take(configuration.ue_count) {
                profile.subscription_verified = verified.contains_key(&profile.ue_id);
            }
            for record in &mut profile_registry.profiles {
                record.profile.subscription_verified = verified.contains_key(&record.profile.ue_id);
            }
        }
        let mut multi_ue = MultiUeController::new(profiles, ueransim_adapter::MAX_LIVE_UES)?;
        multi_ue.configure_count(configuration.ue_count)?;
        if let Ok(value) = fs::read_to_string(&ue_job_state_path) {
            let mut records: Vec<simulator_controller::UeJob> =
                serde_json::from_str(&value).map_err(|_| "UE_JOB_REGISTRY_INVALID".to_string())?;
            discover_reserved_handles(ue_runtime.as_ref(), &mut records)?;
            let approvals = records
                .iter()
                .filter_map(|record| Some((record.ue_id.clone(), record.approved_runtime.clone()?)))
                .collect::<BTreeMap<_, _>>();
            multi_ue.reconcile(records, |ue_id, _, handle| {
                ue_runtime.observe_owned(approvals.get(ue_id)?, handle).ok()
            })?;
        }
        Ok(Self {
            storage_path: std::env::var("POLARIS_STORAGE_PATH")
                .unwrap_or_else(|_| "/root/POLARIS_CONTROL".into())
                .into(),
            static_dir: std::env::var("POLARIS_WEB_DIR")
                .unwrap_or_else(|_| "/root/POLARIS_CONTROL/apps/web/dist".into())
                .into(),
            users_path: std::env::var("POLARIS_USERS_PATH")
                .unwrap_or_else(|_| "/var/lib/polaris-control/users.json".into())
                .into(),
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
            audit_path: std::env::var("POLARIS_AUDIT_PATH")
                .unwrap_or_else(|_| "/var/log/polaris-control/audit.jsonl".into())
                .into(),
            job_state_path,
            ue_job_state_path,
            cpu_decision_path: std::env::var("POLARIS_CPU_DECISION_PATH")
                .unwrap_or_else(|_| "/var/lib/polaris-control/cpu-decisions.json".into())
                .into(),
            cpu_decision_lock: Arc::new(Mutex::new(())),
            latest_cpu_decision: Arc::new(Mutex::new(None)),
            configuration_path,
            profile_store,
            profile_registry: Arc::new(Mutex::new(profile_registry)),
            scenario_definition_store,
            scenario_catalog: Arc::new(Mutex::new(scenario_catalog)),
            definition_live_enabled: std::env::var("POLARIS_DEFINITION_LIVE_ENABLED")
                .is_ok_and(|value| value == "true"),
            definition_jobs: Arc::new(Mutex::new(BTreeMap::new())),
            policy_path,
            policy_enabled: Arc::new(AtomicBool::new(policy_enabled)),
            execution_mode: std::env::var("POLARIS_EXECUTION_MODE")
                .unwrap_or_else(|_| "disabled".into()),
            additional_ue_live_enabled: std::env::var("POLARIS_ADDITIONAL_UE_LIVE_ENABLED")
                .is_ok_and(|value| value == "true"),
            ue01_controller_owned,
            ue_runtime,
            resource_override: None,
            cpu_safety: Arc::new(Mutex::new(CpuSafetyMonitor::default())),
            runtime: Arc::new(Mutex::new(runtime)),
            multi_ue: Arc::new(Mutex::new(multi_ue)),
            configuration: Arc::new(Mutex::new(configuration)),
            ue_operations: Arc::new(Mutex::new(())),
            ue_inventory_running: Arc::new(AtomicBool::new(false)),
            ue_inventory_last_observed_epoch_s: Arc::new(AtomicU64::new(0)),
            ue_inventory_cache_version: Arc::new(AtomicU64::new(0)),
            shared_ue_cache: Arc::new(Mutex::new(None)),
            ue_reconciliation_running: Arc::new(AtomicBool::new(false)),
            ue_reconciliation: Arc::new(Mutex::new(UeReconciliation::default())),
            startup_reconcile: true,
        })
    }
}

fn discover_reserved_handles(
    runtime: &dyn UeRuntime,
    records: &mut [simulator_controller::UeJob],
) -> Result<(), String> {
    for record in records {
        if record.process_handle.is_none() {
            if let Some(spec) = record.approved_runtime.as_ref() {
                record.process_handle = runtime.discover(spec)?;
            }
        }
    }
    Ok(())
}

fn discover_and_reconcile_reserved_handles(state: &AppState) -> Result<(), String> {
    let mut records = state
        .multi_ue
        .lock()
        .map_err(|_| "UE_REGISTRY_UNAVAILABLE")?
        .snapshot();
    discover_reserved_handles(state.ue_runtime.as_ref(), &mut records)?;
    let approvals = records
        .iter()
        .filter_map(|record| Some((record.ue_id.clone(), record.approved_runtime.clone()?)))
        .collect::<BTreeMap<_, _>>();
    let mut controller = state
        .multi_ue
        .lock()
        .map_err(|_| "UE_REGISTRY_UNAVAILABLE")?;
    controller.reconcile(records, |ue_id, _, handle| {
        state
            .ue_runtime
            .observe_owned(approvals.get(ue_id)?, handle)
            .ok()
    })?;
    persist_ue_registry(state, &controller)
}

fn recover_runtime(stored: Option<Value>) -> ControlRuntime {
    let mut history: Vec<Value> = stored
        .as_ref()
        .and_then(|value| value["history"].as_array().cloned())
        .unwrap_or_default();
    for record in &mut history {
        let interrupted_definition = record.get("scenario_definition_id").is_some()
            && matches!(
                record.get("state").and_then(Value::as_str),
                Some("RUNNING" | "STOPPING")
            );
        if interrupted_definition {
            record["state"] = json!("FAILED");
            record["ended_at_epoch_s"] = json!(epoch_seconds());
            record["terminal_result"] = json!("CONTROLLER_RESTART_RECOVERY");
            if let Some(steps) = record.get_mut("steps").and_then(Value::as_array_mut) {
                for step in steps.iter_mut().filter(|step| step["state"] == "RUNNING") {
                    step["state"] = json!("FAILED");
                    step["ended_at"] = json!(epoch_seconds());
                    step["error"] = json!("CONTROLLER_RESTART_INTERRUPTED_STEP");
                }
            }
        }
    }
    history.iter_mut().for_each(normalize_terminal_record);
    if let Some(mut interrupted) = stored.and_then(|value| value["active"].as_object().cloned()) {
        interrupted.insert("state".into(), json!("FAILED"));
        interrupted.insert("traffic_state".into(), json!("FAILED"));
        interrupted.insert("ended_at_epoch_s".into(), json!(epoch_seconds()));
        interrupted.insert(
            "terminal_result".into(),
            json!("CONTROLLER_RESTART_RECOVERY"),
        );
        let mut recovered = Value::Object(interrupted);
        normalize_terminal_record(&mut recovered);
        history.push(recovered);
    }
    ControlRuntime {
        active: None,
        history,
    }
}

fn random_hex(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut value);
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let (key, value) = cookie.trim().split_once('=')?;
                (key == name).then(|| value.to_string())
            })
        })
}

fn load_users(path: &Path) -> Result<UserDatabase, String> {
    let value = fs::read_to_string(path).map_err(|_| "USER_DATABASE_UNAVAILABLE".to_string())?;
    serde_json::from_str(&value).map_err(|_| "USER_DATABASE_INVALID".to_string())
}

pub fn provision_user(
    path: &Path,
    username: &str,
    role: &str,
    password: &str,
) -> Result<(), String> {
    if username.len() < 3
        || username.len() > 48
        || !username
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err("username must use 3-48 ASCII letters, digits, '-' or '_'".into());
    }
    if !matches!(role, "operator" | "administrator") {
        return Err("role must be operator or administrator".into());
    }
    if password.len() < 14 {
        return Err("password must contain at least 14 characters".into());
    }
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| "password hashing failed".to_string())?
        .to_string();
    let mut database = match load_users(path) {
        Ok(database) => database,
        Err(error) if !path.exists() && error == "USER_DATABASE_UNAVAILABLE" => {
            UserDatabase::default()
        }
        Err(error) => return Err(error),
    };
    database.users.retain(|user| user.username != username);
    database.users.push(UserRecord {
        username: username.into(),
        role: role.into(),
        password_hash,
        enabled: true,
    });
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let temporary = path.with_extension("json.tmp");
    fs::write(
        &temporary,
        serde_json::to_vec_pretty(&database).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    fs::rename(temporary, path).map_err(|error| error.to_string())
}

async fn authorize(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let now = epoch_seconds();
    let session_id = cookie_value(request.headers(), "polaris_session");
    let session = session_id.as_ref().and_then(|id| {
        let mut sessions = state.sessions.lock().ok()?;
        sessions.retain(|_, session| session.expires_at > now);
        sessions.get(id).cloned()
    });
    let csrf_valid = session.as_ref().map_or(false, |session| {
        matches!(
            *request.method(),
            Method::GET | Method::HEAD | Method::OPTIONS
        ) || request
            .headers()
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == session.csrf_token)
    });
    let identity = session.map_or(
        EffectiveIdentity {
            role: "viewer".into(),
            username: None,
            session_id: None,
            csrf_valid: true,
        },
        |session| EffectiveIdentity {
            role: session.role,
            username: Some(session.username),
            session_id,
            csrf_valid,
        },
    );
    request.extensions_mut().insert(identity);
    next.run(request).await
}

#[derive(Deserialize)]
struct LoginInput {
    username: String,
    password: String,
}

fn secure_login_channel(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        == Some("https")
        || headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|host| host.starts_with("127.0.0.1:") || host.starts_with("localhost:"))
}

async fn login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<LoginInput>,
) -> Response {
    if !secure_login_channel(&headers) {
        return (
            StatusCode::UPGRADE_REQUIRED,
            Json(json!({"error":"SECURE_LOGIN_CHANNEL_REQUIRED"})),
        )
            .into_response();
    }
    let database = match load_users(&state.users_path) {
        Ok(database) => database,
        Err(error) => {
            audit(&state, "viewer", "LOGIN", &error, None);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":error})),
            )
                .into_response();
        }
    };
    let user = database
        .users
        .iter()
        .find(|user| user.enabled && user.username == input.username);
    let valid = user.is_some_and(|user| {
        PasswordHash::new(&user.password_hash)
            .ok()
            .is_some_and(|hash| {
                Argon2::default()
                    .verify_password(input.password.as_bytes(), &hash)
                    .is_ok()
            })
    });
    if !valid {
        audit(&state, "viewer", "LOGIN", "INVALID_CREDENTIALS", None);
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"INVALID_USERNAME_OR_PASSWORD"})),
        )
            .into_response();
    }
    let user = user.unwrap();
    let session_id = random_hex(32);
    let csrf_token = random_hex(32);
    let expires_at = epoch_seconds() + 8 * 60 * 60;
    state.sessions.lock().unwrap().insert(
        session_id.clone(),
        SessionRecord {
            username: user.username.clone(),
            role: user.role.clone(),
            csrf_token: csrf_token.clone(),
            expires_at,
            certified_validation_until: None,
            certified_scenario_type: None,
            certified_target_ue_id: None,
            ue_control_authorized_until: None,
            ue_control_authorized_ids: BTreeSet::new(),
        },
    );
    audit(&state, &user.role, "LOGIN", "SUCCESS", None);
    let mut response = Json(json!({"authenticated":true,"username":user.username,"role":user.role,"csrf_token":csrf_token,"expires_at_epoch_s":expires_at})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!("polaris_session={session_id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800"))
            .unwrap(),
    );
    response
}

async fn logout(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
) -> Response {
    if identity.role != "viewer" && !identity.csrf_valid {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"CSRF_TOKEN_REQUIRED"})),
        )
            .into_response();
    }
    if let Some(session_id) = identity.session_id {
        state.sessions.lock().unwrap().remove(&session_id);
    }
    audit(&state, &identity.role, "LOGOUT", "SUCCESS", None);
    let mut response = Json(json!({"authenticated":false,"role":"viewer"})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "polaris_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
        ),
    );
    response
}

async fn health() -> Json<Value> {
    Json(
        json!({"status":"ok","service":"POLARIS Control","version":VERSION,"live_control":"OPERATOR_POLICY"}),
    )
}
async fn version() -> Json<Value> {
    Json(
        json!({"platform":"3.2.1","api":VERSION,"scenario_engine":scenario_engine::VERSION,"safety_guard":safety_guard::VERSION,"ueransim_adapter":ueransim_adapter::VERSION,"multi_ue_controller":simulator_controller::VERSION}),
    )
}
async fn capabilities() -> Json<Value> {
    let ue_profile = Path::new("/root/POLARIS/runtime/ueransim/ue.yaml").exists();
    Json(json!({
        "live_control":true,
        "approval_state":"OPERATOR_AUTHORIZATION_REQUIRED",
        "max_ues":ueransim_adapter::MAX_LIVE_UES,
        "max_configured_profiles":ueransim_adapter::MAX_CONFIGURABLE_UES,
        "max_ues_live_certified":1,
        "max_ues_implemented":ueransim_adapter::MAX_LIVE_UES,
        "max_nodes":2,
        "max_nodes_live_certified":1,
        "registration_modes":["STAGGERED"],
        "additional_ue_ids":ueransim_adapter::planned_profiles().into_iter().skip(1).map(|profile|profile.ue_id).collect::<Vec<_>>(),
        "traffic_protocols":["ICMP","UDP","TCP"],
        "approved_destinations":["10.46.0.1"],
        "executable_scenario_step_types":[
            "ue_start",
            "ue_stop",
            "pdu_establish",
            "pdu_release",
            "udp_traffic",
            "wait",
            "traffic_ul",
            "idle",
            "detach",
            "repeat"
        ],
        "unavailable_scenario_step_types":[
            {"type":"traffic_dl","http_status":422,"reason":"DL_SENDER_NOT_AVAILABLE"},
            {"type":"ims_register","http_status":423,"reason":"IMS_NOT_AVAILABLE"},
            {"type":"voice_call","http_status":423,"reason":"IMS_NOT_AVAILABLE"}
        ],
        "scenario_step_limits":{
            "traffic_bytes_max":209715200_u64,
            "repeat_depth_max":2,
            "resolved_steps_max":10000
        },
        "certified_scenarios":[{"id":"bounded-existing-ue-udp-v1","name":"Bounded existing UE UDP","certified":true,"ue_lifecycle":false,"gnb_lifecycle":false,"max_datagrams":5,"destination":"10.46.0.1","destination_port":49001}],
        "profiles":ueransim_adapter::planned_profiles().into_iter().map(|profile|json!({"id":profile.ue_id,"name":profile.pseudonym,"available":profile.configured,"source":profile.profile_name,"subscription_verified":profile.subscription_verified})).collect::<Vec<_>>(),
        "technologies":[
            {"id":"5g-sa","name":"5G SA","simulator":"UERANSIM","available":ue_profile,"certified":true,"node_label":"gNB"},
            {"id":"lte","name":"LTE","simulator":"srsRAN","available":false,"certified":false,"node_label":"eNB","reason":"LTE_ATTACH_NOT_CERTIFIED"}
        ],
        "services":[
            {"id":"registration","name":"Registration","supported":false,"implemented_scope":"BOUNDED_PROVISIONED_PROFILES_THROUGH_UE_10","reason":"LIVE_ACCEPTANCE_NOT_YET_COMPLETE"},
            {"id":"pdu-session","name":"PDU Session","supported":false,"implemented_scope":"OBSERVE_ONLY_AFTER_DEFAULT_SESSION_ESTABLISHMENT","reason":"LIVE_ACCEPTANCE_NOT_YET_COMPLETE"},
            {"id":"udp","name":"UDP Data","supported":true},
            {"id":"icmp","name":"ICMP Data","supported":false,"reason":"NOT_CERTIFIED"},
            {"id":"tcp","name":"TCP Data","supported":false,"reason":"NOT_CERTIFIED"},
            {"id":"session-release","name":"Session Release","supported":false,"reason":"NOT_VALIDATED"},
            {"id":"deregistration","name":"Deregistration","supported":false,"reason":"NOT_VALIDATED"}
        ]
    }))
}

async fn get_configuration(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(configuration_json(
        &state,
        &state.configuration.lock().unwrap(),
    ))
}

#[derive(Deserialize)]
struct ConfigurationInput {
    ue_count: usize,
    gnb_count: usize,
}

async fn apply_configuration(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    Json(input): Json<ConfigurationInput>,
) -> impl IntoResponse {
    if let Err(error) = require_operator(&identity) {
        return error;
    }
    if let Err(error) = validate_configuration(input.ue_count, input.gnb_count) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error":error})),
        );
    }
    if state.execution_mode == "live" && !state.additional_ue_live_enabled {
        return (
            StatusCode::LOCKED,
            Json(json!({"error":"ADDITIONAL_UE_LIVE_AUTHORIZATION_REQUIRED"})),
        );
    }
    if state
        .ue_reconciliation_running
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"UE_RECONCILIATION_IN_PROGRESS"})),
        );
    }
    let previous = state.configuration.lock().unwrap().clone();
    let next = DesiredConfiguration {
        ue_count: input.ue_count,
        gnb_count: input.gnb_count,
        updated_at_epoch_s: epoch_seconds(),
        updated_by: identity
            .username
            .clone()
            .unwrap_or_else(|| identity.role.clone()),
    };
    let mut desired_profiles = state.multi_ue.lock().unwrap().profiles();
    desired_profiles
        .iter_mut()
        .enumerate()
        .for_each(|(index, profile)| profile.configured = index < input.ue_count);
    let verified = if state.execution_mode == "live" {
        let preflight_state = state.clone();
        let preflight_profiles = desired_profiles.clone();
        let additions = if input.ue_count > previous.ue_count {
            let active_owned = state
                .multi_ue
                .lock()
                .unwrap()
                .snapshot()
                .iter()
                .filter(|job| {
                    matches!(
                        job.process_state.as_str(),
                        "STARTING" | "RESTARTING" | "PAUSED" | "RUNNING" | "MOCK_RUNNING"
                    )
                })
                .count();
            input
                .ue_count
                .saturating_sub(1)
                .saturating_sub(active_owned)
        } else {
            0
        };
        let preflight = tokio::task::spawn_blocking(move || {
            if additions > 0 {
                resource_gate_for_additions(&preflight_state, additions)
                    .map_err(|error| (StatusCode::SERVICE_UNAVAILABLE, error))?;
            }
            preflight_state
                .ue_runtime
                .verify_provisioning(&preflight_profiles)
                .map_err(|error| (StatusCode::UNPROCESSABLE_ENTITY, error))
        })
        .await
        .unwrap_or_else(|_| {
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "UE_PREFLIGHT_TASK_FAILED".into(),
            ))
        });
        match preflight {
            Ok(verified) => verified,
            Err((status, error)) => {
                state
                    .ue_reconciliation_running
                    .store(false, Ordering::Release);
                return (status, Json(json!({"error":error})));
            }
        }
    } else {
        desired_profiles
            .iter()
            .filter(|profile| profile.configured)
            .map(|profile| (profile.ue_id.clone(), String::new()))
            .collect()
    };
    if let Err(error) = persist_configuration(&state.configuration_path, &next) {
        state
            .ue_reconciliation_running
            .store(false, Ordering::Release);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":error})),
        );
    }
    *state.configuration.lock().unwrap() = next.clone();
    let operation_id = random_hex(16);
    *state.ue_reconciliation.lock().unwrap() = UeReconciliation {
        operation_id: Some(operation_id.clone()),
        desired_count: input.ue_count,
        state: "RUNNING".into(),
        started_at_epoch_s: Some(epoch_seconds()),
        completed_at_epoch_s: None,
        started: Vec::new(),
        stopped: Vec::new(),
        failures: Vec::new(),
    };
    audit(
        &state,
        &identity.role,
        "APPLY_CONFIGURATION",
        "UE_RECONCILIATION_ACCEPTED",
        Some(&operation_id),
    );
    let reconcile_state = state.clone();
    tokio::task::spawn_blocking(move || {
        reconcile_ue_count(reconcile_state, input.ue_count, verified)
    });
    (
        StatusCode::ACCEPTED,
        Json(configuration_json(&state, &next)),
    )
}
async fn me(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
) -> Json<Value> {
    // A valid HttpOnly session may outlive per-tab sessionStorage. Returning the
    // session's CSRF token from this same-origin authenticated endpoint lets a
    // new tab restore write protection without asking for the password again.
    let csrf_token = identity.session_id.as_ref().and_then(|session_id| {
        state
            .sessions
            .lock()
            .ok()?
            .get(session_id)
            .map(|session| session.csrf_token.clone())
    });
    Json(json!({
        "authenticated": identity.username.is_some(),
        "username": identity.username,
        "role": identity.role,
        "can_start": matches!(identity.role.as_str(), "operator" | "administrator"),
        "can_manage_permissions": identity.role == "administrator",
        "csrf_token": csrf_token
    }))
}

async fn system(State(state): State<Arc<AppState>>) -> Json<Value> {
    let sample = measure(&state.storage_path);
    let decision = evaluate(sample.clone(), Policy::default());
    let disk = sample.ok().map(|s| json!({"total_bytes":s.total_bytes,"used_bytes":s.used_bytes(),"available_bytes":s.available_bytes,"usage_percent":s.basis_points().map(|v|f64::from(v)/100.0),"available_inodes":s.available_inodes}));
    let memory = memory_stats();
    let cpu_safety = cpu_safety_evidence(&state, ScenarioResourceBudget::traffic());
    let four_plane_capture_budget = ScenarioResourceBudget::four_plane_capture();
    Json(
        json!({"disk":disk,"decision":decision,"memory":memory,"cpu":{"usage_percent":cpu_safety.host.usage_percent,"idle_percent":cpu_safety.host.idle_percent,"steal_percent":cpu_safety.host.steal_percent,"iowait_percent":cpu_safety.host.iowait_percent,"logical_cpus":cpu_safety.host.logical_cpus,"sample_duration_ms":cpu_safety.host.sample_duration_ms},"cpu_safety":cpu_safety,"reference_budgets":{"four_plane_capture":four_plane_capture_budget},"load_average":fs::read_to_string("/proc/loadavg").unwrap_or_else(|_|"NOT_AVAILABLE".into()).trim(),"uptime_seconds":fs::read_to_string("/proc/uptime").ok().and_then(|v|v.split_whitespace().next()?.parse::<f64>().ok()),"observed_at_epoch_s":epoch_seconds(),"decision_source":"MEASURED","poll_interval_ms":1000,"capture_limits":{"max_file_bytes":268435456u64,"max_files":8,"max_duration_seconds":900,"max_concurrent_jobs":1},"automatic_cleanup":false}),
    )
}

async fn cpu_decisions(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
) -> impl IntoResponse {
    if !matches!(identity.role.as_str(), "operator" | "administrator") {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"OPERATOR_PERMISSION_REQUIRED"})),
        );
    }
    let records = match fs::read_to_string(&state.cpu_decision_path) {
        Ok(value) => match serde_json::from_str::<Vec<Value>>(&value) {
            Ok(records) => records,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error":"CPU_DECISION_EVIDENCE_INVALID"})),
                )
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"CPU_DECISION_EVIDENCE_UNREADABLE"})),
            )
        }
    };
    let total = records.len();
    let items = records.into_iter().rev().take(50).collect::<Vec<_>>();
    (StatusCode::OK, Json(json!({"total":total,"items":items})))
}

async fn lab(State(state): State<Arc<AppState>>) -> Json<Value> {
    let ue = Path::new("/root/POLARIS/runtime/ueransim/ue.yaml").exists();
    let active_jobs = state
        .runtime
        .lock()
        .map(|runtime| usize::from(runtime.active.is_some()))
        .unwrap_or(0);
    Json(
        json!({"source":"READ_ONLY_HOST_AUDIT","configuration_changed":false,"observed":{
            "ueransim_ue_profile":ue,
            "ueransim_profile":"ue.yaml",
            "open5gs":container_status("oiran-lab-amf-1"),
            "ueransim_gnb":container_status("oiran-lab-ueransim-gnb-1"),
            "ueransim_ue":container_status("oiran-lab-ueransim-ue-1"),
            "srsran_enb":container_status("oiran-lab-srsenb-1"),
            "srsran_ue":container_status("oiran-lab-srsue-1"),
            "lte_attach":"NOT_CERTIFIED",
            "controller_owned_active_jobs":active_jobs
        }}),
    )
}

fn container_status(name: &str) -> Value {
    let output = Command::new("/usr/bin/timeout")
        .args(["--signal=TERM", "--kill-after=1s", "10s", "/usr/bin/docker", "inspect", "--format", "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}not_available{{end}}", name])
        .output();
    match output {
        Ok(value) if value.status.success() => {
            let text = String::from_utf8_lossy(&value.stdout);
            let mut fields = text.trim().split('|');
            json!({"process_state":fields.next().unwrap_or("unknown"),"health":fields.next().unwrap_or("unknown"),"observed":true})
        }
        _ => json!({"process_state":"unknown","health":"unknown","observed":false}),
    }
}

fn memory_stats() -> Value {
    let mut total = None;
    let mut available = None;
    for line in fs::read_to_string("/proc/meminfo")
        .unwrap_or_default()
        .lines()
    {
        let bytes = line
            .split_whitespace()
            .nth(1)
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v * 1024);
        if line.starts_with("MemTotal:") {
            total = bytes;
        }
        if line.starts_with("MemAvailable:") {
            available = bytes;
        }
    }
    json!({"total_bytes":total,"available_bytes":available,"used_bytes":total.zip(available).map(|(t,a)|t.saturating_sub(a))})
}

async fn nodes(State(state): State<Arc<AppState>>) -> Json<Value> {
    let gnb = container_status("oiran-lab-ueransim-gnb-1");
    let enb = container_status("oiran-lab-srsenb-1");
    let configured_gnbs = state.configuration.lock().unwrap().gnb_count;
    Json(json!({
        "items":[
            {"id":"GNB-01","name":"Primary gNB","technology":"5G SA","simulator":"UERANSIM","plmn":"001-01","cell_id":"0x000000010","link_ip":"10.77.0.20","n2_endpoint":"10.77.21.20","n3_endpoint":"10.77.22.20","process_state":gnb["process_state"],"health":gnb["health"],"configured":true,"controller_owned":false,"uptime_seconds":Value::Null,"actions":{"start":false,"stop":false,"reason":"SHARED_NODE_PROTECTED"}},
            {"id":"GNB-02","name":"Second gNB plan","technology":"5G SA","simulator":"UERANSIM","plmn":"001-01","cell_id":"UNASSIGNED","link_ip":"NOT_CONFIGURED","n2_endpoint":Value::Null,"n3_endpoint":Value::Null,"process_state":"NOT_DEPLOYED","health":"NOT_VALIDATED","configured":configured_gnbs==2,"controller_owned":false,"uptime_seconds":Value::Null,"actions":{"start":false,"stop":false,"reason":"LIVE_005_APPROVAL_REQUIRED"}},
            {"id":"ENB-01","name":"LTE eNB profile","technology":"LTE","simulator":"srsRAN","plmn":"001-01","cell_id":"NOT_AVAILABLE","link_ip":"NOT_AVAILABLE","n2_endpoint":Value::Null,"n3_endpoint":Value::Null,"process_state":enb["process_state"],"health":enb["health"],"configured":false,"controller_owned":false,"uptime_seconds":Value::Null,"actions":{"start":false,"stop":false,"reason":"LTE_ATTACH_NOT_CERTIFIED"}}
        ],
        "configured_count":configured_gnbs,
        "running_count":usize::from(gnb["process_state"]=="running"),
        "observed_at_epoch_s":epoch_seconds(),
        "source":"READ_ONLY_LAB_STATE"
    }))
}

fn normalize_terminal_record(value: &mut Value) {
    let Some(record) = value.as_object_mut() else {
        return;
    };
    let started = record
        .get("started_at_epoch_s")
        .and_then(Value::as_u64)
        .or_else(|| record.get("started_at")?.as_str()?.parse().ok())
        .unwrap_or(0);
    let duration = record
        .get("duration_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let state = record
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("UNKNOWN")
        .to_string();
    record.entry("started_at_epoch_s").or_insert(json!(started));
    record.entry("target_ue_id").or_insert(json!("UE-01"));
    record
        .entry("target_ue_pseudonym")
        .or_insert(json!("UE-PSEUDONYM-01"));
    record.entry("tun_interface").or_insert(Value::Null);
    record
        .entry("ended_at_epoch_s")
        .or_insert(json!(started.saturating_add(duration)));
    record.entry("packets_requested").or_insert(json!(5));
    if !record.contains_key("packets_sent") {
        let sent = (state == "COMPLETED"
            && record.get("exit_code").and_then(Value::as_i64) == Some(0))
        .then_some(5_u64);
        record.insert("packets_sent".into(), json!(sent));
    }
    record.entry("terminal_result").or_insert_with(|| {
        json!(match state.as_str() {
            "COMPLETED" => "PROCESS_EXIT_SUCCESS",
            "STOPPED" => "OPERATOR_STOP",
            "FAILED" => "PROCESS_EXIT_FAILURE",
            _ => "UNKNOWN",
        })
    });
    record.entry("process_id").or_insert(Value::Null);
    record
        .entry("duration_milliseconds")
        .or_insert(json!(duration.saturating_mul(1_000)));
    record.entry("packet_size_bytes").or_insert(Value::Null);
    record.entry("packets_received").or_insert(Value::Null);
    record.entry("bytes_sent").or_insert(Value::Null);
    record.entry("bytes_received").or_insert(Value::Null);
    record
        .entry("accounting_source")
        .or_insert(json!("LEGACY_PROCESS_EXIT_ONLY"));
}

fn job_json(job: &OwnedScenarioJob) -> Value {
    let observed_end = job.ended_at.unwrap_or_else(epoch_seconds);
    let observed_end_ms = job.ended_at_epoch_ms.unwrap_or_else(epoch_millis);
    let duration_ms = observed_end_ms.saturating_sub(job.started_at_epoch_ms);
    let duration_seconds = if duration_ms == 0 {
        observed_end.saturating_sub(job.started_at)
    } else {
        duration_ms.saturating_add(999) / 1_000
    };
    json!({"scenario_id":job.job_id,"job_id":job.job_id,"technology":"5G SA","simulator":"UERANSIM","started_at":job.started_at.to_string(),"started_at_epoch_s":job.started_at,"started_at_epoch_ms":job.started_at_epoch_ms,"ended_at_epoch_s":job.ended_at,"ended_at_epoch_ms":job.ended_at_epoch_ms,"duration_seconds":duration_seconds,"duration_milliseconds":duration_ms,"configured_ues":1,"registered_ues":1,"active_pdu_sessions":1,"traffic_state":job.state,"packets_requested":job.packets_requested,"packets_sent":job.packets_sent,"packets_received":job.packets_received,"packet_size_bytes":TRAFFIC_PACKET_BYTES,"bytes_sent":job.bytes_sent,"bytes_received":job.bytes_received,"accounting_source":"OWNED_PROCESS_EXIT_AND_FIXED_PROFILE","receive_accounting":"NOT_OBSERVED_SEND_ONLY_PROFILE","terminal_result":job.terminal_result,"process_id":job.process_id,"cpu":"BOUNDED","memory":"BOUNDED","state":job.state,"controller_owned":true,"target_ue_id":job.target_ue_id,"target_ue_pseudonym":job.target_ue_pseudonym,"tun_interface":job.tun_interface})
}

fn refresh_runtime(runtime: &mut ControlRuntime) -> Option<(String, String)> {
    let finished = runtime.active.as_mut().and_then(|job| {
        job.child
            .as_mut()
            .and_then(|child| child.try_wait().ok().flatten())
            .map(|status| (status.success(), status.code()))
    });
    if let Some((success, code)) = finished {
        if let Some(mut job) = runtime.active.take() {
            job.ended_at = Some(epoch_seconds());
            job.ended_at_epoch_ms = Some(epoch_millis());
            job.state = if success { "COMPLETED" } else { "FAILED" }.into();
            job.packets_sent = success.then_some(job.packets_requested);
            job.bytes_sent =
                success.then_some(job.packets_requested.saturating_mul(TRAFFIC_PACKET_BYTES));
            job.terminal_result = Some(
                if success {
                    "PROCESS_EXIT_SUCCESS"
                } else {
                    "PROCESS_EXIT_FAILURE"
                }
                .into(),
            );
            let mut value = job_json(&job);
            value["exit_code"] = json!(code);
            runtime.history.push(value);
            return Some((job.target_ue_id, job.state));
        }
    }
    None
}

fn refresh_runtime_with_state(state: &AppState, runtime: &mut ControlRuntime) -> bool {
    let Some((target_ue_id, traffic_state)) = refresh_runtime(runtime) else {
        return false;
    };
    if controller_owns_ue(state, &target_ue_id) {
        if let Ok(mut controller) = state.multi_ue.lock() {
            if controller
                .set_traffic(&target_ue_id, &traffic_state)
                .is_ok()
            {
                let _ = persist_ue_registry(state, &controller);
            }
        }
    }
    true
}

fn persist_runtime(state: &AppState, runtime: &ControlRuntime) {
    let active = runtime.active.as_ref().map(job_json);
    let document = json!({"active":active,"history":runtime.history});
    if let Some(parent) = state.job_state_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(
        &state.job_state_path,
        serde_json::to_vec_pretty(&document).unwrap_or_default(),
    );
}

const MAX_CPU_DECISIONS: usize = 256;

fn persist_cpu_decision(state: &AppState, evidence: &CpuSafetyEvidence) -> Result<(), String> {
    let _guard = state
        .cpu_decision_lock
        .lock()
        .map_err(|_| "CPU_DECISION_EVIDENCE_LOCK_FAILED".to_string())?;
    if let Some(parent) = state.cpu_decision_path.parent() {
        fs::create_dir_all(parent).map_err(|_| "CPU_DECISION_EVIDENCE_UNWRITABLE".to_string())?;
    }
    let mut records = match fs::read_to_string(&state.cpu_decision_path) {
        Ok(value) => serde_json::from_str::<Vec<Value>>(&value)
            .map_err(|_| "CPU_DECISION_EVIDENCE_INVALID".to_string())?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(_) => return Err("CPU_DECISION_EVIDENCE_UNREADABLE".into()),
    };
    records.push(
        serde_json::to_value(evidence)
            .map_err(|_| "CPU_DECISION_EVIDENCE_SERIALIZATION_FAILED".to_string())?,
    );
    if records.len() > MAX_CPU_DECISIONS {
        records.drain(..records.len() - MAX_CPU_DECISIONS);
    }
    let serialized = serde_json::to_vec_pretty(&records)
        .map_err(|_| "CPU_DECISION_EVIDENCE_SERIALIZATION_FAILED".to_string())?;
    let temporary = state.cpu_decision_path.with_extension("json.tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| "CPU_DECISION_EVIDENCE_UNWRITABLE".to_string())?;
    file.write_all(&serialized)
        .and_then(|_| file.sync_all())
        .map_err(|_| "CPU_DECISION_EVIDENCE_UNWRITABLE".to_string())?;
    fs::rename(&temporary, &state.cpu_decision_path)
        .map_err(|_| "CPU_DECISION_EVIDENCE_UNWRITABLE".to_string())?;
    if let Some(parent) = state.cpu_decision_path.parent() {
        OpenOptions::new()
            .read(true)
            .open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "CPU_DECISION_EVIDENCE_UNWRITABLE".to_string())?;
    }
    Ok(())
}

fn cpu_error_response(state: &AppState, error: &str) -> Value {
    let decision = state
        .latest_cpu_decision
        .lock()
        .ok()
        .and_then(|latest| latest.clone())
        .filter(|decision| decision.state == error || error.starts_with("CPU_DECISION_"));
    json!({"error":error,"cpu_decision":decision})
}

fn persist_ue_registry(state: &AppState, controller: &MultiUeController) -> Result<(), String> {
    if let Some(parent) = state.ue_job_state_path.parent() {
        fs::create_dir_all(parent).map_err(|_| "UE_JOB_REGISTRY_UNWRITABLE".to_string())?;
    }
    let temporary = state.ue_job_state_path.with_extension("json.tmp");
    let serialized = serde_json::to_vec_pretty(&controller.snapshot())
        .map_err(|_| "UE_JOB_REGISTRY_SERIALIZATION_FAILED".to_string())?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)
        .map_err(|_| "UE_JOB_REGISTRY_UNWRITABLE".to_string())?;
    file.write_all(&serialized)
        .and_then(|_| file.sync_all())
        .map_err(|_| "UE_JOB_REGISTRY_UNWRITABLE".to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
            .map_err(|_| "UE_JOB_REGISTRY_UNWRITABLE".to_string())?;
    }
    fs::rename(temporary, &state.ue_job_state_path)
        .map_err(|_| "UE_JOB_REGISTRY_UNWRITABLE".to_string())?;
    if let Some(parent) = state.ue_job_state_path.parent() {
        OpenOptions::new()
            .read(true)
            .open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "UE_JOB_REGISTRY_UNWRITABLE".to_string())?;
    }
    Ok(())
}

fn validate_configuration(ue_count: usize, gnb_count: usize) -> Result<(), String> {
    if ue_count > ueransim_adapter::MAX_LIVE_UES {
        return Err("UE_COUNT_OUT_OF_RANGE".into());
    }
    if !(1..=2).contains(&gnb_count) {
        return Err("GNB_COUNT_OUT_OF_RANGE".into());
    }
    Ok(())
}

fn persist_configuration(path: &Path, configuration: &DesiredConfiguration) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| "CONFIGURATION_REGISTRY_UNWRITABLE".to_string())?;
    }
    let temporary = path.with_extension("json.tmp");
    let serialized = serde_json::to_vec_pretty(configuration)
        .map_err(|_| "CONFIGURATION_SERIALIZATION_FAILED".to_string())?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)
        .map_err(|_| "CONFIGURATION_REGISTRY_UNWRITABLE".to_string())?;
    file.write_all(&serialized)
        .and_then(|_| file.sync_all())
        .map_err(|_| "CONFIGURATION_REGISTRY_UNWRITABLE".to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
            .map_err(|_| "CONFIGURATION_REGISTRY_UNWRITABLE".to_string())?;
    }
    fs::rename(temporary, path).map_err(|_| "CONFIGURATION_REGISTRY_UNWRITABLE".to_string())?;
    if let Some(parent) = path.parent() {
        OpenOptions::new()
            .read(true)
            .open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "CONFIGURATION_REGISTRY_UNWRITABLE".to_string())?;
    }
    Ok(())
}

fn configuration_json(state: &AppState, configuration: &DesiredConfiguration) -> Value {
    let controller = state.multi_ue.lock().unwrap();
    let profiles = controller.profiles();
    let jobs = controller.snapshot();
    let missing_subscriber_profiles = profiles
        .iter()
        .take(configuration.ue_count)
        .filter(|profile| !profile.subscription_verified)
        .count();
    let observed_controller_running = jobs
        .iter()
        .filter(|job| {
            matches!(
                job.process_state.as_str(),
                "STARTING" | "RESTARTING" | "PAUSED" | "RUNNING" | "MOCK_RUNNING"
            )
        })
        .count();
    let observed_shared_running = !state.ue01_controller_owned
        && state
            .shared_ue_cache
            .lock()
            .ok()
            .and_then(|cache| cache.as_ref().map(|item| item.process_state == "RUNNING"))
            .unwrap_or(false);
    let reconciliation = state.ue_reconciliation.lock().unwrap().clone();
    json!({
        "ue_count":configuration.ue_count,
        "desired_ue_count":configuration.ue_count,
        "gnb_count":configuration.gnb_count,
        "max_ues":ueransim_adapter::MAX_LIVE_UES,
        "max_configured_profiles":ueransim_adapter::MAX_CONFIGURABLE_UES,
        "max_gnbs":2,
        "max_ues_live_certified":1,
        "max_ues_implemented":ueransim_adapter::MAX_LIVE_UES,
        "max_gnbs_live_certified":1,
        "missing_subscriber_profiles":missing_subscriber_profiles,
        "updated_at_epoch_s":configuration.updated_at_epoch_s,
        "updated_by":configuration.updated_by,
        "observed_controller_running":observed_controller_running,
        "observed_total_running":observed_controller_running + usize::from(observed_shared_running),
        "reconciliation":reconciliation,
        "execution_started":reconciliation.state == "RUNNING"
    })
}

fn managed_profile_json(record: &ManagedUeProfile) -> Value {
    json!({
        "ue_id": record.profile.ue_id,
        "name": record.profile.pseudonym,
        "profile": record.profile.profile_name,
        "serving_gnb": record.profile.serving_gnb,
        "plmn":{"mcc":record.profile.plmn_mcc,"mnc":record.profile.plmn_mnc},
        "dnn":record.profile.dnn,
        "snssai":{"sst":record.profile.sst,"sd":record.profile.sd},
        "pdu_session":{"type":"IPv4","dnn":record.profile.dnn},
        "scenario_id":record.scenario_id,
        "auto_run_scenario":record.auto_run_scenario,
        "subscription_status":if record.profile.subscription_verified {"VERIFIED"} else {"PROVISIONING_REQUIRED"},
        "subscriber_identity":"PROTECTED",
        "authentication_material":"PROTECTED",
        "revision":record.revision,
        "updated_at_epoch_s":record.updated_at_epoch_s
    })
}

#[derive(Deserialize, Default)]
struct UeProfileListQuery {
    page: Option<usize>,
    page_size: Option<usize>,
    search: Option<String>,
    scenario_id: Option<String>,
    subscription_status: Option<String>,
}

async fn list_ue_profiles(
    State(state): State<Arc<AppState>>,
    Extension(_identity): Extension<EffectiveIdentity>,
    Query(query): Query<UeProfileListQuery>,
) -> Json<Value> {
    let registry = state.profile_registry.lock().unwrap();
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(100).clamp(1, 500);
    let search = query
        .search
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let filtered = registry
        .profiles
        .iter()
        .filter(|record| {
            let matches_search = search.is_empty()
                || record.profile.ue_id.to_ascii_lowercase().contains(&search)
                || record
                    .profile
                    .pseudonym
                    .to_ascii_lowercase()
                    .contains(&search);
            let matches_scenario = query.scenario_id.as_ref().map_or(true, |scenario| {
                record.scenario_id.as_deref() == Some(scenario.as_str())
            });
            let matches_status =
                query
                    .subscription_status
                    .as_deref()
                    .map_or(true, |status| match status {
                        "VERIFIED" => record.profile.subscription_verified,
                        "PROVISIONING_REQUIRED" => !record.profile.subscription_verified,
                        _ => false,
                    });
            matches_search && matches_scenario && matches_status
        })
        .collect::<Vec<_>>();
    let total = filtered.len();
    let offset = (page - 1).saturating_mul(page_size);
    Json(json!({
        "items":filtered.into_iter().skip(offset).take(page_size).map(managed_profile_json).collect::<Vec<_>>(),
        "total":total,
        "page":page,
        "page_size":page_size,
        "pages":if total == 0 { 0 } else { (total + page_size - 1) / page_size },
        "max":ueransim_adapter::MAX_CONFIGURABLE_UES,
        "secrets_exposed":false
    }))
}

async fn bulk_create_ue_profiles(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    Json(input): Json<BulkProfileInput>,
) -> impl IntoResponse {
    if let Err(error) = require_operator(&identity) {
        return error;
    }
    let _operation = state.ue_operations.lock().unwrap();
    let mut registry = state.profile_registry.lock().unwrap();
    let records = match state.profile_store.create_bulk(&mut registry, input) {
        Ok(records) => records,
        Err(error) => return profile_mutation_error(error),
    };
    if let Err(error) = state.multi_ue.lock().unwrap().add_profiles(
        records
            .iter()
            .map(|record| record.profile.clone())
            .collect(),
    ) {
        return profile_mutation_error(error);
    }
    if let Err(error) = persist_profile_configuration(
        &state,
        registry.profiles.len().min(ueransim_adapter::MAX_LIVE_UES),
        &identity.role,
    ) {
        return profile_mutation_error(error);
    }
    audit(
        &state,
        &identity.role,
        "BULK_CREATE_UE_PROFILES",
        "CREATED",
        None,
    );
    (
        StatusCode::CREATED,
        Json(json!({
            "created":records.len(),
            "total":registry.profiles.len(),
            "subscription_status":"PROVISIONING_REQUIRED",
            "live_started":0
        })),
    )
}

fn csv_cell(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

/// Subscribers already provisioned in Open5GS that a new profile may bind to. Never returns secrets.
async fn list_provisioning_slots(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let registry = state.profile_registry.lock().unwrap();
    match state.profile_store.provisioning_slots(&registry) {
        Ok(slots) => (
            StatusCode::OK,
            Json(json!({
                "items": slots,
                "total": slots.len(),
                "available": slots.iter().filter(|slot| slot.bound_ue_id.is_none()).count(),
                "secrets_exposed": false,
            })),
        ),
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": error})),
        ),
    }
}

/// Read-only registry of gNBs a UE profile may name as `serving_gnb`.
async fn list_gnbs(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let gnbs = state.profile_store.gnbs();
    Json(json!({
        "items": gnbs,
        "total": gnbs.len(),
        "source": if std::env::var_os(ueransim_adapter::GNB_REGISTRY_ENV).is_some() {
            "CONFIGURED_REGISTRY"
        } else {
            "LAB_DEFAULT"
        },
    }))
}

async fn export_ue_profiles_csv(
    State(state): State<Arc<AppState>>,
    Extension(_identity): Extension<EffectiveIdentity>,
) -> impl IntoResponse {
    let registry = state.profile_registry.lock().unwrap();
    let mut csv =
        String::from("ue_id,name,mcc,mnc,dnn,sst,sd,serving_gnb,scenario_id,subscription_status\n");
    for record in &registry.profiles {
        let sst = record.profile.sst.to_string();
        let values = [
            record.profile.ue_id.as_str(),
            record.profile.pseudonym.as_str(),
            record.profile.plmn_mcc.as_str(),
            record.profile.plmn_mnc.as_str(),
            record.profile.dnn.as_str(),
            sst.as_str(),
            record.profile.sd.as_deref().unwrap_or_default(),
            record.profile.serving_gnb.as_str(),
            record.scenario_id.as_deref().unwrap_or_default(),
            if record.profile.subscription_verified {
                "VERIFIED"
            } else {
                "PROVISIONING_REQUIRED"
            },
        ];
        csv.push_str(&values.map(csv_cell).join(","));
        csv.push('\n');
    }
    (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=polaris-ue-profiles.csv",
            ),
        ],
        csv,
    )
}

fn profile_mutation_error(error: String) -> (StatusCode, Json<Value>) {
    let status = match error.as_str() {
        "UNKNOWN_UE_PROFILE" => StatusCode::NOT_FOUND,
        "UE_PROFILE_ACTIVE" | "SHARED_UE_PROTECTED" => StatusCode::LOCKED,
        "UE_PROFILE_ALREADY_EXISTS" | "DUPLICATE_SUBSCRIBER_IDENTITY" => StatusCode::CONFLICT,
        _ => StatusCode::UNPROCESSABLE_ENTITY,
    };
    (status, Json(json!({"error":error})))
}

fn persist_profile_configuration(
    state: &AppState,
    count: usize,
    actor: &str,
) -> Result<(), String> {
    let mut configuration = state.configuration.lock().unwrap();
    configuration.ue_count = count;
    configuration.updated_at_epoch_s = epoch_seconds();
    configuration.updated_by = actor.into();
    persist_configuration(&state.configuration_path, &configuration)
}

async fn create_ue_profile(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    Json(input): Json<ProfileMutationInput>,
) -> impl IntoResponse {
    if let Err(error) = require_operator(&identity) {
        return error;
    }
    let _operation = state.ue_operations.lock().unwrap();
    let mut registry = state.profile_registry.lock().unwrap();
    let record = match state.profile_store.create(&mut registry, input) {
        Ok(record) => record,
        Err(error) => return profile_mutation_error(error),
    };
    if let Err(error) = state
        .multi_ue
        .lock()
        .unwrap()
        .upsert_profile(record.profile.clone())
    {
        return profile_mutation_error(error);
    }
    if let Err(error) = persist_profile_configuration(
        &state,
        registry.profiles.len().min(ueransim_adapter::MAX_LIVE_UES),
        &identity.role,
    ) {
        return profile_mutation_error(error);
    }
    audit(
        &state,
        &identity.role,
        "CREATE_UE_PROFILE",
        "CREATED",
        Some(&record.profile.ue_id),
    );
    (StatusCode::CREATED, Json(managed_profile_json(&record)))
}

async fn update_ue_profile(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    AxumPath(ue_id): AxumPath<String>,
    Json(input): Json<ProfileMutationInput>,
) -> impl IntoResponse {
    if let Err(error) = require_operator(&identity) {
        return error;
    }
    if ue_id == "UE-01" && !state.ue01_controller_owned {
        return profile_mutation_error("SHARED_UE_PROTECTED".into());
    }
    let _operation = state.ue_operations.lock().unwrap();
    if state.multi_ue.lock().unwrap().snapshot().iter().any(|job| {
        job.ue_id == ue_id
            && (job.process_handle.is_some()
                || !matches!(
                    job.lifecycle,
                    simulator_controller::UeLifecycle::Stopped
                        | simulator_controller::UeLifecycle::Failed
                ))
    }) {
        return profile_mutation_error("UE_PROFILE_ACTIVE".into());
    }
    let mut registry = state.profile_registry.lock().unwrap();
    let record = match state.profile_store.update(&mut registry, &ue_id, input) {
        Ok(record) => record,
        Err(error) => return profile_mutation_error(error),
    };
    if let Err(error) = state
        .multi_ue
        .lock()
        .unwrap()
        .upsert_profile(record.profile.clone())
    {
        return profile_mutation_error(error);
    }
    audit(
        &state,
        &identity.role,
        "UPDATE_UE_PROFILE",
        "UPDATED",
        Some(&ue_id),
    );
    (StatusCode::OK, Json(managed_profile_json(&record)))
}

#[derive(Deserialize)]
struct CloneProfileInput {
    target_ue_id: String,
}

async fn clone_ue_profile(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    AxumPath(source_ue_id): AxumPath<String>,
    Json(input): Json<CloneProfileInput>,
) -> impl IntoResponse {
    if let Err(error) = require_operator(&identity) {
        return error;
    }
    let _operation = state.ue_operations.lock().unwrap();
    let mut registry = state.profile_registry.lock().unwrap();
    let record =
        match state
            .profile_store
            .clone_profile(&mut registry, &source_ue_id, &input.target_ue_id)
        {
            Ok(record) => record,
            Err(error) => return profile_mutation_error(error),
        };
    if let Err(error) = state
        .multi_ue
        .lock()
        .unwrap()
        .upsert_profile(record.profile.clone())
    {
        return profile_mutation_error(error);
    }
    if let Err(error) = persist_profile_configuration(
        &state,
        registry.profiles.len().min(ueransim_adapter::MAX_LIVE_UES),
        &identity.role,
    ) {
        return profile_mutation_error(error);
    }
    audit(
        &state,
        &identity.role,
        "CLONE_UE_PROFILE",
        "CREATED",
        Some(&record.profile.ue_id),
    );
    (StatusCode::CREATED, Json(managed_profile_json(&record)))
}

async fn validate_ue_profile_provisioning(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    AxumPath(ue_id): AxumPath<String>,
) -> impl IntoResponse {
    if let Err(error) = require_operator(&identity) {
        return error;
    }
    let profile = match state
        .multi_ue
        .lock()
        .unwrap()
        .profiles()
        .into_iter()
        .find(|profile| profile.ue_id == ue_id)
    {
        Some(profile) => profile,
        None => return profile_mutation_error("UNKNOWN_UE_PROFILE".into()),
    };
    let verified = match state
        .ue_runtime
        .verify_provisioning(std::slice::from_ref(&profile))
    {
        Ok(verified) if verified.contains_key(&ue_id) => true,
        Ok(_) => false,
        Err(error) => return profile_mutation_error(error),
    };
    if let Err(error) = state
        .multi_ue
        .lock()
        .unwrap()
        .set_profile_subscription_verified(&ue_id, verified)
    {
        return profile_mutation_error(error);
    }
    let mut registry = state.profile_registry.lock().unwrap();
    let Some(record) = registry
        .profiles
        .iter_mut()
        .find(|record| record.profile.ue_id == ue_id)
    else {
        return profile_mutation_error("UNKNOWN_UE_PROFILE".into());
    };
    record.profile.subscription_verified = verified;
    record.updated_at_epoch_s = epoch_seconds();
    if let Err(error) = state.profile_store.persist(&registry) {
        return profile_mutation_error(error);
    }
    audit(
        &state,
        &identity.role,
        "VALIDATE_UE_PROVISIONING",
        if verified { "VERIFIED" } else { "REJECTED" },
        Some(&ue_id),
    );
    (
        StatusCode::OK,
        Json(json!({
            "ue_id":ue_id,
            "subscription_status":if verified {"VERIFIED"} else {"NOT_PROVISIONED"},
            "open5gs_changed":false
        })),
    )
}

async fn delete_ue_profile(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    AxumPath(ue_id): AxumPath<String>,
) -> impl IntoResponse {
    if let Err(error) = require_operator(&identity) {
        return error;
    }
    if ue_id == "UE-01" && !state.ue01_controller_owned {
        return profile_mutation_error("SHARED_UE_PROTECTED".into());
    }
    let _operation = state.ue_operations.lock().unwrap();
    let removed = match state.multi_ue.lock().unwrap().delete_profile(&ue_id) {
        Ok(profile) => profile,
        Err(error) => return profile_mutation_error(error),
    };
    let mut registry = state.profile_registry.lock().unwrap();
    let record = match state.profile_store.delete(&mut registry, &ue_id) {
        Ok(record) => record,
        Err(error) => {
            let _ = state.multi_ue.lock().unwrap().upsert_profile(removed);
            return profile_mutation_error(error);
        }
    };
    if let Err(error) = persist_ue_registry(&state, &state.multi_ue.lock().unwrap()) {
        return profile_mutation_error(error);
    }
    if let Err(error) = persist_profile_configuration(
        &state,
        registry.profiles.len().min(ueransim_adapter::MAX_LIVE_UES),
        &identity.role,
    ) {
        return profile_mutation_error(error);
    }
    audit(
        &state,
        &identity.role,
        "DELETE_UE_PROFILE",
        "DELETED",
        Some(&ue_id),
    );
    (
        StatusCode::OK,
        Json(json!({"deleted":record.profile.ue_id,"profile_secret_deleted":true})),
    )
}

async fn discover_legacy_ues(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
) -> impl IntoResponse {
    if let Err(error) = require_operator(&identity) {
        return error;
    }
    let output = match DockerUeRuntime::output(&[
        "ps".into(),
        "--all".into(),
        "--format".into(),
        "{{.ID}}|{{.Names}}|{{.Status}}|{{.Label \"com.docker.compose.project\"}}|{{.Label \"com.docker.compose.service\"}}".into(),
    ]) {
        Ok(output) => output,
        Err(error) => return profile_mutation_error(error),
    };
    let items = output
        .lines()
        .filter_map(|line| {
            let fields = line.split('|').collect::<Vec<_>>();
            let name = *fields.get(1)?;
            (name.contains("ueransim-ue") || name.starts_with("polaris-control-ue-"))
                .then(|| json!({
                    "container_id":fields.first().copied().unwrap_or_default(),
                    "container_name":name,
                    "status":fields.get(2).copied().unwrap_or("unknown"),
                    "compose_project":fields.get(3).copied().unwrap_or_default(),
                    "compose_service":fields.get(4).copied().unwrap_or_default(),
                    "owner":if name.starts_with("polaris-control-") {"POLARIS_CONTROLLER"} else {"LEGACY_DOCKER_COMPOSE"},
                    "migration_supported":name == "oiran-lab-ueransim-ue-1" && !state.ue01_controller_owned
                }))
        })
        .collect::<Vec<_>>();
    (
        StatusCode::OK,
        Json(json!({"items":items,"execution":"NOT_EXECUTED"})),
    )
}

fn legacy_migration_preview(state: &AppState) -> Result<Value, String> {
    if state.ue01_controller_owned {
        return Ok(json!({"ue_id":"UE-01","state":"ALREADY_CONTROLLER_OWNED","executable":false}));
    }
    let fields = DockerUeRuntime::inspect_fields("oiran-lab-ueransim-ue-1")?;
    let container_id = fields.first().cloned().ok_or("LEGACY_UE_NOT_FOUND")?;
    let process_state = fields.get(1).cloned().unwrap_or_else(|| "unknown".into());
    let compose_path = Path::new("/root/POLARIS/compose/docker-compose.oiran-lab.yml");
    let compose = fs::read(compose_path).map_err(|_| "UE01_COMPOSE_UNREADABLE")?;
    let shared_profile = fs::read("/root/POLARIS/runtime/ueransim/ue.yaml")
        .map_err(|_| "UE01_SHARED_PROFILE_UNREADABLE")?;
    let managed_profile =
        fs::read(Path::new(ueransim_adapter::LIVE_PROFILE_ROOT).join("ue-01.yaml"))
            .map_err(|_| "UE01_PROFILE_UNREADABLE")?;
    let shared_sha256 = DockerUeRuntime::hash_bytes(&shared_profile)?;
    let managed_sha256 = DockerUeRuntime::hash_bytes(&managed_profile)?;
    let compose_sha256 = DockerUeRuntime::hash_bytes(&compose)?;
    Ok(json!({
        "ue_id":"UE-01",
        "source":{"container_name":"oiran-lab-ueransim-ue-1","container_id":container_id,"compose_project":"oiran-lab","compose_service":"ueransim-ue","process_state":process_state},
        "target":{"owner":"POLARIS_CONTROLLER","profile":"ue-01.yaml","container_name":"polaris-control-ue-01"},
        "dependencies":{"gnb":"oiran-lab-ueransim-gnb-1","network":"oiran-lab-mgmt","open5gs_change_required":false},
        "integrity":{"compose_sha256":compose_sha256,"shared_profile_sha256":shared_sha256,"managed_profile_sha256":managed_sha256,"profiles_match":shared_sha256 == managed_sha256},
        "transaction":{"backup":true,"disable_restart":true,"stop_legacy":true,"rename_for_rollback":true,"install_attestation":true,"start_new_ue":false},
        "executable":shared_sha256 == managed_sha256,
        "execution":"NOT_EXECUTED"
    }))
}

async fn preview_legacy_migration(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
) -> impl IntoResponse {
    if let Err(error) = require_operator(&identity) {
        return error;
    }
    match legacy_migration_preview(&state) {
        Ok(preview) => (StatusCode::OK, Json(preview)),
        Err(error) => profile_mutation_error(error),
    }
}

#[derive(Deserialize)]
struct LegacyMigrationInput {
    ue_id: String,
    source_container_id: String,
    confirmation: String,
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| "MIGRATION_STORAGE_UNWRITABLE")?;
    }
    let temporary = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| "MIGRATION_STORAGE_UNWRITABLE")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "MIGRATION_STORAGE_UNWRITABLE")?;
    fs::rename(temporary, path).map_err(|_| "MIGRATION_STORAGE_UNWRITABLE".to_string())
}

fn replace_compose_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::metadata(path).map_err(|_| "UE01_COMPOSE_UNREADABLE")?;
    let temporary = path.with_extension("polaris.tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(metadata.permissions().mode())
        .open(&temporary)
        .map_err(|_| "UE01_COMPOSE_UNWRITABLE")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "UE01_COMPOSE_UNWRITABLE")?;
    fs::set_permissions(&temporary, metadata.permissions())
        .map_err(|_| "UE01_COMPOSE_UNWRITABLE")?;
    fs::rename(temporary, path).map_err(|_| "UE01_COMPOSE_UNWRITABLE".to_string())
}

async fn execute_legacy_migration(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    Json(input): Json<LegacyMigrationInput>,
) -> impl IntoResponse {
    if let Err(error) = require_operator(&identity) {
        return error;
    }
    if std::env::var("POLARIS_LEGACY_MIGRATION_ENABLED").as_deref() != Ok("true") {
        return (
            StatusCode::LOCKED,
            Json(json!({"error":"LEGACY_MIGRATION_MAINTENANCE_APPROVAL_REQUIRED"})),
        );
    }
    if input.ue_id != "UE-01"
        || input.confirmation != "TRANSFER_UE01_TO_POLARIS"
        || input.source_container_id.len() != 64
    {
        return profile_mutation_error("MIGRATION_CONFIRMATION_INVALID".into());
    }
    let _operation = state.ue_operations.lock().unwrap();
    let preview = match legacy_migration_preview(&state) {
        Ok(preview) => preview,
        Err(error) => return profile_mutation_error(error),
    };
    if preview["source"]["container_id"].as_str() != Some(&input.source_container_id)
        || preview["integrity"]["profiles_match"] != json!(true)
    {
        return profile_mutation_error("MIGRATION_SOURCE_CHANGED".into());
    }
    if let Err(error) = resource_gate_preview(&state) {
        return profile_mutation_error(error);
    }
    let compose_path = Path::new("/root/POLARIS/compose/docker-compose.oiran-lab.yml");
    let original_compose = match fs::read(compose_path) {
        Ok(value) => value,
        Err(_) => return profile_mutation_error("UE01_COMPOSE_UNREADABLE".into()),
    };
    let disabled_compose =
        match disable_legacy_ue01_service(&String::from_utf8_lossy(&original_compose)) {
            Ok(value) => value,
            Err(error) => return profile_mutation_error(error),
        };
    let timestamp = epoch_seconds();
    let backup_root = PathBuf::from(format!(
        "/var/lib/polaris-control/migrations/ue-01-{timestamp}"
    ));
    if let Err(error) = fs::create_dir_all(&backup_root) {
        let _ = error;
        return profile_mutation_error("MIGRATION_BACKUP_FAILED".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::set_permissions(&backup_root, fs::Permissions::from_mode(0o700)).is_err() {
            return profile_mutation_error("MIGRATION_BACKUP_FAILED".into());
        }
    }
    let container_inspect =
        match DockerUeRuntime::output(&["inspect".into(), input.source_container_id.clone()]) {
            Ok(value) => value,
            Err(error) => return profile_mutation_error(error),
        };
    let original_restart_policy = DockerUeRuntime::inspect_fields(&input.source_container_id)
        .ok()
        .and_then(|fields| fields.get(20).cloned())
        .filter(|policy| {
            matches!(
                policy.as_str(),
                "no" | "always" | "unless-stopped" | "on-failure"
            )
        })
        .unwrap_or_else(|| "no".into());
    let shared_profile = match fs::read("/root/POLARIS/runtime/ueransim/ue.yaml") {
        Ok(value) => value,
        Err(_) => return profile_mutation_error("UE01_SHARED_PROFILE_UNREADABLE".into()),
    };
    let managed_profile =
        match fs::read(Path::new(ueransim_adapter::LIVE_PROFILE_ROOT).join("ue-01.yaml")) {
            Ok(value) => value,
            Err(_) => return profile_mutation_error("UE01_PROFILE_UNREADABLE".into()),
        };
    for (name, bytes) in [
        ("compose.yml", original_compose.as_slice()),
        ("container-inspect.json", container_inspect.as_bytes()),
        ("legacy-ue-01.yaml", shared_profile.as_slice()),
        ("managed-ue-01.yaml", managed_profile.as_slice()),
    ] {
        if write_private_atomic(&backup_root.join(name), bytes).is_err() {
            return profile_mutation_error("MIGRATION_BACKUP_FAILED".into());
        }
    }
    let rollback_name = format!("oiran-lab-ueransim-ue-1-rollback-{timestamp}");
    let result = (|| -> Result<(), String> {
        DockerUeRuntime::output(&[
            "update".into(),
            "--restart=no".into(),
            "oiran-lab-ueransim-ue-1".into(),
        ])?;
        DockerUeRuntime::output(&[
            "stop".into(),
            "--time".into(),
            "20".into(),
            "oiran-lab-ueransim-ue-1".into(),
        ])?;
        DockerUeRuntime::output(&[
            "rename".into(),
            "oiran-lab-ueransim-ue-1".into(),
            rollback_name.clone(),
        ])?;
        replace_compose_atomically(compose_path, disabled_compose.as_bytes())?;
        let profile = fs::read(Path::new(ueransim_adapter::LIVE_PROFILE_ROOT).join("ue-01.yaml"))
            .map_err(|_| "UE01_PROFILE_UNREADABLE")?;
        let ownership_id = std::env::var("POLARIS_UE_OWNERSHIP_ID")
            .map_err(|_| "LIVE_UE_OWNERSHIP_ID_REQUIRED")?;
        let attestation = Ue01OwnershipTransferAttestation {
            schema_version: 1,
            ue_id: "UE-01".into(),
            state: "CONTROLLER_OWNED".into(),
            legacy_container_name: "oiran-lab-ueransim-ue-1".into(),
            legacy_container_id: input.source_container_id.clone(),
            legacy_compose_project: "oiran-lab".into(),
            legacy_compose_service: "ueransim-ue".into(),
            legacy_compose_sha256: DockerUeRuntime::hash_bytes(disabled_compose.as_bytes())?,
            profile_sha256: DockerUeRuntime::hash_bytes(&profile)?,
            ownership_id,
        };
        write_private_atomic(
            Path::new(UE01_TRANSFER_ATTESTATION_PATH),
            &serde_json::to_vec_pretty(&attestation)
                .map_err(|_| "UE01_TRANSFER_ATTESTATION_INVALID")?,
        )
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(UE01_TRANSFER_ATTESTATION_PATH);
        let _ = replace_compose_atomically(compose_path, &original_compose);
        let _ = DockerUeRuntime::output(&[
            "rename".into(),
            rollback_name.clone(),
            "oiran-lab-ueransim-ue-1".into(),
        ]);
        let _ = DockerUeRuntime::output(&[
            "update".into(),
            format!("--restart={original_restart_policy}"),
            "oiran-lab-ueransim-ue-1".into(),
        ]);
        let _ = DockerUeRuntime::output(&["start".into(), "oiran-lab-ueransim-ue-1".into()]);
        audit(
            &state,
            &identity.role,
            "MIGRATE_LEGACY_UE",
            "ROLLED_BACK",
            Some("UE-01"),
        );
        return profile_mutation_error(format!("MIGRATION_ROLLED_BACK:{error}"));
    }
    audit(
        &state,
        &identity.role,
        "MIGRATE_LEGACY_UE",
        "TRANSFERRED_STOPPED",
        Some("UE-01"),
    );
    (
        StatusCode::OK,
        Json(json!({
            "ue_id":"UE-01",
            "state":"TRANSFERRED_STOPPED",
            "legacy_backup_container":rollback_name,
            "backup_path":backup_root,
            "polaris_restart_required":true,
            "ue_started":false,
            "open5gs_changed":false
        })),
    )
}

fn reconcile_ue_count(
    state: Arc<AppState>,
    desired_count: usize,
    verified: BTreeMap<String, String>,
) {
    let _operation_guard = match state.ue_operations.lock() {
        Ok(guard) => guard,
        Err(_) => {
            let mut status = state.ue_reconciliation.lock().unwrap();
            status.state = "FAILED".into();
            status.failures.push((
                "CONTROLLER".into(),
                "UE_OPERATION_COORDINATOR_UNAVAILABLE".into(),
            ));
            status.completed_at_epoch_s = Some(epoch_seconds());
            state
                .ue_reconciliation_running
                .store(false, Ordering::Release);
            return;
        }
    };
    if let Err(error) = discover_and_reconcile_reserved_handles(&state) {
        let mut status = state.ue_reconciliation.lock().unwrap();
        status.state = "FAILED".into();
        status.failures.push(("CONTROLLER".into(), error));
        status.completed_at_epoch_s = Some(epoch_seconds());
        state
            .ue_reconciliation_running
            .store(false, Ordering::Release);
        return;
    }
    let verified_ids = verified.keys().cloned().collect::<BTreeSet<_>>();
    {
        let mut controller = state.multi_ue.lock().unwrap();
        controller.set_subscription_verified(&verified_ids);
        if desired_count >= controller.configured_count() {
            if let Err(error) = controller.configure_count(desired_count) {
                state
                    .ue_reconciliation
                    .lock()
                    .unwrap()
                    .failures
                    .push(("CONFIGURATION".into(), error));
            }
        }
        let _ = persist_ue_registry(&state, &controller);
    }
    let desired_ids = (2..=desired_count)
        .map(|index| format!("UE-{index:02}"))
        .collect::<BTreeSet<_>>();
    let jobs = state.multi_ue.lock().unwrap().snapshot();
    let existing_ids = jobs
        .iter()
        .filter(|job| job.process_handle.is_some())
        .map(|job| job.ue_id.clone())
        .collect::<BTreeSet<_>>();
    let active_ids = jobs
        .into_iter()
        .filter(|job| {
            job.process_handle.is_some()
                && matches!(
                    job.process_state.as_str(),
                    "STARTING" | "RESTARTING" | "PAUSED" | "RUNNING" | "MOCK_RUNNING"
                )
        })
        .map(|job| job.ue_id)
        .collect::<BTreeSet<_>>();

    let mut excess_ids = existing_ids
        .difference(&desired_ids)
        .cloned()
        .collect::<Vec<_>>();
    excess_ids.reverse();
    for ue_id in &excess_ids {
        let outcome = if state.execution_mode == "live" {
            stop_one_live_inner(&state, ue_id).map(|_| ())
        } else {
            let mut controller = state.multi_ue.lock().unwrap();
            controller.stop_offline(ue_id).map(|_| ())
        };
        let mut status = state.ue_reconciliation.lock().unwrap();
        match outcome {
            Ok(()) => status.stopped.push(ue_id.clone()),
            Err(error) => status.failures.push((ue_id.clone(), error)),
        }
    }
    for ue_id in desired_ids.difference(&active_ids) {
        let outcome = if state.execution_mode == "live" {
            start_one_live_inner(&state, ue_id).map(|_| ())
        } else {
            let mut controller = state.multi_ue.lock().unwrap();
            controller.start_offline(ue_id).map(|_| ())
        };
        let mut status = state.ue_reconciliation.lock().unwrap();
        match outcome {
            Ok(()) => status.started.push(ue_id.clone()),
            Err(error) => status.failures.push((ue_id.clone(), error)),
        }
    }
    {
        let mut controller = state.multi_ue.lock().unwrap();
        if !state
            .ue_reconciliation
            .lock()
            .unwrap()
            .failures
            .iter()
            .any(|(ue_id, _)| !desired_ids.contains(ue_id))
        {
            if let Err(error) = controller.configure_count(desired_count) {
                state
                    .ue_reconciliation
                    .lock()
                    .unwrap()
                    .failures
                    .push(("CONFIGURATION".into(), error));
            }
        }
        let _ = persist_ue_registry(&state, &controller);
    }
    let mut status = state.ue_reconciliation.lock().unwrap();
    status.state = if status.failures.is_empty() {
        "COMPLETED"
    } else {
        "FAILED"
    }
    .into();
    status.completed_at_epoch_s = Some(epoch_seconds());
    state
        .ue_reconciliation_running
        .store(false, Ordering::Release);
}

fn audit(state: &AppState, role: &str, action: &str, outcome: &str, job_id: Option<&str>) {
    if let Some(parent) = state.audit_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&state.audit_path)
    {
        let entry = json!({"timestamp_epoch_s":epoch_seconds(),"role":role,"action":action,"outcome":outcome,"job_id":job_id});
        let _ = writeln!(file, "{}", entry);
    }
}

async fn scenarios(State(state): State<Arc<AppState>>) -> Json<Value> {
    let mut runtime = state.runtime.lock().unwrap();
    if refresh_runtime_with_state(&state, &mut runtime) {
        persist_runtime(&state, &runtime);
    }
    let items: Vec<Value> = runtime.active.as_ref().map(job_json).into_iter().collect();
    Json(
        json!({"total":items.len(),"items":items,"source":"controller registry","live_execution":true}),
    )
}
async fn scenario_status(State(state): State<Arc<AppState>>) -> Json<Value> {
    let mut runtime = state.runtime.lock().unwrap();
    if refresh_runtime_with_state(&state, &mut runtime) {
        persist_runtime(&state, &runtime);
    }
    Json(json!({
        "active_job":runtime.active.as_ref().map(job_json),
        "latest_terminal_job":runtime.history.last(),
        "active_count":usize::from(runtime.active.is_some()),
        "history_count":runtime.history.len(),
        "observed_at_epoch_s":epoch_seconds(),
        "source":"controller registry"
    }))
}
async fn history(State(state): State<Arc<AppState>>) -> Json<Value> {
    let mut runtime = state.runtime.lock().unwrap();
    if refresh_runtime_with_state(&state, &mut runtime) {
        persist_runtime(&state, &runtime);
    }
    Json(
        json!({"items":runtime.history,"total":runtime.history.len(),"source":"controller registry"}),
    )
}

fn scenario_definition_error(error: String) -> (StatusCode, Json<Value>) {
    let status = match error.as_str() {
        "SCENARIO_DEFINITION_NOT_FOUND" => StatusCode::NOT_FOUND,
        "SCENARIO_DEFINITION_ALREADY_EXISTS"
        | "SCENARIO_ID_EXISTS"
        | "TEMPLATE_ID_RESERVED"
        | "SCENARIO_TEMPLATE_READ_ONLY" => StatusCode::CONFLICT,
        _ => StatusCode::UNPROCESSABLE_ENTITY,
    };
    (status, Json(json!({"error":error})))
}

async fn estimate_scenario_definition(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    let catalog = state.scenario_catalog.lock().unwrap();
    let Some(definition) = catalog.definitions.iter().find(|item| item.id == id) else {
        return scenario_definition_error("SCENARIO_DEFINITION_NOT_FOUND".into());
    };
    match estimate_duration_ms(definition) {
        Ok(duration_ms) => (StatusCode::OK, Json(json!({"duration_ms":duration_ms}))),
        Err(error) => scenario_definition_error(error),
    }
}

async fn export_scenario_definition(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let catalog = state.scenario_catalog.lock().unwrap();
    let Some(definition) = catalog.definitions.iter().find(|item| item.id == id) else {
        return scenario_definition_error("SCENARIO_DEFINITION_NOT_FOUND".into()).into_response();
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let filename = format!("{}-v{}.json", definition.id, definition.version);
    if let Ok(value) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }
    (
        headers,
        Json(json!({
            "schema_version":EXPORT_SCHEMA_VERSION,
            "exported_at_epoch_s":epoch_seconds(),
            "definition":definition
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct ImportScenarioQuery {
    mode: Option<String>,
    rename: Option<String>,
}

#[derive(Deserialize)]
struct ScenarioExportFile {
    schema_version: String,
    definition: ScenarioDefinition,
}

async fn import_scenario_definition(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    Query(query): Query<ImportScenarioQuery>,
    body: axum::body::Bytes,
) -> Response {
    if let Err(error) = require_operator(&identity) {
        return error.into_response();
    }
    if body.len() > 1024 * 1024 {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({"error":"IMPORT_PAYLOAD_TOO_LARGE"})),
        )
            .into_response();
    }
    let imported: ScenarioExportFile = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => {
            return scenario_definition_error("SCENARIO_IMPORT_INVALID".into()).into_response()
        }
    };
    if imported.schema_version != EXPORT_SCHEMA_VERSION {
        return scenario_definition_error("SCHEMA_UNKNOWN".into()).into_response();
    }
    if query
        .mode
        .as_deref()
        .is_some_and(|mode| mode != "new_version")
        || (query.mode.is_some() && query.rename.is_some())
    {
        return scenario_definition_error("SCENARIO_IMPORT_MODE_INVALID".into()).into_response();
    }
    let mut mutation = ScenarioMutation {
        id: imported.definition.id.clone(),
        name: imported.definition.name,
        loop_count: imported.definition.loop_count,
        steps: imported.definition.steps,
    };
    let mut catalog = state.scenario_catalog.lock().unwrap();
    let result = if let Some(target) = query.rename {
        mutation.id = target;
        state
            .scenario_definition_store
            .create(&mut catalog, mutation)
    } else if query.mode.as_deref() == Some("new_version") {
        let id = mutation.id.clone();
        state
            .scenario_definition_store
            .update(&mut catalog, &id, mutation)
    } else if catalog
        .definitions
        .iter()
        .any(|item| item.id == mutation.id)
    {
        Err("SCENARIO_ID_EXISTS".into())
    } else {
        state
            .scenario_definition_store
            .create(&mut catalog, mutation)
    };
    match result {
        Ok(definition) => (StatusCode::CREATED, Json(json!(definition))).into_response(),
        Err(error) => scenario_definition_error(error).into_response(),
    }
}

async fn list_scenario_definitions(State(state): State<Arc<AppState>>) -> Json<Value> {
    let catalog = state.scenario_catalog.lock().unwrap();
    Json(json!({
        "items":catalog.definitions,
        "total":catalog.definitions.len(),
        "schema_version":catalog.schema_version
    }))
}

async fn get_scenario_definition(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    let catalog = state.scenario_catalog.lock().unwrap();
    match catalog.definitions.iter().find(|item| item.id == id) {
        Some(definition) => (StatusCode::OK, Json(json!(definition))),
        None => scenario_definition_error("SCENARIO_DEFINITION_NOT_FOUND".into()),
    }
}

async fn create_scenario_definition(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    Json(input): Json<ScenarioMutation>,
) -> impl IntoResponse {
    if let Err(error) = require_operator(&identity) {
        return error;
    }
    let mut catalog = state.scenario_catalog.lock().unwrap();
    match state.scenario_definition_store.create(&mut catalog, input) {
        Ok(definition) => (StatusCode::CREATED, Json(json!(definition))),
        Err(error) => scenario_definition_error(error),
    }
}

async fn update_scenario_definition(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<ScenarioMutation>,
) -> impl IntoResponse {
    if let Err(error) = require_operator(&identity) {
        return error;
    }
    let mut catalog = state.scenario_catalog.lock().unwrap();
    match state
        .scenario_definition_store
        .update(&mut catalog, &id, input)
    {
        Ok(definition) => (StatusCode::OK, Json(json!(definition))),
        Err(error) => scenario_definition_error(error),
    }
}

async fn delete_scenario_definition(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    if let Err(error) = require_operator(&identity) {
        return error;
    }
    let mut catalog = state.scenario_catalog.lock().unwrap();
    match state.scenario_definition_store.delete(&mut catalog, &id) {
        Ok(definition) => (StatusCode::OK, Json(json!({"deleted":definition.id}))),
        Err(error) => scenario_definition_error(error),
    }
}

#[derive(Deserialize)]
struct CloneScenarioDefinitionInput {
    target_id: String,
}

async fn clone_scenario_definition(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<CloneScenarioDefinitionInput>,
) -> impl IntoResponse {
    if let Err(error) = require_operator(&identity) {
        return error;
    }
    let mut catalog = state.scenario_catalog.lock().unwrap();
    match state
        .scenario_definition_store
        .clone_definition(&mut catalog, &id, &input.target_id)
    {
        Ok(definition) => (StatusCode::CREATED, Json(json!(definition))),
        Err(error) => scenario_definition_error(error),
    }
}

async fn scenario_steps(
    State(state): State<Arc<AppState>>,
    AxumPath(job_id): AxumPath<String>,
) -> impl IntoResponse {
    let mut runtime = state.runtime.lock().unwrap();
    if refresh_runtime_with_state(&state, &mut runtime) {
        persist_runtime(&state, &runtime);
    }
    let record = runtime
        .active
        .as_ref()
        .map(job_json)
        .filter(|job| job["job_id"] == job_id)
        .or_else(|| {
            runtime
                .history
                .iter()
                .find(|job| job["job_id"] == job_id)
                .cloned()
        });
    match record {
        Some(job) => (
            StatusCode::OK,
            Json(json!({
                "job_id":job_id,
                "scenario_definition_id":job["scenario_definition_id"],
                "steps":job["steps"].as_array().cloned().unwrap_or_default()
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"SCENARIO_JOB_NOT_FOUND"})),
        ),
    }
}
fn authorized_ue_control_ids(state: &AppState, identity: &EffectiveIdentity) -> BTreeSet<String> {
    identity
        .session_id
        .as_ref()
        .and_then(|session_id| {
            let sessions = state.sessions.lock().ok()?;
            let session = sessions.get(session_id)?;
            session
                .ue_control_authorized_until
                .is_some_and(|deadline| deadline >= epoch_seconds())
                .then(|| session.ue_control_authorized_ids.clone())
        })
        .unwrap_or_default()
}

fn ue_control_is_authorized(
    state: &AppState,
    identity: &EffectiveIdentity,
    ue_ids: &[String],
) -> bool {
    let authorized = authorized_ue_control_ids(state, identity);
    !ue_ids.is_empty() && ue_ids.iter().all(|ue_id| authorized.contains(ue_id))
}

async fn ues(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
) -> Json<Value> {
    let pending = state
        .multi_ue
        .lock()
        .map(|controller| controller.snapshot())
        .unwrap_or_default();
    let runtime = state.ue_runtime.clone();
    let live = state.execution_mode == "live";
    let observed_at = state
        .ue_inventory_last_observed_epoch_s
        .load(Ordering::Acquire);
    let cache_fresh = observed_at != 0
        && epoch_seconds().saturating_sub(observed_at) < UE_INVENTORY_OBSERVATION_TTL_SECONDS;
    let perform_observation = !cache_fresh
        && state
            .ue_inventory_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
    let shared_cache = state.shared_ue_cache.clone();
    let ue01_controller_owned = state.ue01_controller_owned;
    let inventory_running = state.ue_inventory_running.clone();
    let last_observed = state.ue_inventory_last_observed_epoch_s.clone();
    let cache_version_counter = state.ue_inventory_cache_version.clone();
    let observed = tokio::task::spawn_blocking(move || {
        let unknown = || UeObservation {
            process_state: "UNKNOWN".into(),
            registration_state: "NOT_OBSERVED".into(),
            pdu_session_state: "INACTIVE".into(),
            ue_ip: None,
        };
        let shared = if ue01_controller_owned {
            unknown()
        } else if perform_observation {
            let observation = runtime.observe_shared().unwrap_or_else(|_| unknown());
            if let Ok(mut cache) = shared_cache.lock() {
                *cache = Some(observation.clone());
            }
            observation
        } else {
            shared_cache
                .lock()
                .ok()
                .and_then(|cache| cache.clone())
                .unwrap_or_else(unknown)
        };
        let owned = if live && perform_observation {
            pending
                .iter()
                .filter(|job| {
                    ueransim_adapter::is_approved_controller_ue(&job.ue_id)
                        && (job.ue_id != "UE-01" || ue01_controller_owned)
                })
                .filter_map(|job| {
                    let handle = job.process_handle.as_deref()?;
                    let spec = job.approved_runtime.as_ref()?;
                    Some((
                        job.ue_id.clone(),
                        handle.to_string(),
                        job.operation_id.clone(),
                        job.generation,
                        runtime
                            .observe_owned(spec, handle)
                            .unwrap_or_else(|_| unknown()),
                    ))
                })
                .take(ueransim_adapter::MAX_CONFIGURABLE_UES - 1)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        if perform_observation {
            last_observed.store(epoch_seconds(), Ordering::Release);
            cache_version_counter.fetch_add(1, Ordering::AcqRel);
            inventory_running.store(false, Ordering::Release);
        }
        (shared, owned)
    })
    .await
    .unwrap_or_else(|_| {
        (
            UeObservation {
                process_state: "UNKNOWN".into(),
                registration_state: "NOT_OBSERVED".into(),
                pdu_session_state: "INACTIVE".into(),
                ue_ip: None,
            },
            Vec::new(),
        )
    });
    let (shared_observation, owned_observations) = observed;
    let managed_profiles = state
        .profile_registry
        .lock()
        .map(|registry| {
            registry
                .profiles
                .iter()
                .map(|record| (record.profile.ue_id.clone(), record.clone()))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let mut controller = state.multi_ue.lock().unwrap();
    if state.execution_mode == "live" {
        for (ue_id, handle, operation_id, generation, observation) in owned_observations {
            let _ = controller.apply_observation_if_current(
                &ue_id,
                &handle,
                operation_id.as_deref(),
                generation,
                &observation,
            );
        }
        let _ = persist_ue_registry(&state, &controller);
    }
    let controller_inventory = controller.inventory();
    let controller_jobs = controller.snapshot();
    let profile_specs = controller.profiles();
    let control_authorized_ids = authorized_ue_control_ids(&state, &identity);
    let items = profile_specs
        .iter()
        .filter(|profile| profile.configured)
        .map(|profile| {
            let managed = managed_profiles.get(&profile.ue_id);
            let job = controller_jobs
                .iter()
                .find(|job| job.ue_id == profile.ue_id);
            let shared = profile.ue_id == "UE-01" && !state.ue01_controller_owned;
            let process_state = if shared {
                shared_observation.process_state.as_str()
            } else if let Some(job) = job {
                job.process_state.as_str()
            } else {
                "NOT_STARTED"
            };
            let registration_state = if shared {
                shared_observation.registration_state.as_str()
            } else if let Some(job) = job {
                job.registration_state.as_str()
            } else {
                "NOT_OBSERVED"
            };
            let pdu_session = if shared {
                shared_observation.pdu_session_state.as_str()
            } else if let Some(job) = job {
                job.pdu_session_state.as_str()
            } else {
                "INACTIVE"
            };
            let traffic_state = if shared {
                "IDLE"
            } else {
                job.map(|job| job.traffic_state.as_str()).unwrap_or("IDLE")
            };
            let traffic_target_verified = !shared
                && job.is_some_and(|value| {
                    value.process_state == "RUNNING"
                        && value.registration_state == "REGISTERED"
                        && value.pdu_session_state == "ACTIVE"
                        && value.process_handle.is_some()
                        && value.approved_runtime.as_ref().is_some_and(|spec| {
                            value
                                .process_handle
                                .as_deref()
                                .is_some_and(|handle| state.ue_runtime.owns(spec, handle))
                        })
                });
            let traffic_reason = if shared {
                "SHARED_UE_PROTECTED"
            } else if process_state != "RUNNING" {
                "UE_NOT_RUNNING"
            } else if registration_state != "REGISTERED" {
                "UE_NOT_REGISTERED"
            } else if pdu_session != "ACTIVE" {
                "PDU_SESSION_NOT_ACTIVE"
            } else if !traffic_target_verified {
                "UE_RUNTIME_OWNERSHIP_NOT_VERIFIED"
            } else {
                "READY"
            };
            let subscription_status = if profile.subscription_verified {
                "VERIFIED"
            } else {
                "PROVISIONING_UNKNOWN"
            };
            let base_reason = if shared {
                "SHARED_UE_PROTECTED"
            } else if !profile.subscription_verified {
                "SUBSCRIBER_PROVISIONING_REVIEW_REQUIRED"
            } else if !ueransim_adapter::is_approved_controller_ue(&profile.ue_id) {
                "PROTECTED_OR_UNAPPROVED_UE"
            } else if state.execution_mode != "live" {
                "LIVE_EXECUTION_NOT_CONFIGURED"
            } else {
                "READY"
            };
            let control_authorized = control_authorized_ids.contains(&profile.ue_id);
            let start_reason = if base_reason != "READY" {
                base_reason
            } else if job.is_some_and(|value| value.process_handle.is_some()) {
                "UE_ALREADY_RUNNING"
            } else if !control_authorized {
                "UE_CONTROL_VALIDATION_REQUIRED"
            } else {
                "READY"
            };
            let stop_reason = if shared {
                "SHARED_UE_PROTECTED"
            } else if job.is_some_and(|value| value.process_handle.is_some()) {
                "READY"
            } else {
                "UE_NOT_RUNNING"
            };
            json!({
                "id":profile.pseudonym,"internal_ue_id":profile.ue_id,"profile":profile.profile_name,
                "profile_state":"CONFIGURED","subscription_status":subscription_status,
                "serving_node":profile.serving_gnb,"process_state":process_state,
                "registration_state":registration_state,"rrc_state":"UNKNOWN","pdu_session":pdu_session,
                "ue_ip":if shared {shared_observation.ue_ip.clone().map_or(Value::Null,Value::from)} else {job.and_then(|value|value.ue_ip.clone()).map_or(Value::Null,Value::from)},
                "traffic_state":traffic_state,
                "uptime_seconds":if shared {Value::Null} else {job.and_then(|value|value.started_at_epoch_s).map(|started|epoch_seconds().saturating_sub(started)).map_or(Value::Null,Value::from)},
                "last_event":job.and_then(|value|value.last_error.clone()).map_or(Value::Null,Value::from),
                "controller_owned":!shared,
                "ownership":if shared {"SHARED_PROTECTED"} else {"POLARIS_CONTROLLER"},
                "scenario_id":managed.and_then(|record|record.scenario_id.clone()),
                "auto_run_scenario":managed.is_some_and(|record|record.auto_run_scenario),
                "control_authorized":control_authorized,
                "traffic_target_verified":traffic_target_verified,
                "actions":{"authorize":base_reason == "READY" && !control_authorized && job.map_or(true, |value| value.process_handle.is_none()),"start":start_reason == "READY","start_reason":start_reason,"stop":stop_reason == "READY","stop_reason":stop_reason,"pdu_start":false,"pdu_stop":false,"traffic":traffic_target_verified,"traffic_reason":traffic_reason,"provisioning_review":!profile.subscription_verified,"reason":if traffic_target_verified {"READY_FOR_BOUNDED_TRAFFIC"} else {traffic_reason}}
            })
        })
        .collect::<Vec<_>>();
    let profiles = profile_specs.iter().map(|profile| {
        let managed = managed_profiles.get(&profile.ue_id);
        let job = controller_inventory.iter().find(|job| job.ue_id == profile.ue_id);
        let state_label = if !profile.configured {
            "NOT_CONFIGURED".to_string()
        } else if !profile.subscription_verified {
            "CONFIGURED_PROVISIONING_REQUIRED".to_string()
        } else {
            job.and_then(|value| serde_json::to_value(&value.lifecycle).ok())
                .and_then(|value| value.as_str().map(str::to_string))
                .unwrap_or_else(|| "CONFIGURED".into())
        };
        let shared = profile.ue_id == "UE-01" && !state.ue01_controller_owned;
        let reason = if shared {"SHARED_UE_PROTECTED"} else if !profile.configured {"NOT_CONFIGURED"} else if !profile.subscription_verified {"SUBSCRIBER_PROVISIONING_REVIEW_REQUIRED"} else if !controller_owns_ue(&state, &profile.ue_id) {"PROTECTED_OR_UNAPPROVED_UE"} else if state.execution_mode != "live" {"LIVE_EXECUTION_NOT_CONFIGURED"} else {"READY"};
        let control_authorized = control_authorized_ids.contains(&profile.ue_id);
        json!({
            "id":profile.ue_id,"pseudonym":profile.pseudonym,"profile":profile.profile_name,"serving_gnb":profile.serving_gnb,"simulator":"UERANSIM",
            "state":state_label,"configured":profile.configured,"controller_owned":!shared,"ownership":if shared {"SHARED_PROTECTED"} else {"POLARIS_CONTROLLER"},"control_authorized":control_authorized,"subscription_status":if profile.subscription_verified {"VERIFIED"}else{"PROVISIONING_UNKNOWN"},
            "scenario_id":managed.and_then(|record|record.scenario_id.clone()),"auto_run_scenario":managed.is_some_and(|record|record.auto_run_scenario),
            "actions":{"authorize":reason == "READY" && !control_authorized && job.map_or(true, |value| value.process_handle.is_none()),"start":reason == "READY" && control_authorized && job.map_or(true, |value| value.process_handle.is_none()),"stop":job.is_some_and(|value|value.process_handle.is_some()),"traffic":false,"reason":if reason == "READY" && !control_authorized {"UE_CONTROL_VALIDATION_REQUIRED"} else {reason}}
        })
    }).collect::<Vec<_>>();
    let controller_active = controller_inventory
        .iter()
        .filter(|job| {
            matches!(
                job.process_state.as_str(),
                "STARTING" | "RESTARTING" | "PAUSED" | "RUNNING" | "MOCK_RUNNING"
            )
        })
        .count();
    let controller_registered = controller_inventory
        .iter()
        .filter(|job| job.registration_state == "REGISTERED")
        .count();
    let controller_pdu = controller_inventory
        .iter()
        .filter(|job| job.pdu_session_state == "ACTIVE")
        .count();
    Json(
        json!({"items":items,"configured_profiles":profiles,"configured_count":controller.configured_count(),"planned_count":controller_inventory.len(),"max_configurable":ueransim_adapter::MAX_CONFIGURABLE_UES,"active_count":usize::from(shared_observation.process_state == "RUNNING")+controller_active,"registered_count":usize::from(shared_observation.registration_state == "REGISTERED")+controller_registered,"pdu_session_count":usize::from(shared_observation.pdu_session_state == "ACTIVE")+controller_pdu,"observed_at_epoch_s":epoch_seconds(),"cache_version":state.ue_inventory_cache_version.load(Ordering::Acquire),"cache_fresh":cache_fresh,"source":"CURRENT_NAS_PDU_AND_CONTROLLER_REGISTRY"}),
    )
}

#[derive(Deserialize)]
struct UeActionInput {
    ue_id: String,
}

#[derive(Deserialize)]
struct UeControlValidationInput {
    ue_ids: Vec<String>,
}

async fn validate_ue_control(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    Json(input): Json<UeControlValidationInput>,
) -> impl IntoResponse {
    if let Err(error) = require_operator(&identity) {
        return error;
    }
    if input.ue_ids.is_empty() || input.ue_ids.len() > ueransim_adapter::MAX_LIVE_UES {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"INVALID_GROUP_REQUEST"})),
        );
    }
    let profiles = state.multi_ue.lock().unwrap().profiles();
    if let Err(error) =
        authorize_live_ue_request(&input.ue_ids, &profiles, state.ue01_controller_owned)
    {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error":error})),
        );
    }
    let additions = {
        let controller = state.multi_ue.lock().unwrap();
        let jobs = controller.snapshot();
        input
            .ue_ids
            .iter()
            .filter(|ue_id| {
                jobs.iter()
                    .find(|job| job.ue_id == **ue_id)
                    .map_or(true, |job| job.process_handle.is_none())
            })
            .count()
    };
    if let Err(error) = resource_gate_for_additions(&state, additions) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":error})),
        );
    }
    let Some(session_id) = identity.session_id.as_ref() else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"OPERATOR_SESSION_REQUIRED"})),
        );
    };
    let expires_at = epoch_seconds() + UE_CONTROL_AUTHORIZATION_SECONDS;
    let mut sessions = state.sessions.lock().unwrap();
    let Some(session) = sessions.get_mut(session_id) else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"OPERATOR_SESSION_REQUIRED"})),
        );
    };
    session.ue_control_authorized_until = Some(expires_at);
    session.ue_control_authorized_ids = input.ue_ids.iter().cloned().collect();
    drop(sessions);
    audit(
        &state,
        &identity.role,
        "VALIDATE_UE_CONTROL",
        "AUTHORIZED_BOUNDED_WINDOW",
        Some(&input.ue_ids.join(",")),
    );
    (
        StatusCode::OK,
        Json(
            json!({"valid":true,"execution":"NOT_EXECUTED","ue_ids":input.ue_ids,"expires_at_epoch_s":expires_at}),
        ),
    )
}

#[derive(Deserialize)]
struct UeGroupActionInput {
    ue_ids: Vec<String>,
    mode: Option<String>,
    stagger_seconds: Option<u8>,
}

fn authorize_live_ue_request(
    ue_ids: &[String],
    profiles: &[ueransim_adapter::UeProfileSpec],
    ue01_controller_owned: bool,
) -> Result<(), String> {
    let mut unique = BTreeSet::new();
    for ue_id in ue_ids {
        if !unique.insert(ue_id.as_str()) {
            return Err("INVALID_GROUP_REQUEST".into());
        }
        if !ueransim_adapter::is_approved_controller_ue(ue_id) {
            return Err("PROTECTED_OR_UNAPPROVED_UE".into());
        }
        if ue_id == "UE-01" && !ue01_controller_owned {
            return Err("SHARED_UE_PROTECTED".into());
        }
        let profile = profiles
            .iter()
            .find(|profile| profile.ue_id == *ue_id)
            .ok_or("UNKNOWN_UE_PROFILE")?;
        if !profile.configured || !profile.subscription_verified {
            return Err("UE_PROFILE_NOT_READY".into());
        }
    }
    Ok(())
}

fn require_operator(identity: &EffectiveIdentity) -> Result<(), (StatusCode, Json<Value>)> {
    if !matches!(identity.role.as_str(), "operator" | "administrator") {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error":"OPERATOR_PERMISSION_REQUIRED"})),
        ));
    }
    if !identity.csrf_valid {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error":"CSRF_TOKEN_REQUIRED"})),
        ));
    }
    Ok(())
}

fn start_one_live_inner(
    state: &AppState,
    ue_id: &str,
) -> Result<simulator_controller::UeJob, String> {
    resource_gate_for_additions(state, 1)?;
    let profiles = state
        .multi_ue
        .lock()
        .map_err(|_| "UE_REGISTRY_UNAVAILABLE")?
        .profiles();
    authorize_live_ue_request(&[ue_id.to_string()], &profiles, state.ue01_controller_owned)?;
    let verified = state.ue_runtime.verify_provisioning(&profiles)?;
    let profile = {
        let controller = state
            .multi_ue
            .lock()
            .map_err(|_| "UE_REGISTRY_UNAVAILABLE")?;
        controller
            .profiles()
            .into_iter()
            .find(|profile| profile.ue_id == ue_id)
            .ok_or("UNKNOWN_UE_PROFILE")?
    };
    let profile_sha256 = verified.get(ue_id).ok_or("UE_PROFILE_NOT_READY")?.clone();
    let approved_runtime = state.ue_runtime.approve_launch(&profile, &profile_sha256)?;
    let operation_id = random_hex(16);
    {
        let mut controller = state
            .multi_ue
            .lock()
            .map_err(|_| "UE_REGISTRY_UNAVAILABLE")?;
        controller.reserve_live_start(ue_id, &operation_id, approved_runtime.clone())?;
        if let Err(error) = persist_ue_registry(state, &controller) {
            let _ = controller.fail_live_operation(
                ue_id,
                &operation_id,
                "UE_START_RESERVATION_NOT_DURABLE",
                false,
            );
            return Err(error);
        }
    }
    let handle = match state.ue_runtime.launch(&approved_runtime) {
        Ok(handle) => handle,
        Err(failure) => {
            let error = failure.error;
            if let Ok(mut controller) = state.multi_ue.lock() {
                if let Some(handle) = failure.process_handle {
                    let attached = controller
                        .attach_live_handle(ue_id, &operation_id, &handle)
                        .is_ok()
                        && persist_ue_registry(state, &controller).is_ok();
                    if attached {
                        drop(controller);
                        let cleanup = state.ue_runtime.stop(&approved_runtime, &handle);
                        if let Ok(mut controller) = state.multi_ue.lock() {
                            let cleanup_error = if cleanup.is_err() {
                                format!("{error};LIVE_UE_CLEANUP_PENDING")
                            } else {
                                error.clone()
                            };
                            let _ = controller.fail_live_operation(
                                ue_id,
                                &operation_id,
                                &cleanup_error,
                                cleanup.is_err(),
                            );
                            let _ = persist_ue_registry(state, &controller);
                        }
                        return Err(error);
                    }
                    let _ = controller
                        .mark_cleanup_pending(ue_id, "UE_START_HANDLE_NOT_DURABLE_CLEANUP_PENDING");
                } else {
                    let _ = controller.fail_live_operation(ue_id, &operation_id, &error, false);
                }
                let _ = persist_ue_registry(state, &controller);
            }
            return Err(error);
        }
    };
    {
        let mut controller = state
            .multi_ue
            .lock()
            .map_err(|_| "UE_REGISTRY_UNAVAILABLE")?;
        controller.attach_live_handle(ue_id, &operation_id, &handle)?;
        if let Err(error) = persist_ue_registry(state, &controller) {
            drop(controller);
            let cleanup = state.ue_runtime.stop(&approved_runtime, &handle);
            if let Ok(mut controller) = state.multi_ue.lock() {
                if cleanup.is_ok() {
                    let _ = controller.fail_live_operation(ue_id, &operation_id, &error, false);
                } else {
                    let _ = controller
                        .mark_cleanup_pending(ue_id, "UE_START_HANDLE_NOT_DURABLE_CLEANUP_PENDING");
                }
                let _ = persist_ue_registry(state, &controller);
            }
            return Err(error);
        }
    }
    let observation = match state.ue_runtime.observe_owned(&approved_runtime, &handle) {
        Ok(observation) if observation.process_state == "RUNNING" => observation,
        Ok(_) => {
            let cleanup = state.ue_runtime.stop(&approved_runtime, &handle);
            if let Ok(mut controller) = state.multi_ue.lock() {
                let _ = controller.fail_live_operation(
                    ue_id,
                    &operation_id,
                    "LIVE_UE_NOT_RUNNING_AFTER_START",
                    cleanup.is_err(),
                );
                let _ = persist_ue_registry(state, &controller);
            }
            return Err("LIVE_UE_NOT_RUNNING_AFTER_START".into());
        }
        Err(error) => {
            let cleanup = state.ue_runtime.stop(&approved_runtime, &handle);
            if let Ok(mut controller) = state.multi_ue.lock() {
                let cleanup_error = if cleanup.is_err() {
                    format!("{error};LIVE_UE_CLEANUP_PENDING")
                } else {
                    error.clone()
                };
                let _ = controller.fail_live_operation(
                    ue_id,
                    &operation_id,
                    &cleanup_error,
                    cleanup.is_err(),
                );
                let _ = persist_ue_registry(state, &controller);
            }
            return Err(error);
        }
    };
    let mut controller = state
        .multi_ue
        .lock()
        .map_err(|_| "UE_REGISTRY_UNAVAILABLE")?;
    controller.complete_live_start(ue_id, &operation_id, &handle)?;
    controller.apply_observation(
        ue_id,
        &observation.process_state,
        &observation.registration_state,
        &observation.pdu_session_state,
        observation.ue_ip.as_deref(),
    )?;
    if let Err(error) = persist_ue_registry(state, &controller) {
        drop(controller);
        let cleanup = state.ue_runtime.stop(&approved_runtime, &handle);
        if let Ok(mut controller) = state.multi_ue.lock() {
            if cleanup.is_ok() {
                let _ = controller.stop_offline(ue_id);
            } else {
                let _ = controller
                    .mark_cleanup_pending(ue_id, "UE_START_REGISTRY_NOT_DURABLE_CLEANUP_PENDING");
            }
            let _ = persist_ue_registry(state, &controller);
        }
        return Err(error);
    }
    controller
        .snapshot()
        .into_iter()
        .find(|job| job.ue_id == ue_id)
        .ok_or_else(|| "UE_REGISTRY_RECORD_MISSING".into())
}

fn start_one_live(state: &AppState, ue_id: &str) -> Result<simulator_controller::UeJob, String> {
    let _operation_guard = state
        .ue_operations
        .lock()
        .map_err(|_| "UE_OPERATION_COORDINATOR_UNAVAILABLE")?;
    start_one_live_inner(state, ue_id)
}

fn stop_one_live_inner(
    state: &AppState,
    ue_id: &str,
) -> Result<simulator_controller::UeJob, String> {
    if !controller_owns_ue(state, ue_id) {
        return Err("PROTECTED_OR_UNAPPROVED_UE".into());
    }
    let operation_id = random_hex(16);
    let (approved_runtime, handle) = {
        let mut controller = state
            .multi_ue
            .lock()
            .map_err(|_| "UE_REGISTRY_UNAVAILABLE")?;
        let job = controller
            .snapshot()
            .into_iter()
            .find(|job| job.ue_id == ue_id)
            .ok_or("UE_NOT_STARTED")?;
        let result = (
            job.approved_runtime
                .ok_or("LIVE_RUNTIME_APPROVAL_MISSING")?,
            job.process_handle.ok_or("UE_NOT_STARTED")?,
        );
        controller.reserve_live_stop(ue_id, &operation_id)?;
        if let Err(error) = persist_ue_registry(state, &controller) {
            let _ = controller.fail_live_operation(ue_id, &operation_id, &error, true);
            return Err(error);
        }
        result
    };
    if let Err(error) = state.ue_runtime.stop(&approved_runtime, &handle) {
        if let Ok(mut controller) = state.multi_ue.lock() {
            let _ = controller.fail_live_operation(
                ue_id,
                &operation_id,
                &format!("{error};LIVE_UE_CLEANUP_PENDING"),
                true,
            );
            let _ = persist_ue_registry(state, &controller);
        }
        return Err(error);
    }
    let mut controller = state
        .multi_ue
        .lock()
        .map_err(|_| "UE_REGISTRY_UNAVAILABLE")?;
    let job = controller.stop_offline(ue_id)?.clone();
    persist_ue_registry(state, &controller)?;
    Ok(job)
}

fn stop_one_live(state: &AppState, ue_id: &str) -> Result<simulator_controller::UeJob, String> {
    let _operation_guard = state
        .ue_operations
        .lock()
        .map_err(|_| "UE_OPERATION_COORDINATOR_UNAVAILABLE")?;
    stop_one_live_inner(state, ue_id)
}

async fn start_ue(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    Json(input): Json<UeActionInput>,
) -> impl IntoResponse {
    if let Err(error) = require_operator(&identity) {
        return error;
    }
    if state.execution_mode != "live" {
        if let Err(error) = resource_gate(&state) {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":error})),
            );
        }
    }
    if state.execution_mode == "live" {
        if !ue_control_is_authorized(&state, &identity, &[input.ue_id.clone()]) {
            return (
                StatusCode::PRECONDITION_REQUIRED,
                Json(json!({"error":"UE_CONTROL_VALIDATION_REQUIRED"})),
            );
        }
        let live_state = state.clone();
        let ue_id = input.ue_id.clone();
        let outcome = tokio::task::spawn_blocking(move || start_one_live(&live_state, &ue_id))
            .await
            .unwrap_or_else(|_| Err("UE_RUNTIME_TASK_FAILED".into()));
        return match outcome {
            Ok(job) => (
                StatusCode::OK,
                Json(serde_json::to_value(job).unwrap_or(Value::Null)),
            ),
            Err(error) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error":error})),
            ),
        };
    }
    if state.execution_mode != "mock" {
        audit(
            &state,
            &identity.role,
            "START_UE",
            "LIVE_EXECUTION_NOT_CONFIGURED",
            Some(&input.ue_id),
        );
        return (
            StatusCode::LOCKED,
            Json(json!({"error":"LIVE_EXECUTION_NOT_CONFIGURED"})),
        );
    }
    let mut controller = state.multi_ue.lock().unwrap();
    let outcome = controller.start_offline(&input.ue_id).cloned();
    match outcome {
        Ok(job) => match persist_ue_registry(&state, &controller) {
            Ok(()) => (
                StatusCode::OK,
                Json(serde_json::to_value(job).unwrap_or(Value::Null)),
            ),
            Err(error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":error})),
            ),
        },
        Err(error) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error":error})),
        ),
    }
}

async fn stop_ue(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    Json(input): Json<UeActionInput>,
) -> impl IntoResponse {
    if let Err(error) = require_operator(&identity) {
        return error;
    }
    if state.execution_mode == "live" {
        let live_state = state.clone();
        let ue_id = input.ue_id.clone();
        let outcome = tokio::task::spawn_blocking(move || stop_one_live(&live_state, &ue_id))
            .await
            .unwrap_or_else(|_| Err("UE_RUNTIME_TASK_FAILED".into()));
        return match outcome {
            Ok(job) => (
                StatusCode::OK,
                Json(serde_json::to_value(job).unwrap_or(Value::Null)),
            ),
            Err(error) => (StatusCode::CONFLICT, Json(json!({"error":error}))),
        };
    }
    let mut controller = state.multi_ue.lock().unwrap();
    let outcome = controller.stop_offline(&input.ue_id).cloned();
    match outcome {
        Ok(job) => match persist_ue_registry(&state, &controller) {
            Ok(()) => (
                StatusCode::OK,
                Json(serde_json::to_value(job).unwrap_or(Value::Null)),
            ),
            Err(error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":error})),
            ),
        },
        Err(error) => (StatusCode::NOT_FOUND, Json(json!({"error":error}))),
    }
}

async fn start_ue_group(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    Json(input): Json<UeGroupActionInput>,
) -> impl IntoResponse {
    if let Err(error) = require_operator(&identity) {
        return error;
    }
    if input.ue_ids.is_empty()
        || input.ue_ids.len() > ueransim_adapter::MAX_LIVE_UES
        || !matches!(
            input.mode.as_deref().unwrap_or("STAGGERED"),
            "SEQUENTIAL" | "STAGGERED" | "CONCURRENT"
        )
        || input.stagger_seconds.unwrap_or(0) > 30
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"INVALID_GROUP_REQUEST"})),
        );
    }
    if state.execution_mode != "live" {
        if let Err(error) = resource_gate(&state) {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":error})),
            );
        }
    }
    if state.execution_mode == "live" {
        if input.mode.as_deref().unwrap_or("STAGGERED") != "STAGGERED" {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"LIVE_GROUP_MUST_BE_STAGGERED"})),
            );
        }
        if input.stagger_seconds.unwrap_or(2) < 2 {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"LIVE_STAGGER_MINIMUM_TWO_SECONDS"})),
            );
        }
        let profiles = state.multi_ue.lock().unwrap().profiles();
        if let Err(error) =
            authorize_live_ue_request(&input.ue_ids, &profiles, state.ue01_controller_owned)
        {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error":error})),
            );
        }
        if !ue_control_is_authorized(&state, &identity, &input.ue_ids) {
            return (
                StatusCode::PRECONDITION_REQUIRED,
                Json(json!({"error":"UE_CONTROL_VALIDATION_REQUIRED"})),
            );
        }
        let mut result = simulator_controller::GroupResult {
            started: Vec::new(),
            failed: Vec::new(),
        };
        for (index, ue_id) in input.ue_ids.iter().enumerate() {
            if index > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(u64::from(
                    input.stagger_seconds.unwrap_or(2),
                )))
                .await;
            }
            let live_state = state.clone();
            let item = ue_id.clone();
            let outcome = tokio::task::spawn_blocking(move || start_one_live(&live_state, &item))
                .await
                .unwrap_or_else(|_| Err("UE_RUNTIME_TASK_FAILED".into()));
            match outcome {
                Ok(_) => result.started.push(ue_id.clone()),
                Err(error) => result.failed.push((ue_id.clone(), error)),
            }
        }
        return (
            StatusCode::OK,
            Json(serde_json::to_value(result).unwrap_or(Value::Null)),
        );
    }
    if state.execution_mode != "mock" {
        return (
            StatusCode::LOCKED,
            Json(json!({"error":"LIVE_EXECUTION_NOT_CONFIGURED"})),
        );
    }
    let result = state
        .multi_ue
        .lock()
        .unwrap()
        .start_group_offline(&input.ue_ids);
    let controller = state.multi_ue.lock().unwrap();
    match persist_ue_registry(&state, &controller) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::to_value(result).unwrap_or(Value::Null)),
        ),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":error})),
        ),
    }
}

async fn stop_ue_group(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    Json(input): Json<UeGroupActionInput>,
) -> impl IntoResponse {
    if let Err(error) = require_operator(&identity) {
        return error;
    }
    if input.ue_ids.is_empty() || input.ue_ids.len() > ueransim_adapter::MAX_LIVE_UES {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"INVALID_GROUP_REQUEST"})),
        );
    }
    if state.execution_mode == "live" {
        let mut result = simulator_controller::GroupResult {
            started: Vec::new(),
            failed: Vec::new(),
        };
        for ue_id in &input.ue_ids {
            let live_state = state.clone();
            let item = ue_id.clone();
            let outcome = tokio::task::spawn_blocking(move || stop_one_live(&live_state, &item))
                .await
                .unwrap_or_else(|_| Err("UE_RUNTIME_TASK_FAILED".into()));
            match outcome {
                Ok(_) => result.started.push(ue_id.clone()),
                Err(error) => result.failed.push((ue_id.clone(), error)),
            }
        }
        return (
            StatusCode::OK,
            Json(json!({"stopped":result.started,"failed":result.failed})),
        );
    }
    let result = state
        .multi_ue
        .lock()
        .unwrap()
        .stop_group_offline(&input.ue_ids);
    let controller = state.multi_ue.lock().unwrap();
    match persist_ue_registry(&state, &controller) {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({"stopped":result.started,"failed":result.failed})),
        ),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":error})),
        ),
    }
}
async fn traffic_status(State(state): State<Arc<AppState>>) -> Json<Value> {
    let mut runtime = state.runtime.lock().unwrap();
    if refresh_runtime_with_state(&state, &mut runtime) {
        persist_runtime(&state, &runtime);
    }
    let active = runtime.active.as_ref().map(job_json);
    let latest = runtime.history.last();
    let selected = active.as_ref().or(latest);
    Json(json!({
        "state":selected.and_then(|j|j["traffic_state"].as_str()).unwrap_or("IDLE"),
        "packets_requested":selected.and_then(|j|j["packets_requested"].as_u64()).unwrap_or(0),
        "packets_sent":selected.and_then(|j|j["packets_sent"].as_u64()),
        "packets_received":selected.and_then(|j|j["packets_received"].as_u64()),
        "packet_size_bytes":selected.and_then(|j|j["packet_size_bytes"].as_u64()),
        "bytes":selected.and_then(|j|j["bytes_sent"].as_u64()),
        "bytes_sent":selected.and_then(|j|j["bytes_sent"].as_u64()),
        "bytes_received":selected.and_then(|j|j["bytes_received"].as_u64()),
        "accounting_source":selected.and_then(|j|j["accounting_source"].as_str()).unwrap_or("NOT_AVAILABLE"),
        "receive_accounting":selected.and_then(|j|j["receive_accounting"].as_str()).unwrap_or("NOT_OBSERVED_SEND_ONLY_PROFILE"),
        "target_ue_id":selected.and_then(|job|job["target_ue_id"].as_str()),
        "target_ue_pseudonym":selected.and_then(|job|job["target_ue_pseudonym"].as_str()),
        "tun_interface":selected.and_then(|job|job["tun_interface"].as_str()),
        "last_result":latest,
        "approved_destinations":["10.46.0.1"]
    }))
}

fn cpu_safety_evidence(state: &AppState, budget: ScenarioResourceBudget) -> CpuSafetyEvidence {
    state
        .cpu_safety
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .evaluate(budget)
}

fn resource_gate_for_budget(
    state: &AppState,
    budget: ScenarioResourceBudget,
    record_decision: bool,
) -> Result<Value, String> {
    if let Some(result) = state.resource_override.clone() {
        return result.map(|_| json!({"test_override":true}));
    }
    let disk = measure(&state.storage_path).map_err(|_| "DISK_MONITOR_FAILURE".to_string())?;
    let usage = disk.basis_points().unwrap_or(10_000);
    if usage >= 8_500 {
        return Err("DISK_STOP_THRESHOLD".into());
    }
    let memory = memory_stats();
    if memory["available_bytes"].as_u64().unwrap_or(0) < 1_073_741_824 {
        return Err("INSUFFICIENT_MEMORY".into());
    }
    let cpu = cpu_safety_evidence(state, budget);
    if let Ok(mut latest) = state.latest_cpu_decision.lock() {
        *latest = Some(cpu.clone());
    }
    if record_decision {
        persist_cpu_decision(state, &cpu)?;
    }
    if !cpu.ready {
        return Err(cpu.state.clone());
    }
    let mut required_containers = vec![
        "oiran-lab-amf-1",
        "oiran-lab-upf-1",
        "oiran-lab-ueransim-gnb-1",
        "oiran-lab-capture-1",
    ];
    if !state.ue01_controller_owned {
        required_containers.push("oiran-lab-ueransim-ue-1");
    }
    if !required_containers
        .iter()
        .all(|name| container_is_healthy(name))
    {
        return Err("LAB_HEALTH_GATE_FAILED".into());
    }
    let required_profile = if state.ue01_controller_owned {
        Path::new(ueransim_adapter::LIVE_PROFILE_ROOT).join("ue-01.yaml")
    } else {
        PathBuf::from("/root/POLARIS/runtime/ueransim/ue.yaml")
    };
    if !required_profile.exists() {
        return Err("UE_PROFILE_UNAVAILABLE".into());
    }
    Ok(
        json!({"disk_usage_percent":f64::from(usage)/100.0,"memory_available_bytes":memory["available_bytes"],"cpu_safety":cpu}),
    )
}

fn resource_gate(state: &AppState) -> Result<Value, String> {
    resource_gate_for_budget(state, ScenarioResourceBudget::traffic(), true)
}

fn resource_gate_preview(state: &AppState) -> Result<Value, String> {
    resource_gate_for_budget(state, ScenarioResourceBudget::traffic(), false)
}

fn resource_gate_for_additions(state: &AppState, additions: usize) -> Result<Value, String> {
    let evidence =
        resource_gate_for_budget(state, ScenarioResourceBudget::ue(additions.max(1)), true)?;
    if state.resource_override.is_some() || additions == 0 {
        return Ok(evidence);
    }
    let available = evidence["memory_available_bytes"].as_u64().unwrap_or(0);
    let required = 1_073_741_824_u64.saturating_add((additions as u64).saturating_mul(536_870_912));
    if available < required {
        return Err("INSUFFICIENT_UE_MEMORY_BUDGET".into());
    }
    Ok(evidence)
}

async fn scenario_capabilities(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
) -> Json<Value> {
    let enabled = state.policy_enabled.load(Ordering::SeqCst);
    let active = state
        .runtime
        .lock()
        .map(|runtime| runtime.active.is_some())
        .unwrap_or(true);
    let (status, reason) = if !matches!(identity.role.as_str(), "operator" | "administrator") {
        (
            "OPERATOR_PERMISSION_REQUIRED".to_string(),
            "Authenticate as Operator or Administrator".to_string(),
        )
    } else if !enabled {
        (
            "SCENARIO_NOT_CERTIFIED".to_string(),
            "The Administrator disabled this scenario policy".to_string(),
        )
    } else if active {
        (
            "RUNNING".to_string(),
            "A controller-owned scenario is already active".to_string(),
        )
    } else {
        match resource_gate_preview(&state) {
            Ok(_) => (
                "READY_TO_START".to_string(),
                "All authorization and safety checks pass".to_string(),
            ),
            Err(error) => ("INSUFFICIENT_RESOURCES".to_string(), error),
        }
    };
    let cpu_decision = state
        .latest_cpu_decision
        .lock()
        .ok()
        .and_then(|decision| decision.clone());
    Json(json!({"items":[
            {"id":"bounded-existing-ue-udp-v1","version":"1.0.0","certified":true,"enabled":enabled,"technology":"5G SA","simulator":"UERANSIM","existing_ue_only":true,"creates_ue":false,"controls_gnb":false,"protocol":"UDP","datagrams":5,"destination":"10.46.0.1","destination_port":49001,"target_scope":"SHARED_UE_01_COMPATIBILITY"},
            {"id":"bounded-controller-ue-udp-v1","version":"1.0.0","certified":true,"enabled":enabled,"technology":"5G SA","simulator":"UERANSIM","existing_ue_only":true,"creates_ue":false,"controls_gnb":false,"protocol":"UDP","datagrams":5,"destination":"10.46.0.1","destination_port":49001,"target_scope":"VERIFIED_CONTROLLER_OWNED_UE"}
        ],"execution_status":status,"reason":reason,"resource_evidence":cpu_decision,"role":identity.role}))
}

#[derive(Deserialize)]
struct StartScenarioInput {
    #[serde(default)]
    scenario_id: Option<String>,
    #[serde(default)]
    scenario_type: Option<String>,
    #[serde(default)]
    target_ue_id: Option<String>,
    #[serde(default)]
    scenario_definition_id: Option<String>,
    #[serde(default)]
    ue_ids: Vec<String>,
}

fn valid_job_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

fn run_mock_definition_scenario(
    state: &AppState,
    definition_id: &str,
    ue_ids: &[String],
) -> Result<Value, (StatusCode, Json<Value>)> {
    if state.execution_mode != "mock" {
        return Err((
            StatusCode::LOCKED,
            Json(json!({"error":"SCENARIO_DEFINITION_LIVE_EXECUTION_NOT_AUTHORIZED"})),
        ));
    }
    if ue_ids.is_empty() || ue_ids.len() > ueransim_adapter::MAX_LIVE_UES {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error":"SCENARIO_UE_SELECTION_INVALID"})),
        ));
    }
    if ue_ids.iter().collect::<BTreeSet<_>>().len() != ue_ids.len() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error":"SCENARIO_UE_SELECTION_DUPLICATE"})),
        ));
    }
    let profiles = state.multi_ue.lock().unwrap().profiles();
    if ue_ids.iter().any(|ue_id| {
        !controller_owns_ue(state, ue_id) || !profiles.iter().any(|profile| profile.ue_id == *ue_id)
    }) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error":"SCENARIO_UE_NOT_CONTROLLER_OWNED"})),
        ));
    }
    let definition = state
        .scenario_catalog
        .lock()
        .unwrap()
        .definitions
        .iter()
        .find(|item| item.id == definition_id)
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error":"SCENARIO_DEFINITION_NOT_FOUND"})),
            )
        })?;
    let resolved = resolve_steps(&definition).map_err(|error| scenario_definition_error(error))?;
    let job_id = format!("{}-{}", definition.id, random_hex(6));
    let started_at = epoch_seconds();
    let steps = resolved
        .iter()
        .map(|step| {
            json!({
                "index":step.index,
                "type":step.step_type,
                "scenario_loop":{"iteration":step.scenario_loop_iteration,"count":step.scenario_loop_count},
                "step_loop":{"iteration":step.step_loop_iteration,"count":step.step_loop_count},
                "state":"PENDING",
                "started_at":Value::Null,
                "ended_at":Value::Null,
                "error":Value::Null,
                "resolved_parameters":step.parameters
            })
        })
        .collect::<Vec<_>>();
    let record = json!({
        "job_id":job_id,
        "scenario_id":definition.id,
        "scenario_definition_id":definition.id,
        "scenario_definition_version":definition.version,
        "ue_ids":ue_ids,
        "state":"RUNNING",
        "traffic_state":"NOT_EXECUTED_OFFLINE",
        "started_at_epoch_s":started_at,
        "ended_at_epoch_s":Value::Null,
        "terminal_result":Value::Null,
        "steps":steps
    });
    let mut runtime = state.runtime.lock().unwrap();
    runtime.history.push(record);
    persist_runtime(state, &runtime);
    // Mock mode is the deterministic offline executor. Each PENDING state is durably published
    // before the ordered transition; no UE process, PDU session or traffic generator is touched.
    let record_index = runtime.history.len() - 1;
    for step_index in 0..resolved.len() {
        runtime.history[record_index]["steps"][step_index]["state"] = json!("RUNNING");
        runtime.history[record_index]["steps"][step_index]["started_at"] = json!(epoch_seconds());
        persist_runtime(state, &runtime);
        runtime.history[record_index]["steps"][step_index]["state"] = json!("COMPLETED");
        runtime.history[record_index]["steps"][step_index]["ended_at"] = json!(epoch_seconds());
        persist_runtime(state, &runtime);
    }
    runtime.history[record_index]["state"] = json!("COMPLETED");
    runtime.history[record_index]["ended_at_epoch_s"] = json!(epoch_seconds());
    runtime.history[record_index]["terminal_result"] = json!("OFFLINE_MOCK_COMPLETED");
    persist_runtime(state, &runtime);
    Ok(runtime.history[record_index].clone())
}

fn definition_record_index(runtime: &ControlRuntime, job_id: &str) -> Option<usize> {
    runtime
        .history
        .iter()
        .position(|record| record["job_id"].as_str() == Some(job_id))
}

fn update_definition_record(
    state: &AppState,
    job_id: &str,
    update: impl FnOnce(&mut Value),
) -> Result<Value, String> {
    let mut runtime = state
        .runtime
        .lock()
        .map_err(|_| "SCENARIO_RUNTIME_UNAVAILABLE".to_string())?;
    let index = definition_record_index(&runtime, job_id).ok_or("SCENARIO_JOB_NOT_FOUND")?;
    update(&mut runtime.history[index]);
    let value = runtime.history[index].clone();
    persist_runtime(state, &runtime);
    Ok(value)
}

fn resolved_parameter_u64(
    step: &ResolvedStep,
    name: &str,
    default: u64,
    maximum: u64,
) -> Result<u64, String> {
    let value = step
        .parameters
        .get(name)
        .map(|value| value.as_u64().ok_or("SCENARIO_PARAMETER_INVALID"))
        .transpose()?
        .unwrap_or(default);
    if value > maximum {
        return Err("SCENARIO_PARAMETER_OUT_OF_RANGE".into());
    }
    Ok(value)
}

fn observe_controller_ue(state: &AppState, ue_id: &str) -> Result<UeObservation, String> {
    let job = state
        .multi_ue
        .lock()
        .map_err(|_| "UE_REGISTRY_UNAVAILABLE".to_string())?
        .snapshot()
        .into_iter()
        .find(|job| job.ue_id == ue_id)
        .ok_or("UE_NOT_STARTED")?;
    let approved = job
        .approved_runtime
        .ok_or("LIVE_RUNTIME_APPROVAL_MISSING")?;
    let handle = job.process_handle.ok_or("UE_NOT_STARTED")?;
    let observation = state.ue_runtime.observe_owned(&approved, &handle)?;
    let mut controller = state
        .multi_ue
        .lock()
        .map_err(|_| "UE_REGISTRY_UNAVAILABLE".to_string())?;
    controller.apply_observation(
        ue_id,
        &observation.process_state,
        &observation.registration_state,
        &observation.pdu_session_state,
        observation.ue_ip.as_deref(),
    )?;
    persist_ue_registry(state, &controller)?;
    Ok(observation)
}

fn run_bounded_udp_for_ue(state: &AppState, ue_id: &str) -> Result<(), String> {
    let target = resolve_controller_traffic_target(state, ue_id)?;
    state.ue_runtime.execute_bounded_udp(&target)
}

fn cancellable_wait(control: &DefinitionJobControl, duration_ms: u64) -> Result<(), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(duration_ms);
    while std::time::Instant::now() < deadline {
        if control.cancel.load(Ordering::SeqCst) {
            return Err("SCENARIO_STOP_REQUESTED".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Ok(())
}

fn execute_live_definition_step(
    state: &AppState,
    step: &ResolvedStep,
    ue_ids: &[String],
    control: &DefinitionJobControl,
) -> Result<Value, String> {
    match step.step_type.as_str() {
        "wait" => {
            let duration_ms = resolved_parameter_u64(step, "duration_ms", 1_000, 120_000)?;
            cancellable_wait(control, duration_ms)?;
            Ok(json!({"duration_ms":duration_ms}))
        }
        "ue_start" => {
            for ue_id in ue_ids {
                if control.cancel.load(Ordering::SeqCst) {
                    return Err("SCENARIO_STOP_REQUESTED".into());
                }
                let already_running = state
                    .multi_ue
                    .lock()
                    .map_err(|_| "UE_REGISTRY_UNAVAILABLE".to_string())?
                    .snapshot()
                    .iter()
                    .any(|job| job.ue_id == *ue_id && job.process_state == "RUNNING");
                if !already_running {
                    start_one_live(state, ue_id)?;
                    control
                        .started_ues
                        .lock()
                        .map_err(|_| "SCENARIO_RUNTIME_UNAVAILABLE".to_string())?
                        .insert(ue_id.clone());
                }
            }
            Ok(json!({}))
        }
        "ue_stop" => {
            for ue_id in ue_ids {
                let running = state
                    .multi_ue
                    .lock()
                    .map_err(|_| "UE_REGISTRY_UNAVAILABLE".to_string())?
                    .snapshot()
                    .iter()
                    .any(|job| job.ue_id == *ue_id && job.process_state == "RUNNING");
                if running {
                    stop_one_live(state, ue_id)?;
                }
                control
                    .started_ues
                    .lock()
                    .map_err(|_| "SCENARIO_RUNTIME_UNAVAILABLE".to_string())?
                    .remove(ue_id);
            }
            Ok(json!({}))
        }
        "pdu_establish" => {
            let timeout = resolved_parameter_u64(step, "timeout_seconds", 30, 120)?;
            for ue_id in ue_ids {
                let (job, mut profile) = {
                    let controller = state
                        .multi_ue
                        .lock()
                        .map_err(|_| "UE_REGISTRY_UNAVAILABLE".to_string())?;
                    let job = controller
                        .snapshot()
                        .into_iter()
                        .find(|job| job.ue_id == *ue_id)
                        .ok_or("UE_NOT_STARTED")?;
                    let profile = controller
                        .profiles()
                        .into_iter()
                        .find(|profile| profile.ue_id == *ue_id)
                        .ok_or("UNKNOWN_UE_PROFILE")?;
                    (job, profile)
                };
                if let Some(dnn) = step.parameters.get("dnn").and_then(Value::as_str) {
                    if !matches!(dnn, "internet" | "ims") {
                        return Err("DNN_NOT_ALLOWED".into());
                    }
                    profile.dnn = dnn.into();
                }
                state
                    .ue_runtime
                    .establish_pdu(&job, &profile, timeout, &control.cancel)?;
                let observation = observe_controller_ue(state, ue_id)?;
                if observation.pdu_session_state != "ACTIVE" {
                    return Err("PDU_STATE_ACTIVE_NOT_OBSERVED".into());
                }
            }
            Ok(json!({"pdu_state":"ACTIVE"}))
        }
        "pdu_release" => {
            let timeout = resolved_parameter_u64(step, "timeout_seconds", 30, 120)?;
            for ue_id in ue_ids {
                let job = state
                    .multi_ue
                    .lock()
                    .map_err(|_| "UE_REGISTRY_UNAVAILABLE".to_string())?
                    .snapshot()
                    .into_iter()
                    .find(|job| job.ue_id == *ue_id)
                    .ok_or("UE_NOT_STARTED")?;
                state
                    .ue_runtime
                    .release_pdu(&job, timeout, &control.cancel)?;
                let observation = observe_controller_ue(state, ue_id)?;
                if observation.pdu_session_state != "INACTIVE" {
                    return Err("PDU_STATE_INACTIVE_NOT_OBSERVED".into());
                }
            }
            Ok(json!({"pdu_state":"INACTIVE"}))
        }
        "udp_traffic" => {
            let packets = resolved_parameter_u64(step, "packet_count", 5, 5)?;
            if packets != 5 {
                return Err("UDP_PROFILE_MUST_USE_FIVE_DATAGRAMS".into());
            }
            for ue_id in ue_ids {
                if control.cancel.load(Ordering::SeqCst) {
                    return Err("SCENARIO_STOP_REQUESTED".into());
                }
                run_bounded_udp_for_ue(state, ue_id)?;
            }
            Ok(json!({"datagrams":5}))
        }
        "traffic_dl" => Err("DL_SENDER_NOT_AVAILABLE".into()),
        "traffic_ul" => {
            let bytes = resolved_parameter_u64(step, "bytes", 0, 200 * 1024 * 1024)?;
            if bytes == 0 {
                return Err("TRAFFIC_BYTES_OUT_OF_RANGE".into());
            }
            let mut measured = 0_u64;
            for ue_id in ue_ids {
                if control.cancel.load(Ordering::SeqCst) {
                    return Err("SCENARIO_STOP_REQUESTED".into());
                }
                let target = resolve_controller_traffic_target(state, ue_id)?;
                measured = measured
                    .checked_add(state.ue_runtime.execute_iperf_ul(&target, bytes)?)
                    .ok_or("IPERF3_BYTES_OVERFLOW")?;
            }
            Ok(json!({"requested_bytes_per_ue":bytes,"measured_ul_bytes":measured}))
        }
        "idle" => {
            let duration_ms = resolved_parameter_u64(step, "duration_ms", 1_000, 3_600_000)?;
            for ue_id in ue_ids {
                if observe_controller_ue(state, ue_id)?.pdu_session_state != "ACTIVE" {
                    return Err("IDLE_REQUIRES_ACTIVE_PDU".into());
                }
            }
            cancellable_wait(control, duration_ms)?;
            for ue_id in ue_ids {
                if observe_controller_ue(state, ue_id)?.pdu_session_state != "ACTIVE" {
                    return Err("IDLE_DID_NOT_PRESERVE_PDU".into());
                }
            }
            Ok(json!({"duration_ms":duration_ms,"pdu_preserved":true}))
        }
        "detach" => {
            for ue_id in ue_ids {
                let job = state
                    .multi_ue
                    .lock()
                    .map_err(|_| "UE_REGISTRY_UNAVAILABLE".to_string())?
                    .snapshot()
                    .into_iter()
                    .find(|job| job.ue_id == *ue_id)
                    .ok_or("UE_NOT_STARTED")?;
                state.ue_runtime.release_pdu(&job, 30, &control.cancel)?;
                state.ue_runtime.deregister_switch_off(&job)?;
                stop_one_live(state, ue_id)?;
                control
                    .started_ues
                    .lock()
                    .map_err(|_| "SCENARIO_RUNTIME_UNAVAILABLE".to_string())?
                    .remove(ue_id);
            }
            Ok(
                json!({"pdu_state":"INACTIVE","registration_state":"DEREGISTERED","process_state":"STOPPED"}),
            )
        }
        "ims_register" | "voice_call" => Err("IMS_NOT_AVAILABLE".into()),
        "repeat" => Err("SCENARIO_REPEAT_NOT_RESOLVED".into()),
        _ => Err("SCENARIO_STEP_TYPE_UNSUPPORTED".into()),
    }
}

fn cleanup_definition_started_ues(state: &AppState, control: &DefinitionJobControl) -> Vec<String> {
    let started = control
        .started_ues
        .lock()
        .map(|ids| ids.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let mut errors = Vec::new();
    for ue_id in started {
        if let Err(error) = stop_one_live(state, &ue_id) {
            errors.push(format!("{ue_id}:{error}"));
        } else if let Ok(mut ids) = control.started_ues.lock() {
            ids.remove(&ue_id);
        }
    }
    errors
}

fn execute_live_definition_job(
    state: Arc<AppState>,
    job_id: String,
    resolved: Vec<ResolvedStep>,
    ue_ids: Vec<String>,
    control: DefinitionJobControl,
) {
    let mut terminal_state = "COMPLETED";
    let mut terminal_result = "LIVE_COMPLETED".to_string();
    for (position, step) in resolved.iter().enumerate() {
        if control.cancel.load(Ordering::SeqCst) {
            terminal_state = "STOPPED";
            terminal_result = "OPERATOR_STOP".into();
            break;
        }
        let _ = update_definition_record(&state, &job_id, |record| {
            record["steps"][position]["state"] = json!("RUNNING");
            record["steps"][position]["started_at"] = json!(epoch_seconds());
        });
        match execute_live_definition_step(&state, step, &ue_ids, &control) {
            Ok(measurements) => {
                let _ = update_definition_record(&state, &job_id, |record| {
                    record["steps"][position]["state"] = json!("COMPLETED");
                    record["steps"][position]["ended_at"] = json!(epoch_seconds());
                    record["steps"][position]["measurements"] = measurements;
                });
            }
            Err(error) if error == "SCENARIO_STOP_REQUESTED" => {
                terminal_state = "STOPPED";
                terminal_result = "OPERATOR_STOP".into();
                let _ = update_definition_record(&state, &job_id, |record| {
                    record["steps"][position]["state"] = json!("FAILED");
                    record["steps"][position]["ended_at"] = json!(epoch_seconds());
                    record["steps"][position]["error"] = json!(error);
                });
                break;
            }
            Err(error) => {
                terminal_state = "FAILED";
                terminal_result = "STEP_FAILED".into();
                let _ = update_definition_record(&state, &job_id, |record| {
                    record["steps"][position]["state"] = json!("FAILED");
                    record["steps"][position]["ended_at"] = json!(epoch_seconds());
                    record["steps"][position]["error"] = json!(error);
                });
                break;
            }
        }
    }
    let cleanup_errors = if terminal_state == "COMPLETED" {
        Vec::new()
    } else {
        cleanup_definition_started_ues(&state, &control)
    };
    if !cleanup_errors.is_empty() {
        terminal_state = "FAILED";
        terminal_result = "UE_CLEANUP_FAILED".into();
    }
    let _ = update_definition_record(&state, &job_id, |record| {
        record["state"] = json!(terminal_state);
        record["ended_at_epoch_s"] = json!(epoch_seconds());
        record["terminal_result"] = json!(terminal_result);
        record["cleanup_errors"] = json!(cleanup_errors);
    });
    if let Ok(mut jobs) = state.definition_jobs.lock() {
        jobs.remove(&job_id);
    }
}

fn start_live_definition_scenario(
    state: Arc<AppState>,
    definition_id: &str,
    ue_ids: &[String],
) -> Result<Value, (StatusCode, Json<Value>)> {
    if !state.definition_live_enabled || state.execution_mode != "live" {
        return Err((
            StatusCode::LOCKED,
            Json(json!({"error":"SCENARIO_DEFINITION_LIVE_EXECUTION_NOT_AUTHORIZED"})),
        ));
    }
    if ue_ids.is_empty() || ue_ids.len() > ueransim_adapter::MAX_LIVE_UES {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error":"SCENARIO_UE_SELECTION_INVALID"})),
        ));
    }
    if ue_ids.iter().collect::<BTreeSet<_>>().len() != ue_ids.len() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error":"SCENARIO_UE_SELECTION_DUPLICATE"})),
        ));
    }
    let profiles = state.multi_ue.lock().unwrap().profiles();
    if ue_ids.iter().any(|ue_id| {
        !controller_owns_ue(&state, ue_id)
            || !profiles.iter().any(|profile| profile.ue_id == *ue_id)
    }) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error":"SCENARIO_UE_NOT_CONTROLLER_OWNED"})),
        ));
    }
    resource_gate(&state).map_err(|error| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(cpu_error_response(&state, &error)),
        )
    })?;
    let definition = state
        .scenario_catalog
        .lock()
        .unwrap()
        .definitions
        .iter()
        .find(|item| item.id == definition_id)
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error":"SCENARIO_DEFINITION_NOT_FOUND"})),
            )
        })?;
    let resolved = resolve_steps(&definition).map_err(scenario_definition_error)?;
    let job_id = format!("{}-{}", definition.id, random_hex(6));
    let steps = resolved
        .iter()
        .map(|step| {
            json!({
                "index":step.index,
                "type":step.step_type,
                "scenario_loop":{"iteration":step.scenario_loop_iteration,"count":step.scenario_loop_count},
                "step_loop":{"iteration":step.step_loop_iteration,"count":step.step_loop_count},
                "state":"PENDING","started_at":Value::Null,"ended_at":Value::Null,
                "error":Value::Null,"resolved_parameters":step.parameters
            })
        })
        .collect::<Vec<_>>();
    let record = json!({
        "job_id":job_id,"scenario_id":definition.id,"scenario_definition_id":definition.id,
        "scenario_definition_version":definition.version,"ue_ids":ue_ids,"state":"RUNNING",
        "traffic_state":"PENDING","started_at_epoch_s":epoch_seconds(),
        "ended_at_epoch_s":Value::Null,"terminal_result":Value::Null,"steps":steps
    });
    let control = DefinitionJobControl {
        cancel: Arc::new(AtomicBool::new(false)),
        started_ues: Arc::new(Mutex::new(BTreeSet::new())),
    };
    {
        let mut jobs = state.definition_jobs.lock().unwrap();
        if !jobs.is_empty() {
            return Err((
                StatusCode::CONFLICT,
                Json(json!({"error":"SCENARIO_CONFLICT"})),
            ));
        }
        jobs.insert(job_id.clone(), control.clone());
    }
    {
        let mut runtime = state.runtime.lock().unwrap();
        runtime.history.push(record.clone());
        persist_runtime(&state, &runtime);
    }
    let worker_state = state.clone();
    let worker_job_id = job_id.clone();
    let worker_ues = ue_ids.to_vec();
    std::thread::spawn(move || {
        execute_live_definition_job(worker_state, worker_job_id, resolved, worker_ues, control)
    });
    Ok(record)
}

async fn start_scenario(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    Json(input): Json<StartScenarioInput>,
) -> impl IntoResponse {
    if !matches!(identity.role.as_str(), "operator" | "administrator") {
        let audit_id = input
            .scenario_definition_id
            .as_deref()
            .or(input.scenario_id.as_deref());
        audit(
            &state,
            &identity.role,
            "START_SCENARIO",
            "DENIED_ROLE",
            audit_id,
        );
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"OPERATOR_PERMISSION_REQUIRED"})),
        );
    }
    if !identity.csrf_valid {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"CSRF_TOKEN_REQUIRED"})),
        );
    }
    if let Some(definition_id) = input.scenario_definition_id.as_deref() {
        let definition = state
            .scenario_catalog
            .lock()
            .unwrap()
            .definitions
            .iter()
            .find(|item| item.id == definition_id)
            .cloned();
        let Some(definition) = definition else {
            return scenario_definition_error("SCENARIO_DEFINITION_NOT_FOUND".into());
        };
        let resolved = match resolve_steps(&definition) {
            Ok(value) => value,
            Err(error) => return scenario_definition_error(error),
        };
        if resolved
            .iter()
            .any(|step| matches!(step.step_type.as_str(), "ims_register" | "voice_call"))
        {
            return (
                StatusCode::LOCKED,
                Json(json!({"error":"IMS_NOT_AVAILABLE"})),
            );
        }
        if resolved.iter().any(|step| step.step_type == "traffic_dl") {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error":"DL_SENDER_NOT_AVAILABLE"})),
            );
        }
        let outcome = if state.execution_mode == "mock" {
            run_mock_definition_scenario(&state, definition_id, &input.ue_ids)
        } else {
            start_live_definition_scenario(state.clone(), definition_id, &input.ue_ids)
        };
        return match outcome {
            Ok(record) => (StatusCode::OK, Json(record)),
            Err(error) => error,
        };
    }
    let Some(scenario_id) = input.scenario_id.as_deref() else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error":"SCENARIO_ID_REQUIRED"})),
        );
    };
    let Some(scenario_type) = input.scenario_type.as_deref() else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error":"SCENARIO_TYPE_REQUIRED"})),
        );
    };
    let requested_target = input.target_ue_id.clone().unwrap_or_else(|| "UE-01".into());
    let scenario_target_valid = match scenario_type {
        "bounded-existing-ue-udp-v1" => requested_target == "UE-01" && !state.ue01_controller_owned,
        "bounded-controller-ue-udp-v1" => controller_owns_ue(&state, &requested_target),
        _ => false,
    };
    if !scenario_target_valid
        || !valid_job_id(scenario_id)
        || !state.policy_enabled.load(Ordering::SeqCst)
    {
        audit(
            &state,
            &identity.role,
            "START_SCENARIO",
            "DENIED_POLICY",
            Some(scenario_id),
        );
        return (
            StatusCode::LOCKED,
            Json(json!({"error":"SCENARIO_NOT_CERTIFIED"})),
        );
    }
    let validated = identity.session_id.as_ref().is_some_and(|session_id| {
        state
            .sessions
            .lock()
            .ok()
            .and_then(|sessions| {
                let session = sessions.get(session_id)?;
                Some(
                    session
                        .certified_validation_until
                        .is_some_and(|deadline| deadline >= epoch_seconds())
                        && session.certified_scenario_type.as_deref() == Some(scenario_type)
                        && session.certified_target_ue_id.as_deref()
                            == Some(requested_target.as_str()),
                )
            })
            .unwrap_or(false)
    });
    if !validated {
        return (
            StatusCode::PRECONDITION_REQUIRED,
            Json(json!({"error":"CERTIFIED_SCENARIO_VALIDATION_REQUIRED"})),
        );
    }
    let mut runtime = state.runtime.lock().unwrap();
    if refresh_runtime_with_state(&state, &mut runtime) {
        persist_runtime(&state, &runtime);
    }
    if let Some(previous) = runtime
        .history
        .iter()
        .find(|item| item["job_id"] == scenario_id)
    {
        if previous["target_ue_id"].as_str() != Some(requested_target.as_str()) {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error":"OWNERSHIP_TARGET_MISMATCH"})),
            );
        }
        let mut response = previous.clone();
        response["idempotent"] = json!(true);
        return (StatusCode::OK, Json(response));
    }
    if let Some(active) = runtime.active.as_ref() {
        if active.job_id == scenario_id {
            return (StatusCode::OK, Json(job_json(active)));
        }
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"SCENARIO_CONFLICT","active_job_id":active.job_id})),
        );
    }
    if let Err(error) = resource_gate(&state) {
        audit(
            &state,
            &identity.role,
            "START_SCENARIO",
            &error,
            Some(scenario_id),
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(cpu_error_response(&state, &error)),
        );
    }
    let target = if requested_target == "UE-01" && !state.ue01_controller_owned {
        let pid = if state.execution_mode == "live" {
            match DockerUeRuntime::namespace_pid("oiran-lab-ueransim-ue-1") {
                Ok(pid) => pid,
                Err(error) => {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({"error":error})),
                    )
                }
            }
        } else {
            0
        };
        VerifiedTrafficTarget {
            ue_id: "UE-01".into(),
            pseudonym: "UE-PSEUDONYM-01".into(),
            namespace_pid: pid,
            tun_interface: "SHARED_UE_COMPATIBILITY_PATH".into(),
            ue_ip: "OBSERVED_AT_RUNTIME".into(),
        }
    } else {
        match resolve_controller_traffic_target(&state, &requested_target) {
            Ok(target) => target,
            Err(error) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({"error":error})),
                )
            }
        }
    };
    let mut child = if state.execution_mode == "live" {
        match Command::new("/usr/bin/nsenter")
            .args([
                "--target",
                &target.namespace_pid.to_string(),
                "--net",
                "--",
                "/usr/bin/bash",
                "-lc",
                TRAFFIC_EXECUTION_COMMAND,
            ])
            .spawn()
        {
            Ok(child) => Some(child),
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error":"TRAFFIC_PROCESS_SPAWN_FAILED"})),
                )
            }
        }
    } else if state.execution_mode == "mock" {
        None
    } else {
        return (
            StatusCode::LOCKED,
            Json(json!({"error":"LIVE_EXECUTION_NOT_CONFIGURED"})),
        );
    };
    if controller_owns_ue(&state, &target.ue_id) {
        let traffic_state = state
            .multi_ue
            .lock()
            .map_err(|_| "UE_REGISTRY_UNAVAILABLE".to_string())
            .and_then(|mut controller| {
                controller.set_traffic(&target.ue_id, "RUNNING")?;
                persist_ue_registry(&state, &controller)
            });
        if let Err(error) = traffic_state {
            if let Some(process) = child.as_mut() {
                let _ = process.kill();
                let _ = process.wait();
            }
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":error})),
            );
        }
    }
    let process_id = child.as_ref().map(Child::id);
    runtime.active = Some(OwnedScenarioJob {
        job_id: scenario_id.to_string(),
        started_at: epoch_seconds(),
        started_at_epoch_ms: epoch_millis(),
        ended_at: None,
        ended_at_epoch_ms: None,
        state: "RUNNING".into(),
        child,
        process_id,
        packets_requested: TRAFFIC_PACKET_COUNT,
        packets_sent: None,
        packets_received: None,
        bytes_sent: None,
        bytes_received: None,
        terminal_result: None,
        target_ue_id: target.ue_id,
        target_ue_pseudonym: target.pseudonym,
        tun_interface: (target.tun_interface != "SHARED_UE_COMPATIBILITY_PATH")
            .then_some(target.tun_interface),
    });
    persist_runtime(&state, &runtime);
    audit(
        &state,
        &identity.role,
        "START_SCENARIO",
        "RUNNING",
        Some(scenario_id),
    );
    (
        StatusCode::OK,
        Json(job_json(runtime.active.as_ref().unwrap())),
    )
}

#[derive(Deserialize)]
struct StopScenarioInput {
    job_id: String,
}

async fn stop_scenario(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    Json(input): Json<StopScenarioInput>,
) -> impl IntoResponse {
    if !matches!(identity.role.as_str(), "operator" | "administrator") {
        audit(
            &state,
            &identity.role,
            "STOP_SCENARIO",
            "DENIED_ROLE",
            Some(&input.job_id),
        );
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"OPERATOR_PERMISSION_REQUIRED"})),
        );
    }
    if !identity.csrf_valid {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"CSRF_TOKEN_REQUIRED"})),
        );
    }
    let definition_control = state
        .definition_jobs
        .lock()
        .ok()
        .and_then(|jobs| jobs.get(&input.job_id).cloned());
    if let Some(control) = definition_control {
        control.cancel.store(true, Ordering::SeqCst);
        let response = update_definition_record(&state, &input.job_id, |record| {
            record["state"] = json!("STOPPING");
            record["terminal_result"] = json!("OPERATOR_STOP_REQUESTED");
        })
        .unwrap_or_else(|_| json!({"job_id":input.job_id,"state":"STOPPING"}));
        audit(
            &state,
            &identity.role,
            "STOP_SCENARIO_DEFINITION",
            "STOPPING",
            Some(&input.job_id),
        );
        return (StatusCode::OK, Json(response));
    }
    let mut runtime = state.runtime.lock().unwrap();
    if refresh_runtime_with_state(&state, &mut runtime) {
        persist_runtime(&state, &runtime);
    }
    let Some(mut job) = runtime.active.take() else {
        let terminal = runtime
            .history
            .iter()
            .find(|item| item["job_id"] == input.job_id)
            .cloned();
        return if let Some(mut terminal) = terminal {
            terminal["idempotent"] = json!(true);
            (StatusCode::OK, Json(terminal))
        } else {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error":"JOB_NOT_FOUND"})),
            )
        };
    };
    if job.job_id != input.job_id {
        runtime.active = Some(job);
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"OWNERSHIP_TARGET_MISMATCH"})),
        );
    }
    job.state = "STOPPING".into();
    if let Some(child) = job.child.as_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
    job.state = "STOPPED".into();
    job.ended_at = Some(epoch_seconds());
    job.terminal_result = Some("OPERATOR_STOP".into());
    if controller_owns_ue(&state, &job.target_ue_id) {
        if let Ok(mut controller) = state.multi_ue.lock() {
            if controller.set_traffic(&job.target_ue_id, "STOPPED").is_ok() {
                let _ = persist_ue_registry(&state, &controller);
            }
        }
    }
    let value = job_json(&job);
    runtime.history.push(value.clone());
    persist_runtime(&state, &runtime);
    audit(
        &state,
        &identity.role,
        "STOP_SCENARIO",
        "STOPPED",
        Some(&input.job_id),
    );
    (StatusCode::OK, Json(value))
}

#[derive(Deserialize)]
struct PolicyInput {
    enabled: bool,
}

async fn update_policy(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    Json(input): Json<PolicyInput>,
) -> impl IntoResponse {
    if identity.role != "administrator" {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"ADMINISTRATOR_PERMISSION_REQUIRED"})),
        );
    }
    if !identity.csrf_valid {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"CSRF_TOKEN_REQUIRED"})),
        );
    }
    state.policy_enabled.store(input.enabled, Ordering::SeqCst);
    if let Some(parent) = state.policy_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if fs::write(
        &state.policy_path,
        json!({"enabled":input.enabled}).to_string(),
    )
    .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"POLICY_PERSISTENCE_FAILED"})),
        );
    }
    audit(
        &state,
        &identity.role,
        "UPDATE_SCENARIO_POLICY",
        if input.enabled { "ENABLED" } else { "DISABLED" },
        None,
    );
    (
        StatusCode::OK,
        Json(json!({"scenario_type":"bounded-existing-ue-udp-v1","enabled":input.enabled})),
    )
}

fn live_record() -> &'static Mutex<Option<Value>> {
    LIVE_RECORD.get_or_init(|| Mutex::new(None))
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn container_is_healthy(name: &str) -> bool {
    let status = container_status(name);
    status["process_state"] == "running" && status["health"] == "healthy"
}

async fn live_test_status() -> Json<Value> {
    let record = live_record()
        .lock()
        .ok()
        .and_then(|value| value.clone())
        .or_else(|| {
            fs::read_to_string(LIVE_RESULT_PATH)
                .ok()
                .and_then(|value| serde_json::from_str(&value).ok())
        });
    let consumed = LIVE_APPROVAL_CONSUMED.load(Ordering::SeqCst) || record.is_some();
    Json(json!({
        "test_id": LIVE_TEST_ID,
        "running": LIVE_RUNNING.load(Ordering::SeqCst),
        "approval_present": Path::new(LIVE_APPROVAL_PATH).exists(),
        "approval_consumed": consumed,
        "generic_live_control": false,
        "record": record
    }))
}

#[derive(Deserialize)]
struct ValidateInput {
    scenario_id: String,
    name: String,
    ue_count: u8,
    start_mode: String,
    stagger_seconds: u8,
    protocol: String,
    destination: String,
    packet_count: u16,
    packet_size: u16,
    rate_per_second: u16,
    duration_seconds: u16,
    #[serde(default)]
    target_ue_id: Option<String>,
}

fn resolve_controller_traffic_target(
    state: &AppState,
    ue_id: &str,
) -> Result<VerifiedTrafficTarget, String> {
    if !controller_owns_ue(state, ue_id) {
        return Err("SHARED_UE_TRAFFIC_TARGET_FORBIDDEN".into());
    }
    let job = state
        .multi_ue
        .lock()
        .map_err(|_| "UE_REGISTRY_UNAVAILABLE".to_string())?
        .snapshot()
        .into_iter()
        .find(|job| job.ue_id == ue_id)
        .ok_or("UE_NOT_RUNNING")?;
    if !job.controller_owned
        || job.process_state != "RUNNING"
        || job.registration_state != "REGISTERED"
        || job.pdu_session_state != "ACTIVE"
        || job.process_handle.is_none()
        || job.ue_ip.is_none()
    {
        return Err("UE_TRAFFIC_PREREQUISITES_NOT_MET".into());
    }
    state.ue_runtime.resolve_traffic_target(&job, "10.46.0.1")
}

async fn validate_scenario(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<EffectiveIdentity>,
    Json(input): Json<ValidateInput>,
) -> impl IntoResponse {
    if !matches!(identity.role.as_str(), "operator" | "administrator") {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"valid":false,"error":"OPERATOR_PERMISSION_REQUIRED"})),
        );
    }
    if !identity.csrf_valid {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"valid":false,"error":"CSRF_TOKEN_REQUIRED"})),
        );
    }
    let exact_certified_profile = input.ue_count == 1
        && input.start_mode == "SEQUENTIAL"
        && input.stagger_seconds == 0
        && input.protocol == "UDP"
        && input.destination == "10.46.0.1"
        && input.packet_count == 5
        && input.packet_size == 64
        && input.rate_per_second == 1
        && input.duration_seconds == 5;
    if !exact_certified_profile {
        return (
            StatusCode::LOCKED,
            Json(json!({"valid":false,"error":"SCENARIO_NOT_CERTIFIED"})),
        );
    }
    use scenario_engine::{Scenario, StartMode, State as ScenarioState};
    use traffic_engine::{Profile, Protocol};
    let mode = match input.start_mode.as_str() {
        "SEQUENTIAL" => StartMode::Sequential,
        "CONCURRENT" => StartMode::Concurrent,
        _ => StartMode::Staggered,
    };
    let protocol = match input.protocol.as_str() {
        "ICMP" => Protocol::Icmp,
        "TCP" => Protocol::Tcp,
        _ => Protocol::Udp,
    };
    let destination = match input.destination.parse() {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"valid":false,"error":"INVALID_DESTINATION"})),
            )
        }
    };
    let scenario = Scenario {
        scenario_id: input.scenario_id,
        name: input.name,
        ue_count: input.ue_count,
        start_mode: mode,
        stagger_seconds: input.stagger_seconds,
        traffic: Profile {
            protocol,
            destination,
            packet_count: input.packet_count,
            packet_size: input.packet_size,
            rate_per_second: input.rate_per_second,
            duration_seconds: input.duration_seconds,
        },
        state: ScenarioState::Draft,
    };
    match scenario_engine::validate(&scenario)
        .and_then(|_| traffic_engine::validate(&scenario.traffic, &["10.46.0.1".parse().unwrap()]))
    {
        Ok(()) => {
            let target_ue_id = input.target_ue_id.unwrap_or_else(|| "UE-01".into());
            let scenario_type = if target_ue_id == "UE-01" && !state.ue01_controller_owned {
                "bounded-existing-ue-udp-v1"
            } else {
                if let Err(error) = resolve_controller_traffic_target(&state, &target_ue_id) {
                    return (
                        StatusCode::LOCKED,
                        Json(json!({"valid":false,"error":error})),
                    );
                }
                "bounded-controller-ue-udp-v1"
            };
            if let Some(session_id) = identity.session_id {
                if let Ok(mut sessions) = state.sessions.lock() {
                    if let Some(session) = sessions.get_mut(&session_id) {
                        session.certified_validation_until = Some(epoch_seconds() + 5 * 60);
                        session.certified_scenario_type = Some(scenario_type.into());
                        session.certified_target_ue_id = Some(target_ue_id.clone());
                    }
                }
            }
            (
                StatusCode::OK,
                Json(
                    json!({"valid":true,"execution":"NOT_EXECUTED","next":"certified Start is authorized for five minutes","scenario_type":scenario_type,"target_ue_id":target_ue_id}),
                ),
            )
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"valid":false,"error":e})),
        ),
    }
}

pub fn api_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/capabilities", get(capabilities))
        .route(
            "/configuration",
            get(get_configuration).post(apply_configuration),
        )
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
        .route("/system/health", get(system))
        .route("/system/cpu-decisions", get(cpu_decisions))
        .route("/lab", get(lab))
        .route("/nodes", get(nodes))
        .route("/ues", get(ues))
        .route("/gnbs", get(list_gnbs))
        .route(
            "/ue-profiles",
            get(list_ue_profiles).post(create_ue_profile),
        )
        .route("/ue-profiles/bulk", post(bulk_create_ue_profiles))
        .route(
            "/ue-profiles/provisioning-slots",
            get(list_provisioning_slots),
        )
        .route("/ue-profiles/export.csv", get(export_ue_profiles_csv))
        .route(
            "/ue-profiles/:ue_id",
            put(update_ue_profile).delete(delete_ue_profile),
        )
        .route("/ue-profiles/:ue_id/clone", post(clone_ue_profile))
        .route(
            "/ue-profiles/:ue_id/validate-provisioning",
            post(validate_ue_profile_provisioning),
        )
        .route("/ues/legacy/discovery", get(discover_legacy_ues))
        .route(
            "/ues/legacy/migration/preview",
            post(preview_legacy_migration),
        )
        .route(
            "/ues/legacy/migration/execute",
            post(execute_legacy_migration),
        )
        .route("/ues/control/validate", post(validate_ue_control))
        .route("/ues/start", post(start_ue))
        .route("/ues/stop", post(stop_ue))
        .route("/ues/group/start", post(start_ue_group))
        .route("/ues/group/stop", post(stop_ue_group))
        .route("/traffic/status", get(traffic_status))
        .route("/live-tests/polaris-live-001", get(live_test_status))
        .route("/scenario-capabilities", get(scenario_capabilities))
        .route("/admin/scenario-policy", post(update_policy))
        .route("/scenarios", get(scenarios))
        .route(
            "/scenario-definitions",
            get(list_scenario_definitions).post(create_scenario_definition),
        )
        .route(
            "/scenario-definitions/:id",
            get(get_scenario_definition)
                .put(update_scenario_definition)
                .delete(delete_scenario_definition),
        )
        .route(
            "/scenario-definitions/:id/clone",
            post(clone_scenario_definition),
        )
        .route(
            "/scenario-definitions/:id/estimate",
            get(estimate_scenario_definition),
        )
        .route(
            "/scenario-definitions/:id/export",
            get(export_scenario_definition),
        )
        .route(
            "/scenario-definitions/import",
            post(import_scenario_definition),
        )
        .route("/scenarios/running", get(scenarios))
        .route("/scenarios/status", get(scenario_status))
        .route("/scenarios/history", get(history))
        .route("/scenarios/:job_id/steps", get(scenario_steps))
        .route("/scenarios/validate", post(validate_scenario))
        .route("/scenarios/start", post(start_scenario))
        .route("/scenarios/stop", post(stop_scenario))
        .route_layer(middleware::from_fn_with_state(state.clone(), authorize))
        .with_state(state)
}

pub fn app(state: AppState) -> Router {
    let shared = Arc::new(state);
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        let monitor = shared.cpu_safety.clone();
        handle.spawn(async move {
            loop {
                let interval = {
                    let mut monitor = monitor
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    monitor.refresh();
                    monitor.sample_interval()
                };
                tokio::time::sleep(interval).await;
            }
        });
    }
    if shared.startup_reconcile
        && shared.execution_mode == "live"
        && shared.additional_ue_live_enabled
        && shared
            .ue_reconciliation_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        let recovery_state = shared.clone();
        let desired_count = recovery_state.configuration.lock().unwrap().ue_count;
        *recovery_state.ue_reconciliation.lock().unwrap() = UeReconciliation {
            operation_id: Some(random_hex(16)),
            desired_count,
            state: "RUNNING".into(),
            started_at_epoch_s: Some(epoch_seconds()),
            completed_at_epoch_s: None,
            started: Vec::new(),
            stopped: Vec::new(),
            failures: Vec::new(),
        };
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn_blocking(move || {
                let profiles = recovery_state.multi_ue.lock().unwrap().profiles();
                match recovery_state.ue_runtime.verify_provisioning(&profiles) {
                    Ok(verified) => {
                        reconcile_ue_count(recovery_state.clone(), desired_count, verified)
                    }
                    Err(error) => {
                        let mut status = recovery_state.ue_reconciliation.lock().unwrap();
                        status.state = "FAILED".into();
                        status.failures.push(("PROVISIONING".into(), error));
                        status.completed_at_epoch_s = Some(epoch_seconds());
                        recovery_state
                            .ue_reconciliation_running
                            .store(false, Ordering::Release);
                    }
                }
            });
        } else {
            shared
                .ue_reconciliation_running
                .store(false, Ordering::Release);
        }
    }
    let fallback = ServeFile::new(shared.static_dir.join("index.html"));
    let static_service = ServeDir::new(shared.static_dir.clone()).not_found_service(fallback);
    Router::new()
        .nest("/api/v1", api_router(shared))
        .fallback_service(static_service)
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
}

#[cfg(test)]
mod p0_tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    use tower::ServiceExt;

    const OPERATOR_PASSWORD: &str = "operator-test-password-2026";
    const ADMIN_PASSWORD: &str = "administrator-test-password-2026";
    static TEST_ID: AtomicU64 = AtomicU64::new(1);

    struct FakeLiveUeRuntime {
        stopped: Arc<Mutex<Vec<String>>>,
        launched: Arc<Mutex<Vec<String>>>,
        fail_observation: bool,
        fail_verification: bool,
        fail_stop: bool,
    }

    impl FakeLiveUeRuntime {
        fn observation(ip: &str) -> UeObservation {
            UeObservation {
                process_state: "RUNNING".into(),
                registration_state: "REGISTERED".into(),
                pdu_session_state: "ACTIVE".into(),
                ue_ip: Some(ip.into()),
            }
        }

        fn approval(profile: &UeProfileSpec, profile_sha256: &str) -> LiveLaunchSpec {
            LiveLaunchSpec {
                ue_id: profile.ue_id.clone(),
                profile_basename: profile.profile_name.clone(),
                container_name: format!("polaris-control-{}", profile.ue_id.to_ascii_lowercase()),
                owner_id: "b".repeat(64),
                profile_sha256: profile_sha256.into(),
                script_sha256: "c".repeat(64),
                image_id: format!("sha256:{}", "d".repeat(64)),
                docker_args: Vec::new(),
            }
        }
    }

    impl UeRuntime for FakeLiveUeRuntime {
        fn verify_provisioning(
            &self,
            profiles: &[UeProfileSpec],
        ) -> Result<BTreeMap<String, String>, String> {
            if self.fail_verification {
                return Err("PROVISIONED_PROFILE_UNAVAILABLE".into());
            }
            Ok(profiles
                .iter()
                .filter(|profile| profile.configured)
                .map(|profile| (profile.ue_id.clone(), "a".repeat(64)))
                .collect())
        }

        fn approve_launch(
            &self,
            profile: &UeProfileSpec,
            profile_sha256: &str,
        ) -> Result<LiveLaunchSpec, String> {
            Ok(Self::approval(profile, profile_sha256))
        }

        fn launch(&self, spec: &LiveLaunchSpec) -> Result<String, UeLaunchFailure> {
            self.launched.lock().unwrap().push(spec.ue_id.clone());
            let digit = spec.ue_id.chars().last().unwrap_or('0');
            Ok(format!("container:{}", digit.to_string().repeat(64)))
        }

        fn discover(&self, spec: &LiveLaunchSpec) -> Result<Option<String>, String> {
            Ok(self
                .launched
                .lock()
                .unwrap()
                .contains(&spec.ue_id)
                .then(|| {
                    let digit = spec.ue_id.chars().last().unwrap_or('0');
                    format!("container:{}", digit.to_string().repeat(64))
                }))
        }

        fn observe_owned(&self, spec: &LiveLaunchSpec, _: &str) -> Result<UeObservation, String> {
            if self.fail_observation {
                return Err("INJECTED_OBSERVATION_FAILURE".into());
            }
            if self
                .stopped
                .lock()
                .unwrap()
                .contains(&format!("PDU_RELEASED:{}", spec.ue_id))
            {
                return Ok(UeObservation {
                    process_state: "RUNNING".into(),
                    registration_state: "REGISTERED".into(),
                    pdu_session_state: "INACTIVE".into(),
                    ue_ip: None,
                });
            }
            Ok(Self::observation(if spec.ue_id == "UE-02" {
                "10.46.0.5"
            } else {
                "10.46.0.6"
            }))
        }

        fn observe_shared(&self) -> Result<UeObservation, String> {
            Ok(Self::observation("10.46.0.4"))
        }

        fn owns(&self, spec: &LiveLaunchSpec, handle: &str) -> bool {
            ueransim_adapter::is_approved_controller_ue(&spec.ue_id)
                && handle.starts_with("container:")
        }

        fn stop(&self, spec: &LiveLaunchSpec, _: &str) -> Result<(), String> {
            self.stopped.lock().unwrap().push(spec.ue_id.clone());
            if self.fail_stop {
                Err("INJECTED_STOP_FAILURE".into())
            } else {
                Ok(())
            }
        }

        fn establish_pdu(
            &self,
            job: &simulator_controller::UeJob,
            _: &UeProfileSpec,
            _: u64,
            _: &AtomicBool,
        ) -> Result<(), String> {
            self.stopped
                .lock()
                .unwrap()
                .retain(|item| item != &format!("PDU_RELEASED:{}", job.ue_id));
            Ok(())
        }

        fn release_pdu(
            &self,
            job: &simulator_controller::UeJob,
            _: u64,
            _: &AtomicBool,
        ) -> Result<(), String> {
            self.stopped
                .lock()
                .unwrap()
                .push(format!("PDU_RELEASED:{}", job.ue_id));
            Ok(())
        }

        fn resolve_traffic_target(
            &self,
            job: &simulator_controller::UeJob,
            destination: &str,
        ) -> Result<VerifiedTrafficTarget, String> {
            if destination != "10.46.0.1"
                || !job.controller_owned
                || !ueransim_adapter::is_approved_controller_ue(&job.ue_id)
                || job.process_state != "RUNNING"
                || job.registration_state != "REGISTERED"
                || job.pdu_session_state != "ACTIVE"
                || job.process_handle.is_none()
            {
                return Err("UE_TRAFFIC_PREREQUISITES_NOT_MET".into());
            }
            Ok(VerifiedTrafficTarget {
                ue_id: job.ue_id.clone(),
                pseudonym: job.pseudonym.clone(),
                namespace_pid: 4242,
                tun_interface: format!(
                    "uesimtun{}",
                    job.ue_id
                        .trim_start_matches("UE-")
                        .parse::<u8>()
                        .unwrap_or(0)
                ),
                ue_ip: job.ue_ip.clone().ok_or("UE_IP_NOT_VERIFIED")?,
            })
        }

        fn execute_bounded_udp(&self, _: &VerifiedTrafficTarget) -> Result<(), String> {
            Ok(())
        }
    }

    struct PostRunInspectionFailureRuntime {
        handle: String,
        stop_attempts: Arc<Mutex<usize>>,
    }

    impl UeRuntime for PostRunInspectionFailureRuntime {
        fn verify_provisioning(
            &self,
            profiles: &[UeProfileSpec],
        ) -> Result<BTreeMap<String, String>, String> {
            Ok(profiles
                .iter()
                .filter(|profile| profile.configured)
                .map(|profile| (profile.ue_id.clone(), "a".repeat(64)))
                .collect())
        }

        fn approve_launch(
            &self,
            profile: &UeProfileSpec,
            profile_sha256: &str,
        ) -> Result<LiveLaunchSpec, String> {
            Ok(FakeLiveUeRuntime::approval(profile, profile_sha256))
        }

        fn launch(&self, _: &LiveLaunchSpec) -> Result<String, UeLaunchFailure> {
            Err(UeLaunchFailure::after_launch(
                "DOCKER_COMMAND_FAILED".into(),
                self.handle.clone(),
            ))
        }

        fn discover(&self, _: &LiveLaunchSpec) -> Result<Option<String>, String> {
            Ok(Some(self.handle.clone()))
        }

        fn observe_owned(&self, _: &LiveLaunchSpec, _: &str) -> Result<UeObservation, String> {
            Err("DOCKER_COMMAND_FAILED".into())
        }

        fn observe_shared(&self) -> Result<UeObservation, String> {
            Ok(FakeLiveUeRuntime::observation("10.46.0.4"))
        }

        fn owns(&self, _: &LiveLaunchSpec, _: &str) -> bool {
            false
        }

        fn stop(&self, _: &LiveLaunchSpec, _: &str) -> Result<(), String> {
            *self.stop_attempts.lock().unwrap() += 1;
            Err("LIVE_UE_OWNERSHIP_NOT_PROVEN".into())
        }
    }

    struct ThreadRecordingRuntime {
        verification_thread: Arc<Mutex<Option<std::thread::ThreadId>>>,
    }

    impl UeRuntime for ThreadRecordingRuntime {
        fn verify_provisioning(
            &self,
            profiles: &[UeProfileSpec],
        ) -> Result<BTreeMap<String, String>, String> {
            *self.verification_thread.lock().unwrap() = Some(std::thread::current().id());
            Ok(profiles
                .iter()
                .filter(|profile| profile.configured)
                .map(|profile| (profile.ue_id.clone(), "a".repeat(64)))
                .collect())
        }

        fn approve_launch(
            &self,
            profile: &UeProfileSpec,
            profile_sha256: &str,
        ) -> Result<LiveLaunchSpec, String> {
            Ok(FakeLiveUeRuntime::approval(profile, profile_sha256))
        }

        fn launch(&self, spec: &LiveLaunchSpec) -> Result<String, UeLaunchFailure> {
            let digit = spec.ue_id.chars().last().unwrap_or('0');
            Ok(format!("container:{}", digit.to_string().repeat(64)))
        }

        fn discover(&self, _: &LiveLaunchSpec) -> Result<Option<String>, String> {
            Ok(None)
        }

        fn observe_owned(&self, _: &LiveLaunchSpec, _: &str) -> Result<UeObservation, String> {
            Ok(FakeLiveUeRuntime::observation("10.46.0.5"))
        }

        fn observe_shared(&self) -> Result<UeObservation, String> {
            Ok(FakeLiveUeRuntime::observation("10.46.0.4"))
        }

        fn owns(&self, _: &LiveLaunchSpec, handle: &str) -> bool {
            handle.starts_with("container:")
        }

        fn stop(&self, _: &LiveLaunchSpec, _: &str) -> Result<(), String> {
            Ok(())
        }
    }

    fn process_job(exit_code: i32) -> OwnedScenarioJob {
        let child = Command::new("/bin/sh")
            .args(["-c", &format!("exit {exit_code}")])
            .spawn()
            .unwrap();
        OwnedScenarioJob {
            job_id: format!("process-job-{exit_code}"),
            started_at: epoch_seconds(),
            started_at_epoch_ms: epoch_millis(),
            ended_at: None,
            ended_at_epoch_ms: None,
            state: "RUNNING".into(),
            process_id: Some(child.id()),
            child: Some(child),
            packets_requested: 5,
            packets_sent: None,
            packets_received: None,
            bytes_sent: None,
            bytes_received: None,
            terminal_result: None,
            target_ue_id: "UE-01".into(),
            target_ue_pseudonym: "UE-PSEUDONYM-01".into(),
            tun_interface: None,
        }
    }

    fn await_terminal(runtime: &mut ControlRuntime) {
        for _ in 0..100 {
            let _ = refresh_runtime(runtime);
            if runtime.active.is_none() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("test process did not reach a terminal state");
    }

    fn state() -> AppState {
        let id = TEST_ID.fetch_add(1, AtomicOrdering::Relaxed);
        let root = PathBuf::from(format!(
            "/root/.hermes/cache/scratch/polaris-control-p0-{}-{id}",
            std::process::id()
        ));
        let users_path = root.join("users.json");
        provision_user(&users_path, "operator-test", "operator", OPERATOR_PASSWORD).unwrap();
        provision_user(
            &users_path,
            "administrator-test",
            "administrator",
            ADMIN_PASSWORD,
        )
        .unwrap();
        let mut profiles = ueransim_adapter::planned_profiles();
        profiles
            .iter_mut()
            .for_each(|profile| profile.subscription_verified = true);
        let now = epoch_seconds();
        let profile_registry = UeProfileRegistry {
            schema_version: 1,
            profiles: profiles
                .iter()
                .cloned()
                .map(|profile| ManagedUeProfile {
                    profile,
                    subscriber_identity_sha256: "0".repeat(64),
                    scenario_id: None,
                    auto_run_scenario: false,
                    revision: 1,
                    created_at_epoch_s: now,
                    updated_at_epoch_s: now,
                })
                .collect(),
        };
        AppState {
            storage_path: "/root/POLARIS_CONTROL".into(),
            static_dir: root.join("no-web"),
            users_path,
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
            audit_path: root.join("audit.jsonl"),
            job_state_path: root.join("jobs.json"),
            ue_job_state_path: root.join("ue-jobs.json"),
            cpu_decision_path: root.join("cpu-decisions.json"),
            cpu_decision_lock: Arc::new(Mutex::new(())),
            latest_cpu_decision: Arc::new(Mutex::new(None)),
            configuration_path: root.join("configuration.json"),
            profile_store: ProfileStore::new(
                root.join("ue-profile-registry.json"),
                root.join("ue-profiles"),
            ),
            profile_registry: Arc::new(Mutex::new(profile_registry)),
            scenario_definition_store: ScenarioDefinitionStore::new(
                root.join("scenario-definitions.json"),
            ),
            scenario_catalog: Arc::new(Mutex::new(ScenarioCatalog::default())),
            definition_live_enabled: false,
            definition_jobs: Arc::new(Mutex::new(BTreeMap::new())),
            policy_path: root.join("policy.json"),
            policy_enabled: Arc::new(AtomicBool::new(true)),
            execution_mode: "mock".into(),
            additional_ue_live_enabled: false,
            ue01_controller_owned: false,
            ue_runtime: Arc::new(FakeLiveUeRuntime {
                stopped: Arc::new(Mutex::new(Vec::new())),
                launched: Arc::new(Mutex::new(Vec::new())),
                fail_observation: false,
                fail_verification: false,
                fail_stop: false,
            }),
            resource_override: Some(Ok(())),
            cpu_safety: Arc::new(Mutex::new(CpuSafetyMonitor::default())),
            runtime: Arc::new(Mutex::new(ControlRuntime {
                active: None,
                history: Vec::new(),
            })),
            multi_ue: Arc::new(Mutex::new(
                MultiUeController::new(profiles, ueransim_adapter::MAX_LIVE_UES).unwrap(),
            )),
            configuration: Arc::new(Mutex::new(DesiredConfiguration::default())),
            ue_operations: Arc::new(Mutex::new(())),
            ue_inventory_running: Arc::new(AtomicBool::new(false)),
            ue_inventory_last_observed_epoch_s: Arc::new(AtomicU64::new(0)),
            ue_inventory_cache_version: Arc::new(AtomicU64::new(0)),
            shared_ue_cache: Arc::new(Mutex::new(None)),
            ue_reconciliation_running: Arc::new(AtomicBool::new(false)),
            ue_reconciliation: Arc::new(Mutex::new(UeReconciliation::default())),
            startup_reconcile: false,
        }
    }

    async fn login_session(
        application: &Router,
        username: &str,
        password: &str,
    ) -> (String, String) {
        let response = application
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/auth/login")
                    .header(header::HOST, "127.0.0.1:49153")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"username":username,"password":password}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        (cookie, value["csrf_token"].as_str().unwrap().to_string())
    }

    fn scenario_request(cookie: &str, csrf: &str, kind: &str) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/scenarios/start")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, cookie)
            .header("x-csrf-token", csrf)
            .body(Body::from(
                json!({"scenario_id":"test-job-1","scenario_type":kind}).to_string(),
            ))
            .unwrap()
    }

    async fn validate_certified(application: &Router, cookie: &str, csrf: &str) {
        let response = application.clone().oneshot(Request::builder().method(Method::POST).uri("/api/v1/scenarios/validate").header(header::CONTENT_TYPE,"application/json").header(header::COOKIE,cookie).header("x-csrf-token",csrf).body(Body::from(json!({"scenario_id":"test-job-1","name":"Certified bounded existing UE traffic","ue_count":1,"start_mode":"SEQUENTIAL","stagger_seconds":0,"protocol":"UDP","destination":"10.46.0.1","packet_count":5,"packet_size":64,"rate_per_second":1,"duration_seconds":5}).to_string())).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    fn prepare_owned_traffic_target(test_state: &AppState, ue_id: &str, pdu_active: bool) {
        let mut controller = test_state.multi_ue.lock().unwrap();
        let index = ue_id.trim_start_matches("UE-").parse::<usize>().unwrap();
        controller.configure_count(index).unwrap();
        let profile = controller
            .profiles()
            .into_iter()
            .find(|profile| profile.ue_id == ue_id)
            .unwrap();
        let approval = FakeLiveUeRuntime::approval(&profile, &"a".repeat(64));
        controller
            .reserve_live_start(ue_id, "test-operation", approval)
            .unwrap();
        let handle = format!("container:{}", "4".repeat(64));
        controller
            .complete_live_start(ue_id, "test-operation", &handle)
            .unwrap();
        controller
            .apply_observation(
                ue_id,
                "RUNNING",
                "REGISTERED",
                if pdu_active { "ACTIVE" } else { "INACTIVE" },
                pdu_active.then_some("10.46.0.6"),
            )
            .unwrap();
    }

    fn targeted_scenario_request(
        cookie: &str,
        csrf: &str,
        scenario_id: &str,
        target_ue_id: &str,
    ) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/scenarios/start")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, cookie)
            .header("x-csrf-token", csrf)
            .body(Body::from(
                json!({"scenario_id":scenario_id,"scenario_type":"bounded-controller-ue-udp-v1","target_ue_id":target_ue_id}).to_string(),
            ))
            .unwrap()
    }

    async fn validate_targeted(
        application: &Router,
        cookie: &str,
        csrf: &str,
        target_ue_id: &str,
    ) -> StatusCode {
        application.clone().oneshot(Request::builder().method(Method::POST).uri("/api/v1/scenarios/validate").header(header::CONTENT_TYPE,"application/json").header(header::COOKIE,cookie).header("x-csrf-token",csrf).body(Body::from(json!({"scenario_id":"targeted-job","name":"Certified bounded controller UE traffic","ue_count":1,"start_mode":"SEQUENTIAL","stagger_seconds":0,"protocol":"UDP","destination":"10.46.0.1","packet_count":5,"packet_size":64,"rate_per_second":1,"duration_seconds":5,"target_ue_id":target_ue_id}).to_string())).unwrap()).await.unwrap().status()
    }

    #[tokio::test]
    async fn capabilities_publish_executable_and_locked_scenario_step_types() {
        let response = app(state())
            .oneshot(
                Request::builder()
                    .uri("/api/v1/capabilities")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(
            body["executable_scenario_step_types"],
            json!([
                "ue_start",
                "ue_stop",
                "pdu_establish",
                "pdu_release",
                "udp_traffic",
                "wait",
                "traffic_ul",
                "idle",
                "detach",
                "repeat"
            ])
        );
        assert_eq!(
            body["unavailable_scenario_step_types"],
            json!([
                {"type":"traffic_dl","http_status":422,"reason":"DL_SENDER_NOT_AVAILABLE"},
                {"type":"ims_register","http_status":423,"reason":"IMS_NOT_AVAILABLE"},
                {"type":"voice_call","http_status":423,"reason":"IMS_NOT_AVAILABLE"}
            ])
        );
        assert_eq!(
            body["scenario_step_limits"]["traffic_bytes_max"],
            209_715_200
        );
        assert_eq!(body["scenario_step_limits"]["repeat_depth_max"], 2);
        assert_eq!(body["scenario_step_limits"]["resolved_steps_max"], 10_000);
    }

    #[tokio::test]
    async fn anonymous_user_is_viewer_and_cannot_validate_start_or_stop() {
        let application = app(state());
        for (uri, body) in [
            (
                "/api/v1/scenarios/validate",
                json!({"scenario_id":"x","name":"x","ue_count":1,"start_mode":"SEQUENTIAL","stagger_seconds":0,"protocol":"UDP","destination":"10.46.0.1","packet_count":5,"packet_size":64,"rate_per_second":1,"duration_seconds":5}),
            ),
            (
                "/api/v1/scenarios/start",
                json!({"scenario_id":"x","scenario_type":"bounded-existing-ue-udp-v1"}),
            ),
            ("/api/v1/scenarios/stop", json!({"job_id":"x"})),
        ] {
            let response = application
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri(uri)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn login_rejects_invalid_password_and_reports_operator_role() {
        let application = app(state());
        let denied = application
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/auth/login")
                    .header(header::HOST, "127.0.0.1:49153")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"username":"operator-test","password":"wrong-password-value"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        let me = application
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth/me")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let value: Value =
            serde_json::from_slice(&to_bytes(me.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(value["role"], "operator");
        assert_eq!(value["authenticated"], true);
        assert_eq!(value["csrf_token"], csrf);
    }

    #[tokio::test]
    async fn operator_can_start_only_certified_mock_and_stop_idempotently() {
        let application = app(state());
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        let before_validation = application
            .clone()
            .oneshot(scenario_request(
                &cookie,
                &csrf,
                "bounded-existing-ue-udp-v1",
            ))
            .await
            .unwrap();
        assert_eq!(
            before_validation.status(),
            StatusCode::PRECONDITION_REQUIRED
        );
        validate_certified(&application, &cookie, &csrf).await;
        let started = application
            .clone()
            .oneshot(scenario_request(
                &cookie,
                &csrf,
                "bounded-existing-ue-udp-v1",
            ))
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::OK);
        let started_value: Value =
            serde_json::from_slice(&to_bytes(started.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(started_value["state"], "RUNNING");
        let duplicate = application
            .clone()
            .oneshot(scenario_request(
                &cookie,
                &csrf,
                "bounded-existing-ue-udp-v1",
            ))
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::OK);
        let stop = || {
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/scenarios/stop")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::from(json!({"job_id":"test-job-1"}).to_string()))
                .unwrap()
        };
        let stopped = application.clone().oneshot(stop()).await.unwrap();
        assert_eq!(stopped.status(), StatusCode::OK);
        let stopped_value: Value =
            serde_json::from_slice(&to_bytes(stopped.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(stopped_value["state"], "STOPPED");
        let repeated = application.clone().oneshot(stop()).await.unwrap();
        assert_eq!(repeated.status(), StatusCode::OK);
        let repeated_value: Value =
            serde_json::from_slice(&to_bytes(repeated.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(repeated_value["state"], "STOPPED");
        assert_eq!(repeated_value["idempotent"], true);
        let blocked = application
            .oneshot(scenario_request(&cookie, &csrf, "create-new-multi-ue"))
            .await
            .unwrap();
        assert_eq!(blocked.status(), StatusCode::LOCKED);
    }

    #[tokio::test]
    async fn operator_targets_verified_owned_ue_and_stop_preserves_ue_lifecycle() {
        let test_state = state();
        prepare_owned_traffic_target(&test_state, "UE-04", true);
        let inspection = test_state.clone();
        let application = app(test_state);
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        assert_eq!(
            validate_targeted(&application, &cookie, &csrf, "UE-04").await,
            StatusCode::OK
        );
        let started = application
            .clone()
            .oneshot(targeted_scenario_request(
                &cookie,
                &csrf,
                "targeted-job",
                "UE-04",
            ))
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::OK);
        let value: Value =
            serde_json::from_slice(&to_bytes(started.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(value["target_ue_id"], "UE-04");
        assert_eq!(value["tun_interface"], "uesimtun4");
        assert_eq!(value["packets_requested"], 5);

        let duplicate = application
            .clone()
            .oneshot(targeted_scenario_request(
                &cookie,
                &csrf,
                "another-job",
                "UE-04",
            ))
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::CONFLICT);

        let stopped = application
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/scenarios/stop")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::from(json!({"job_id":"targeted-job"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stopped.status(), StatusCode::OK);
        let job = inspection
            .multi_ue
            .lock()
            .unwrap()
            .snapshot()
            .into_iter()
            .find(|job| job.ue_id == "UE-04")
            .unwrap();
        assert_eq!(job.process_state, "RUNNING");
        assert_eq!(job.registration_state, "REGISTERED");
        assert_eq!(job.pdu_session_state, "ACTIVE");
        assert_eq!(job.traffic_state, "STOPPED");
    }

    #[tokio::test]
    async fn targeted_traffic_rejects_shared_unknown_and_missing_pdu_targets() {
        let test_state = state();
        prepare_owned_traffic_target(&test_state, "UE-04", false);
        let application = app(test_state);
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        for ue_id in ["UE-99", "UE-04"] {
            let status = validate_targeted(&application, &cookie, &csrf, ue_id).await;
            assert_eq!(status, StatusCode::LOCKED, "unexpected status for {ue_id}");
        }
        assert_eq!(
            validate_targeted(&application, &cookie, &csrf, "UE-01").await,
            StatusCode::OK
        );
        let shared_as_owned = application
            .oneshot(targeted_scenario_request(
                &cookie,
                &csrf,
                "shared-as-owned",
                "UE-01",
            ))
            .await
            .unwrap();
        assert_eq!(shared_as_owned.status(), StatusCode::LOCKED);
    }

    #[test]
    fn tunnel_route_and_cpu_contention_validation_fail_closed() {
        let interfaces = r#"[{"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1"}]},{"ifname":"uesimtun4","addr_info":[{"family":"inet","local":"10.46.0.6"}]}]"#;
        assert_eq!(
            verified_tun_from_ip_json(interfaces, "10.46.0.6").unwrap(),
            "uesimtun4"
        );
        assert!(verified_tun_from_ip_json(interfaces, "10.46.0.7").is_err());
        assert!(verified_route_uses_tun(
            "10.46.0.1 dev uesimtun4 src 10.46.0.6 uid 0",
            "10.46.0.1",
            "uesimtun4",
            "10.46.0.6"
        )
        .is_ok());
        assert!(verified_route_uses_tun(
            "10.46.0.1 dev eth0 src 10.46.0.6 uid 0",
            "10.46.0.1",
            "uesimtun4",
            "10.46.0.6"
        )
        .is_err());
    }

    #[tokio::test]
    async fn csrf_is_enforced_and_resource_failure_blocks_start() {
        let mut test_state = state();
        test_state.resource_override = Some(Err("DISK_STOP_THRESHOLD".into()));
        let application = app(test_state);
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        let missing_csrf = application
            .clone()
            .oneshot(scenario_request(
                &cookie,
                "bad",
                "bounded-existing-ue-udp-v1",
            ))
            .await
            .unwrap();
        assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);
        validate_certified(&application, &cookie, &csrf).await;
        let blocked = application
            .oneshot(scenario_request(
                &cookie,
                &csrf,
                "bounded-existing-ue-udp-v1",
            ))
            .await
            .unwrap();
        assert_eq!(blocked.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn administrator_controls_policy_and_operator_cannot() {
        let application = app(state());
        for (username, password, expected) in [
            ("operator-test", OPERATOR_PASSWORD, StatusCode::FORBIDDEN),
            ("administrator-test", ADMIN_PASSWORD, StatusCode::OK),
        ] {
            let (cookie, csrf) = login_session(&application, username, password).await;
            let response = application
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/api/v1/admin/scenario-policy")
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(header::COOKIE, cookie)
                        .header("x-csrf-token", csrf)
                        .body(Body::from(json!({"enabled":false}).to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }
    }

    #[test]
    fn running_transitions_to_completed_or_failed_with_terminal_accounting() {
        for (exit_code, expected, sent) in [(0, "COMPLETED", Some(5)), (7, "FAILED", None)] {
            let mut runtime = ControlRuntime {
                active: Some(process_job(exit_code)),
                history: Vec::new(),
            };
            assert_eq!(runtime.active.as_ref().unwrap().state, "RUNNING");
            await_terminal(&mut runtime);
            assert_eq!(runtime.history[0]["state"], expected);
            assert_eq!(runtime.history[0]["packets_sent"].as_u64(), sent);
            assert_eq!(
                runtime.history[0]["bytes_sent"].as_u64(),
                sent.map(|packets| packets * TRAFFIC_PACKET_BYTES)
            );
            assert!(runtime.history[0]["packets_received"].is_null());
            assert_eq!(
                runtime.history[0]["receive_accounting"],
                "NOT_OBSERVED_SEND_ONLY_PROFILE"
            );
            assert!(runtime.history[0]["ended_at_epoch_s"].as_u64().is_some());
            assert!(runtime.history[0]["ended_at_epoch_ms"].as_u64().is_some());
            assert!(runtime.history[0]["duration_seconds"].as_u64().unwrap() <= 1);
        }
    }

    #[test]
    fn bounded_udp_profile_is_five_fixed_size_datagrams_with_real_spacing() {
        assert_eq!(TRAFFIC_PACKET_COUNT, 5);
        assert_eq!(TRAFFIC_PACKET_BYTES, 64);
        assert!(TRAFFIC_EXECUTION_COMMAND.contains("for i in 1 2 3 4 5"));
        assert!(TRAFFIC_EXECUTION_COMMAND.contains("printf '%-64s'"));
        assert!(TRAFFIC_EXECUTION_COMMAND.contains("/usr/bin/sleep 1"));
        assert!(!TRAFFIC_EXECUTION_COMMAND.contains("</dev/null"));
    }

    #[tokio::test]
    async fn stop_after_completion_preserves_completed_result() {
        let test_state = state();
        test_state.runtime.lock().unwrap().history.push(json!({
            "job_id":"already-complete","scenario_id":"already-complete","state":"COMPLETED","traffic_state":"COMPLETED","started_at":"10","started_at_epoch_s":10,"ended_at_epoch_s":11,"duration_seconds":1,"packets_requested":5,"packets_sent":5,"terminal_result":"PROCESS_EXIT_SUCCESS"
        }));
        let application = app(test_state);
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        let response = application
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/scenarios/stop")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie)
                    .header("x-csrf-token", csrf)
                    .body(Body::from(json!({"job_id":"already-complete"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(value["state"], "COMPLETED");
        assert_eq!(value["idempotent"], true);
    }

    #[test]
    fn registry_recovery_marks_interrupted_job_failed_and_retains_history() {
        let stored = json!({
            "active":{"job_id":"interrupted","scenario_id":"interrupted","started_at":"10","duration_seconds":2,"state":"RUNNING"},
            "history":[{"job_id":"done","scenario_id":"done","started_at":"1","duration_seconds":1,"state":"COMPLETED","exit_code":0}]
        });
        let runtime = recover_runtime(Some(stored));
        assert!(runtime.active.is_none());
        assert_eq!(runtime.history.len(), 2);
        assert_eq!(runtime.history[1]["state"], "FAILED");
        assert_eq!(
            runtime.history[1]["terminal_result"],
            "CONTROLLER_RESTART_RECOVERY"
        );
    }

    #[tokio::test]
    async fn status_survives_page_refresh_and_multiple_browser_sessions() {
        let application = app(state());
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        validate_certified(&application, &cookie, &csrf).await;
        assert_eq!(
            application
                .clone()
                .oneshot(scenario_request(
                    &cookie,
                    &csrf,
                    "bounded-existing-ue-udp-v1"
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        for _ in 0..2 {
            let response = application
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/scenarios/status")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let value: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(value["active_job"]["job_id"], "test-job-1");
            assert_eq!(value["active_job"]["state"], "RUNNING");
        }
    }

    #[tokio::test]
    async fn wrong_stop_target_never_terminates_owned_job() {
        let application = app(state());
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        validate_certified(&application, &cookie, &csrf).await;
        application
            .clone()
            .oneshot(scenario_request(
                &cookie,
                &csrf,
                "bounded-existing-ue-udp-v1",
            ))
            .await
            .unwrap();
        let response = application
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/scenarios/stop")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::from(
                        json!({"job_id":"unrelated-process"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let status = application
            .oneshot(
                Request::builder()
                    .uri("/api/v1/scenarios/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let value: Value =
            serde_json::from_slice(&to_bytes(status.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(value["active_job"]["state"], "RUNNING");
    }

    #[tokio::test]
    async fn viewer_is_denied_and_operator_controls_only_provisioned_ue() {
        let application = app(state());
        let viewer = application
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/ues/start")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({"ue_id":"UE-01"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(viewer.status(), StatusCode::FORBIDDEN);
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        let action = |path: &str, id: &str| {
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::from(json!({"ue_id":id}).to_string()))
                .unwrap()
        };
        let started = application
            .clone()
            .oneshot(action("/api/v1/ues/start", "UE-01"))
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::OK);
        let blocked = application
            .clone()
            .oneshot(action("/api/v1/ues/start", "UE-02"))
            .await
            .unwrap();
        assert_eq!(blocked.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let stopped = application
            .oneshot(action("/api/v1/ues/stop", "UE-01"))
            .await
            .unwrap();
        assert_eq!(stopped.status(), StatusCode::OK);
    }

    #[test]
    fn live_ue_authorization_uses_configured_provisioned_bounded_allowlist() {
        let configured = ueransim_adapter::planned_profiles()
            .into_iter()
            .take(5)
            .map(|mut profile| {
                profile.configured = true;
                profile.subscription_verified = true;
                profile
            })
            .collect::<Vec<_>>();
        assert!(authorize_live_ue_request(&["UE-02".into()], &configured, false).is_ok());
        assert!(
            authorize_live_ue_request(&["UE-02".into(), "UE-03".into()], &configured, false)
                .is_ok()
        );
        assert_eq!(
            authorize_live_ue_request(&["UE-01".into()], &configured, false).unwrap_err(),
            "SHARED_UE_PROTECTED"
        );
        assert!(authorize_live_ue_request(&["UE-01".into()], &configured, true).is_ok());
        assert!(
            authorize_live_ue_request(&["UE-04".into(), "UE-05".into()], &configured, false)
                .is_ok()
        );
        assert_eq!(
            authorize_live_ue_request(&["UE-10".into()], &configured, false).unwrap_err(),
            "UNKNOWN_UE_PROFILE"
        );
        assert_eq!(
            authorize_live_ue_request(&["UE-02".into(), "UE-02".into()], &configured, false)
                .unwrap_err(),
            "INVALID_GROUP_REQUEST"
        );
    }

    #[test]
    fn ue01_transfer_requires_exact_evidence_and_no_legacy_owner() {
        let transfer = Ue01OwnershipTransferAttestation {
            schema_version: 1,
            ue_id: "UE-01".into(),
            state: "CONTROLLER_OWNED".into(),
            legacy_container_name: "oiran-lab-ueransim-ue-1".into(),
            legacy_container_id: "a".repeat(64),
            legacy_compose_project: "oiran-lab".into(),
            legacy_compose_service: "ueransim-ue".into(),
            legacy_compose_sha256: "b".repeat(64),
            profile_sha256: "c".repeat(64),
            ownership_id: "d".repeat(64),
        };
        let evidence = Ue01OwnershipTransferEvidence {
            legacy_container_present: false,
            legacy_container_running: false,
            legacy_container_id: None,
            compose_sha256: "b".repeat(64),
            profile_sha256: "c".repeat(64),
            ownership_id: "d".repeat(64),
        };
        assert!(validate_ue01_ownership_transfer(&transfer, &evidence).is_ok());
        assert_eq!(
            validate_ue01_ownership_transfer(
                &transfer,
                &Ue01OwnershipTransferEvidence {
                    legacy_container_present: true,
                    ..evidence.clone()
                }
            )
            .unwrap_err(),
            "UE01_LEGACY_OWNER_STILL_PRESENT"
        );
        assert_eq!(
            validate_ue01_ownership_transfer(
                &transfer,
                &Ue01OwnershipTransferEvidence {
                    profile_sha256: "e".repeat(64),
                    ..evidence
                }
            )
            .unwrap_err(),
            "UE01_TRANSFER_EVIDENCE_MISMATCH"
        );
        assert!(compose_disables_legacy_ue01(
            "services:\n  ueransim-ue:\n    # POLARIS_UE01_OWNERSHIP_TRANSFERRED\n    profiles: [\"polaris-transferred\"]\n  amf:\n    image: example"
        ));
        assert!(!compose_disables_legacy_ue01(
            "services:\n  ueransim-ue:\n    # POLARIS_UE01_OWNERSHIP_TRANSFERRED\n    profiles: [\"5g\"]"
        ));
        let disabled = disable_legacy_ue01_service(
            "services:\n  ueransim-ue:\n    profiles: [\"5g\"]\n    image: pinned\n  amf:\n    image: pinned\n",
        )
        .unwrap();
        assert!(compose_disables_legacy_ue01(&disabled));
        assert!(disabled.contains("polaris-ue01-legacy-disabled"));
        assert_eq!(disable_legacy_ue01_service(&disabled).unwrap(), disabled);
    }

    #[tokio::test]
    async fn live_group_starts_only_ue_02_and_ue_03_and_inventory_uses_current_observations() {
        let mut test_state = state();
        test_state.execution_mode = "live".into();
        // Direct, controller-owned lifecycle operations use an explicit,
        // short-lived Operator validation instead of the desired-count gate.
        test_state.additional_ue_live_enabled = false;
        test_state
            .multi_ue
            .lock()
            .unwrap()
            .configure_count(3)
            .unwrap();
        test_state.configuration.lock().unwrap().ue_count = 3;
        test_state.ue_runtime = Arc::new(FakeLiveUeRuntime {
            stopped: Arc::new(Mutex::new(Vec::new())),
            launched: Arc::new(Mutex::new(Vec::new())),
            fail_observation: false,
            fail_verification: false,
            fail_stop: false,
        });
        let application = app(test_state);
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        let unvalidated = application
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/ues/group/start")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::from(
                        json!({"ue_ids":["UE-02","UE-03"],"mode":"STAGGERED","stagger_seconds":2})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unvalidated.status(), StatusCode::PRECONDITION_REQUIRED);
        let validated = application
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/ues/control/validate")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::from(json!({"ue_ids":["UE-02","UE-03"]}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(validated.status(), StatusCode::OK);
        let response = application
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/ues/group/start")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::from(
                        json!({"ue_ids":["UE-02","UE-03"],"mode":"STAGGERED","stagger_seconds":2})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let started: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(started["started"], json!(["UE-02", "UE-03"]));

        let inventory = application
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/ues")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let inventory: Value =
            serde_json::from_slice(&to_bytes(inventory.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(inventory["active_count"], 3);
        assert_eq!(inventory["registered_count"], 3);
        assert_eq!(inventory["pdu_session_count"], 3);
        assert_eq!(inventory["items"][1]["ue_ip"], "10.46.0.5");
        assert_eq!(inventory["items"][2]["ue_ip"], "10.46.0.6");

        let stopped = application
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/ues/group/stop")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::from(json!({"ue_ids":["UE-02"]}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stopped.status(), StatusCode::OK);
        let stopped: Value =
            serde_json::from_slice(&to_bytes(stopped.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(stopped["stopped"], json!(["UE-02"]));
        assert!(stopped.get("started").is_none());

        let protected_stop = application
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/ues/stop")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::from(r#"{"ue_id":"UE-01"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(protected_stop.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn actual_inline_profile_slices_are_parsed_structurally_and_must_agree() {
        let profile = "supi: 'imsi-001010000000002'\nmcc: '001'\nmnc: '01'\nconfigured-nssai: [{sst: 1, sd: 0x010203}]\ndefault-nssai: [{sst: 1, sd: 0x010203}]\nsessions:\n  - type: IPv4\n    apn: internet\n    slice: {sst: 1, sd: 0x010203}\n";
        assert_eq!(
            DockerUeRuntime::profile_network(profile),
            Some(("internet".into(), 1, Some("010203".into())))
        );
        let mismatched = profile.replacen("default-nssai: [{sst: 1", "default-nssai: [{sst: 2", 1);
        assert_eq!(DockerUeRuntime::profile_network(&mismatched), None);
        assert_eq!(
            DockerUeRuntime::profile_network(&format!(
                "{profile}default-nssai: [{{sst: 1, sd: 0x010203}}]\n"
            )),
            None
        );
        assert_eq!(
            DockerUeRuntime::top_level_scalar(profile, "mcc").as_deref(),
            Some("001")
        );
        assert_eq!(DockerUeRuntime::top_level_scalar(profile, "sd"), None);
    }

    #[test]
    fn offline_fixture_verifies_open5gs_identity_auth_and_network_without_secret_output() {
        let yaml = include_bytes!("../../../tests/fixtures/provisioning/ue-01.yaml");
        let export: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/provisioning/open5gs-records.json"
        ))
        .unwrap();
        let binding = verify_open5gs_profile_binding(
            &ueransim_adapter::planned_profiles()[0],
            yaml,
            &export["subscribers"][0],
        )
        .unwrap();
        assert_eq!(binding.ue_id, "UE-01");
        assert_eq!(binding.authority, "OPEN5GS");
        let mut wrong = export["subscribers"][0].clone();
        wrong["security"]["k"] = Value::String("0".repeat(32));
        assert_eq!(
            verify_open5gs_profile_binding(&ueransim_adapter::planned_profiles()[0], yaml, &wrong,)
                .unwrap_err(),
            "OPEN5GS_AUTH_MATERIAL_MISMATCH"
        );
    }

    #[test]
    fn exact_runtime_envelope_rejects_any_adoption_drift() {
        let spec = LiveLaunchSpec {
            ue_id: "UE-02".into(),
            profile_basename: "ue-02.yaml".into(),
            container_name: "polaris-control-ue-02".into(),
            owner_id: "b".repeat(64),
            profile_sha256: "c".repeat(64),
            script_sha256: "d".repeat(64),
            image_id: format!("sha256:{}", "a".repeat(64)),
            docker_args: Vec::new(),
        };
        let actual_inspect_mounts = json!([
            {"Type":"bind","Source":"/var/lib/polaris-control/ue-profiles/ue-02.yaml","Destination":"/run/secrets/ue.yaml","RW":false},
            {"Type":"bind","Source":"/root/POLARIS/scripts/start-ueransim-ue.sh","Destination":"/usr/local/bin/start-ueransim-ue","RW":false}
        ]);
        let devices = json!([{"PathOnHost":"/dev/net/tun","PathInContainer":"/dev/net/tun","CgroupPermissions":"rwm"}]);
        let tmpfs = json!({"/tmp":"size=64m","/etc/iproute2":"size=1m"});
        let mut fields = vec![
            "e".repeat(64),
            "running".into(),
            spec.image_id.clone(),
            "polaris-control".into(),
            spec.ue_id.clone(),
            spec.profile_basename.clone(),
            spec.owner_id.clone(),
            spec.profile_sha256.clone(),
            spec.script_sha256.clone(),
            ueransim_adapter::LIVE_DOCKER_NETWORK.into(),
            r#"["/usr/local/bin/start-ueransim-ue"]"#.into(),
            r#"["/run/secrets/ue.yaml"]"#.into(),
            "0:0".into(),
            r#"["CAP_NET_ADMIN"]"#.into(),
            r#"["ALL"]"#.into(),
            "true".into(),
            r#"["no-new-privileges:true"]"#.into(),
            "128".into(),
            "750000000".into(),
            "536870912".into(),
            "no".into(),
            actual_inspect_mounts.to_string(),
            tmpfs.to_string(),
            devices.to_string(),
            "false".into(),
            "".into(),
            "private".into(),
            json!({ueransim_adapter::LIVE_DOCKER_NETWORK:{"IPAddress":"10.77.0.32"}}).to_string(),
        ];
        assert!(DockerUeRuntime::envelope_matches(&fields, &spec));

        fields[13] = r#"["NET_ADMIN"]"#.into();
        assert!(DockerUeRuntime::envelope_matches(&fields, &spec));
        fields[13] = r#"["CAP_SYS_ADMIN"]"#.into();
        assert!(!DockerUeRuntime::envelope_matches(&fields, &spec));
        fields[13] = r#"["CAP_NET_ADMIN","CAP_SYS_ADMIN"]"#.into();
        assert!(!DockerUeRuntime::envelope_matches(&fields, &spec));
        fields[13] = r#"["CAP_NET_ADMIN"]"#.into();

        let fixture_mounts = json!([
            {"Type":"bind","Source":"/var/lib/polaris-control/ue-profiles/ue-02.yaml","Destination":"/run/secrets/ue.yaml","RW":false},
            {"Type":"bind","Source":"/root/POLARIS/scripts/start-ueransim-ue.sh","Destination":"/usr/local/bin/start-ueransim-ue","RW":false},
            {"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true},
            {"Type":"tmpfs","Source":"","Destination":"/etc/iproute2","RW":true}
        ]);
        fields[21] = fixture_mounts.to_string();
        assert!(DockerUeRuntime::envelope_matches(&fields, &spec));
        let mut unexpected_mounts = fixture_mounts;
        unexpected_mounts[3]["Destination"] = Value::String("/unexpected".into());
        fields[21] = unexpected_mounts.to_string();
        assert!(!DockerUeRuntime::envelope_matches(&fields, &spec));
        fields[21] = actual_inspect_mounts.to_string();

        for index in [
            2_usize, 6, 7, 9, 10, 12, 13, 15, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
        ] {
            let original = fields[index].clone();
            fields[index] = "unexpected".into();
            assert!(!DockerUeRuntime::envelope_matches(&fields, &spec));
            fields[index] = original;
        }
    }

    #[test]
    fn observation_uses_real_ueransim_cli_argument_syntax_without_a_shell() {
        assert_eq!(
            DockerUeRuntime::node_list_command("container-id"),
            ["exec", "container-id", "nr-cli", "--dump"]
        );
        let commands = DockerUeRuntime::observation_commands("container-id", "ue-node");
        assert_eq!(
            commands[0],
            ["exec", "container-id", "nr-cli", "ue-node", "-e", "status"]
        );
        assert_eq!(
            commands[1],
            ["exec", "container-id", "nr-cli", "ue-node", "-e", "ps-list"]
        );
        assert_eq!(
            commands[2],
            ["exec", "container-id", "ip", "-o", "-4", "addr", "show"]
        );
        assert!(commands
            .iter()
            .flatten()
            .all(|argument| argument != "sh" && argument != "-c"));
        let profile = ueransim_adapter::planned_profiles().remove(0);
        assert_eq!(
            DockerUeRuntime::pdu_establish_command(&profile),
            "ps-establish IPv4 --dnn internet --sst 1 --sd 010203"
        );
    }

    #[test]
    fn pdu_commands_change_session_state_without_stopping_owned_ue() {
        let mut test_state = state();
        test_state.execution_mode = "live".into();
        test_state.additional_ue_live_enabled = true;
        test_state
            .multi_ue
            .lock()
            .unwrap()
            .configure_count(2)
            .unwrap();
        start_one_live(&test_state, "UE-02").unwrap();
        let (job, profile) = {
            let controller = test_state.multi_ue.lock().unwrap();
            (
                controller
                    .snapshot()
                    .into_iter()
                    .find(|item| item.ue_id == "UE-02")
                    .unwrap(),
                controller
                    .profiles()
                    .into_iter()
                    .find(|item| item.ue_id == "UE-02")
                    .unwrap(),
            )
        };
        let cancel = AtomicBool::new(false);
        test_state.ue_runtime.release_pdu(&job, 1, &cancel).unwrap();
        let released = observe_controller_ue(&test_state, "UE-02").unwrap();
        assert_eq!(released.process_state, "RUNNING");
        assert_eq!(released.pdu_session_state, "INACTIVE");
        test_state
            .ue_runtime
            .establish_pdu(&job, &profile, 1, &cancel)
            .unwrap();
        let established = observe_controller_ue(&test_state, "UE-02").unwrap();
        assert_eq!(established.process_state, "RUNNING");
        assert_eq!(established.pdu_session_state, "ACTIVE");
    }

    #[test]
    fn live_start_failure_injection_rolls_back_exact_container_and_clears_handle() {
        let mut test_state = state();
        test_state.execution_mode = "live".into();
        test_state.additional_ue_live_enabled = true;
        test_state
            .multi_ue
            .lock()
            .unwrap()
            .configure_count(3)
            .unwrap();
        let stopped = Arc::new(Mutex::new(Vec::new()));
        let launched = Arc::new(Mutex::new(Vec::new()));
        test_state.ue_runtime = Arc::new(FakeLiveUeRuntime {
            stopped: stopped.clone(),
            launched,
            fail_observation: true,
            fail_verification: false,
            fail_stop: false,
        });
        assert_eq!(
            start_one_live(&test_state, "UE-02").unwrap_err(),
            "INJECTED_OBSERVATION_FAILURE"
        );
        assert_eq!(&*stopped.lock().unwrap(), &["UE-02"]);
        let job = test_state
            .multi_ue
            .lock()
            .unwrap()
            .snapshot()
            .into_iter()
            .find(|job| job.ue_id == "UE-02")
            .unwrap();
        assert_eq!(job.lifecycle, simulator_controller::UeLifecycle::Failed);
        assert_eq!(job.process_handle, None);
    }

    #[test]
    fn failed_post_launch_cleanup_retains_exact_handle_and_approval() {
        let mut test_state = state();
        test_state.execution_mode = "live".into();
        test_state.additional_ue_live_enabled = true;
        test_state
            .multi_ue
            .lock()
            .unwrap()
            .configure_count(3)
            .unwrap();
        test_state.ue_runtime = Arc::new(FakeLiveUeRuntime {
            stopped: Arc::new(Mutex::new(Vec::new())),
            launched: Arc::new(Mutex::new(Vec::new())),
            fail_observation: true,
            fail_verification: false,
            fail_stop: true,
        });
        assert_eq!(
            start_one_live(&test_state, "UE-02").unwrap_err(),
            "INJECTED_OBSERVATION_FAILURE"
        );
        let job = test_state
            .multi_ue
            .lock()
            .unwrap()
            .snapshot()
            .into_iter()
            .find(|job| job.ue_id == "UE-02")
            .unwrap();
        assert_eq!(job.lifecycle, simulator_controller::UeLifecycle::Failed);
        assert!(job.process_handle.is_some());
        assert!(job.approved_runtime.is_some());
        assert!(job
            .last_error
            .as_deref()
            .unwrap()
            .contains("CLEANUP_PENDING"));
    }

    #[test]
    fn post_run_inspection_and_rollback_failures_survive_same_process_decrease() {
        let mut test_state = state();
        test_state.execution_mode = "live".into();
        test_state.additional_ue_live_enabled = true;
        test_state
            .multi_ue
            .lock()
            .unwrap()
            .configure_count(3)
            .unwrap();
        let handle = format!("container:{}", "2".repeat(64));
        let stop_attempts = Arc::new(Mutex::new(0));
        test_state.ue_runtime = Arc::new(PostRunInspectionFailureRuntime {
            handle: handle.clone(),
            stop_attempts: stop_attempts.clone(),
        });

        assert_eq!(
            start_one_live(&test_state, "UE-02").unwrap_err(),
            "DOCKER_COMMAND_FAILED"
        );
        let failed_start = test_state
            .multi_ue
            .lock()
            .unwrap()
            .snapshot()
            .into_iter()
            .find(|job| job.ue_id == "UE-02")
            .unwrap();
        assert_eq!(
            failed_start.process_handle.as_deref(),
            Some(handle.as_str())
        );
        assert!(failed_start.approved_runtime.is_some());
        assert!(failed_start
            .last_error
            .as_deref()
            .unwrap()
            .contains("CLEANUP_PENDING"));
        let durable: Vec<simulator_controller::UeJob> =
            serde_json::from_slice(&fs::read(&test_state.ue_job_state_path).unwrap()).unwrap();
        assert_eq!(durable[0].process_handle.as_deref(), Some(handle.as_str()));

        *test_state.ue_reconciliation.lock().unwrap() = UeReconciliation {
            desired_count: 1,
            state: "RUNNING".into(),
            ..UeReconciliation::default()
        };
        reconcile_ue_count(
            Arc::new(test_state.clone()),
            1,
            [("UE-01".into(), "a".repeat(64))].into_iter().collect(),
        );

        let status = test_state.ue_reconciliation.lock().unwrap().clone();
        assert_eq!(status.state, "FAILED");
        assert!(status.stopped.is_empty());
        assert_eq!(status.failures[0].0, "UE-02");
        assert_eq!(*stop_attempts.lock().unwrap(), 2);
        let cleanup_pending = test_state
            .multi_ue
            .lock()
            .unwrap()
            .snapshot()
            .into_iter()
            .find(|job| job.ue_id == "UE-02")
            .unwrap();
        assert_eq!(
            cleanup_pending.process_handle.as_deref(),
            Some(handle.as_str())
        );
        assert!(cleanup_pending
            .last_error
            .as_deref()
            .unwrap()
            .contains("CLEANUP_PENDING"));
        assert_eq!(test_state.multi_ue.lock().unwrap().configured_count(), 3);
    }

    #[test]
    fn reserved_orphan_is_discovered_exactly_and_stopped_before_decrease_delta() {
        let mut test_state = state();
        test_state.execution_mode = "live".into();
        test_state.additional_ue_live_enabled = true;
        test_state
            .multi_ue
            .lock()
            .unwrap()
            .configure_count(3)
            .unwrap();
        let profile = test_state
            .multi_ue
            .lock()
            .unwrap()
            .profiles()
            .into_iter()
            .find(|profile| profile.ue_id == "UE-02")
            .unwrap();
        let approval = FakeLiveUeRuntime::approval(&profile, &"a".repeat(64));
        test_state
            .multi_ue
            .lock()
            .unwrap()
            .reserve_live_start("UE-02", "crashed-operation", approval.clone())
            .unwrap();
        let stopped = Arc::new(Mutex::new(Vec::new()));
        let runtime = Arc::new(FakeLiveUeRuntime {
            stopped: stopped.clone(),
            launched: Arc::new(Mutex::new(vec!["UE-02".into()])),
            fail_observation: false,
            fail_verification: false,
            fail_stop: false,
        });
        test_state.ue_runtime = runtime;
        *test_state.ue_reconciliation.lock().unwrap() = UeReconciliation {
            desired_count: 1,
            state: "RUNNING".into(),
            ..UeReconciliation::default()
        };
        reconcile_ue_count(
            Arc::new(test_state.clone()),
            1,
            [("UE-01".into(), "a".repeat(64))].into_iter().collect(),
        );
        assert_eq!(&*stopped.lock().unwrap(), &["UE-02"]);
        let job = test_state
            .multi_ue
            .lock()
            .unwrap()
            .snapshot()
            .into_iter()
            .find(|job| job.ue_id == "UE-02")
            .unwrap();
        assert_eq!(job.process_handle, None);
    }

    #[test]
    fn reconciliation_reports_actionable_per_ue_failures_and_keeps_successful_delta() {
        let mut test_state = state();
        test_state.execution_mode = "live".into();
        test_state.additional_ue_live_enabled = true;
        test_state.ue_runtime = Arc::new(FakeLiveUeRuntime {
            stopped: Arc::new(Mutex::new(Vec::new())),
            launched: Arc::new(Mutex::new(Vec::new())),
            fail_observation: true,
            fail_verification: false,
            fail_stop: false,
        });
        *test_state.ue_reconciliation.lock().unwrap() = UeReconciliation {
            desired_count: 3,
            state: "RUNNING".into(),
            ..UeReconciliation::default()
        };
        let verified = (1..=3)
            .map(|index| (format!("UE-{index:02}"), "a".repeat(64)))
            .collect();
        reconcile_ue_count(Arc::new(test_state.clone()), 3, verified);
        let status = test_state.ue_reconciliation.lock().unwrap().clone();
        assert_eq!(status.state, "FAILED");
        assert_eq!(status.failures.len(), 2);
        assert_eq!(status.failures[0].0, "UE-02");
        assert_eq!(status.failures[1].0, "UE-03");
        assert!(test_state
            .multi_ue
            .lock()
            .unwrap()
            .snapshot()
            .iter()
            .all(|job| job.process_handle.is_none()));
    }

    #[test]
    fn live_start_never_launches_when_durable_reservation_write_fails() {
        let mut test_state = state();
        test_state.execution_mode = "live".into();
        test_state
            .multi_ue
            .lock()
            .unwrap()
            .configure_count(3)
            .unwrap();
        let blocker = test_state
            .ue_job_state_path
            .parent()
            .unwrap()
            .join("registry-parent-is-file");
        fs::write(&blocker, b"block").unwrap();
        test_state.ue_job_state_path = blocker.join("ue-jobs.json");
        let launched = Arc::new(Mutex::new(Vec::new()));
        test_state.ue_runtime = Arc::new(FakeLiveUeRuntime {
            stopped: Arc::new(Mutex::new(Vec::new())),
            launched: launched.clone(),
            fail_observation: false,
            fail_verification: false,
            fail_stop: false,
        });
        assert_eq!(
            start_one_live(&test_state, "UE-02").unwrap_err(),
            "UE_JOB_REGISTRY_UNWRITABLE"
        );
        assert!(launched.lock().unwrap().is_empty());
    }

    #[test]
    fn concurrent_live_starts_are_serialized_and_launch_once() {
        let mut test_state = state();
        test_state.execution_mode = "live".into();
        test_state
            .multi_ue
            .lock()
            .unwrap()
            .configure_count(3)
            .unwrap();
        let launched = Arc::new(Mutex::new(Vec::new()));
        test_state.ue_runtime = Arc::new(FakeLiveUeRuntime {
            stopped: Arc::new(Mutex::new(Vec::new())),
            launched: launched.clone(),
            fail_observation: false,
            fail_verification: false,
            fail_stop: false,
        });
        let state = Arc::new(test_state);
        let first_state = state.clone();
        let first = std::thread::spawn(move || start_one_live(&first_state, "UE-02"));
        let second_state = state.clone();
        let second = std::thread::spawn(move || start_one_live(&second_state, "UE-02"));
        let results = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(launched.lock().unwrap().as_slice(), &["UE-02"]);
    }

    #[tokio::test]
    async fn multi_ue_inventory_reports_planned_profiles_without_claiming_live_state() {
        let application = app(state());
        let response = application
            .oneshot(
                Request::builder()
                    .uri("/api/v1/ues")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(value["planned_count"], 10);
        assert_eq!(value["max_configurable"], 10_000);
        assert!(value["configured_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .all(|profile| profile["subscription_status"] == "VERIFIED"));
    }

    #[tokio::test]
    async fn verified_transfer_removes_shared_state_and_exposes_ue01_control_contract() {
        let mut test_state = state();
        test_state.execution_mode = "live".into();
        test_state.ue01_controller_owned = true;
        let response = app(test_state)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/ues")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        let ue01 = &value["items"][0];
        assert_eq!(ue01["internal_ue_id"], "UE-01");
        assert_eq!(ue01["controller_owned"], true);
        assert_eq!(ue01["ownership"], "POLARIS_CONTROLLER");
        assert_eq!(ue01["process_state"], "NOT_STARTED");
        assert_eq!(ue01["actions"]["authorize"], true);
        assert_eq!(value["active_count"], 0);
    }

    #[tokio::test]
    async fn ue_inventory_reuses_fresh_runtime_observation_without_blocking_navigation() {
        let test_state = Arc::new(state());
        let viewer = || {
            Extension(EffectiveIdentity {
                role: "viewer".into(),
                username: None,
                session_id: None,
                csrf_valid: true,
            })
        };
        let first = ues(State(test_state.clone()), viewer()).await.0;
        assert_eq!(first["configured_count"], 1);
        assert_eq!(first["registered_count"], 1);
        assert_eq!(first["cache_version"], 1);
        assert!(
            test_state
                .ue_inventory_last_observed_epoch_s
                .load(Ordering::Acquire)
                > 0
        );

        // A fresh observation must be reusable even if another refresh owns
        // the observation slot. This is the route-change race exercised by
        // the production browser suite.
        test_state
            .ue_inventory_running
            .store(true, Ordering::Release);
        let started = std::time::Instant::now();
        let cached = ues(State(test_state.clone()), viewer()).await.0;
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
        assert_eq!(cached["configured_count"], 1);
        assert_eq!(cached["registered_count"], 1);
        assert_eq!(cached["cache_version"], first["cache_version"]);
        assert_eq!(cached["cache_fresh"], true);
        assert!(test_state.ue_inventory_running.load(Ordering::Acquire));
        test_state
            .ue_inventory_running
            .store(false, Ordering::Release);
    }

    #[tokio::test]
    async fn configured_profile_visibility_is_complete_without_fabricated_runtime() {
        for configured_count in [1, 3, 5, 10] {
            let test_state = state();
            test_state
                .multi_ue
                .lock()
                .unwrap()
                .configure_count(configured_count)
                .unwrap();
            test_state.configuration.lock().unwrap().ue_count = configured_count;
            let response = app(test_state)
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/ues")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let value: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            let items = value["items"].as_array().unwrap();
            assert_eq!(items.len(), configured_count);
            assert_eq!(items[0]["internal_ue_id"], "UE-01");
            assert!(matches!(
                items[0]["process_state"].as_str(),
                Some("RUNNING" | "UNKNOWN")
            ));
            if items[0]["process_state"] == "RUNNING" {
                assert_eq!(items[0]["registration_state"], "REGISTERED");
                assert_eq!(items[0]["pdu_session"], "ACTIVE");
            }
            assert!(items.iter().skip(1).all(|item| {
                item["process_state"] == "NOT_STARTED"
                    && item["registration_state"] == "NOT_OBSERVED"
                    && item["pdu_session"] == "INACTIVE"
                    && item["subscription_status"] == "VERIFIED"
            }));
        }
    }

    #[tokio::test]
    async fn configuration_apply_reconciles_only_delta_and_protects_shared_ue() {
        let test_state = state();
        let application = app(test_state.clone());
        let viewer = application
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/configuration")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"ue_count":2,"gnb_count":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(viewer.status(), StatusCode::FORBIDDEN);
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        for (ue_count, expected_started) in [(3, 2), (5, 4), (5, 4), (1, 0)] {
            let response = application
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/api/v1/configuration")
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(header::COOKIE, &cookie)
                        .header("x-csrf-token", &csrf)
                        .body(Body::from(
                            json!({"ue_count":ue_count,"gnb_count":1}).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::ACCEPTED);
            let value: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(value["ue_count"], ue_count);
            assert_eq!(value["desired_ue_count"], ue_count);
            for _ in 0..100 {
                if !test_state.ue_reconciliation_running.load(Ordering::Acquire) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            let running = test_state
                .multi_ue
                .lock()
                .unwrap()
                .snapshot()
                .into_iter()
                .filter(|job| job.process_handle.is_some())
                .count();
            assert_eq!(running, expected_started);
            assert!(test_state
                .multi_ue
                .lock()
                .unwrap()
                .snapshot()
                .iter()
                .all(|job| job.ue_id != "UE-01"));
            let status = test_state.ue_reconciliation.lock().unwrap().clone();
            assert_eq!(status.state, "COMPLETED");
            if ue_count == 5 && expected_started == 4 && status.started.is_empty() {
                assert!(status.stopped.is_empty(), "repeat apply must be idempotent");
            }
        }
        let persisted: DesiredConfiguration =
            serde_json::from_slice(&fs::read(&test_state.configuration_path).unwrap()).unwrap();
        assert_eq!(persisted.ue_count, 1);
        assert_eq!(persisted.gnb_count, 1);
    }

    #[tokio::test]
    async fn configuration_rejects_out_of_range_counts() {
        assert!(validate_configuration(0, 1).is_ok());
        let application = app(state());
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        let response = application
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/configuration")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie)
                    .header("x-csrf-token", csrf)
                    .body(Body::from(r#"{"ue_count":11,"gnb_count":3}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn configuration_apply_runs_external_preflight_on_blocking_pool() {
        let mut test_state = state();
        test_state.execution_mode = "live".into();
        test_state.additional_ue_live_enabled = true;
        let verification_thread = Arc::new(Mutex::new(None));
        test_state.ue_runtime = Arc::new(ThreadRecordingRuntime {
            verification_thread: verification_thread.clone(),
        });
        let application = app(test_state);
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        let async_worker = std::thread::current().id();
        let response = application
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/configuration")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie)
                    .header("x-csrf-token", csrf)
                    .body(Body::from(r#"{"ue_count":3,"gnb_count":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_ne!(verification_thread.lock().unwrap().unwrap(), async_worker);
    }

    #[tokio::test]
    async fn configuration_apply_rejects_unavailable_provisioned_profiles_before_launch() {
        let mut test_state = state();
        test_state.execution_mode = "live".into();
        test_state.additional_ue_live_enabled = true;
        let launched = Arc::new(Mutex::new(Vec::new()));
        test_state.ue_runtime = Arc::new(FakeLiveUeRuntime {
            stopped: Arc::new(Mutex::new(Vec::new())),
            launched: launched.clone(),
            fail_observation: false,
            fail_verification: true,
            fail_stop: false,
        });
        let application = app(test_state);
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        let response = application
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/configuration")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie)
                    .header("x-csrf-token", csrf)
                    .body(Body::from(r#"{"ue_count":3,"gnb_count":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(launched.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn configuration_apply_rejects_resource_budget_failure_before_launch() {
        let mut test_state = state();
        test_state.execution_mode = "live".into();
        test_state.additional_ue_live_enabled = true;
        test_state.resource_override = Some(Err("INSUFFICIENT_UE_MEMORY_BUDGET".into()));
        let launched = Arc::new(Mutex::new(Vec::new()));
        test_state.ue_runtime = Arc::new(FakeLiveUeRuntime {
            stopped: Arc::new(Mutex::new(Vec::new())),
            launched: launched.clone(),
            fail_observation: false,
            fail_verification: false,
            fail_stop: false,
        });
        let application = app(test_state);
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        let response = application
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/configuration")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie)
                    .header("x-csrf-token", csrf)
                    .body(Body::from(r#"{"ue_count":3,"gnb_count":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(launched.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn rapid_configuration_updates_create_only_one_reconciliation_job() {
        let test_state = state();
        let coordinator = test_state.ue_operations.clone();
        let application = app(test_state);
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        let guard = coordinator.lock().unwrap();
        let request = |count| {
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/configuration")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::from(
                    json!({"ue_count":count,"gnb_count":1}).to_string(),
                ))
                .unwrap()
        };
        let (first, second) = tokio::join!(
            application.clone().oneshot(request(3)),
            application.clone().oneshot(request(5)),
        );
        drop(guard);
        let statuses = [first.unwrap().status(), second.unwrap().status()];
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::ACCEPTED)
                .count(),
            1
        );
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::CONFLICT)
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn durable_desired_count_resumes_reconciliation_after_controller_restart() {
        let mut test_state = state();
        test_state.execution_mode = "live".into();
        test_state.additional_ue_live_enabled = true;
        test_state.startup_reconcile = true;
        test_state.configuration.lock().unwrap().ue_count = 3;
        test_state
            .multi_ue
            .lock()
            .unwrap()
            .configure_count(3)
            .unwrap();
        let launched = Arc::new(Mutex::new(Vec::new()));
        test_state.ue_runtime = Arc::new(FakeLiveUeRuntime {
            stopped: Arc::new(Mutex::new(Vec::new())),
            launched: launched.clone(),
            fail_observation: false,
            fail_verification: false,
            fail_stop: false,
        });
        let running = test_state.ue_reconciliation_running.clone();
        let _application = app(test_state);
        for _ in 0..100 {
            if !running.load(Ordering::Acquire) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(launched.lock().unwrap().as_slice(), &["UE-02", "UE-03"]);
    }

    #[test]
    fn provisioning_hashes_password_and_never_persists_plaintext() {
        let path = PathBuf::from(format!(
            "/tmp/polaris-user-test-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        provision_user(&path, "operator-one", "operator", OPERATOR_PASSWORD).unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains(OPERATOR_PASSWORD));
        assert!(raw.contains("$argon2"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn cpu_decision_evidence_is_private_atomic_and_bounded() {
        use std::os::unix::fs::PermissionsExt;

        let test_state = state();
        let mut monitor = CpuSafetyMonitor::default();
        for _ in 0..(MAX_CPU_DECISIONS + 12) {
            let evidence = monitor.evaluate(ScenarioResourceBudget::traffic());
            persist_cpu_decision(&test_state, &evidence).unwrap();
        }
        let raw = fs::read_to_string(&test_state.cpu_decision_path).unwrap();
        let records: Vec<Value> = serde_json::from_str(&raw).unwrap();
        assert_eq!(records.len(), MAX_CPU_DECISIONS);
        assert!(records.iter().all(|record| {
            record["decision_id"].is_string()
                && record["classification"] == "BLOCKED"
                && record["budget"]["id"] == "BOUNDED_UDP_TRAFFIC"
        }));
        assert_eq!(
            fs::metadata(&test_state.cpu_decision_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(!raw.contains(OPERATOR_PASSWORD));
    }

    #[test]
    fn cpu_error_response_exposes_the_exact_durable_decision() {
        let test_state = state();
        let evidence = CpuSafetyMonitor::default().evaluate(ScenarioResourceBudget::traffic());
        *test_state.latest_cpu_decision.lock().unwrap() = Some(evidence.clone());
        let response = cpu_error_response(&test_state, &evidence.state);
        assert_eq!(response["error"], evidence.state);
        assert_eq!(
            response["cpu_decision"]["decision_id"],
            evidence.decision_id
        );
        assert_eq!(response["cpu_decision"]["blocking"], true);
    }

    #[tokio::test]
    async fn profile_mutation_requires_operator_and_migration_fails_closed() {
        std::env::remove_var("POLARIS_LEGACY_MIGRATION_ENABLED");
        let application = app(state());
        let anonymous = application
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/ue-profiles")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "ue_id":"UE-05","name":"test","supi":"imsi-001010000000005",
                            "authentication_key":"11".repeat(16),"opc":"22".repeat(16),
                            "plmn_mcc":"001","plmn_mnc":"01","dnn":"internet","sst":1,
                            "sd":"010203","serving_gnb":"GNB-01","scenario_id":null,
                            "auto_run_scenario":false
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(anonymous.status(), StatusCode::FORBIDDEN);

        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        let blocked = application
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/ues/legacy/migration/execute")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie)
                    .header("x-csrf-token", csrf)
                    .body(Body::from(
                        json!({
                            "ue_id":"UE-01",
                            "source_container_id":"a".repeat(64),
                            "confirmation":"TRANSFER_UE01_TO_POLARIS"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blocked.status(), StatusCode::LOCKED);
    }

    #[tokio::test]
    async fn profile_inventory_is_server_paginated_and_searchable() {
        let application = app(state());
        let response = application
            .oneshot(
                Request::builder()
                    .uri("/api/v1/ue-profiles?page=2&page_size=3&search=UE-")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["page"], 2);
        assert_eq!(body["page_size"], 3);
        assert!(body["total"].as_u64().unwrap() >= 4);
        assert_eq!(body["items"].as_array().unwrap().len(), 3);
        assert!(body.to_string().find("authentication_key").is_none());
    }

    fn profile_http_input(ue_id: &str, supi: &str, name: &str) -> Value {
        json!({
            "ue_id":ue_id,"name":name,"supi":supi,
            "authentication_key":"11".repeat(16),"opc":"22".repeat(16),
            "plmn_mcc":"001","plmn_mnc":"01","dnn":"internet","sst":1,
            "sd":"010203","serving_gnb":"GNB-01","scenario_id":"scenario-a",
            "auto_run_scenario":false
        })
    }

    fn profile_http_request(
        method: Method,
        uri: &str,
        body: Value,
        cookie: &str,
        csrf: &str,
    ) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, cookie)
            .header("x-csrf-token", csrf)
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn create_http_profile(
        application: &Router,
        cookie: &str,
        csrf: &str,
        ue_id: &str,
        supi: &str,
    ) {
        let response = application
            .clone()
            .oneshot(profile_http_request(
                Method::POST,
                "/api/v1/ue-profiles",
                profile_http_input(ue_id, supi, ue_id),
                cookie,
                csrf,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn ue_profile_http_put_succeeds_for_stopped_profile() {
        let application = app(state());
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        create_http_profile(
            &application,
            &cookie,
            &csrf,
            "UE-11",
            "imsi-001010000000011",
        )
        .await;
        let mut update = profile_http_input("UE-11", "imsi-001010000000011", "UE 11 updated");
        update["supi"] = Value::Null;
        update["authentication_key"] = Value::Null;
        update["opc"] = Value::Null;
        let response = application
            .oneshot(profile_http_request(
                Method::PUT,
                "/api/v1/ue-profiles/UE-11",
                update,
                &cookie,
                &csrf,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ue_profile_http_unknown_serving_gnb_is_rejected() {
        let application = app(state());
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        let mut input = profile_http_input("UE-13", "imsi-001010000000013", "UE 13");
        input["serving_gnb"] = json!("GNB-99");
        let response = application
            .oneshot(profile_http_request(
                Method::POST,
                "/api/v1/ue-profiles",
                input,
                &cookie,
                &csrf,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["error"], "UNKNOWN_SERVING_GNB");
    }

    #[tokio::test]
    async fn gnbs_http_lists_the_registry_without_secrets() {
        let application = app(state());
        let (cookie, _csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        let response = application
            .oneshot(
                Request::builder()
                    .uri("/api/v1/gnbs")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["gnb_id"], "GNB-01");
        assert_eq!(body["items"][0]["link_ip"], "10.77.0.20");
        assert_eq!(body["source"], "LAB_DEFAULT");
    }

    #[tokio::test]
    async fn ue_profile_http_clone_succeeds_for_stopped_profile() {
        let application = app(state());
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        create_http_profile(
            &application,
            &cookie,
            &csrf,
            "UE-11",
            "imsi-001010000000011",
        )
        .await;
        let response = application
            .oneshot(profile_http_request(
                Method::POST,
                "/api/v1/ue-profiles/UE-11/clone",
                json!({"target_ue_id":"UE-12"}),
                &cookie,
                &csrf,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn ue_profile_http_delete_succeeds_for_stopped_profile() {
        let application = app(state());
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        create_http_profile(
            &application,
            &cookie,
            &csrf,
            "UE-11",
            "imsi-001010000000011",
        )
        .await;
        let response = application
            .oneshot(profile_http_request(
                Method::DELETE,
                "/api/v1/ue-profiles/UE-11",
                json!({}),
                &cookie,
                &csrf,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn scenario_definition_http_contract_is_versioned_strict_and_step_observable() {
        let application = app(state());
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;
        let request = |method: Method, uri: &str, body: Value| {
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::from(body.to_string()))
                .unwrap()
        };
        let definition = |id: &str, name: &str, step_type: &str| {
            json!({
                "id":id,"name":name,
                "loop_count":2,
                "steps":[{
                    "type":step_type,"loop_count":2,
                    "parameters":{"duration_ms":{"random":{"min":10,"max":20}}}
                }]
            })
        };
        let unsupported = application
            .clone()
            .oneshot(request(
                Method::POST,
                "/api/v1/scenario-definitions",
                definition("bad", "bad", "rrc_idle"),
            ))
            .await
            .unwrap();
        assert_eq!(unsupported.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let error: Value =
            serde_json::from_slice(&to_bytes(unsupported.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(error["error"], "SCENARIO_STEP_TYPE_UNSUPPORTED");

        let created = application
            .clone()
            .oneshot(request(
                Method::POST,
                "/api/v1/scenario-definitions",
                definition("scenario-one", "one", "wait"),
            ))
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);

        let listed = application
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/scenario-definitions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(listed.status(), StatusCode::OK);
        let listed: Value =
            serde_json::from_slice(&to_bytes(listed.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(listed["total"], 1);
        assert_eq!(listed["schema_version"], 1);

        let fetched = application
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/scenario-definitions/scenario-one")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(fetched.status(), StatusCode::OK);
        let fetched: Value =
            serde_json::from_slice(&to_bytes(fetched.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(fetched["id"], "scenario-one");
        assert_eq!(fetched["version"], 1);

        let updated = application
            .clone()
            .oneshot(request(
                Method::PUT,
                "/api/v1/scenario-definitions/scenario-one",
                definition("scenario-one", "two", "wait"),
            ))
            .await
            .unwrap();
        let updated: Value =
            serde_json::from_slice(&to_bytes(updated.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(updated["version"], 2);
        let cloned = application
            .clone()
            .oneshot(request(
                Method::POST,
                "/api/v1/scenario-definitions/scenario-one/clone",
                json!({"target_id":"scenario-two"}),
            ))
            .await
            .unwrap();
        assert_eq!(cloned.status(), StatusCode::CREATED);

        let duplicate_selection = application
            .clone()
            .oneshot(request(
                Method::POST,
                "/api/v1/scenarios/start",
                json!({"scenario_definition_id":"scenario-one","ue_ids":["UE-02","UE-02"]}),
            ))
            .await
            .unwrap();
        assert_eq!(
            duplicate_selection.status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );

        let started = application
            .clone()
            .oneshot(request(
                Method::POST,
                "/api/v1/scenarios/start",
                json!({"scenario_definition_id":"scenario-one","ue_ids":["UE-02"]}),
            ))
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::OK);
        let job: Value =
            serde_json::from_slice(&to_bytes(started.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(job["steps"].as_array().unwrap().len(), 4);
        assert!(job["steps"].as_array().unwrap().iter().all(|step| {
            step["state"] == "COMPLETED"
                && step["scenario_loop"]["count"] == 2
                && step["step_loop"]["count"] == 2
                && (10..=20).contains(&step["resolved_parameters"]["duration_ms"].as_i64().unwrap())
        }));
        let steps = application
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/scenarios/{}/steps",
                        job["job_id"].as_str().unwrap()
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(steps.status(), StatusCode::OK);

        for id in ["scenario-two", "scenario-one"] {
            let deleted = application
                .clone()
                .oneshot(request(
                    Method::DELETE,
                    &format!("/api/v1/scenario-definitions/{id}"),
                    json!({}),
                ))
                .await
                .unwrap();
            assert_eq!(deleted.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn scenario_template_export_import_estimate_and_unavailable_steps_are_honest() {
        let test_state = state();
        test_state.scenario_catalog.lock().unwrap().definitions =
            scenario_definitions::builtin_templates();
        let application = app(test_state);
        let (cookie, csrf) = login_session(&application, "operator-test", OPERATOR_PASSWORD).await;

        let estimate = application
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/scenario-definitions/tpl-high-runner/estimate")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(estimate.status(), StatusCode::OK);

        let exported = application
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/scenario-definitions/tpl-high-runner/export")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(exported.status(), StatusCode::OK);
        assert!(exported
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("tpl-high-runner-v1.json"));
        let exported_bytes = to_bytes(exported.into_body(), usize::MAX).await.unwrap();

        let imported = application
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/scenario-definitions/import?rename=high-runner-copy")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::from(exported_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(imported.status(), StatusCode::CREATED);
        let imported: Value =
            serde_json::from_slice(&to_bytes(imported.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(imported["id"], "high-runner-copy");

        for (id, expected, error) in [
            ("tpl-voice-short", StatusCode::LOCKED, "IMS_NOT_AVAILABLE"),
            (
                "tpl-small-traffic",
                StatusCode::UNPROCESSABLE_ENTITY,
                "DL_SENDER_NOT_AVAILABLE",
            ),
        ] {
            let response = application
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/api/v1/scenarios/start")
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(header::COOKIE, &cookie)
                        .header("x-csrf-token", &csrf)
                        .body(Body::from(
                            json!({"scenario_definition_id":id,"ue_ids":["UE-02"]}).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(body["error"], error);
        }
    }

    fn install_definition(
        test_state: &mut AppState,
        id: &str,
        steps: Vec<scenario_definitions::ScenarioStep>,
    ) {
        let now = epoch_seconds();
        test_state
            .scenario_catalog
            .lock()
            .unwrap()
            .definitions
            .push(scenario_definitions::ScenarioDefinition {
                id: id.into(),
                name: id.into(),
                version: 1,
                loop_count: 1,
                steps,
                created_at_epoch_s: now,
                updated_at_epoch_s: now,
            });
    }

    fn fixed_parameter(value: Value) -> scenario_definitions::ParameterSpec {
        scenario_definitions::ParameterSpec::Fixed { fixed: value }
    }

    #[test]
    fn definition_live_execution_is_locked_by_default() {
        let test_state = Arc::new(state());
        let error =
            start_live_definition_scenario(test_state, "missing", &["UE-02".into()]).unwrap_err();
        assert_eq!(error.0, StatusCode::LOCKED);
        assert_eq!(
            error.1 .0["error"],
            "SCENARIO_DEFINITION_LIVE_EXECUTION_NOT_AUTHORIZED"
        );
    }

    #[test]
    fn definition_recovery_fails_interrupted_step_closed() {
        let recovered = recover_runtime(Some(json!({
            "active":Value::Null,
            "history":[{
                "job_id":"definition-restart",
                "scenario_definition_id":"definition",
                "state":"RUNNING",
                "started_at_epoch_s":1,
                "steps":[{"state":"RUNNING","error":Value::Null}]
            }]
        })));
        assert_eq!(recovered.history[0]["state"], "FAILED");
        assert_eq!(
            recovered.history[0]["terminal_result"],
            "CONTROLLER_RESTART_RECOVERY"
        );
        assert_eq!(recovered.history[0]["steps"][0]["state"], "FAILED");
        assert_eq!(
            recovered.history[0]["steps"][0]["error"],
            "CONTROLLER_RESTART_INTERRUPTED_STEP"
        );
    }

    #[test]
    fn live_definition_reports_real_step_transitions_without_host_execution() {
        let mut test_state = state();
        test_state.execution_mode = "live".into();
        test_state.definition_live_enabled = true;
        test_state.additional_ue_live_enabled = true;
        test_state
            .multi_ue
            .lock()
            .unwrap()
            .configure_count(2)
            .unwrap();
        install_definition(
            &mut test_state,
            "live-state-test",
            vec![
                scenario_definitions::ScenarioStep {
                    step_type: "ue_start".into(),
                    loop_count: 1,
                    parameters: BTreeMap::new(),
                    steps: Vec::new(),
                },
                scenario_definitions::ScenarioStep {
                    step_type: "pdu_establish".into(),
                    loop_count: 1,
                    parameters: BTreeMap::from([(
                        "timeout_seconds".into(),
                        fixed_parameter(json!(1)),
                    )]),
                    steps: Vec::new(),
                },
                scenario_definitions::ScenarioStep {
                    step_type: "wait".into(),
                    loop_count: 1,
                    parameters: BTreeMap::from([("duration_ms".into(), fixed_parameter(json!(1)))]),
                    steps: Vec::new(),
                },
                scenario_definitions::ScenarioStep {
                    step_type: "udp_traffic".into(),
                    loop_count: 1,
                    parameters: BTreeMap::from([(
                        "packet_count".into(),
                        fixed_parameter(json!(5)),
                    )]),
                    steps: Vec::new(),
                },
                scenario_definitions::ScenarioStep {
                    step_type: "pdu_release".into(),
                    loop_count: 1,
                    parameters: BTreeMap::new(),
                    steps: Vec::new(),
                },
                scenario_definitions::ScenarioStep {
                    step_type: "ue_stop".into(),
                    loop_count: 1,
                    parameters: BTreeMap::new(),
                    steps: Vec::new(),
                },
            ],
        );
        let state = Arc::new(test_state);
        let record =
            start_live_definition_scenario(state.clone(), "live-state-test", &["UE-02".into()])
                .unwrap();
        let job_id = record["job_id"].as_str().unwrap().to_string();
        for _ in 0..200 {
            let terminal = state
                .runtime
                .lock()
                .unwrap()
                .history
                .iter()
                .find(|item| item["job_id"] == job_id)
                .cloned()
                .unwrap();
            if terminal["state"] != "RUNNING" {
                assert_eq!(terminal["state"], "COMPLETED");
                assert!(terminal["steps"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|step| step["state"] == "COMPLETED"));
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("definition job did not terminate");
    }

    #[test]
    fn operator_stop_cancels_definition_and_cleans_only_job_started_ues() {
        let mut test_state = state();
        test_state.execution_mode = "live".into();
        test_state.definition_live_enabled = true;
        test_state.additional_ue_live_enabled = true;
        test_state
            .multi_ue
            .lock()
            .unwrap()
            .configure_count(2)
            .unwrap();
        install_definition(
            &mut test_state,
            "cancel-test",
            vec![
                scenario_definitions::ScenarioStep {
                    step_type: "ue_start".into(),
                    loop_count: 1,
                    parameters: BTreeMap::new(),
                    steps: Vec::new(),
                },
                scenario_definitions::ScenarioStep {
                    step_type: "wait".into(),
                    loop_count: 1,
                    parameters: BTreeMap::from([(
                        "duration_ms".into(),
                        fixed_parameter(json!(5_000)),
                    )]),
                    steps: Vec::new(),
                },
            ],
        );
        let state = Arc::new(test_state);
        let record =
            start_live_definition_scenario(state.clone(), "cancel-test", &["UE-02".into()])
                .unwrap();
        let job_id = record["job_id"].as_str().unwrap().to_string();
        for _ in 0..100 {
            let started = state
                .definition_jobs
                .lock()
                .unwrap()
                .get(&job_id)
                .unwrap()
                .started_ues
                .lock()
                .unwrap()
                .contains("UE-02");
            if started {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        state
            .definition_jobs
            .lock()
            .unwrap()
            .get(&job_id)
            .unwrap()
            .cancel
            .store(true, Ordering::SeqCst);
        for _ in 0..200 {
            if !state.definition_jobs.lock().unwrap().contains_key(&job_id) {
                let terminal = state
                    .runtime
                    .lock()
                    .unwrap()
                    .history
                    .iter()
                    .find(|item| item["job_id"] == job_id)
                    .cloned()
                    .unwrap();
                assert_eq!(terminal["state"], "STOPPED");
                let ue = state
                    .multi_ue
                    .lock()
                    .unwrap()
                    .snapshot()
                    .into_iter()
                    .find(|item| item.ue_id == "UE-02")
                    .unwrap();
                assert_ne!(ue.process_state, "RUNNING");
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("definition cancellation did not terminate");
    }
}
