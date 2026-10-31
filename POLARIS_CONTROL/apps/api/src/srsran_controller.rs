use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::process::Command;
use std::sync::{Arc, Mutex};

pub const VERSION: &str = "0.2.0";
pub const LTE_UE_ID: &str = "LTE-SRSUE-TEST-01";
pub const ENB_ID: &str = "ENB-01";
const ENB_CONTAINER: &str = "oiran-lab-srsenb-1";
const UE_CONTAINER: &str = "oiran-lab-srsue-1";
const EPC_CONTAINER: &str = "oiran-lab-mme-1";
const COMPOSE_FILE: &str = "/root/POLARIS/compose/docker-compose.oiran-lab.yml";
const ENV_FILE: &str = "/root/POLARIS/compose/versions.env";
const COMPOSE_PROJECT: &str = "oiran-lab";
const EXPECTED_IMAGE_DIGEST: &str =
    "sha256:69e094349657cc6a062ce3717661d6b8a553a23ce571f821e33256beec753d43";
const PROFILE_CONFIGS: [&str; 5] = [
    "/root/POLARIS/runtime/srsran/ue.conf",
    "/root/POLARIS/config/srsran/enb.conf",
    "/root/POLARIS/config/srsran/rr.conf",
    COMPOSE_FILE,
    ENV_FILE,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target {
    Enb,
    Ue,
}

impl Target {
    pub fn parse(component: &str, ue_id: Option<&str>) -> Result<Self, String> {
        match component {
            "ENB-01" if ue_id.is_none() => Ok(Self::Enb),
            LTE_UE_ID if ue_id.is_none() || ue_id == Some(LTE_UE_ID) => Ok(Self::Ue),
            _ => Err("SRSRAN_TARGET_NOT_ALLOWLISTED".into()),
        }
    }

    fn container(self) -> &'static str {
        match self {
            Self::Enb => ENB_CONTAINER,
            Self::Ue => UE_CONTAINER,
        }
    }

    fn service(self) -> &'static str {
        match self {
            Self::Enb => "srsenb",
            Self::Ue => "srsue",
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Self::Enb => ENB_ID,
            Self::Ue => LTE_UE_ID,
        }
    }
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct ProcessObservation {
    pub process_state: String,
    pub health: String,
    pub observed: bool,
    pub last_error: Option<String>,
}

impl ProcessObservation {
    fn unavailable() -> Self {
        Self {
            process_state: "NOT_OBSERVED".into(),
            health: "unknown".into(),
            observed: false,
            last_error: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct LteStatus {
    pub technology: &'static str,
    pub simulator: &'static str,
    pub certified: bool,
    pub live_enabled: bool,
    pub epc: ProcessObservation,
    pub s1_state: String,
    pub enb: ProcessObservation,
    pub ue: ProcessObservation,
    pub ue_id: &'static str,
    pub attach_state: String,
    pub apn: &'static str,
    pub ue_ip: Option<String>,
    pub active_sessions: u8,
}

pub trait SrsranRuntime: Send + Sync {
    fn status(&self, certified: bool, live_enabled: bool) -> Result<LteStatus, String>;
    fn start(&self, target: Target) -> Result<(), String>;
    fn stop(&self, target: Target) -> Result<(), String>;
    fn logs(&self, target: Target) -> Result<Vec<String>, String>;
}

#[derive(Default)]
pub struct DockerSrsranRuntime;

impl DockerSrsranRuntime {
    fn verify_ownership(target: Target) -> Result<(), String> {
        let format = "{{index .Config.Labels \"com.docker.compose.project\"}}|{{index .Config.Labels \"com.docker.compose.service\"}}|{{.Image}}";
        let output = Command::new("docker")
            .args(["inspect", "--format", format, target.container()])
            .output()
            .map_err(|_| "SRSRAN_RUNTIME_UNAVAILABLE")?;
        if !output.status.success() {
            return Err("LTE_RUNTIME_OWNERSHIP_CONFLICT".into());
        }
        let observed = String::from_utf8_lossy(&output.stdout);
        let mut fields = observed.trim().split('|');
        if fields.next().unwrap_or_default() != COMPOSE_PROJECT
            || fields.next().unwrap_or_default() != target.service()
            || fields.next().unwrap_or_default() != EXPECTED_IMAGE_DIGEST
        {
            return Err("LTE_RUNTIME_OWNERSHIP_CONFLICT".into());
        }
        Ok(())
    }

    fn observe_container(name: &str) -> ProcessObservation {
        let output = Command::new("docker")
            .args([
                "inspect",
                "--format",
                "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}not_available{{end}}|{{.State.Error}}",
                name,
            ])
            .output();
        let Ok(output) = output else {
            return ProcessObservation::unavailable();
        };
        if !output.status.success() {
            return ProcessObservation::unavailable();
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let mut fields = text.trim().splitn(3, '|');
        ProcessObservation {
            process_state: fields.next().unwrap_or("unknown").to_string(),
            health: fields.next().unwrap_or("unknown").to_string(),
            observed: true,
            last_error: fields
                .next()
                .filter(|value| !value.is_empty())
                .map(|_| "CONTAINER_REPORTED_ERROR".to_string()),
        }
    }

    fn filtered_logs(name: &str) -> Result<Vec<String>, String> {
        let output = Command::new("docker")
            .args(["logs", "--tail", "200", name])
            .output()
            .map_err(|_| "SRSRAN_LOGS_UNAVAILABLE")?;
        if !output.status.success() {
            return Err("SRSRAN_LOGS_UNAVAILABLE".into());
        }
        let mut combined = output.stdout;
        combined.extend_from_slice(&output.stderr);
        Ok(String::from_utf8_lossy(&combined)
            .lines()
            .filter_map(sanitize_log_line)
            .collect())
    }

    fn run_exact(target: Target, verb: &str) -> Result<(), String> {
        Self::verify_ownership(target)?;
        let action = match verb {
            "start" => "start",
            "stop" => "stop",
            _ => return Err("SRSRAN_ACTION_NOT_ALLOWLISTED".into()),
        };
        let mut command = Command::new("/usr/bin/timeout");
        command.args([
            "30s", "docker", "compose", "--project-name", COMPOSE_PROJECT, "--file",
            COMPOSE_FILE, "--env-file", ENV_FILE, action, target.service(),
        ]);
        let status = command.status().map_err(|_| "SRSRAN_RUNTIME_UNAVAILABLE")?;
        status
            .success()
            .then_some(())
            .ok_or_else(|| "SRSRAN_ACTION_FAILED".into())
    }
}

pub fn profile_configuration_sha256() -> Result<String, String> {
    let mut hasher = Sha256::new();
    for path in PROFILE_CONFIGS {
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update(fs::read(path).map_err(|_| "LTE_PROFILE_CONFIGURATION_UNREADABLE")?);
        hasher.update([0]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

impl SrsranRuntime for DockerSrsranRuntime {
    fn status(&self, certified: bool, live_enabled: bool) -> Result<LteStatus, String> {
        let enb = Self::observe_container(ENB_CONTAINER);
        let ue = Self::observe_container(UE_CONTAINER);
        let epc = Self::observe_container(EPC_CONTAINER);
        let logs = Self::filtered_logs(UE_CONTAINER).unwrap_or_default();
        let attached = logs.iter().any(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("attach complete") || lower.contains("network attach successful")
        });
        let s1_connected = Self::filtered_logs(ENB_CONTAINER)
            .unwrap_or_default()
            .iter()
            .any(|line| line.to_ascii_lowercase().contains("s1 setup"));
        Ok(LteStatus {
            technology: "LTE 4G",
            simulator: "srsRAN",
            certified,
            live_enabled,
            epc,
            s1_state: if s1_connected {
                "CONNECTED"
            } else {
                "NOT_OBSERVED"
            }
            .into(),
            enb,
            ue: ue.clone(),
            ue_id: LTE_UE_ID,
            attach_state: if attached {
                "ATTACHED"
            } else if ue.process_state == "running" {
                "NOT_OBSERVED"
            } else {
                "DETACHED"
            }
            .into(),
            apn: "internet",
            ue_ip: None,
            active_sessions: u8::from(attached),
        })
    }

    fn start(&self, target: Target) -> Result<(), String> {
        Self::run_exact(target, "start")
    }

    fn stop(&self, target: Target) -> Result<(), String> {
        Self::run_exact(target, "stop")
    }

    fn logs(&self, target: Target) -> Result<Vec<String>, String> {
        Self::filtered_logs(target.container())
    }
}

fn sanitize_log_line(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let secret_markers = ["imsi", "supi", "opc", "auth key", "subscriber key", " ki="];
    if secret_markers.iter().any(|marker| lower.contains(marker)) {
        return Some("[REDACTED_SUBSCRIBER_MATERIAL]".into());
    }
    let trimmed = line.trim();
    (!trimmed.is_empty()).then(|| trimmed.chars().take(500).collect())
}

#[derive(Clone, Default)]
pub struct MockSrsranRuntime {
    pub started: Arc<Mutex<Vec<String>>>,
    pub stopped: Arc<Mutex<Vec<String>>>,
}

impl SrsranRuntime for MockSrsranRuntime {
    fn status(&self, certified: bool, live_enabled: bool) -> Result<LteStatus, String> {
        Ok(LteStatus {
            technology: "LTE 4G",
            simulator: "srsRAN",
            certified,
            live_enabled,
            epc: ProcessObservation::unavailable(),
            s1_state: "NOT_OBSERVED".into(),
            enb: ProcessObservation::unavailable(),
            ue: ProcessObservation::unavailable(),
            ue_id: LTE_UE_ID,
            attach_state: "DETACHED".into(),
            apn: "internet",
            ue_ip: None,
            active_sessions: 0,
        })
    }

    fn start(&self, target: Target) -> Result<(), String> {
        self.started.lock().unwrap().push(target.id().into());
        Ok(())
    }

    fn stop(&self, target: Target) -> Result<(), String> {
        self.stopped.lock().unwrap().push(target.id().into());
        Ok(())
    }

    fn logs(&self, _target: Target) -> Result<Vec<String>, String> {
        Ok(vec!["mock log".into()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_allowlist_rejects_arbitrary_container_or_ue() {
        assert_eq!(Target::parse("ENB-01", None), Ok(Target::Enb));
        assert_eq!(Target::parse(LTE_UE_ID, Some(LTE_UE_ID)), Ok(Target::Ue));
        assert_eq!(
            Target::parse("../../docker", None),
            Err("SRSRAN_TARGET_NOT_ALLOWLISTED".into())
        );
        assert!(Target::parse(LTE_UE_ID, Some("LTE-UE-99")).is_err());
    }

    #[test]
    fn subscriber_material_is_redacted_from_logs() {
        assert_eq!(
            sanitize_log_line("IMSI 001010000000001 attach"),
            Some("[REDACTED_SUBSCRIBER_MATERIAL]".into())
        );
        assert_eq!(
            sanitize_log_line("S1 setup complete"),
            Some("S1 setup complete".into())
        );
    }

    #[test]
    fn mock_runtime_never_starts_a_real_process() {
        let runtime = MockSrsranRuntime::default();
        runtime.start(Target::Enb).unwrap();
        runtime.stop(Target::Ue).unwrap();
        assert_eq!(*runtime.started.lock().unwrap(), vec![ENB_ID]);
        assert_eq!(*runtime.stopped.lock().unwrap(), vec![LTE_UE_ID]);
    }
}
