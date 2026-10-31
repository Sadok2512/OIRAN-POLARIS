use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

pub const VERSION: &str = "0.2.0";
pub const LTE_UE_ID: &str = "LTE-SRSUE-TEST-01";
pub const ENB_ID: &str = "ENB-01";
const PROJECT: &str = "oiran-lab";
const COMPOSE: &str = "/root/POLARIS/compose/docker-compose.oiran-lab.yml";
const ENV_FILE: &str = "/root/POLARIS/compose/versions.env";
const UE_CONFIG: &str = "/root/POLARIS/runtime/srsran/ue.conf";
const LEDGER: &str = "/var/lib/polaris-control/srsran-ownership.json";
const EXPECTED_IMAGE_REFERENCE: &str =
    "oiran/srsran4g@sha256:69e094349657cc6a062ce3717661d6b8a553a23ce571f821e33256beec753d43";
const PROFILE_CONFIGS: [&str; 5] = [
    "/root/POLARIS/runtime/srsran/ue.conf",
    "/root/POLARIS/config/srsran/enb.conf",
    "/root/POLARIS/config/srsran/rr.conf",
    COMPOSE,
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
            ENB_ID if ue_id.is_none() => Ok(Self::Enb),
            LTE_UE_ID if ue_id.is_none() || ue_id == Some(LTE_UE_ID) => Ok(Self::Ue),
            _ => Err("SRSRAN_TARGET_NOT_ALLOWLISTED".into()),
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

#[derive(Clone, Debug)]
struct Output {
    code: i32,
    stdout: String,
    stderr: String,
}
trait Executor: Send + Sync {
    fn run(&self, args: &[String], seconds: u64) -> Result<Output, String>;
}
#[derive(Default)]
struct HostExecutor;
impl Executor for HostExecutor {
    fn run(&self, args: &[String], seconds: u64) -> Result<Output, String> {
        let limit = format!("{}s", seconds.max(1));
        let result = Command::new("/usr/bin/timeout")
            .args([
                "--signal=TERM",
                "--kill-after=2s",
                &limit,
                "/usr/bin/docker",
            ])
            .args(args)
            .output()
            .map_err(|_| "SRSRAN_RUNTIME_UNAVAILABLE".to_string())?;
        let code = result.status.code().unwrap_or(137);
        classify_exit(code)?;
        Ok(Output {
            code,
            stdout: String::from_utf8_lossy(&result.stdout).into(),
            stderr: String::from_utf8_lossy(&result.stderr).into(),
        })
    }
}

fn classify_exit(code: i32) -> Result<(), String> {
    if matches!(code, 124 | 137) {
        Err("SRSRAN_COMMAND_TIMEOUT".into())
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct ProcessObservation {
    pub process_state: String,
    pub health: String,
    pub observed: bool,
    pub controller_owned: bool,
    pub last_error: Option<String>,
}
impl ProcessObservation {
    fn unknown() -> Self {
        Self {
            process_state: "UNKNOWN".into(),
            health: "unknown".into(),
            observed: false,
            controller_owned: false,
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
    pub apn: String,
    pub ue_ip: Option<String>,
    pub session_state: String,
    pub active_sessions: u8,
    pub ownership_verified: bool,
    pub traffic_ready: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrafficMeasurement {
    pub bytes_ul: u64,
    pub bytes_dl: u64,
    pub rate_ul_bps: Option<u64>,
    pub rate_dl_bps: Option<u64>,
}

pub trait SrsranRuntime: Send + Sync {
    fn status(&self, certified: bool, live_enabled: bool) -> Result<LteStatus, String>;
    fn start(&self, target: Target) -> Result<(), String>;
    fn stop(&self, target: Target) -> Result<(), String>;
    fn logs(&self, target: Target) -> Result<Vec<String>, String>;
    fn verify_ownership(&self, target: Target) -> Result<(), String>;
    fn measure_traffic(
        &self,
        direction: &str,
        protocol: &str,
        rate_mbps: u32,
    ) -> Result<TrafficMeasurement, String>;
}

#[derive(Clone)]
struct Container {
    id: String,
    state: String,
    health: String,
    error: String,
}
#[derive(Default, Serialize, Deserialize)]
struct Ownership {
    schema: u8,
    project: String,
    compose: String,
    components: BTreeMap<String, String>,
}

pub struct DockerSrsranRuntime {
    executor: Arc<dyn Executor>,
    ledger: PathBuf,
}
impl Default for DockerSrsranRuntime {
    fn default() -> Self {
        Self {
            executor: Arc::new(HostExecutor),
            ledger: PathBuf::from(
                std::env::var("POLARIS_SRSRAN_OWNERSHIP_LEDGER").unwrap_or_else(|_| LEDGER.into()),
            ),
        }
    }
}
impl DockerSrsranRuntime {
    fn run(&self, args: &[&str], seconds: u64) -> Result<Output, String> {
        self.executor.run(
            &args.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
            seconds,
        )
    }
    fn ok(output: Output, error: &str) -> Result<Output, String> {
        if output.code == 0 {
            Ok(output)
        } else {
            let _ = output.stderr;
            Err(error.into())
        }
    }
    fn resolve(&self, service: &str) -> Result<Option<Container>, String> {
        let pf = format!("label=com.docker.compose.project={PROJECT}");
        let sf = format!("label=com.docker.compose.service={service}");
        let found = Self::ok(
            self.run(&["ps", "-aq", "--filter", &pf, "--filter", &sf], 5)?,
            "SRSRAN_DISCOVERY_FAILED",
        )?;
        let ids = found
            .stdout
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        if ids.is_empty() {
            return Ok(None);
        }
        if ids.len() != 1 {
            return Err("SRSRAN_AMBIGUOUS_SERVICE_INSTANCE".into());
        }
        let fmt = "{{.Id}}|{{index .Config.Labels \"com.docker.compose.project\"}}|{{index .Config.Labels \"com.docker.compose.service\"}}|{{index .Config.Labels \"com.docker.compose.project.config_files\"}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}not_available{{end}}|{{.State.Error}}|{{.Config.Image}}";
        let data = Self::ok(
            self.run(&["inspect", "--format", fmt, ids[0]], 5)?,
            "SRSRAN_DISCOVERY_FAILED",
        )?;
        let f = data.stdout.trim().splitn(8, '|').collect::<Vec<_>>();
        let digest_matches = !matches!(service, "srsenb" | "srsue")
            || f.get(7)
                .is_some_and(|reference| *reference == EXPECTED_IMAGE_REFERENCE);
        if f.len() != 8 || f[1] != PROJECT || f[2] != service || f[3] != COMPOSE || !digest_matches
        {
            return Err("LTE_RUNTIME_OWNERSHIP_CONFLICT".into());
        }
        Ok(Some(Container {
            id: f[0].into(),
            state: f[4].into(),
            health: f[5].into(),
            error: f[6].into(),
        }))
    }
    fn load(&self) -> Result<Ownership, String> {
        let bytes = match fs::read(&self.ledger) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Ownership {
                    schema: 1,
                    project: PROJECT.into(),
                    compose: COMPOSE.into(),
                    components: BTreeMap::new(),
                })
            }
            Err(_) => return Err("SRSRAN_OWNERSHIP_LEDGER_UNAVAILABLE".into()),
        };
        let metadata =
            fs::metadata(&self.ledger).map_err(|_| "SRSRAN_OWNERSHIP_LEDGER_UNAVAILABLE")?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err("SRSRAN_OWNERSHIP_LEDGER_INSECURE".into());
        }
        let value: Ownership =
            serde_json::from_slice(&bytes).map_err(|_| "SRSRAN_OWNERSHIP_LEDGER_INVALID")?;
        if value.schema != 1 || value.project != PROJECT || value.compose != COMPOSE {
            return Err("SRSRAN_OWNERSHIP_LEDGER_INVALID".into());
        }
        Ok(value)
    }
    fn save(&self, value: &Ownership) -> Result<(), String> {
        let parent = self
            .ledger
            .parent()
            .ok_or_else(|| "SRSRAN_OWNERSHIP_LEDGER_INVALID".to_string())?;
        fs::create_dir_all(parent).map_err(|_| "SRSRAN_OWNERSHIP_LEDGER_UNAVAILABLE")?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|_| "SRSRAN_OWNERSHIP_LEDGER_UNAVAILABLE")?;
        let tmp = parent.join(format!(".srsran-ownership.{}.tmp", std::process::id()));
        let bytes = serde_json::to_vec(value).map_err(|_| "SRSRAN_OWNERSHIP_LEDGER_INVALID")?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|_| "SRSRAN_OWNERSHIP_LEDGER_UNAVAILABLE")?;
        if file
            .write_all(&bytes)
            .and_then(|_| file.sync_all())
            .is_err()
        {
            let _ = fs::remove_file(&tmp);
            return Err("SRSRAN_OWNERSHIP_LEDGER_UNAVAILABLE".into());
        }
        if fs::rename(&tmp, &self.ledger).is_err() {
            let _ = fs::remove_file(&tmp);
            return Err("SRSRAN_OWNERSHIP_LEDGER_UNAVAILABLE".into());
        }
        Ok(())
    }
    fn set_owned(&self, target: Target, id: Option<String>) -> Result<(), String> {
        let mut l = self.load()?;
        if let Some(id) = id {
            l.components.insert(target.service().into(), id);
        } else {
            l.components.remove(target.service());
        }
        self.save(&l)
    }
    fn owned(&self, target: Target) -> Result<Container, String> {
        let c = self
            .resolve(target.service())?
            .ok_or_else(|| "SRSRAN_SERVICE_NOT_FOUND".to_string())?;
        if self.load()?.components.get(target.service()) == Some(&c.id) {
            Ok(c)
        } else {
            Err("SRSRAN_CONTROLLER_OWNERSHIP_REQUIRED".into())
        }
    }
    fn is_owned(&self, target: Target, c: Option<&Container>) -> bool {
        self.load()
            .ok()
            .zip(c)
            .is_some_and(|(l, c)| l.components.get(target.service()) == Some(&c.id))
    }
    fn observe(&self, target: Target) -> Result<(ProcessObservation, Option<Container>), String> {
        let c = self.resolve(target.service())?;
        let owned = self.is_owned(target, c.as_ref());
        let o = c
            .as_ref()
            .map_or_else(ProcessObservation::unknown, |c| ProcessObservation {
                process_state: c.state.clone(),
                health: c.health.clone(),
                observed: true,
                controller_owned: owned,
                last_error: (!c.error.is_empty()).then(|| "CONTAINER_REPORTED_ERROR".into()),
            });
        Ok((o, c))
    }
    fn epc(&self) -> ProcessObservation {
        self.resolve("mme")
            .ok()
            .flatten()
            .map_or_else(ProcessObservation::unknown, |c| ProcessObservation {
                process_state: c.state,
                health: c.health,
                observed: true,
                controller_owned: false,
                last_error: (!c.error.is_empty()).then(|| "CONTAINER_REPORTED_ERROR".into()),
            })
    }
    fn s1(&self, c: Option<&Container>) -> String {
        let Some(c) = c.filter(|c| c.state == "running") else {
            return "UNKNOWN".into();
        };
        match self.run(
            &[
                "exec",
                &c.id,
                "ss",
                "-H",
                "-n",
                "-A",
                "sctp",
                "state",
                "established",
            ],
            3,
        ) {
            Ok(o) if o.code == 0 && o.stdout.contains(":36412") => "CONNECTED".into(),
            _ => "UNKNOWN".into(),
        }
    }
    fn ue_ip(&self, c: Option<&Container>) -> Option<String> {
        let c = c.filter(|c| c.state == "running")?;
        let o = self
            .run(
                &[
                    "exec",
                    &c.id,
                    "ip",
                    "-o",
                    "-4",
                    "addr",
                    "show",
                    "dev",
                    "tun_srsue",
                ],
                3,
            )
            .ok()?;
        if o.code != 0 {
            return None;
        }
        o.stdout
            .split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .find_map(|w| {
                (w[0] == "inet")
                    .then(|| w[1].split('/').next().unwrap_or_default().to_string())
                    .filter(|v| {
                        v.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| {
                            let octets = ip.octets();
                            octets[0] == 10 && octets[1] == 45
                        })
                    })
            })
    }
    fn apn() -> String {
        fs::read_to_string(UE_CONFIG)
            .ok()
            .and_then(|s| {
                s.lines().find_map(|line| {
                    let (k, v) = line.split_once('=')?;
                    k.trim()
                        .eq_ignore_ascii_case("apn")
                        .then(|| v.trim().trim_matches('"').to_string())
                })
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "UNKNOWN".into())
    }
    fn create(&self, target: Target) -> Result<(), String> {
        Self::ok(
            self.run(
                &[
                    "compose",
                    "--project-name",
                    PROJECT,
                    "--env-file",
                    ENV_FILE,
                    "-f",
                    COMPOSE,
                    "--profile",
                    "lte",
                    "create",
                    target.service(),
                ],
                60,
            )?,
            "SRSRAN_CREATE_FAILED",
        )
        .map(|_| ())
    }
    fn remove(&self, id: &str, force: bool) -> Result<(), String> {
        let args = if force {
            vec!["rm", "-f", id]
        } else {
            vec!["rm", id]
        };
        Self::ok(self.run(&args, 20)?, "SRSRAN_CLEANUP_FAILED").map(|_| ())
    }
    fn iperf(
        &self,
        ue: &Container,
        reverse: bool,
        protocol: &str,
        rate: u32,
    ) -> Result<(u64, u64), String> {
        let peer = std::env::var("POLARIS_LTE_TRAFFIC_PEER_IP")
            .map_err(|_| "LTE_TRAFFIC_PEER_NOT_CONFIGURED")?;
        if peer.parse::<std::net::IpAddr>().is_err() {
            return Err("LTE_TRAFFIC_PEER_INVALID".into());
        }
        let rate_arg = format!("{rate}M");
        let mut args = vec![
            "exec",
            ue.id.as_str(),
            "iperf3",
            "-c",
            peer.as_str(),
            "-t",
            "1",
            "-J",
        ];
        if protocol == "udp" {
            args.extend(["-u", "-b", rate_arg.as_str()]);
        }
        if reverse {
            args.push("-R");
        }
        let output = Self::ok(self.run(&args, 5)?, "LTE_TRAFFIC_COMMAND_FAILED")?;
        let json: serde_json::Value =
            serde_json::from_str(&output.stdout).map_err(|_| "LTE_TRAFFIC_RESULT_INVALID")?;
        let summary = if reverse {
            json.pointer("/end/sum_received")
        } else {
            json.pointer("/end/sum_sent")
        }
        .ok_or("LTE_TRAFFIC_RESULT_INVALID")?;
        let bytes = summary
            .get("bytes")
            .and_then(|v| v.as_u64())
            .ok_or("LTE_TRAFFIC_RESULT_INVALID")?;
        let bps = summary
            .get("bits_per_second")
            .and_then(|v| v.as_f64())
            .filter(|v| v.is_finite() && *v >= 0.0)
            .map(|v| v as u64)
            .ok_or("LTE_TRAFFIC_RESULT_INVALID")?;
        Ok((bytes, bps))
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
        let (enb, ec) = self.observe(Target::Enb)?;
        let (ue, uc) = self.observe(Target::Ue)?;
        let s1 = self.s1(ec.as_ref());
        let ip = self.ue_ip(uc.as_ref());
        let attached = s1 == "CONNECTED" && ip.is_some();
        let ownership = enb.controller_owned && ue.controller_owned;
        let traffic_peer_configured = std::env::var("POLARIS_LTE_TRAFFIC_PEER_IP")
            .ok()
            .and_then(|value| value.parse::<std::net::IpAddr>().ok())
            .is_some();
        Ok(LteStatus {
            technology: "LTE 4G",
            simulator: "srsRAN",
            certified,
            live_enabled,
            epc: self.epc(),
            s1_state: s1,
            enb,
            ue,
            ue_id: LTE_UE_ID,
            attach_state: if attached { "ATTACHED" } else { "UNKNOWN" }.into(),
            apn: Self::apn(),
            ue_ip: ip,
            session_state: if attached { "ACTIVE" } else { "UNKNOWN" }.into(),
            active_sessions: u8::from(attached),
            ownership_verified: ownership,
            traffic_ready: certified
                && live_enabled
                && ownership
                && attached
                && traffic_peer_configured,
        })
    }
    fn start(&self, target: Target) -> Result<(), String> {
        let (c, created) = if let Some(c) = self.resolve(target.service())? {
            self.owned(target)?;
            (c, false)
        } else {
            if let Err(error) = self.create(target) {
                if let Ok(Some(partial)) = self.resolve(target.service()) {
                    let _ = self.remove(&partial.id, true);
                }
                return Err(error);
            }
            let c = self
                .resolve(target.service())?
                .ok_or_else(|| "SRSRAN_CREATE_FAILED".to_string())?;
            if let Err(e) = self.set_owned(target, Some(c.id.clone())) {
                let _ = self.remove(&c.id, true);
                return Err(e);
            }
            (c, true)
        };
        let start_result = self
            .run(&["start", &c.id], 20)
            .and_then(|output| Self::ok(output, "SRSRAN_ACTION_FAILED").map(|_| ()));
        if let Err(error) = start_result {
            if created {
                let cleanup = self.remove(&c.id, true);
                let _ = self.set_owned(target, None);
                if cleanup.is_err() {
                    return Err("SRSRAN_START_FAILED_ROLLBACK_FAILED".into());
                }
            }
            return Err(error);
        }
        Ok(())
    }
    fn stop(&self, target: Target) -> Result<(), String> {
        if target == Target::Enb && self.resolve("srsue")?.is_some_and(|c| c.state == "running") {
            return Err("SRSRAN_DEPENDENT_UE_RUNNING".into());
        }
        let c = self.owned(target)?;
        Self::ok(
            self.run(&["stop", "--time", "10", &c.id], 20)?,
            "SRSRAN_ACTION_FAILED",
        )?;
        self.remove(&c.id, false)?;
        self.set_owned(target, None)
    }
    fn logs(&self, target: Target) -> Result<Vec<String>, String> {
        let c = self
            .resolve(target.service())?
            .ok_or_else(|| "SRSRAN_SERVICE_NOT_FOUND".to_string())?;
        let o = Self::ok(
            self.run(&["logs", "--tail", "200", &c.id], 5)?,
            "SRSRAN_LOGS_UNAVAILABLE",
        )?;
        Ok(format!("{}{}", o.stdout, o.stderr)
            .lines()
            .filter_map(sanitize_log_line)
            .collect())
    }
    fn verify_ownership(&self, target: Target) -> Result<(), String> {
        self.owned(target).map(|_| ())
    }
    fn measure_traffic(
        &self,
        direction: &str,
        protocol: &str,
        rate: u32,
    ) -> Result<TrafficMeasurement, String> {
        if !matches!(direction, "ul" | "dl" | "both") || !matches!(protocol, "udp" | "tcp") {
            return Err("LTE_TRAFFIC_PARAMETERS_INVALID".into());
        }
        let ue = self.owned(Target::Ue)?;
        if ue.state != "running" {
            return Err("LTE_UE_NOT_RUNNING".into());
        }
        let mut m = TrafficMeasurement::default();
        if matches!(direction, "ul" | "both") {
            let (v, b) = self.iperf(&ue, false, protocol, rate)?;
            m.bytes_ul = v;
            m.rate_ul_bps = Some(b);
        }
        if matches!(direction, "dl" | "both") {
            let (v, b) = self.iperf(&ue, true, protocol, rate)?;
            m.bytes_dl = v;
            m.rate_dl_bps = Some(b);
        }
        Ok(m)
    }
}

fn sanitize_log_line(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    if ["imsi", "supi", "opc", "auth key", "subscriber key", " ki="]
        .iter()
        .any(|m| lower.contains(m))
    {
        return Some("[REDACTED_SUBSCRIBER_MATERIAL]".into());
    }
    let value = line.trim();
    (!value.is_empty()).then(|| value.chars().take(500).collect())
}

#[derive(Clone)]
pub struct MockSrsranRuntime {
    pub started: Arc<Mutex<Vec<String>>>,
    pub stopped: Arc<Mutex<Vec<String>>>,
    pub ownership_verified: Arc<Mutex<bool>>,
    pub status_override: Arc<Mutex<Option<LteStatus>>>,
    pub start_error: Arc<Mutex<Option<String>>>,
}
impl Default for MockSrsranRuntime {
    fn default() -> Self {
        Self {
            started: Arc::new(Mutex::new(vec![])),
            stopped: Arc::new(Mutex::new(vec![])),
            ownership_verified: Arc::new(Mutex::new(true)),
            status_override: Arc::new(Mutex::new(None)),
            start_error: Arc::new(Mutex::new(None)),
        }
    }
}
impl SrsranRuntime for MockSrsranRuntime {
    fn status(&self, certified: bool, live_enabled: bool) -> Result<LteStatus, String> {
        if let Some(mut s) = self.status_override.lock().unwrap().clone() {
            s.certified = certified;
            s.live_enabled = live_enabled;
            return Ok(s);
        }
        Ok(LteStatus {
            technology: "LTE 4G",
            simulator: "srsRAN",
            certified,
            live_enabled,
            epc: ProcessObservation::unknown(),
            s1_state: "UNKNOWN".into(),
            enb: ProcessObservation::unknown(),
            ue: ProcessObservation::unknown(),
            ue_id: LTE_UE_ID,
            attach_state: "UNKNOWN".into(),
            apn: "UNKNOWN".into(),
            ue_ip: None,
            session_state: "UNKNOWN".into(),
            active_sessions: 0,
            ownership_verified: *self.ownership_verified.lock().unwrap(),
            traffic_ready: false,
        })
    }
    fn start(&self, t: Target) -> Result<(), String> {
        if let Some(e) = self.start_error.lock().unwrap().clone() {
            return Err(e);
        }
        self.started.lock().unwrap().push(t.id().into());
        Ok(())
    }
    fn stop(&self, t: Target) -> Result<(), String> {
        self.stopped.lock().unwrap().push(t.id().into());
        Ok(())
    }
    fn logs(&self, _: Target) -> Result<Vec<String>, String> {
        Ok(vec!["mock log".into()])
    }
    fn verify_ownership(&self, _: Target) -> Result<(), String> {
        if *self.ownership_verified.lock().unwrap() {
            Ok(())
        } else {
            Err("SRSRAN_CONTROLLER_OWNERSHIP_REQUIRED".into())
        }
    }
    fn measure_traffic(
        &self,
        direction: &str,
        _: &str,
        rate: u32,
    ) -> Result<TrafficMeasurement, String> {
        let bytes = u64::from(rate) * 1_000_000 / 8;
        Ok(TrafficMeasurement {
            bytes_ul: if matches!(direction, "ul" | "both") {
                bytes
            } else {
                0
            },
            bytes_dl: if matches!(direction, "dl" | "both") {
                bytes
            } else {
                0
            },
            rate_ul_bps: matches!(direction, "ul" | "both").then_some(u64::from(rate) * 1_000_000),
            rate_dl_bps: matches!(direction, "dl" | "both").then_some(u64::from(rate) * 1_000_000),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    #[derive(Default)]
    struct ScriptExecutor {
        outputs: Mutex<VecDeque<Result<Output, String>>>,
        calls: Mutex<Vec<Vec<String>>>,
    }
    impl Executor for ScriptExecutor {
        fn run(&self, args: &[String], _: u64) -> Result<Output, String> {
            self.calls.lock().unwrap().push(args.to_vec());
            self.outputs
                .lock()
                .unwrap()
                .pop_front()
                .expect("script output")
        }
    }
    fn output(code: i32, stdout: &str) -> Result<Output, String> {
        Ok(Output {
            code,
            stdout: stdout.into(),
            stderr: String::new(),
        })
    }
    #[test]
    fn allowlist() {
        assert_eq!(Target::parse(ENB_ID, None), Ok(Target::Enb));
        assert!(Target::parse("../../docker", None).is_err());
    }
    #[test]
    fn redacts() {
        assert_eq!(
            sanitize_log_line("IMSI 001 attach"),
            Some("[REDACTED_SUBSCRIBER_MATERIAL]".into())
        );
    }
    #[test]
    fn ownership_is_independent() {
        let r = MockSrsranRuntime::default();
        *r.ownership_verified.lock().unwrap() = false;
        assert_eq!(
            r.verify_ownership(Target::Ue),
            Err("SRSRAN_CONTROLLER_OWNERSHIP_REQUIRED".into())
        );
    }
    #[test]
    fn failed_start_has_no_side_effect() {
        let r = MockSrsranRuntime::default();
        *r.start_error.lock().unwrap() = Some("SRSRAN_ACTION_FAILED".into());
        assert!(r.start(Target::Enb).is_err());
        assert!(r.started.lock().unwrap().is_empty());
    }
    #[test]
    fn host_timeout_is_fail_closed() {
        assert_eq!(classify_exit(124), Err("SRSRAN_COMMAND_TIMEOUT".into()));
        assert_eq!(classify_exit(137), Err("SRSRAN_COMMAND_TIMEOUT".into()));
        assert_eq!(classify_exit(1), Ok(()));
    }
    #[test]
    fn failed_new_container_start_removes_exact_id_and_clears_ownership() {
        let executor = Arc::new(ScriptExecutor::default());
        let id = "0123456789abcdef";
        executor.outputs.lock().unwrap().extend([
            output(0, ""),
            output(0, ""),
            output(0, &format!("{id}\n")),
            output(
                0,
                &format!(
                    "{id}|{PROJECT}|srsenb|{COMPOSE}|created|not_available||{EXPECTED_IMAGE_REFERENCE}\n"
                ),
            ),
            output(1, ""),
            output(0, ""),
        ]);
        let root =
            std::env::temp_dir().join(format!("polaris-srsran-rollback-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let runtime = DockerSrsranRuntime {
            executor: executor.clone(),
            ledger: root.join("ledger.json"),
        };
        assert_eq!(
            runtime.start(Target::Enb),
            Err("SRSRAN_ACTION_FAILED".into())
        );
        assert!(executor
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|args| args == &vec!["rm".to_string(), "-f".to_string(), id.to_string()]));
        assert!(runtime.load().unwrap().components.is_empty());
        let _ = fs::remove_dir_all(root);
    }
}
