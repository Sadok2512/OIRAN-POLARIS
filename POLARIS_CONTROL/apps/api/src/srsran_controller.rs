use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub const VERSION: &str = "0.2.4";
pub const LTE_UE_ID: &str = "LTE-SRSUE-TEST-01";
pub const ENB_ID: &str = "ENB-01";
const PROJECT: &str = "oiran-lab";
const LTE_PROFILE: &str = "lte";
const COMPOSE: &str = "/root/POLARIS/compose/docker-compose.oiran-lab.yml";
const ENV_FILE: &str = "/root/POLARIS/compose/versions.env";
const UE_CONFIG: &str = "/root/POLARIS/runtime/srsran/ue.conf";
const LEDGER: &str = "/var/lib/polaris-control/srsran-ownership.json";
pub const CERTIFIED_IMAGE_REFERENCE: &str =
    "oiran/srsran4g@sha256:69e094349657cc6a062ce3717661d6b8a553a23ce571f821e33256beec753d43";
pub const CERTIFIED_IMAGE_ID: &str =
    "sha256:69e094349657cc6a062ce3717661d6b8a553a23ce571f821e33256beec753d43";
pub const CERTIFIED_COMPOSE_MODEL_SHA256: &str =
    "308053a274844259c16da7751708b39e6559cfec2b8d958dc4fcafebecd0da19";
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
    pub attach_success_observed: bool,
    pub epc_context_observed: bool,
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PingMeasurement {
    pub sent: u32,
    pub received: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachProtocolEvidence {
    pub event_at_epoch_ms: u64,
    pub observed_at_epoch_ms: u64,
    pub provenance: &'static str,
}

pub trait SrsranRuntime: Send + Sync {
    fn status(&self, certified: bool, live_enabled: bool) -> Result<LteStatus, String>;
    fn validate_traffic_configuration(&self) -> Result<(), String>;
    fn start(&self, target: Target) -> Result<(), String>;
    fn stop(&self, target: Target) -> Result<(), String>;
    fn logs(&self, target: Target) -> Result<Vec<String>, String>;
    fn verify_ownership(&self, target: Target) -> Result<(), String>;
    fn attach_complete_event(
        &self,
        not_before_epoch_ms: u64,
        not_after_epoch_ms: u64,
    ) -> Result<Option<AttachProtocolEvidence>, String>;
    fn measure_traffic(
        &self,
        direction: &str,
        protocol: &str,
        rate_mbps: u32,
    ) -> Result<TrafficMeasurement, String>;
    fn measure_bounded_udp(
        &self,
        direction: &str,
        rate_bps: u64,
        duration_seconds: u32,
        payload_bytes: u32,
    ) -> Result<TrafficMeasurement, String>;
    fn ping(&self, direction: &str, packets: u32) -> Result<PingMeasurement, String>;
    /// Remove only sidecars carrying the exact run label, then prove none remain.
    fn cleanup_run_sidecars(&self, run_id: &str) -> Result<bool, String>;
}

fn attach_is_proven(s1_state: &str, attach_success: bool, epc_context: bool) -> bool {
    s1_state == "CONNECTED" && attach_success && epc_context
}

// 0.29.3: LTE SGi path uses a dedicated DN sender container, pinned by env.
// No silent fallback to the 5G N6 container is tolerated. The DL preflight is
// policy-driven (required next-hop PGW-U LTE, required UE subnet, forbidden
// outbound devices such as the N6 bridge/loopback/blackhole). Missing tools in
// the DN container (`iperf3`, `ping`, `ip`) surface as
// `LTE_DN_SENDER_TOOLING_MISSING` instead of a generic ping failure.
//
// 0.29.2 history: LTE SGi peer decoupled from `POLARIS_DL_SENDER_IP`; UL route
// preflight requires `tun_srsue`.
pub const LTE_UE_TUN: &str = "tun_srsue";
pub const LTE_UE_SUBNET_DEFAULT: &str = "10.45.0.0/16";

fn validate_traffic_peer_values(
    traffic_peer: Option<&str>,
    _dl_sender: Option<&str>,
) -> Result<std::net::Ipv4Addr, String> {
    let peer = traffic_peer.ok_or("LTE_TRAFFIC_PEER_NOT_CONFIGURED")?;
    peer.parse::<std::net::Ipv4Addr>()
        .map_err(|_| "LTE_TRAFFIC_PEER_INVALID".into())
}

fn configured_traffic_peer() -> Result<std::net::Ipv4Addr, String> {
    let peer = std::env::var("POLARIS_LTE_TRAFFIC_PEER_IP").ok();
    let sender = std::env::var("POLARIS_DL_SENDER_IP").ok();
    let peer = validate_traffic_peer_values(peer.as_deref(), sender.as_deref())?;
    // 0.29.3: an operator pointing the LTE SGi peer at the 5G N6 sender is
    // explicitly rejected now — the two DNs must be distinct in prod.
    if let Some(n6) = sender {
        if let Ok(n6_ip) = n6.parse::<std::net::Ipv4Addr>() {
            if n6_ip == peer {
                return Err("LTE_SGI_COLLIDES_WITH_N6".into());
            }
        }
    }
    Ok(peer)
}

/// 0.29.3: LTE DN sender container name is deployment-specified and must NOT
/// silently fall back to the 5G N6 `polaris-dn-sender`. Operators must set
/// `POLARIS_LTE_DN_SENDER_CONTAINER` explicitly.
fn configured_lte_dn_sender_container() -> Result<String, String> {
    let name = std::env::var("POLARIS_LTE_DN_SENDER_CONTAINER")
        .map_err(|_| "LTE_DN_SENDER_NOT_CONFIGURED".to_string())?;
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("LTE_DN_SENDER_NOT_CONFIGURED".into());
    }
    // Forbid the N6 container name verbatim to make the "no silent fallback"
    // rule explicit at the configuration boundary.
    if trimmed == "polaris-dn-sender" {
        return Err("LTE_DN_SENDER_COLLIDES_WITH_N6".into());
    }
    if trimmed.len() > 64
        || !trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err("LTE_DN_SENDER_NAME_INVALID".into());
    }
    Ok(trimmed.to_string())
}

/// Policy consumed by `evaluate_lte_dl_return_route`. All three fields are
/// deployment-specified. The policy makes the N6-vs-SGi distinction explicit:
/// `forbidden_devs` names outbound interfaces that would route the UE traffic
/// through the 5G DN rather than the SGi fabric.
#[derive(Clone, Debug)]
pub struct SgiReturnRoutePolicy {
    pub required_next_hop: String,
    pub required_ue_subnet: String,
    pub forbidden_devs: Vec<String>,
}

/// 0.29.3: Build a policy from env. All vars are required; missing values
/// fail-closed to prevent silent degradation to 5G N6 routing. Returns the
/// specific error code the caller surfaces in the step record.
pub fn configured_lte_dl_return_policy() -> Result<SgiReturnRoutePolicy, String> {
    let required_next_hop = std::env::var("POLARIS_LTE_PGW_U_NEXT_HOP")
        .map_err(|_| "LTE_PGW_U_NEXT_HOP_NOT_CONFIGURED".to_string())?;
    required_next_hop
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| "LTE_PGW_U_NEXT_HOP_INVALID".to_string())?;
    let required_ue_subnet = std::env::var("POLARIS_LTE_UE_SUBNET")
        .unwrap_or_else(|_| LTE_UE_SUBNET_DEFAULT.to_string());
    parse_cidr_v4(&required_ue_subnet).map_err(|_| "LTE_UE_SUBNET_INVALID".to_string())?;
    let forbidden_devs = std::env::var("POLARIS_LTE_FORBIDDEN_RETURN_DEVS")
        .unwrap_or_else(|_| "lo,null0,blackhole,eth0,oiran-lab-n6".to_string())
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect();
    Ok(SgiReturnRoutePolicy {
        required_next_hop,
        required_ue_subnet,
        forbidden_devs,
    })
}

/// LTE SGi UL route preflight. Wraps the shared `evaluate_ue_route_preflight`
/// with the LTE-specific device (`tun_srsue`) and error code.
pub fn evaluate_lte_ul_route(raw: &str, peer: &str) -> crate::UeRoutePreflight {
    crate::evaluate_ue_route_preflight(raw, peer, LTE_UE_TUN, "LTE_UL_ROUTE_NOT_VIA_UE_TUN")
}

fn after_token(line: &str, key: &str) -> Option<String> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    fields
        .iter()
        .position(|value| *value == key)
        .and_then(|index| fields.get(index + 1).copied())
        .map(str::to_string)
}

fn parse_cidr_v4(cidr: &str) -> Result<(std::net::Ipv4Addr, u32), String> {
    let (net, prefix) = cidr.split_once('/').ok_or("missing /")?;
    let net = net.parse::<std::net::Ipv4Addr>().map_err(|e| e.to_string())?;
    let prefix: u32 = prefix.parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
    if prefix > 32 {
        return Err("prefix >32".into());
    }
    Ok((net, prefix))
}

fn ip_in_v4_cidr(ip: &str, cidr: &str) -> bool {
    let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let Ok((net, prefix)) = parse_cidr_v4(cidr) else {
        return false;
    };
    let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    (u32::from(addr) & mask) == (u32::from(net) & mask)
}

/// LTE SGi DL return-route preflight — hardened. Validates:
/// - the UE address falls inside the configured UE subnet,
/// - the raw `ip route get` resolution is not `unreachable`,
/// - a `dev` field is parseable and is NOT in `forbidden_devs`,
/// - a `via` next-hop is present and matches `required_next_hop`.
///
/// Returns a specific error code on each failure so the step evidence tells
/// operators exactly which gate rejected the run.
pub fn evaluate_lte_dl_return_route(
    raw: &str,
    ue_ip: &str,
    policy: &SgiReturnRoutePolicy,
) -> Result<(), String> {
    if !ip_in_v4_cidr(ue_ip, &policy.required_ue_subnet) {
        return Err("LTE_UE_IP_OUTSIDE_SUBNET".into());
    }
    let bounded: String = raw.chars().take(1024).collect();
    let line = bounded.lines().next().unwrap_or("");
    let lower = line.to_ascii_lowercase();
    if lower.contains("unreachable") || lower.contains("network is unreachable") {
        return Err("LTE_DL_RETURN_ROUTE_UNAVAILABLE".into());
    }
    let dev = after_token(line, "dev").ok_or("LTE_DL_RETURN_ROUTE_UNAVAILABLE".to_string())?;
    if policy.forbidden_devs.iter().any(|forbidden| forbidden == &dev) {
        return Err("LTE_DL_RETURN_ROUTE_VIA_FORBIDDEN_DEV".into());
    }
    let via = after_token(line, "via").ok_or("LTE_DL_RETURN_ROUTE_MISSING_VIA".to_string())?;
    if via != policy.required_next_hop {
        return Err("LTE_DL_RETURN_ROUTE_WRONG_NEXT_HOP".into());
    }
    Ok(())
}

/// 0.29.3: classifier for DN container exec exit codes. 126 and 127 are
/// shell's "cannot execute" / "command not found" conventions; sanitized
/// stderr snippets containing the same phrasing are also treated as a
/// tooling gap so operators get a precise diagnostic without raw stderr
/// leaking.
pub fn classify_dn_container_exit(code: i32, stderr: &str) -> Result<(), String> {
    if code == 126 || code == 127 {
        return Err("LTE_DN_SENDER_TOOLING_MISSING".into());
    }
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("command not found") || lower.contains("executable file not found") {
        return Err("LTE_DN_SENDER_TOOLING_MISSING".into());
    }
    Ok(())
}

fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

fn parse_rfc3339_utc_millis(value: &str) -> Option<u64> {
    let value = value.strip_suffix('Z')?;
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.len() != 19
        || whole.as_bytes().get(4) != Some(&b'-')
        || whole.as_bytes().get(7) != Some(&b'-')
        || whole.as_bytes().get(10) != Some(&b'T')
        || whole.as_bytes().get(13) != Some(&b':')
        || whole.as_bytes().get(16) != Some(&b':')
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let parse = |range: std::ops::Range<usize>| whole.get(range)?.parse::<u32>().ok();
    let year = whole.get(0..4)?.parse::<i64>().ok()?;
    let month = parse(5..7)?;
    let day = parse(8..10)?;
    let hour = parse(11..13)?;
    let minute = parse(14..16)?;
    let second = parse(17..19)?;
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let millis = fraction
        .bytes()
        .take(3)
        .fold(0_u64, |value, byte| value * 10 + u64::from(byte - b'0'))
        * match fraction.len().min(3) {
            0 => 1_000,
            1 => 100,
            2 => 10,
            _ => 1,
        };
    let days = days_from_civil(year, month, day)?;
    if days < 0 {
        return None;
    }
    u64::try_from(days)
        .ok()?
        .checked_mul(86_400_000)?
        .checked_add(u64::from(hour) * 3_600_000)?
        .checked_add(u64::from(minute) * 60_000)?
        .checked_add(u64::from(second.min(59)) * 1_000)?
        .checked_add(millis)
}

fn unix_millis_argument(value: u64) -> String {
    format!("{}.{:03}", value / 1_000, value % 1_000)
}

pub fn s1_setup_is_proven(status: &LteStatus) -> bool {
    status.enb.process_state == "running"
        && status.epc.process_state == "running"
        && status.s1_state == "CONNECTED"
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DockerHealth {
    Absent,
    Starting,
    Healthy,
    Unhealthy,
    Unknown,
}
impl DockerHealth {
    fn from_state(state: &serde_json::Value) -> Self {
        match state.get("Health") {
            None | Some(serde_json::Value::Null) => Self::Absent,
            Some(health) => match health.get("Status").and_then(serde_json::Value::as_str) {
                Some("starting") => Self::Starting,
                Some("healthy") => Self::Healthy,
                Some("unhealthy") => Self::Unhealthy,
                _ => Self::Unknown,
            },
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "not_available",
            Self::Starting => "starting",
            Self::Healthy => "healthy",
            Self::Unhealthy => "unhealthy",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Container {
    id: String,
    state: String,
    health: DockerHealth,
    error: String,
}
impl Container {
    /// Docker process state is only startup evidence. It never proves S1 Setup.
    fn process_started(&self) -> bool {
        self.state == "running"
            && matches!(
                self.health,
                DockerHealth::Absent | DockerHealth::Starting | DockerHealth::Healthy
            )
    }
}

fn parse_container_inspect(data: &str, service: &str) -> Result<Container, String> {
    let value: serde_json::Value =
        serde_json::from_str(data.trim()).map_err(|_| "SRSRAN_DISCOVERY_FAILED")?;
    let id = value
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("SRSRAN_DISCOVERY_FAILED")?;
    let labels = value
        .pointer("/Config/Labels")
        .and_then(serde_json::Value::as_object)
        .ok_or("LTE_RUNTIME_OWNERSHIP_CONFLICT")?;
    let label = |name: &str| labels.get(name).and_then(serde_json::Value::as_str);
    let image = value
        .pointer("/Config/Image")
        .and_then(serde_json::Value::as_str)
        .ok_or("LTE_RUNTIME_OWNERSHIP_CONFLICT")?;
    if label("com.docker.compose.project") != Some(PROJECT)
        || label("com.docker.compose.service") != Some(service)
        || label("com.docker.compose.project.config_files") != Some(COMPOSE)
        || (matches!(service, "srsenb" | "srsue") && image != CERTIFIED_IMAGE_REFERENCE)
    {
        return Err("LTE_RUNTIME_OWNERSHIP_CONFLICT".into());
    }
    let state = value
        .get("State")
        .and_then(serde_json::Value::as_object)
        .ok_or("SRSRAN_DISCOVERY_FAILED")?;
    let state_value = serde_json::Value::Object(state.clone());
    let process_state = state
        .get("Status")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("SRSRAN_DISCOVERY_FAILED")?;
    let error = state
        .get("Error")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    Ok(Container {
        id: id.into(),
        state: process_state.into(),
        health: DockerHealth::from_state(&state_value),
        error: error.into(),
    })
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
        // Inspect the complete JSON object. Accessing `.State.Health` in a Go
        // template is not portable across containers that have no healthcheck.
        let data = Self::ok(
            self.run(&["inspect", "--format", "{{json .}}", ids[0]], 5)?,
            "SRSRAN_DISCOVERY_FAILED",
        )?;
        parse_container_inspect(&data.stdout, service).map(Some)
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
                health: c.health.as_str().into(),
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
                health: c.health.as_str().into(),
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
    fn sanitized_logs(&self, container: &Container) -> Vec<String> {
        self.run(&["logs", "--tail", "400", &container.id], 5)
            .ok()
            .filter(|output| output.code == 0)
            .map(|output| {
                format!("{}{}", output.stdout, output.stderr)
                    .lines()
                    .filter_map(sanitize_log_line)
                    .collect()
            })
            .unwrap_or_default()
    }
    fn attach_proof(&self, ue: Option<&Container>) -> bool {
        let Some(ue) = ue.filter(|container| container.state == "running") else {
            return false;
        };
        self.sanitized_logs(ue).iter().any(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("network attach successful") || lower.contains("attach complete")
        })
    }
    fn epc_context_proof(&self) -> bool {
        let Ok(Some(mme)) = self.resolve("mme") else {
            return false;
        };
        if mme.state != "running" {
            return false;
        }
        self.sanitized_logs(&mme).iter().any(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("initial context setup response")
                || lower.contains("create session response")
                || lower.contains("emm-context") && lower.contains("registered")
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
        rate_bps: u64,
        duration_seconds: u32,
        payload_bytes: u32,
    ) -> Result<(u64, u64), String> {
        let peer = configured_traffic_peer()?.to_string();
        let rate_arg = rate_bps.to_string();
        let duration_arg = duration_seconds.to_string();
        let payload_arg = payload_bytes.to_string();
        // 0.29.2: preflight UE SGi route to the peer before iperf3 is spawned.
        // The UE must reach the SGi DN via `tun_srsue`; any other outbound
        // interface is rejected fail-closed.
        let route = self
            .run(&["exec", &ue.id, "ip", "route", "get", &peer], 3)
            .map_err(|_| "LTE_UL_ROUTE_PROBE_FAILED".to_string())?;
        if route.code != 0 {
            return Err("LTE_UL_ROUTE_PROBE_FAILED".into());
        }
        let preflight = evaluate_lte_ul_route(&route.stdout, &peer);
        if !preflight.ok {
            return Err(preflight
                .code
                .unwrap_or_else(|| "LTE_UL_ROUTE_NOT_VIA_UE_TUN".into()));
        }
        // 0.29.2: bind iperf3 source to the UE tun IP so the stack cannot pick
        // a bridge interface even if the UE container has one.
        let ue_source = self.ue_ip(Some(ue)).ok_or("LTE_UE_IP_NOT_READY")?;
        let mut args = vec![
            "exec",
            ue.id.as_str(),
            "iperf3",
            "-c",
            peer.as_str(),
            "-B",
            ue_source.as_str(),
            "-t",
            duration_arg.as_str(),
            "-J",
        ];
        if protocol == "udp" {
            args.extend(["-u", "-b", rate_arg.as_str(), "-l", payload_arg.as_str()]);
        }
        if reverse {
            args.push("-R");
        }
        let output = Self::ok(
            self.run(&args, u64::from(duration_seconds).saturating_add(5))?,
            "LTE_TRAFFIC_COMMAND_FAILED",
        )?;
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

fn canonical_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            let mut sorted = serde_json::Map::new();
            for key in keys {
                sorted.insert(key.clone(), canonical_json(&map[key]));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(canonical_json).collect())
        }
        other => other.clone(),
    }
}

pub fn compose_model_sha256() -> Result<String, String> {
    let output = Command::new("/usr/bin/timeout")
        .args(compose_config_args())
        .output()
        .map_err(|_| "LTE_COMPOSE_MODEL_UNAVAILABLE")?;
    if !output.status.success() {
        return Err("LTE_COMPOSE_MODEL_UNAVAILABLE".into());
    }
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|_| "LTE_COMPOSE_MODEL_INVALID")?;
    let bytes =
        serde_json::to_vec(&canonical_json(&parsed)).map_err(|_| "LTE_COMPOSE_MODEL_INVALID")?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn validate_certified_release_subject(image_reference: &str, compose_model: &str) -> Result<(), String> {
    if image_reference != CERTIFIED_IMAGE_REFERENCE {
        return Err("LTE_CERTIFIED_IMAGE_MISMATCH".into());
    }
    if compose_model != CERTIFIED_COMPOSE_MODEL_SHA256 {
        return Err("LTE_CERTIFIED_COMPOSE_MODEL_MISMATCH".into());
    }
    Ok(())
}

pub fn verify_certified_release_subject() -> Result<(), String> {
    let versions =
        fs::read_to_string(ENV_FILE).map_err(|_| "LTE_CERTIFIED_IMAGE_UNAVAILABLE")?;
    let image_reference = versions
        .lines()
        .find_map(|line| line.strip_prefix("SRSRAN4G_IMAGE="))
        .ok_or("LTE_CERTIFIED_IMAGE_UNAVAILABLE")?;
    let compose_model = compose_model_sha256()?;
    validate_certified_release_subject(image_reference, &compose_model)?;
    let output = Command::new("/usr/bin/timeout")
        .args([
            "10s",
            "/usr/bin/docker",
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            CERTIFIED_IMAGE_ID,
        ])
        .output()
        .map_err(|_| "LTE_CERTIFIED_IMAGE_UNAVAILABLE")?;
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != CERTIFIED_IMAGE_ID {
        return Err("LTE_CERTIFIED_IMAGE_UNAVAILABLE".into());
    }
    Ok(())
}

fn compose_config_args() -> [&'static str; 14] {
    [
        "10s",
        "/usr/bin/docker",
        "compose",
        "--project-name",
        PROJECT,
        "--profile",
        LTE_PROFILE,
        "--env-file",
        ENV_FILE,
        "-f",
        COMPOSE,
        "config",
        "--format",
        "json",
    ]
}

impl SrsranRuntime for DockerSrsranRuntime {
    fn status(&self, certified: bool, live_enabled: bool) -> Result<LteStatus, String> {
        let (enb, ec) = self.observe(Target::Enb)?;
        let (ue, uc) = self.observe(Target::Ue)?;
        let s1 = self.s1(ec.as_ref());
        let ip = self.ue_ip(uc.as_ref());
        let attach_success_observed = self.attach_proof(uc.as_ref());
        let epc_context_observed = self.epc_context_proof();
        let attached = attach_is_proven(&s1, attach_success_observed, epc_context_observed);
        let ownership = enb.controller_owned && ue.controller_owned;
        let traffic_peer_configured = configured_traffic_peer().is_ok();
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
            attach_success_observed,
            epc_context_observed,
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
    fn validate_traffic_configuration(&self) -> Result<(), String> {
        configured_traffic_peer().map(|_| ())
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
        let started = match self.resolve(target.service()) {
            Ok(observed) => observed
                .filter(|observed| observed.id == c.id)
                .is_some_and(|observed| observed.process_started()),
            Err(error) => {
                if created {
                    let cleanup = self.remove(&c.id, true);
                    let _ = self.set_owned(target, None);
                    if cleanup.is_err() {
                        return Err("SRSRAN_START_FAILED_ROLLBACK_FAILED".into());
                    }
                }
                return Err(error);
            }
        };
        if !started {
            if created {
                let cleanup = self.remove(&c.id, true);
                let _ = self.set_owned(target, None);
                if cleanup.is_err() {
                    return Err("SRSRAN_START_FAILED_ROLLBACK_FAILED".into());
                }
            }
            return Err("SRSRAN_PROCESS_NOT_RUNNING".into());
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
    fn attach_complete_event(
        &self,
        not_before_epoch_ms: u64,
        not_after_epoch_ms: u64,
    ) -> Result<Option<AttachProtocolEvidence>, String> {
        if not_before_epoch_ms > not_after_epoch_ms {
            return Err("LTE_ATTACH_EVIDENCE_WINDOW_INVALID".into());
        }
        let mme = self
            .resolve("mme")?
            .filter(|container| container.state == "running")
            .ok_or("LTE_MME_NOT_RUNNING")?;
        let since = unix_millis_argument(not_before_epoch_ms);
        let until = unix_millis_argument(not_after_epoch_ms);
        let output = Self::ok(
            self.run(
                &[
                    "logs",
                    "--timestamps",
                    "--since",
                    &since,
                    "--until",
                    &until,
                    "--tail",
                    "400",
                    &mme.id,
                ],
                5,
            )?,
            "LTE_ATTACH_EVIDENCE_UNAVAILABLE",
        )?;
        let event_at_epoch_ms = format!("{}{}", output.stdout, output.stderr)
            .lines()
            .filter_map(|line| {
                let (timestamp, message) = line.split_once(' ')?;
                message
                    .to_ascii_lowercase()
                    .contains("attach complete")
                    .then(|| parse_rfc3339_utc_millis(timestamp))
                    .flatten()
            })
            .filter(|timestamp| {
                *timestamp >= not_before_epoch_ms && *timestamp <= not_after_epoch_ms
            })
            .max();
        Ok(event_at_epoch_ms.map(|event_at_epoch_ms| AttachProtocolEvidence {
            event_at_epoch_ms,
            observed_at_epoch_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            provenance: "OPEN5GS_MME_DOCKER_LOG_RFC3339",
        }))
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
            let (v, b) = self.iperf(
                &ue,
                false,
                protocol,
                u64::from(rate).saturating_mul(1_000_000),
                1,
                1_200,
            )?;
            m.bytes_ul = v;
            m.rate_ul_bps = Some(b);
        }
        if matches!(direction, "dl" | "both") {
            let (v, b) = self.iperf(
                &ue,
                true,
                protocol,
                u64::from(rate).saturating_mul(1_000_000),
                1,
                1_200,
            )?;
            m.bytes_dl = v;
            m.rate_dl_bps = Some(b);
        }
        Ok(m)
    }

    fn measure_bounded_udp(
        &self,
        direction: &str,
        rate_bps: u64,
        duration_seconds: u32,
        payload_bytes: u32,
    ) -> Result<TrafficMeasurement, String> {
        if !matches!(direction, "ul" | "dl")
            || rate_bps == 0
            || rate_bps > 1_000_000
            || duration_seconds == 0
            || duration_seconds > 30
            || payload_bytes == 0
            || payload_bytes > 1_200
        {
            return Err("LTE_TRAFFIC_PARAMETERS_INVALID".into());
        }
        let ue = self.owned(Target::Ue)?;
        if ue.state != "running" {
            return Err("LTE_UE_NOT_RUNNING".into());
        }
        let reverse = direction == "dl";
        let (bytes, bps) = self.iperf(
            &ue,
            reverse,
            "udp",
            rate_bps,
            duration_seconds,
            payload_bytes,
        )?;
        Ok(TrafficMeasurement {
            bytes_ul: if reverse { 0 } else { bytes },
            bytes_dl: if reverse { bytes } else { 0 },
            rate_ul_bps: (!reverse).then_some(bps),
            rate_dl_bps: reverse.then_some(bps),
        })
    }

    fn ping(&self, direction: &str, packets: u32) -> Result<PingMeasurement, String> {
        if !matches!(direction, "ul" | "dl") || packets == 0 || packets > 5 {
            return Err("LTE_PING_PARAMETERS_INVALID".into());
        }
        let ue = self.owned(Target::Ue)?;
        if ue.state != "running" {
            return Err("LTE_UE_NOT_RUNNING".into());
        }
        let peer = configured_traffic_peer()?.to_string();
        let count = packets.to_string();
        let output = if direction == "ul" {
            // 0.29.2: preflight UE SGi route via tun_srsue before any ping.
            let route = self
                .run(&["exec", &ue.id, "ip", "route", "get", &peer], 3)
                .map_err(|_| "LTE_UL_ROUTE_PROBE_FAILED".to_string())?;
            if route.code != 0 {
                return Err("LTE_UL_ROUTE_PROBE_FAILED".into());
            }
            let preflight = evaluate_lte_ul_route(&route.stdout, &peer);
            if !preflight.ok {
                return Err(preflight
                    .code
                    .unwrap_or_else(|| "LTE_UL_ROUTE_NOT_VIA_UE_TUN".into()));
            }
            Self::ok(
                self.run(
                    &[
                        "exec", &ue.id, "ping", "-n", "-I", LTE_UE_TUN, "-c", &count, "-W", "1",
                        &peer,
                    ],
                    10,
                )?,
                "LTE_PING_FAILED",
            )?
        } else {
            let ue_ip = self.ue_ip(Some(&ue)).ok_or("LTE_UE_IP_NOT_READY")?;
            // 0.29.3: DN container is env-driven and must not silently fall
            // back to the 5G N6 sender. Policy for the return route is also
            // env-driven (next-hop, UE subnet, forbidden devs).
            let dn_container = configured_lte_dn_sender_container()?;
            let dl_policy = configured_lte_dl_return_policy()?;
            let route = self
                .run(
                    &[
                        "exec",
                        dn_container.as_str(),
                        "ip",
                        "route",
                        "get",
                        &ue_ip,
                    ],
                    3,
                )
                .map_err(|_| "LTE_DL_RETURN_ROUTE_UNAVAILABLE".to_string())?;
            classify_dn_container_exit(route.code, &route.stderr)?;
            if route.code != 0 {
                return Err("LTE_DL_RETURN_ROUTE_UNAVAILABLE".into());
            }
            evaluate_lte_dl_return_route(&route.stdout, &ue_ip, &dl_policy)?;
            let ping_output = self.run(
                &[
                    "exec",
                    dn_container.as_str(),
                    "ping",
                    "-n",
                    "-c",
                    &count,
                    "-W",
                    "1",
                    &ue_ip,
                ],
                10,
            )?;
            classify_dn_container_exit(ping_output.code, &ping_output.stderr)?;
            Self::ok(ping_output, "LTE_PING_FAILED")?
        };
        let summary = output
            .stdout
            .lines()
            .find(|line| line.contains("packets transmitted"))
            .ok_or("LTE_PING_RESULT_INVALID")?;
        let values = summary.split(',').collect::<Vec<_>>();
        let sent = values
            .first()
            .and_then(|v| v.split_whitespace().next())
            .and_then(|v| v.parse().ok())
            .ok_or("LTE_PING_RESULT_INVALID")?;
        let received = values
            .get(1)
            .and_then(|v| v.split_whitespace().next())
            .and_then(|v| v.parse().ok())
            .ok_or("LTE_PING_RESULT_INVALID")?;
        Ok(PingMeasurement { sent, received })
    }
    fn cleanup_run_sidecars(&self, run_id: &str) -> Result<bool, String> {
        if run_id.len() > 64
            || !run_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("LTE_RUN_ID_INVALID".into());
        }
        let label = format!("label=polaris.lte.run_id={run_id}");
        let listed = Self::ok(
            self.run(&["ps", "-aq", "--filter", &label], 5)?,
            "LTE_SIDECAR_DISCOVERY_FAILED",
        )?;
        for id in listed
            .stdout
            .lines()
            .map(str::trim)
            .filter(|id| !id.is_empty())
        {
            let actual = Self::ok(
                self.run(
                    &[
                        "inspect",
                        "--format",
                        "{{index .Config.Labels \"polaris.lte.run_id\"}}",
                        id,
                    ],
                    5,
                )?,
                "LTE_SIDECAR_DISCOVERY_FAILED",
            )?;
            if actual.stdout.trim() != run_id {
                return Err("LTE_SIDECAR_OWNERSHIP_CONFLICT".into());
            }
            Self::ok(
                self.run(&["rm", "-f", id], 20)?,
                "LTE_SIDECAR_CLEANUP_FAILED",
            )?;
        }
        let remaining = Self::ok(
            self.run(&["ps", "-aq", "--filter", &label], 5)?,
            "LTE_SIDECAR_DISCOVERY_FAILED",
        )?;
        Ok(remaining.stdout.lines().all(|line| line.trim().is_empty()))
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
    pub sidecars_absent: Arc<Mutex<bool>>,
    pub attach_evidence: Arc<Mutex<Option<AttachProtocolEvidence>>>,
    pub traffic_configuration_error: Arc<Mutex<Option<String>>>,
}
impl Default for MockSrsranRuntime {
    fn default() -> Self {
        Self {
            started: Arc::new(Mutex::new(vec![])),
            stopped: Arc::new(Mutex::new(vec![])),
            ownership_verified: Arc::new(Mutex::new(true)),
            status_override: Arc::new(Mutex::new(None)),
            start_error: Arc::new(Mutex::new(None)),
            sidecars_absent: Arc::new(Mutex::new(true)),
            attach_evidence: Arc::new(Mutex::new(None)),
            traffic_configuration_error: Arc::new(Mutex::new(None)),
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
            attach_success_observed: false,
            epc_context_observed: false,
            apn: "UNKNOWN".into(),
            ue_ip: None,
            session_state: "UNKNOWN".into(),
            active_sessions: 0,
            ownership_verified: *self.ownership_verified.lock().unwrap(),
            traffic_ready: false,
        })
    }
    fn validate_traffic_configuration(&self) -> Result<(), String> {
        match self.traffic_configuration_error.lock().unwrap().clone() {
            Some(error) => Err(error),
            None => Ok(()),
        }
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
    fn attach_complete_event(
        &self,
        not_before_epoch_ms: u64,
        not_after_epoch_ms: u64,
    ) -> Result<Option<AttachProtocolEvidence>, String> {
        Ok(self
            .attach_evidence
            .lock()
            .unwrap()
            .clone()
            .filter(|evidence| {
                evidence.event_at_epoch_ms >= not_before_epoch_ms
                    && evidence.event_at_epoch_ms <= not_after_epoch_ms
            }))
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
    fn measure_bounded_udp(
        &self,
        direction: &str,
        rate_bps: u64,
        duration_seconds: u32,
        payload_bytes: u32,
    ) -> Result<TrafficMeasurement, String> {
        if !matches!(direction, "ul" | "dl")
            || rate_bps == 0
            || rate_bps > 1_000_000
            || duration_seconds == 0
            || duration_seconds > 30
            || payload_bytes == 0
            || payload_bytes > 1_200
        {
            return Err("LTE_TRAFFIC_PARAMETERS_INVALID".into());
        }
        let bytes = rate_bps
            .saturating_mul(u64::from(duration_seconds))
            .saturating_div(8);
        Ok(TrafficMeasurement {
            bytes_ul: if direction == "ul" { bytes } else { 0 },
            bytes_dl: if direction == "dl" { bytes } else { 0 },
            rate_ul_bps: (direction == "ul").then_some(rate_bps),
            rate_dl_bps: (direction == "dl").then_some(rate_bps),
        })
    }
    fn ping(&self, _direction: &str, packets: u32) -> Result<PingMeasurement, String> {
        Ok(PingMeasurement {
            sent: packets,
            received: packets,
        })
    }
    fn cleanup_run_sidecars(&self, _: &str) -> Result<bool, String> {
        Ok(*self.sidecars_absent.lock().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
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
    enum TestHealth<'a> {
        Absent,
        Null,
        Status(&'a str),
    }
    fn inspect_json(
        id: &str,
        service: &str,
        status: &str,
        health: TestHealth<'_>,
        error: &str,
    ) -> String {
        let mut state = json!({"Status":status,"Error":error});
        match health {
            TestHealth::Absent => {}
            TestHealth::Null => state["Health"] = serde_json::Value::Null,
            TestHealth::Status(value) => state["Health"] = json!({"Status":value}),
        }
        json!({
            "Id":id,
            "Config":{
                "Labels":{
                    "com.docker.compose.project":PROJECT,
                    "com.docker.compose.service":service,
                    "com.docker.compose.project.config_files":COMPOSE
                },
                "Image":CERTIFIED_IMAGE_REFERENCE
            },
            "State":state
        })
        .to_string()
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
    fn s1_and_ip_cannot_substitute_for_attach_and_epc_context_proof() {
        assert!(!attach_is_proven("CONNECTED", false, false));
        assert!(!attach_is_proven("CONNECTED", true, false));
        assert!(!attach_is_proven("CONNECTED", false, true));
        assert!(attach_is_proven("CONNECTED", true, true));
    }
    #[test]
    fn docker_health_absent_null_starting_healthy_and_unhealthy_are_explicit() {
        let id = "0123456789abcdef";
        let absent = parse_container_inspect(
            &inspect_json(id, "srsenb", "created", TestHealth::Absent, ""),
            "srsenb",
        )
        .unwrap();
        let null = parse_container_inspect(
            &inspect_json(id, "srsenb", "running", TestHealth::Null, ""),
            "srsenb",
        )
        .unwrap();
        let starting = parse_container_inspect(
            &inspect_json(id, "srsenb", "running", TestHealth::Status("starting"), ""),
            "srsenb",
        )
        .unwrap();
        let healthy = parse_container_inspect(
            &inspect_json(id, "srsenb", "running", TestHealth::Status("healthy"), ""),
            "srsenb",
        )
        .unwrap();
        let unhealthy = parse_container_inspect(
            &inspect_json(id, "srsenb", "running", TestHealth::Status("unhealthy"), ""),
            "srsenb",
        )
        .unwrap();
        let unknown = parse_container_inspect(
            &inspect_json(id, "srsenb", "running", TestHealth::Status("mystery"), ""),
            "srsenb",
        )
        .unwrap();
        assert_eq!(absent.health, DockerHealth::Absent);
        assert_eq!(null.health, DockerHealth::Absent);
        assert_eq!(starting.health, DockerHealth::Starting);
        assert_eq!(healthy.health, DockerHealth::Healthy);
        assert_eq!(unhealthy.health, DockerHealth::Unhealthy);
        assert_eq!(unknown.health, DockerHealth::Unknown);
        assert!(!absent.process_started());
        assert!(null.process_started());
        assert!(starting.process_started());
        assert!(healthy.process_started());
        assert!(!unhealthy.process_started());
        assert!(!unknown.process_started());
    }
    #[test]
    fn stopped_and_crashed_containers_are_not_started() {
        let stopped = parse_container_inspect(
            &inspect_json("stopped", "srsenb", "exited", TestHealth::Absent, ""),
            "srsenb",
        )
        .unwrap();
        let crashed = parse_container_inspect(
            &inspect_json(
                "crashed",
                "srsenb",
                "exited",
                TestHealth::Absent,
                "signal: killed",
            ),
            "srsenb",
        )
        .unwrap();
        assert!(!stopped.process_started());
        assert!(!crashed.process_started());
        assert_eq!(crashed.error, "signal: killed");
    }
    #[test]
    fn running_without_healthcheck_does_not_prove_s1_ready() {
        let process = ProcessObservation {
            process_state: "running".into(),
            health: "not_available".into(),
            observed: true,
            controller_owned: true,
            last_error: None,
        };
        let mut status = LteStatus {
            technology: "LTE 4G",
            simulator: "srsRAN",
            certified: false,
            live_enabled: true,
            epc: process.clone(),
            s1_state: "UNKNOWN".into(),
            enb: process,
            ue: ProcessObservation::unknown(),
            ue_id: LTE_UE_ID,
            attach_state: "UNKNOWN".into(),
            attach_success_observed: false,
            epc_context_observed: false,
            apn: "UNKNOWN".into(),
            ue_ip: None,
            session_state: "UNKNOWN".into(),
            active_sessions: 0,
            ownership_verified: true,
            traffic_ready: false,
        };
        assert!(!s1_setup_is_proven(&status));
        status.s1_state = "CONNECTED".into();
        assert!(s1_setup_is_proven(&status));
    }
    #[test]
    fn sidecar_cleanup_is_explicit_in_runtime_fixture() {
        let runtime = MockSrsranRuntime::default();
        assert!(runtime.cleanup_run_sidecars("lte-run-test").unwrap());
        *runtime.sidecars_absent.lock().unwrap() = false;
        assert!(!runtime.cleanup_run_sidecars("lte-run-test").unwrap());
    }
    #[test]
    fn bounded_udp_rejects_any_value_above_certification_caps() {
        let runtime = MockSrsranRuntime::default();
        assert_eq!(
            runtime.measure_bounded_udp("ul", 1_000_001, 1, 1_200),
            Err("LTE_TRAFFIC_PARAMETERS_INVALID".into())
        );
        assert_eq!(
            runtime.measure_bounded_udp("dl", 1_000_000, 31, 1_200),
            Err("LTE_TRAFFIC_PARAMETERS_INVALID".into())
        );
        assert_eq!(
            runtime.measure_bounded_udp("ul", 1_000_000, 1, 1_201),
            Err("LTE_TRAFFIC_PARAMETERS_INVALID".into())
        );
    }
    #[test]
    fn udp_iperf_command_enforces_payload_block_length_and_binds_ue_tun() {
        // Each iperf call now consumes 3 docker exec outputs:
        //   1. preflight: `ip route get PEER`
        //   2. ue_ip:     `ip -o -4 addr show dev tun_srsue`
        //   3. iperf3:    the actual measurement
        let route_ok = "192.0.2.1 dev tun_srsue src 10.45.0.5 uid 0\n";
        let ue_ip_line = "1: tun_srsue    inet 10.45.0.5/24 scope global tun_srsue\n";
        let executor = Arc::new(ScriptExecutor::default());
        {
            let mut outputs = executor.outputs.lock().unwrap();
            // UDP call
            outputs.push_back(output(0, route_ok));
            outputs.push_back(output(0, ue_ip_line));
            outputs.push_back(output(
                0,
                r#"{"end":{"sum_sent":{"bytes":125000,"bits_per_second":1000000}}}"#,
            ));
            // TCP call
            outputs.push_back(output(0, route_ok));
            outputs.push_back(output(0, ue_ip_line));
            outputs.push_back(output(
                0,
                r#"{"end":{"sum_sent":{"bytes":125000,"bits_per_second":1000000}}}"#,
            ));
        }
        let runtime = DockerSrsranRuntime {
            executor: executor.clone(),
            ledger: PathBuf::from("/unused-in-command-test"),
        };
        let ue = Container {
            id: "owned-ue".into(),
            state: "running".into(),
            health: DockerHealth::Healthy,
            error: String::new(),
        };
        let previous_peer = std::env::var_os("POLARIS_LTE_TRAFFIC_PEER_IP");
        std::env::set_var("POLARIS_LTE_TRAFFIC_PEER_IP", "192.0.2.1");
        // 0.29.2: do NOT set POLARIS_DL_SENDER_IP — proves the LTE path no
        // longer requires it to be defined.
        std::env::remove_var("POLARIS_DL_SENDER_IP");
        let udp_result = runtime.iperf(&ue, false, "udp", 750_000, 7, 900);
        let tcp_result = runtime.iperf(&ue, false, "tcp", 1_000_000, 1, 1_200);
        match previous_peer {
            Some(value) => std::env::set_var("POLARIS_LTE_TRAFFIC_PEER_IP", value),
            None => std::env::remove_var("POLARIS_LTE_TRAFFIC_PEER_IP"),
        }
        udp_result.unwrap();
        tcp_result.unwrap();
        let calls = executor.calls.lock().unwrap();
        // UDP iperf call is the third call (index 2).
        let udp = &calls[2];
        assert!(udp.windows(2).any(|args| args == ["-l", "900"]));
        assert!(udp.windows(2).any(|args| args == ["-b", "750000"]));
        assert!(udp.windows(2).any(|args| args == ["-t", "7"]));
        assert!(
            udp.windows(2).any(|args| args == ["-B", "10.45.0.5"]),
            "iperf3 UL must bind source to the UE tun IP: {:?}",
            udp
        );
        // TCP iperf call is the sixth call (index 5).
        let tcp = &calls[5];
        assert!(!tcp.iter().any(|arg| arg == "-u" || arg == "-l"));
        assert!(
            tcp.windows(2).any(|args| args == ["-B", "10.45.0.5"]),
            "iperf3 UL TCP must also bind source to the UE tun IP: {:?}",
            tcp
        );
    }

    #[test]
    fn iperf_ul_fails_closed_when_route_bypasses_tun_srsue() {
        let executor = Arc::new(ScriptExecutor::default());
        // Route output: default via eth0 (NOT via tun_srsue) → preflight rejects.
        executor.outputs.lock().unwrap().push_back(output(
            0,
            "192.0.2.1 via 10.0.2.2 dev eth0 src 10.0.2.15 uid 0\n",
        ));
        let runtime = DockerSrsranRuntime {
            executor: executor.clone(),
            ledger: PathBuf::from("/unused-route-reject-test"),
        };
        let ue = Container {
            id: "owned-ue".into(),
            state: "running".into(),
            health: DockerHealth::Healthy,
            error: String::new(),
        };
        let previous_peer = std::env::var_os("POLARIS_LTE_TRAFFIC_PEER_IP");
        std::env::set_var("POLARIS_LTE_TRAFFIC_PEER_IP", "192.0.2.1");
        let result = runtime.iperf(&ue, false, "udp", 750_000, 5, 900);
        match previous_peer {
            Some(value) => std::env::set_var("POLARIS_LTE_TRAFFIC_PEER_IP", value),
            None => std::env::remove_var("POLARIS_LTE_TRAFFIC_PEER_IP"),
        }
        assert_eq!(result, Err("LTE_UL_ROUTE_NOT_VIA_UE_TUN".into()));
        // Only the probe ran; no iperf3 spawn, no ue_ip query.
        let calls = executor.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].iter().any(|arg| arg == "route"));
    }
    #[test]
    fn lte_sgi_peer_is_decoupled_from_n6_dl_sender() {
        // Missing peer still fails fail-closed with the exact code.
        assert_eq!(
            validate_traffic_peer_values(None, Some("10.77.24.30")),
            Err("LTE_TRAFFIC_PEER_NOT_CONFIGURED".into())
        );
        // Invalid IPv4 remains fail-closed.
        assert_eq!(
            validate_traffic_peer_values(Some("not-an-ip"), Some("10.77.24.30")),
            Err("LTE_TRAFFIC_PEER_INVALID".into())
        );
        // 0.29.2: a missing or distinct POLARIS_DL_SENDER_IP no longer rejects
        // the LTE SGi peer. The SGi DN is a separate endpoint from the 5G N6
        // sender; equality is not required and must not be enforced.
        assert_eq!(
            validate_traffic_peer_values(Some("10.77.24.30"), None),
            Ok("10.77.24.30".parse().unwrap())
        );
        assert_eq!(
            validate_traffic_peer_values(Some("10.77.16.30"), Some("10.77.24.30")),
            Ok("10.77.16.30".parse().unwrap())
        );
        // Equal values are still accepted (back-compat for the current drop-in).
        assert_eq!(
            validate_traffic_peer_values(Some("10.77.24.30"), Some("10.77.24.30")),
            Ok("10.77.24.30".parse().unwrap())
        );
    }

    #[test]
    fn lte_ul_route_preflight_requires_tun_srsue() {
        // Happy path: kernel resolved via tun_srsue → ok.
        let raw = "10.77.16.30 dev tun_srsue src 10.45.0.5 uid 0";
        let evidence = evaluate_lte_ul_route(raw, "10.77.16.30");
        assert!(evidence.ok);
        assert_eq!(evidence.expected_dev, "tun_srsue");
        assert_eq!(evidence.actual_dev.as_deref(), Some("tun_srsue"));
        assert_eq!(evidence.code, None);

        // Bridge default route → rejected with the LTE-specific code.
        let bridge = "10.77.16.30 via 10.0.2.2 dev eth0 src 10.0.2.15 uid 0";
        let evidence = evaluate_lte_ul_route(bridge, "10.77.16.30");
        assert!(!evidence.ok);
        assert_eq!(evidence.code.as_deref(), Some("LTE_UL_ROUTE_NOT_VIA_UE_TUN"));
        assert_eq!(evidence.actual_dev.as_deref(), Some("eth0"));

        // 5G uesimtun0 is not a valid LTE SGi outbound (keeps LTE vs 5G separate).
        let five_g = "10.77.16.30 dev uesimtun0 src 10.46.0.5 uid 0";
        let evidence = evaluate_lte_ul_route(five_g, "10.77.16.30");
        assert!(!evidence.ok);
        assert_eq!(evidence.code.as_deref(), Some("LTE_UL_ROUTE_NOT_VIA_UE_TUN"));
    }

    fn policy() -> SgiReturnRoutePolicy {
        SgiReturnRoutePolicy {
            required_next_hop: "10.77.16.15".into(),
            required_ue_subnet: "10.45.0.0/16".into(),
            forbidden_devs: vec![
                "lo".into(),
                "null0".into(),
                "blackhole".into(),
                "eth0".into(),
                "oiran-lab-n6".into(),
            ],
        }
    }

    #[test]
    fn lte_dl_return_route_preflight_requires_next_hop_subnet_and_device() {
        // Happy path: correct next-hop + usable dev + UE in subnet.
        assert_eq!(
            evaluate_lte_dl_return_route(
                "10.45.0.2 via 10.77.16.15 dev sgi_lte src 10.77.16.30 uid 0",
                "10.45.0.2",
                &policy(),
            ),
            Ok(())
        );

        // UE IP outside the configured subnet is rejected first.
        assert_eq!(
            evaluate_lte_dl_return_route(
                "10.9.9.2 via 10.77.16.15 dev sgi_lte src 10.77.16.30 uid 0",
                "10.9.9.2",
                &policy(),
            ),
            Err("LTE_UE_IP_OUTSIDE_SUBNET".into())
        );

        // Network unreachable.
        assert_eq!(
            evaluate_lte_dl_return_route(
                "RTNETLINK answers: Network is unreachable",
                "10.45.0.2",
                &policy(),
            ),
            Err("LTE_DL_RETURN_ROUTE_UNAVAILABLE".into())
        );

        // No dev field.
        assert_eq!(
            evaluate_lte_dl_return_route("??? garbage ???", "10.45.0.2", &policy()),
            Err("LTE_DL_RETURN_ROUTE_UNAVAILABLE".into())
        );

        // Loopback/blackhole (in forbidden list).
        assert_eq!(
            evaluate_lte_dl_return_route(
                "10.45.0.2 dev lo src 127.0.0.1",
                "10.45.0.2",
                &policy()
            ),
            Err("LTE_DL_RETURN_ROUTE_VIA_FORBIDDEN_DEV".into())
        );
        assert_eq!(
            evaluate_lte_dl_return_route(
                "blackhole 10.45.0.2 dev blackhole",
                "10.45.0.2",
                &policy()
            ),
            Err("LTE_DL_RETURN_ROUTE_VIA_FORBIDDEN_DEV".into())
        );

        // Route out via N6 bridge is explicitly forbidden.
        assert_eq!(
            evaluate_lte_dl_return_route(
                "10.45.0.2 via 10.77.24.1 dev eth0 src 10.77.24.30 uid 0",
                "10.45.0.2",
                &policy(),
            ),
            Err("LTE_DL_RETURN_ROUTE_VIA_FORBIDDEN_DEV".into())
        );
        assert_eq!(
            evaluate_lte_dl_return_route(
                "10.45.0.2 via 10.77.24.1 dev oiran-lab-n6 src 10.77.24.30 uid 0",
                "10.45.0.2",
                &policy(),
            ),
            Err("LTE_DL_RETURN_ROUTE_VIA_FORBIDDEN_DEV".into())
        );

        // Missing via (direct route is wrong — SGi must traverse PGW-U).
        assert_eq!(
            evaluate_lte_dl_return_route(
                "10.45.0.2 dev sgi_lte src 10.77.16.30 uid 0",
                "10.45.0.2",
                &policy(),
            ),
            Err("LTE_DL_RETURN_ROUTE_MISSING_VIA".into())
        );

        // Wrong next-hop (not the configured PGW-U LTE).
        assert_eq!(
            evaluate_lte_dl_return_route(
                "10.45.0.2 via 10.77.24.1 dev sgi_lte src 10.77.16.30 uid 0",
                "10.45.0.2",
                &policy(),
            ),
            Err("LTE_DL_RETURN_ROUTE_WRONG_NEXT_HOP".into())
        );
    }

    #[test]
    fn configured_lte_dn_sender_container_requires_explicit_setting() {
        let prev = std::env::var_os("POLARIS_LTE_DN_SENDER_CONTAINER");
        std::env::remove_var("POLARIS_LTE_DN_SENDER_CONTAINER");
        assert_eq!(
            configured_lte_dn_sender_container(),
            Err("LTE_DN_SENDER_NOT_CONFIGURED".into())
        );
        std::env::set_var("POLARIS_LTE_DN_SENDER_CONTAINER", "   ");
        assert_eq!(
            configured_lte_dn_sender_container(),
            Err("LTE_DN_SENDER_NOT_CONFIGURED".into())
        );
        std::env::set_var("POLARIS_LTE_DN_SENDER_CONTAINER", "polaris-dn-sender");
        assert_eq!(
            configured_lte_dn_sender_container(),
            Err("LTE_DN_SENDER_COLLIDES_WITH_N6".into())
        );
        std::env::set_var("POLARIS_LTE_DN_SENDER_CONTAINER", "polaris-lte-sgi-dn ");
        assert_eq!(
            configured_lte_dn_sender_container(),
            Ok("polaris-lte-sgi-dn".to_string())
        );
        std::env::set_var("POLARIS_LTE_DN_SENDER_CONTAINER", "bad name!");
        assert_eq!(
            configured_lte_dn_sender_container(),
            Err("LTE_DN_SENDER_NAME_INVALID".into())
        );
        match prev {
            Some(value) => std::env::set_var("POLARIS_LTE_DN_SENDER_CONTAINER", value),
            None => std::env::remove_var("POLARIS_LTE_DN_SENDER_CONTAINER"),
        }
    }

    #[test]
    fn classify_dn_container_exit_detects_missing_tooling() {
        assert_eq!(classify_dn_container_exit(0, ""), Ok(()));
        assert_eq!(classify_dn_container_exit(1, ""), Ok(()));
        assert_eq!(
            classify_dn_container_exit(127, ""),
            Err("LTE_DN_SENDER_TOOLING_MISSING".into())
        );
        assert_eq!(
            classify_dn_container_exit(126, ""),
            Err("LTE_DN_SENDER_TOOLING_MISSING".into())
        );
        assert_eq!(
            classify_dn_container_exit(2, "ping: command not found\n"),
            Err("LTE_DN_SENDER_TOOLING_MISSING".into())
        );
        assert_eq!(
            classify_dn_container_exit(2, "exec: \"iperf3\": executable file not found in $PATH"),
            Err("LTE_DN_SENDER_TOOLING_MISSING".into())
        );
    }

    #[test]
    fn configured_traffic_peer_rejects_collision_with_n6_sender() {
        let prev_peer = std::env::var_os("POLARIS_LTE_TRAFFIC_PEER_IP");
        let prev_sender = std::env::var_os("POLARIS_DL_SENDER_IP");
        std::env::set_var("POLARIS_LTE_TRAFFIC_PEER_IP", "10.77.24.30");
        std::env::set_var("POLARIS_DL_SENDER_IP", "10.77.24.30");
        assert_eq!(
            configured_traffic_peer(),
            Err("LTE_SGI_COLLIDES_WITH_N6".into())
        );
        std::env::set_var("POLARIS_LTE_TRAFFIC_PEER_IP", "10.77.16.30");
        std::env::set_var("POLARIS_DL_SENDER_IP", "10.77.24.30");
        assert_eq!(configured_traffic_peer(), Ok("10.77.16.30".parse().unwrap()));
        match prev_peer {
            Some(value) => std::env::set_var("POLARIS_LTE_TRAFFIC_PEER_IP", value),
            None => std::env::remove_var("POLARIS_LTE_TRAFFIC_PEER_IP"),
        }
        match prev_sender {
            Some(value) => std::env::set_var("POLARIS_DL_SENDER_IP", value),
            None => std::env::remove_var("POLARIS_DL_SENDER_IP"),
        }
    }

    #[test]
    fn configured_lte_dl_return_policy_requires_pgw_u_next_hop() {
        let prev_hop = std::env::var_os("POLARIS_LTE_PGW_U_NEXT_HOP");
        let prev_subnet = std::env::var_os("POLARIS_LTE_UE_SUBNET");
        std::env::remove_var("POLARIS_LTE_PGW_U_NEXT_HOP");
        assert_eq!(
            configured_lte_dl_return_policy().err(),
            Some("LTE_PGW_U_NEXT_HOP_NOT_CONFIGURED".into())
        );
        std::env::set_var("POLARIS_LTE_PGW_U_NEXT_HOP", "not-an-ip");
        assert_eq!(
            configured_lte_dl_return_policy().err(),
            Some("LTE_PGW_U_NEXT_HOP_INVALID".into())
        );
        std::env::set_var("POLARIS_LTE_PGW_U_NEXT_HOP", "10.77.16.15");
        std::env::set_var("POLARIS_LTE_UE_SUBNET", "not-a-cidr");
        assert_eq!(
            configured_lte_dl_return_policy().err(),
            Some("LTE_UE_SUBNET_INVALID".into())
        );
        std::env::remove_var("POLARIS_LTE_UE_SUBNET"); // use default
        let built = configured_lte_dl_return_policy().unwrap();
        assert_eq!(built.required_next_hop, "10.77.16.15");
        assert_eq!(built.required_ue_subnet, "10.45.0.0/16");
        assert!(built.forbidden_devs.contains(&"oiran-lab-n6".to_string()));
        assert!(built.forbidden_devs.contains(&"lo".to_string()));
        match prev_hop {
            Some(value) => std::env::set_var("POLARIS_LTE_PGW_U_NEXT_HOP", value),
            None => std::env::remove_var("POLARIS_LTE_PGW_U_NEXT_HOP"),
        }
        match prev_subnet {
            Some(value) => std::env::set_var("POLARIS_LTE_UE_SUBNET", value),
            None => std::env::remove_var("POLARIS_LTE_UE_SUBNET"),
        }
    }
    #[test]
    fn traffic_preflight_failure_has_no_lifecycle_side_effect() {
        let runtime = MockSrsranRuntime::default();
        *runtime.traffic_configuration_error.lock().unwrap() =
            Some("LTE_TRAFFIC_PEER_NOT_CONFIGURED".into());
        assert_eq!(
            runtime.validate_traffic_configuration(),
            Err("LTE_TRAFFIC_PEER_NOT_CONFIGURED".into())
        );
        assert!(runtime.started.lock().unwrap().is_empty());
        assert!(runtime.stopped.lock().unwrap().is_empty());
    }
    #[test]
    fn canonical_n6_dropin_sets_only_n6_variables() {
        let dropin = include_str!(
            "../../../deployment/dn-sender/polaris-control-dl-sender.conf"
        );
        assert!(dropin.contains("Environment=POLARIS_DL_SENDER_IP=10.77.24.30"));
        // 0.29.3: the N6 drop-in no longer sets any LTE variable; those live
        // in lte-sgi/polaris-control-lte-sgi.conf and are activated only
        // after Codex confirms addressing and image digest.
        assert!(
            !dropin
                .lines()
                .any(|line| line.trim_start().starts_with("Environment=POLARIS_LTE_")),
            "N6 drop-in must not set any POLARIS_LTE_* variable"
        );
    }

    #[test]
    fn candidate_lte_sgi_dropin_is_fail_closed_until_codex_confirms() {
        let dropin = include_str!(
            "../../../deployment/dn-sender/lte-sgi/polaris-control-lte-sgi.conf"
        );
        for required in [
            "POLARIS_LTE_DN_SENDER_CONTAINER",
            "POLARIS_LTE_TRAFFIC_PEER_IP",
            "POLARIS_LTE_PGW_U_NEXT_HOP",
            "POLARIS_LTE_UE_SUBNET",
        ] {
            // Each required variable must be mentioned in a COMMENT, not an
            // active Environment= line, so an operator cannot deploy this
            // file verbatim.
            let active = format!("Environment={required}=");
            assert!(
                !dropin
                    .lines()
                    .any(|line| line.trim_start().starts_with(&active)),
                "{required} must stay commented in the candidate drop-in"
            );
            let commented = format!("# Environment={required}=");
            assert!(
                dropin.contains(&commented),
                "{required} must be shown as a commented example"
            );
        }
    }

    #[test]
    fn candidate_lte_sgi_sidecar_pins_image_digest_placeholder_and_hardens_pod() {
        let compose = include_str!(
            "../../../deployment/dn-sender/lte-sgi/compose.yaml"
        );
        // Image is pinned by @sha256 but the digest is a placeholder; Codex
        // must replace it before activation.
        assert!(compose.contains("@sha256:"));
        assert!(compose.contains("SIDE_CAR_IMAGE_DIGEST=PENDING"));
        // Hardening gates — any removal of these breaks the test.
        for marker in [
            "cap_drop:",
            "- ALL",
            "no-new-privileges:true",
            "read_only: true",
            "user: \"65532:65532\"",
            "polaris.sidecar.image_digest_state=PENDING",
        ] {
            assert!(
                compose.contains(marker),
                "candidate sidecar must retain hardening marker {marker}"
            );
        }
    }
    #[test]
    fn host_timeout_is_fail_closed() {
        assert_eq!(classify_exit(124), Err("SRSRAN_COMMAND_TIMEOUT".into()));
        assert_eq!(classify_exit(137), Err("SRSRAN_COMMAND_TIMEOUT".into()));
        assert_eq!(classify_exit(1), Ok(()));
    }
    #[test]
    fn docker_inspect_timeout_is_propagated() {
        let executor = Arc::new(ScriptExecutor::default());
        executor.outputs.lock().unwrap().extend([
            output(0, "container-id\n"),
            Err("SRSRAN_COMMAND_TIMEOUT".into()),
        ]);
        let runtime = DockerSrsranRuntime {
            executor,
            ledger: PathBuf::from("/unused-timeout-test"),
        };
        assert_eq!(
            runtime.resolve("srsenb"),
            Err("SRSRAN_COMMAND_TIMEOUT".into())
        );
    }
    #[test]
    fn docker_mme_attach_complete_has_bounded_timestamp_and_provenance() {
        let executor = Arc::new(ScriptExecutor::default());
        let id = "mme-container-id";
        executor.outputs.lock().unwrap().extend([
            output(0, &format!("{id}\n")),
            output(
                0,
                &inspect_json(id, "mme", "running", TestHealth::Absent, ""),
            ),
            output(
                0,
                "2026-11-01T12:00:00.123456789Z MME Attach Complete received\n",
            ),
        ]);
        let runtime = DockerSrsranRuntime {
            executor: executor.clone(),
            ledger: PathBuf::from("/unused-attach-evidence-test"),
        };
        let evidence = runtime
            .attach_complete_event(1_793_534_400_000, 1_793_534_400_500)
            .unwrap()
            .unwrap();
        assert_eq!(evidence.event_at_epoch_ms, 1_793_534_400_123);
        assert_eq!(evidence.provenance, "OPEN5GS_MME_DOCKER_LOG_RFC3339");
        let calls = executor.calls.lock().unwrap();
        assert!(calls[2].windows(2).any(|args| args == ["--timestamps", "--since"]));
        assert!(calls[2].windows(2).any(|args| args == ["--until", "1793534400.500"]));
    }
    #[test]
    fn docker_timestamp_parser_is_utc_and_millisecond_bounded() {
        assert_eq!(
            parse_rfc3339_utc_millis("2026-11-01T12:00:00.123456789Z"),
            Some(1_793_534_400_123)
        );
        assert_eq!(
            parse_rfc3339_utc_millis("2026-11-01T12:00:00Z"),
            Some(1_793_534_400_000)
        );
        assert_eq!(parse_rfc3339_utc_millis("2026-11-01 12:00:00Z"), None);
        assert_eq!(parse_rfc3339_utc_millis("2026-11-01T12:00:00+00:00"), None);
    }
    #[test]
    fn canonical_compose_model_includes_the_lte_profile() {
        let args = compose_config_args();
        assert!(args.windows(2).any(|pair| pair == ["--profile", "lte"]));
        assert!(args
            .windows(3)
            .any(|window| { window == ["config", "--format", "json"] }));
    }
    #[test]
    fn canonical_compose_json_is_invariant_to_object_key_order() {
        let left: serde_json::Value = serde_json::from_str(
            r#"{"services":{"srsue":{"image":"sha256:test","profiles":["lte"]}},"name":"oiran-lab"}"#,
        )
        .unwrap();
        let right: serde_json::Value = serde_json::from_str(
            r#"{"name":"oiran-lab","services":{"srsue":{"profiles":["lte"],"image":"sha256:test"}}}"#,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_vec(&canonical_json(&left)).unwrap(),
            serde_json::to_vec(&canonical_json(&right)).unwrap()
        );
    }
    #[test]
    fn certification_subject_requires_both_certified_digests() {
        assert!(validate_certified_release_subject(
            CERTIFIED_IMAGE_REFERENCE,
            CERTIFIED_COMPOSE_MODEL_SHA256
        )
        .is_ok());
        assert_eq!(
            validate_certified_release_subject(
                "oiran/srsran4g@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                CERTIFIED_COMPOSE_MODEL_SHA256
            ),
            Err("LTE_CERTIFIED_IMAGE_MISMATCH".into())
        );
        assert_eq!(
            validate_certified_release_subject(CERTIFIED_IMAGE_REFERENCE, &"f".repeat(64)),
            Err("LTE_CERTIFIED_COMPOSE_MODEL_MISMATCH".into())
        );
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
                &inspect_json(id, "srsenb", "created", TestHealth::Absent, ""),
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
    #[test]
    fn newly_created_container_without_healthcheck_is_accepted_as_started_only() {
        let executor = Arc::new(ScriptExecutor::default());
        let id = "fedcba9876543210";
        executor.outputs.lock().unwrap().extend([
            output(0, ""),
            output(0, ""),
            output(0, &format!("{id}\n")),
            output(
                0,
                &inspect_json(id, "srsenb", "created", TestHealth::Absent, ""),
            ),
            output(0, ""),
            output(0, &format!("{id}\n")),
            output(
                0,
                &inspect_json(id, "srsenb", "running", TestHealth::Absent, ""),
            ),
        ]);
        let root =
            std::env::temp_dir().join(format!("polaris-srsran-no-health-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let runtime = DockerSrsranRuntime {
            executor,
            ledger: root.join("ledger.json"),
        };
        assert_eq!(runtime.start(Target::Enb), Ok(()));
        assert!(runtime.load().unwrap().components.contains_key("srsenb"));
        let _ = fs::remove_dir_all(root);
    }
    #[test]
    fn post_start_inspect_timeout_cleans_new_container_and_ownership() {
        let executor = Arc::new(ScriptExecutor::default());
        let id = "abcdef0123456789";
        executor.outputs.lock().unwrap().extend([
            output(0, ""),
            output(0, ""),
            output(0, &format!("{id}\n")),
            output(
                0,
                &inspect_json(id, "srsenb", "created", TestHealth::Absent, ""),
            ),
            output(0, ""),
            output(0, &format!("{id}\n")),
            Err("SRSRAN_COMMAND_TIMEOUT".into()),
            output(0, ""),
        ]);
        let root = std::env::temp_dir().join(format!(
            "polaris-srsran-start-timeout-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let runtime = DockerSrsranRuntime {
            executor: executor.clone(),
            ledger: root.join("ledger.json"),
        };
        assert_eq!(
            runtime.start(Target::Enb),
            Err("SRSRAN_COMMAND_TIMEOUT".into())
        );
        assert!(runtime.load().unwrap().components.is_empty());
        assert!(executor
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|args| args == &vec!["rm".to_string(), "-f".to_string(), id.to_string()]));
        let _ = fs::remove_dir_all(root);
    }
}
