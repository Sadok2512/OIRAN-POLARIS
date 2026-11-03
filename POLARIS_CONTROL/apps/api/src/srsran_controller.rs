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
const COMPOSE_0298_OVERRIDE: &str = "/root/POLARIS/compose/docker-compose.polaris-0.29.8.yml";
const UE_CONFIG: &str = "/root/POLARIS/runtime/srsran/ue.conf";
const ENB_CONFIG: &str = "/root/POLARIS/config/srsran/enb.conf";
const LEDGER: &str = "/var/lib/polaris-control/srsran-ownership.json";
pub const CERTIFIED_IMAGE_REFERENCE: &str = "oiran/srsran4g-ue-tools:0.29.6-rc1";
pub const CERTIFIED_IMAGE_ID: &str =
    "sha256:aab719ffdfa518777ed3d197ffe02cdcef02f78f578095d9abb1da9f327db2a5";
pub const CERTIFIED_DN_IMAGE_REFERENCE: &str =
    "polaris-lte-sgi-dn@sha256:e60eb72bf7619fd049f6bbbc45cf06927eb73ed7c613446678644f6742af31f3";
pub const CERTIFIED_COMPOSE_MODEL_SHA256: &str =
    "b25bc0137713697140aa96cb8e4964c844ce84754a1deb998387c2ed9595e560";
const PROFILE_CONFIGS: [&str; 6] = [
    "/root/POLARIS/runtime/srsran/ue.conf",
    "/root/POLARIS/config/srsran/enb.conf",
    "/root/POLARIS/config/srsran/rr.conf",
    COMPOSE,
    COMPOSE_0298_OVERRIDE,
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

#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct PingMeasurement {
    pub sent: u32,
    pub received: u32,
}
#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct EnbRuntimeEvidence {
    pub gtp_bind_addr: Option<String>,
    pub s1c_bind_addr: Option<String>,
    pub networks: BTreeMap<String, String>,
    pub s1u_network_present: bool,
    pub ul_bitrate: Option<String>,
    pub dl_bitrate: Option<String>,
}
#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct PingRuntimeEvidence {
    pub ping: CommandDiagnostic,
    pub ue_link: CommandDiagnostic,
    pub ue_routes: CommandDiagnostic,
    pub srsue_log_tail: CommandDiagnostic,
    pub srsenb_log_tail: CommandDiagnostic,
    pub enb: EnbRuntimeEvidence,
    pub enb_link_counters: BTreeMap<String, CommandDiagnostic>,
    pub container_image_ids: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct PingOperation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurement: Option<PingMeasurement>,
    pub evidence: PingRuntimeEvidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}
impl PingOperation {
    pub fn succeeded(&self) -> bool {
        self.error_code.is_none() && self.measurement.is_some()
    }
}

/// 0.29.7: metadata about the full sanitized `docker logs` of one container
/// persisted on the host **before** the cleanup drops the container. The
/// public API returns only the metadata (path + sha256 + byte count +
/// bounded tail), never the raw contents.
#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct FullLogRecord {
    pub component: String,
    /// Host-side absolute path (root-only, mode 0o600).
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    /// Sanitized tail (last 512 UTF-8 bytes, same bound as the other
    /// evidence streams). The full stream lives in the file.
    #[serde(skip)]
    pub sanitized_tail: String,
    /// Private RRC/PDCP/RLC extract, bounded to the final 4096 UTF-8 bytes.
    pub rrc_path: String,
    pub rrc_bytes: u64,
    pub rrc_sha256: String,
    pub persisted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

/// 0.29.7: eNB + SGW-U read-only network diagnostics collected before
/// cleanup to catch an ARP/neighbor regression on the S1-U fabric.
#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct EnbNetworkDiagnostics {
    pub enb_ip_neigh: CommandDiagnostic,
    pub enb_ip_s_link: CommandDiagnostic,
    pub sgw_u_ip_neigh: CommandDiagnostic,
}

/// 0.29.7: terminal evidence collected before cleanup. Full sanitized
/// logs are persisted on disk; the public struct only carries their
/// metadata (path + SHA256 + bounded tail) plus the eNB/SGW-U network
/// diagnostics. Nothing in this struct exposes raw log contents to the
/// public API.
#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct TerminalEvidence {
    pub srsue_log: FullLogRecord,
    pub srsenb_log: FullLogRecord,
    pub enb_network: EnbNetworkDiagnostics,
    /// 0.29.8: `[RRC]` lines extracted from the srsUE and srsENB logs,
    /// sanitized and bounded to 4 KiB per component with the end
    /// preserved. Keyed by component ("srsue", "srsenb"). The private
    /// evidence remains in the root-only run store at
    /// `/var/lib/polaris-control/lte-runs-v2/<run_id>.json`.
    #[serde(skip)]
    pub rrc_extracts: BTreeMap<String, String>,
}

/// 0.29.8: fixed `[log]` section the orchestrator writes into the per-run
/// `/root/POLARIS/runtime/srsran/ue.conf` before `runtime.start(Target::Ue)`.
/// Addresses the 15730a0f pathology where 99.77% of 156 328 srsUE log
/// lines were PHY_LIB/I noise and the RRC window vanished with Docker log
/// rotation. The nine pairs are frozen.
pub const RUN_UE_LOG_SECTION: &[(&str, &str)] = &[
    ("phy_lib_level", "none"),
    ("phy_level", "warning"),
    ("mac_level", "info"),
    ("rlc_level", "debug"),
    ("pdcp_level", "debug"),
    ("rrc_level", "debug"),
    ("nas_level", "debug"),
    ("usim_level", "warning"),
    ("all_hex_limit", "64"),
];

/// 0.29.8: POLARIS does NOT currently generate a per-run `enb.conf`; the
/// file at `ENB_CONFIG` is a committed deployment artifact and MUST stay
/// untouched. If future work introduces per-run eNB config generation,
/// these are the four levels to inject. Documented in CHANGELOG.
pub const RUN_ENB_LOG_SECTION_PLACEHOLDER: &[(&str, &str)] = &[
    ("phy_level", "warning"),
    ("rrc_level", "debug"),
    ("s1ap_level", "debug"),
    ("gtpu_level", "debug"),
];

/// 0.29.8: result of writing the per-run `[log]` section into the UE
/// config file. Recorded in the run store so the evidence trail shows
/// which log levels were in effect for the run.
#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct LogSectionPatch {
    pub path: String,
    pub previous_sha256: String,
    pub new_sha256: String,
    pub bytes_before: u64,
    pub bytes_after: u64,
    pub applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

/// 0.29.8: section-aware INI patcher. Reads an srsRAN-style config,
/// replaces the body of the `[section]` block (keeping the section
/// header) with the exact `pairs`, and appends a new `[section]` block
/// if none exists. All other sections are byte-identical to the input.
/// Pure function.
pub fn inject_log_section(existing: &str, section: &str, pairs: &[(&str, &str)]) -> String {
    let target_header = format!("[{section}]");
    let mut out = String::with_capacity(existing.len() + 256);
    let mut found = false;
    let mut lines = existing.lines().peekable();
    while let Some(line) = lines.next() {
        if line.trim() == target_header {
            found = true;
            out.push_str(line);
            out.push('\n');
            for (key, value) in pairs {
                out.push_str(&format!("{key} = {value}\n"));
            }
            // Skip the old section body until we hit the next header.
            while let Some(peek) = lines.peek() {
                let trimmed = peek.trim();
                if trimmed.starts_with('[') && trimmed.ends_with(']') {
                    break;
                }
                lines.next();
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if !found {
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&target_header);
        out.push('\n');
        for (key, value) in pairs {
            out.push_str(&format!("{key} = {value}\n"));
        }
    }
    out
}

fn log_section_matches(existing: &str, section: &str, pairs: &[(&str, &str)]) -> bool {
    let target_header = format!("[{section}]");
    let mut in_target = false;
    let mut observed = BTreeMap::new();
    for line in existing.lines() {
        let trimmed = line.split('#').next().unwrap_or_default().trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_target = trimmed == target_header;
            continue;
        }
        if !in_target || trimmed.is_empty() {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            observed.insert(key.trim(), value.trim());
        }
    }
    pairs
        .iter()
        .all(|(key, value)| observed.get(key).is_some_and(|actual| actual == value))
}

/// 0.29.8: filter all `[RRC]` lines out of a sanitised log stream, keep
/// the last `max_bytes` on a UTF-8 code-point boundary. The returned
/// string is also sanitised via `sanitize_log_line` to drop subscriber
/// identity even if any leaked through.
pub fn extract_rrc_lines(logs: &str, max_bytes: usize) -> String {
    let filtered = logs
        .lines()
        .filter_map(sanitize_log_line)
        .filter(|line| line.contains("[RRC]"))
        .collect::<Vec<_>>()
        .join("\n");
    truncate_utf8_tail(&filtered, max_bytes)
}

/// 0.29.7: evidence that the EPS bearer control plane completed before
/// user plane traffic is attempted. Both markers are mandatory.
#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct ErabEstablishmentEvidence {
    pub ics_response_observed: bool,
    pub ics_response_e_rab_markers: u32,
    pub modify_bearer_response_observed: bool,
    pub modify_bearer_response_markers: u32,
    /// Sanitized summary of what was seen vs. expected. Bounded 512.
    pub summary: String,
}

#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct CommandDiagnostic {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct RouteOperation {
    pub diagnostic: CommandDiagnostic,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

impl RouteOperation {
    pub fn succeeded(&self) -> bool {
        self.error_code.is_none()
    }
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
    fn install_lte_ul_route(&self) -> RouteOperation {
        RouteOperation::default()
    }
    fn probe_traffic_route(&self, _direction: &str) -> RouteOperation {
        RouteOperation::default()
    }
    /// 0.29.7: fail-closed EPS bearer gate run **before** any ping/UDP.
    /// Default returns `Ok(default)` (used by the Mock); the Docker runtime
    /// reads srsENB + MME logs and delegates to `evaluate_erab_establishment`.
    fn verify_erab_established(
        &self,
    ) -> Result<ErabEstablishmentEvidence, (String, ErabEstablishmentEvidence)> {
        Ok(ErabEstablishmentEvidence::default())
    }
    /// 0.29.8: write the required `[log]` section into the UE config at
    /// `UE_CONFIG` **before** `runtime.start(Target::Ue)`. Section-aware
    /// patch: only the `[log]` body changes; every other section stays
    /// byte-identical. Default returns an empty record for Mock-based tests.
    fn apply_run_ue_log_section(&self) -> LogSectionPatch {
        LogSectionPatch {
            path: UE_CONFIG.to_string(),
            ..LogSectionPatch::default()
        }
    }
    /// 0.29.7: persist the FULL `docker logs` of srsENB + srsUE (and
    /// collect eNB + SGW-U network diagnostics) **before** cleanup. The
    /// default returns empty records so Mock-based tests do not force disk
    /// writes.
    fn collect_terminal_evidence(
        &self,
        _run_id: &str,
        _run_dir: &std::path::Path,
    ) -> TerminalEvidence {
        TerminalEvidence::default()
    }
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
    fn ping_with_evidence(&self, direction: &str, packets: u32) -> PingOperation {
        match self.ping(direction, packets) {
            Ok(measurement) => PingOperation {
                measurement: Some(measurement),
                ..PingOperation::default()
            },
            Err(error_code) => PingOperation {
                error_code: Some(error_code),
                ..PingOperation::default()
            },
        }
    }
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

fn bounded_diagnostic(output: &Output) -> CommandDiagnostic {
    fn bounded(value: &str) -> String {
        let sanitized = value
            .lines()
            .filter_map(sanitize_log_line)
            .collect::<Vec<_>>()
            .join("\n");
        truncate_utf8_tail(&sanitized, 512)
    }
    CommandDiagnostic {
        exit_code: output.code,
        stdout: bounded(&output.stdout),
        stderr: bounded(&output.stderr),
    }
}
fn truncate_utf8_bytes(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}
fn truncate_utf8_tail(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut start = value.len() - max_bytes;
    while !value.is_char_boundary(start) {
        start += 1;
    }
    value[start..].to_string()
}
fn useful_lte_log_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    [
        "gtpu", "gtp", "rlc", "pdcp", "rrc", "error", "warn", "drop", "bitrate", "tun",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}
fn bounded_filtered_log_diagnostic(output: &Output) -> CommandDiagnostic {
    let filter = |value: &str| {
        let useful = value
            .lines()
            .filter_map(sanitize_log_line)
            .filter(|line| useful_lte_log_line(line))
            .collect::<Vec<_>>()
            .join("\n");
        truncate_utf8_tail(&useful, 512)
    };
    CommandDiagnostic {
        exit_code: output.code,
        stdout: filter(&output.stdout),
        stderr: filter(&output.stderr),
    }
}
fn interface_for_ipv4(output: &str, address: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let inet = fields.iter().position(|field| *field == "inet")?;
        let observed = fields.get(inet + 1)?.split('/').next()?;
        if observed == address {
            fields
                .get(1)
                .map(|field| field.trim_end_matches(':').to_string())
        } else {
            None
        }
    })
}
fn classify_ping_output(direction: &str, output: &Output) -> Result<(), String> {
    if direction == "dl" {
        classify_dn_container_exit(output.code, &output.stderr)
    } else {
        Ok(())
    }
}
fn failed_diagnostic(error: &str) -> CommandDiagnostic {
    CommandDiagnostic {
        exit_code: 125,
        stdout: String::new(),
        stderr: truncate_utf8_bytes(error, 512),
    }
}
fn parse_enb_bind_config(contents: &str) -> (Option<String>, Option<String>) {
    let value = |key: &str| {
        contents.lines().find_map(|line| {
            let line = line.split('#').next()?.trim();
            let (name, value) = line.split_once('=')?;
            (name.trim() == key)
                .then(|| value.trim().trim_matches('"').to_string())
                .filter(|value| value.parse::<std::net::Ipv4Addr>().is_ok())
        })
    };
    (value("gtp_bind_addr"), value("s1c_bind_addr"))
}
fn parse_docker_networks(contents: &str) -> BTreeMap<String, String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(contents.trim()) else {
        return BTreeMap::new();
    };
    value
        .as_object()
        .into_iter()
        .flat_map(|networks| networks.iter())
        .filter_map(|(name, config)| {
            let address = config.get("IPAddress")?.as_str()?;
            address
                .parse::<std::net::Ipv4Addr>()
                .ok()
                .map(|_| (name.clone(), address.to_string()))
        })
        .collect()
}
fn parse_enb_bitrates(logs: &str) -> (Option<String>, Option<String>) {
    let (mut ul, mut dl) = (None, None);
    for line in logs.lines().filter_map(sanitize_log_line) {
        let lower = line.to_ascii_lowercase();
        if lower.contains("bitrate") || lower.contains("bit/s") || lower.contains("bps") {
            if lower.contains("ul") {
                ul = Some(truncate_utf8_bytes(&line, 512));
            }
            if lower.contains("dl") {
                dl = Some(truncate_utf8_bytes(&line, 512));
            }
        }
    }
    (ul, dl)
}
fn parse_ping_measurement(stdout: &str) -> Option<PingMeasurement> {
    let values = stdout
        .lines()
        .find(|line| line.contains("packets transmitted"))?
        .split(',')
        .collect::<Vec<_>>();
    Some(PingMeasurement {
        sent: values.first()?.split_whitespace().next()?.parse().ok()?,
        received: values.get(1)?.split_whitespace().next()?.parse().ok()?,
    })
}

fn lte_ul_route_install_args(container_id: &str, peer: std::net::Ipv4Addr) -> Vec<String> {
    vec![
        "exec".into(),
        container_id.into(),
        "ip".into(),
        "route".into(),
        "replace".into(),
        format!("{peer}/32"),
        "dev".into(),
        LTE_UE_TUN.into(),
    ]
}

fn classify_route_install(output: &Output) -> RouteOperation {
    RouteOperation {
        diagnostic: bounded_diagnostic(output),
        error_code: (output.code != 0).then(|| "LTE_UL_ROUTE_INSTALL_FAILED".into()),
    }
}

/// 0.29.6: the Grant-time exec preflight runs the UE and the DN SGi
/// containers with the exact capability sets, user, filesystem mode and
/// `--security-opt no-new-privileges:true` declared by the live service. If
/// a cap_drop that applies in production is missing from the preflight the
/// gate is theatre; if the preflight uses extra caps it masks real failures.
pub struct ContainerExecSpec {
    pub role: &'static str,
    pub cap_drop: &'static [&'static str],
    pub cap_add: &'static [&'static str],
    pub user: &'static str,
    pub read_only: bool,
    pub no_new_privileges: bool,
}

/// Mirrors the UE service capability profile documented in the 0.29.6-rc1
/// srsran4g-ue-tools CHANGELOG entry:
/// `cap_drop: ALL`, `cap_add: [NET_ADMIN, SYS_NICE]`, read-only root FS,
/// no-new-privileges, running as root (uid 0:0) because `tun_srsue` creation
/// still requires it.
pub const UE_SERVICE_EXEC_SPEC: ContainerExecSpec = ContainerExecSpec {
    role: "ue",
    cap_drop: &["ALL"],
    cap_add: &["NET_ADMIN", "SYS_NICE"],
    user: "0:0",
    read_only: true,
    no_new_privileges: true,
};

/// Mirrors the LTE SGi DN sidecar `compose.yaml` under
/// `deployment/dn-sender/lte-sgi/`: `cap_drop: ALL`, no cap_add, non-root
/// user `65532:65532`, read-only root FS, no-new-privileges.
pub const DN_SGI_SERVICE_EXEC_SPEC: ContainerExecSpec = ContainerExecSpec {
    role: "dn",
    cap_drop: &["ALL"],
    cap_add: &[],
    user: "65532:65532",
    read_only: true,
    no_new_privileges: true,
};

/// Script the exec preflight runs inside the disposable container. The
/// unprivileged loopback ping proves the tooling + capability combination
/// is sufficient; `iperf3 --version` proves the binary is present and
/// executable under the exact security policy.
pub const EXEC_PREFLIGHT_SCRIPT: &str = "ping -c1 -W1 127.0.0.1 && iperf3 --version";

pub fn ue_tooling_exec_args(image_reference: &str, spec: &ContainerExecSpec) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "run".into(),
        "--rm".into(),
        "--network".into(),
        "none".into(),
    ];
    if spec.no_new_privileges {
        args.extend(["--security-opt".into(), "no-new-privileges:true".into()]);
    }
    if spec.read_only {
        args.push("--read-only".into());
    }
    args.extend(["--user".into(), spec.user.into()]);
    for cap in spec.cap_drop {
        args.extend(["--cap-drop".into(), (*cap).into()]);
    }
    for cap in spec.cap_add {
        args.extend(["--cap-add".into(), (*cap).into()]);
    }
    args.extend([
        "--entrypoint".into(),
        "/bin/sh".into(),
        image_reference.into(),
        "-ec".into(),
        EXEC_PREFLIGHT_SCRIPT.into(),
    ]);
    args
}

/// Classifier for the exec preflight output. The caller provides the role
/// (`"ue"` or `"dn"`) and the observed exit code / stdout / stderr. Returns
/// `Ok(())` on exit 0 and `Err((code, diagnostic))` otherwise, where
/// `diagnostic` is bounded tail-512 and sanitized.
pub fn classify_tooling_exec(
    role: &str,
    exit_code: i32,
    stdout: &str,
    stderr: &str,
) -> Result<(), (String, CommandDiagnostic)> {
    let diag = CommandDiagnostic {
        exit_code,
        stdout: truncate_utf8_tail(stdout, 512),
        stderr: truncate_utf8_tail(stderr, 512),
    };
    if exit_code == 0 {
        return Ok(());
    }
    let error_code = match role {
        "dn" => "LTE_DN_TOOLING_NOT_EXECUTABLE",
        _ => "LTE_UE_TOOLING_NOT_EXECUTABLE",
    };
    Err((error_code.into(), diag))
}

// ---------------------------------------------------------------------------
// 0.29.7 ERAB gate + terminal evidence (pure functions, offline testable).
// ---------------------------------------------------------------------------

/// Markers the eNB stdout emits when it finishes the Initial Context Setup
/// procedure (S1AP procedure 9 successfulOutcome). This exact string is
/// emitted by srsRAN 25.10 `s1ap.cc` through `sctp_send_s1ap_pdu`.
const ICS_RESPONSE_LOG_MARKERS: &[&str] = &["tx s1ap sdu, initialcontextsetupresponse"];

/// Exact info-level marker emitted by Open5GS SGW-C `s5c-handler.c` after
/// receiving the S11/S5-C Modify Bearer Response. The MME is not the source.
const MODIFY_BEARER_RESPONSE_MARKERS: &[&str] = &["modify bearer response"];

/// Count occurrences of any of `markers` across the sanitized log lines.
fn count_markers(logs: &str, markers: &[&str]) -> u32 {
    let mut count: u32 = 0;
    for line in logs.lines() {
        if let Some(sanitized) = sanitize_log_line(line) {
            let lower = sanitized.to_ascii_lowercase();
            if markers.iter().any(|m| lower.contains(m)) {
                count = count.saturating_add(1);
            }
        }
    }
    count
}

/// 0.29.7: fail-closed EPS bearer establishment gate. Must be called by the
/// orchestrator **before** any ping / UDP step. The gate requires:
///
/// - at least one srsENB-side marker that an Initial Context Setup Response
///   (S1AP procedure 9 successfulOutcome, E-RAB id 5 in the certified
///   profile) was emitted;
/// - at least one SGW-C-side marker that a Modify Bearer Response (S11
///   GTPv2-C type 35) was emitted.
///
/// Returns `Ok(evidence)` on success, `Err(("LTE_ERAB_NOT_ESTABLISHED",
/// evidence))` otherwise. The returned evidence is JSON-serialisable and
/// bounded.
pub fn evaluate_erab_establishment(
    srsenb_logs: &str,
    sgwc_logs: &str,
) -> Result<ErabEstablishmentEvidence, (String, ErabEstablishmentEvidence)> {
    let ics_markers = count_markers(srsenb_logs, ICS_RESPONSE_LOG_MARKERS);
    let mbr_markers = count_markers(sgwc_logs, MODIFY_BEARER_RESPONSE_MARKERS);
    let ics_ok = ics_markers > 0;
    let mbr_ok = mbr_markers > 0;
    let summary = truncate_utf8_tail(
        &format!(
            "ics_response_markers={ics_markers} mbr_response_markers={mbr_markers} \
             ics_response_observed={ics_ok} modify_bearer_response_observed={mbr_ok}"
        ),
        512,
    );
    let evidence = ErabEstablishmentEvidence {
        ics_response_observed: ics_ok,
        ics_response_e_rab_markers: ics_markers,
        modify_bearer_response_observed: mbr_ok,
        modify_bearer_response_markers: mbr_markers,
        summary,
    };
    if ics_ok && mbr_ok {
        Ok(evidence)
    } else {
        Err(("LTE_ERAB_NOT_ESTABLISHED".into(), evidence))
    }
}

/// Docker arg generator for `docker exec <container> ip neigh`.
pub fn ip_neigh_args(container_id: &str) -> Vec<String> {
    vec![
        "exec".into(),
        container_id.into(),
        "ip".into(),
        "neigh".into(),
    ]
}

/// Docker arg generator for `docker exec <container> ip -s link`.
pub fn ip_s_link_args(container_id: &str) -> Vec<String> {
    vec![
        "exec".into(),
        container_id.into(),
        "ip".into(),
        "-s".into(),
        "link".into(),
    ]
}

/// Build a `FullLogRecord` from raw container logs + the on-disk persistence
/// result. Pure function: no filesystem writes, no stdout capture.
///
/// `raw_logs` is the unsanitised docker stdout+stderr; it is fed to
/// `sanitize_log_line` before being considered for the bounded tail. The
/// SHA256 is computed over the sanitised stream so the digest matches what
/// the host writes to disk.
pub fn build_full_log_record(component: &str, path: &str, raw_logs: &str) -> FullLogRecord {
    let sanitized = sanitize_log_stream(raw_logs);
    let sanitized_tail = truncate_utf8_tail(&sanitized, 512);
    let bytes = sanitized.len() as u64;
    let sha256 = format!("{:x}", Sha256::digest(sanitized.as_bytes()));
    FullLogRecord {
        component: component.to_string(),
        path: path.to_string(),
        bytes,
        sha256,
        sanitized_tail,
        rrc_path: format!("{path}.rrc"),
        rrc_bytes: 0,
        rrc_sha256: String::new(),
        persisted: false,
        error_code: None,
    }
}

fn bounded_sanitized_log(raw: &str) -> String {
    truncate_utf8_tail(&sanitize_log_stream(raw), 5 * 1024 * 1024 - 1)
}

fn build_rrc_extract(sanitized: &str) -> String {
    truncate_utf8_tail(
        &sanitized
            .lines()
            .filter(|line| {
                let lower = line.to_ascii_lowercase();
                ["[rrc", "[pdcp", "[rlc", "srb1", "s1ap"]
                    .iter()
                    .any(|marker| lower.contains(marker))
            })
            .collect::<Vec<_>>()
            .join("\n"),
        4096,
    )
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
    let net = net
        .parse::<std::net::Ipv4Addr>()
        .map_err(|e| e.to_string())?;
    let prefix: u32 = prefix
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
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
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
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
    if policy
        .forbidden_devs
        .iter()
        .any(|forbidden| forbidden == &dev)
    {
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
    fn diagnostic(&self, args: &[&str], seconds: u64) -> CommandDiagnostic {
        match self.run(args, seconds) {
            Ok(output) => bounded_diagnostic(&output),
            Err(error) => failed_diagnostic(&error),
        }
    }
    fn collect_ping_evidence(
        &self,
        ue: &Container,
        ping: CommandDiagnostic,
    ) -> PingRuntimeEvidence {
        let ue_link = self.diagnostic(&["exec", &ue.id, "ip", "-s", "link", "show", LTE_UE_TUN], 3);
        let ue_routes = self.diagnostic(&["exec", &ue.id, "ip", "route"], 3);
        let srsue_log_tail = match self.run(&["logs", "--tail", "200", &ue.id], 5) {
            Ok(output) => bounded_filtered_log_diagnostic(&output),
            Err(error) => failed_diagnostic(&error),
        };
        let mut evidence = PingRuntimeEvidence {
            ping,
            ue_link,
            ue_routes,
            srsue_log_tail,
            ..PingRuntimeEvidence::default()
        };
        let Ok(Some(enb)) = self.resolve("srsenb") else {
            return evidence;
        };
        let (srsenb_log_tail, ul_bitrate, dl_bitrate) = match self
            .run(&["logs", "--tail", "200", &enb.id], 5)
        {
            Ok(output) => {
                let (ul, dl) = parse_enb_bitrates(&format!("{}\n{}", output.stdout, output.stderr));
                (bounded_filtered_log_diagnostic(&output), ul, dl)
            }
            Err(error) => (failed_diagnostic(&error), None, None),
        };
        evidence.srsenb_log_tail = srsenb_log_tail;
        let (gtp_bind_addr, s1c_bind_addr) = fs::read_to_string(ENB_CONFIG)
            .ok()
            .map(|contents| parse_enb_bind_config(&contents))
            .unwrap_or_default();
        let networks = self
            .run(
                &[
                    "inspect",
                    "--format",
                    "{{json .NetworkSettings.Networks}}",
                    &enb.id,
                ],
                3,
            )
            .ok()
            .filter(|output| output.code == 0)
            .map(|output| parse_docker_networks(&output.stdout))
            .unwrap_or_default();
        let s1u_network_present = gtp_bind_addr
            .as_ref()
            .is_some_and(|address| networks.values().any(|value| value == address));
        let enb_addresses = self.run(&["exec", &enb.id, "ip", "-o", "-4", "addr", "show"], 3);
        let mut enb_link_counters = BTreeMap::new();
        let zmq_address = networks
            .iter()
            .find(|(name, _)| name.to_ascii_lowercase().contains("zmq"))
            .map(|(_, address)| address);
        for (role, address) in [("s1u", gtp_bind_addr.as_ref()), ("zmq", zmq_address)] {
            let counters = match (&enb_addresses, address) {
                (Ok(output), Some(address)) if output.code == 0 => {
                    interface_for_ipv4(&output.stdout, address)
                        .map(|interface| {
                            self.diagnostic(
                                &[
                                    "exec", &enb.id, "ip", "-s", "link", "show", "dev", &interface,
                                ],
                                3,
                            )
                        })
                        .unwrap_or_else(|| failed_diagnostic("LTE_ENB_LINK_INTERFACE_NOT_FOUND"))
                }
                (Err(error), _) => failed_diagnostic(error),
                _ => failed_diagnostic("LTE_ENB_LINK_INTERFACE_NOT_FOUND"),
            };
            enb_link_counters.insert(role.to_string(), counters);
        }
        evidence.enb = EnbRuntimeEvidence {
            gtp_bind_addr,
            s1c_bind_addr,
            networks,
            s1u_network_present,
            ul_bitrate,
            dl_bitrate,
        };
        evidence.enb_link_counters = enb_link_counters;
        for (component, container) in [("srsue", ue), ("srsenb", &enb)] {
            let image = self.diagnostic(&["inspect", "--format", "{{.Image}}", &container.id], 3);
            let value = image.stdout.trim();
            if image.exit_code == 0 && value.starts_with("sha256:") && value.len() == 71 {
                evidence
                    .container_image_ids
                    .insert(component.into(), value.into());
            }
        }
        evidence
    }
    fn execute_ping_with_evidence(&self, direction: &str, packets: u32) -> PingOperation {
        let fail = |error_code: &str| PingOperation {
            error_code: Some(error_code.into()),
            ..PingOperation::default()
        };
        if !matches!(direction, "ul" | "dl") || packets == 0 || packets > 5 {
            return fail("LTE_PING_PARAMETERS_INVALID");
        }
        let ue = match self.owned(Target::Ue) {
            Ok(ue) if ue.state == "running" => ue,
            Ok(_) => return fail("LTE_UE_NOT_RUNNING"),
            Err(error) => return fail(&error),
        };
        let peer = match configured_traffic_peer() {
            Ok(peer) => peer.to_string(),
            Err(error) => return fail(&error),
        };
        let count = packets.to_string();
        let ping_output = if direction == "ul" {
            let route = match self.run(&["exec", &ue.id, "ip", "route", "get", &peer], 3) {
                Ok(output) => output,
                Err(error) => {
                    return PingOperation {
                        evidence: self.collect_ping_evidence(&ue, failed_diagnostic(&error)),
                        error_code: Some("LTE_UL_ROUTE_PROBE_FAILED".into()),
                        ..PingOperation::default()
                    }
                }
            };
            let preflight = evaluate_lte_ul_route(&route.stdout, &peer);
            if route.code != 0 || !preflight.ok {
                return PingOperation {
                    evidence: self.collect_ping_evidence(&ue, bounded_diagnostic(&route)),
                    error_code: Some(
                        preflight
                            .code
                            .unwrap_or_else(|| "LTE_UL_ROUTE_PROBE_FAILED".into()),
                    ),
                    ..PingOperation::default()
                };
            }
            self.run(
                &[
                    "exec", &ue.id, "ping", "-n", "-I", LTE_UE_TUN, "-c", &count, "-W", "1", &peer,
                ],
                10,
            )
        } else {
            let ue_ip = match self.ue_ip(Some(&ue)) {
                Some(value) => value,
                None => {
                    return PingOperation {
                        evidence: self
                            .collect_ping_evidence(&ue, failed_diagnostic("LTE_UE_IP_NOT_READY")),
                        error_code: Some("LTE_UE_IP_NOT_READY".into()),
                        ..PingOperation::default()
                    }
                }
            };
            let dn = match configured_lte_dn_sender_container() {
                Ok(value) => value,
                Err(error) => return fail(&error),
            };
            let policy = match configured_lte_dl_return_policy() {
                Ok(value) => value,
                Err(error) => return fail(&error),
            };
            let route = match self.run(&["exec", dn.as_str(), "ip", "route", "get", &ue_ip], 3) {
                Ok(output) => output,
                Err(error) => {
                    return PingOperation {
                        evidence: self.collect_ping_evidence(&ue, failed_diagnostic(&error)),
                        error_code: Some("LTE_DL_RETURN_ROUTE_UNAVAILABLE".into()),
                        ..PingOperation::default()
                    }
                }
            };
            let route_error = classify_dn_container_exit(route.code, &route.stderr)
                .and_then(|_| {
                    (route.code == 0)
                        .then_some(())
                        .ok_or_else(|| "LTE_DL_RETURN_ROUTE_UNAVAILABLE".into())
                })
                .and_then(|_| evaluate_lte_dl_return_route(&route.stdout, &ue_ip, &policy));
            if let Err(error_code) = route_error {
                return PingOperation {
                    evidence: self.collect_ping_evidence(&ue, bounded_diagnostic(&route)),
                    error_code: Some(error_code),
                    ..PingOperation::default()
                };
            }
            self.run(
                &[
                    "exec",
                    dn.as_str(),
                    "ping",
                    "-n",
                    "-c",
                    &count,
                    "-W",
                    "1",
                    &ue_ip,
                ],
                10,
            )
        };
        let output = match ping_output {
            Ok(output) => output,
            Err(error) => {
                return PingOperation {
                    evidence: self.collect_ping_evidence(&ue, failed_diagnostic(&error)),
                    error_code: Some("LTE_PING_FAILED".into()),
                    ..PingOperation::default()
                }
            }
        };
        let evidence = self.collect_ping_evidence(&ue, bounded_diagnostic(&output));
        if let Err(error_code) = classify_ping_output(direction, &output) {
            return PingOperation {
                evidence,
                error_code: Some(error_code),
                ..PingOperation::default()
            };
        }
        if output.code != 0 {
            return PingOperation {
                evidence,
                error_code: Some("LTE_PING_FAILED".into()),
                ..PingOperation::default()
            };
        }
        match parse_ping_measurement(&output.stdout) {
            Some(measurement) => PingOperation {
                measurement: Some(measurement),
                evidence,
                error_code: None,
            },
            None => PingOperation {
                evidence,
                error_code: Some("LTE_PING_RESULT_INVALID".into()),
                ..PingOperation::default()
            },
        }
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

fn validate_certified_release_subject(
    image_reference: &str,
    compose_model: &str,
) -> Result<(), String> {
    if image_reference != CERTIFIED_IMAGE_REFERENCE {
        return Err("LTE_CERTIFIED_IMAGE_MISMATCH".into());
    }
    if compose_model != CERTIFIED_COMPOSE_MODEL_SHA256 {
        return Err("LTE_CERTIFIED_COMPOSE_MODEL_MISMATCH".into());
    }
    Ok(())
}

pub fn verify_certified_release_subject() -> Result<(), String> {
    let versions = fs::read_to_string(ENV_FILE).map_err(|_| "LTE_CERTIFIED_IMAGE_UNAVAILABLE")?;
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
    if !output.status.success()
        || String::from_utf8_lossy(&output.stdout).trim() != CERTIFIED_IMAGE_ID
    {
        return Err("LTE_CERTIFIED_IMAGE_UNAVAILABLE".into());
    }
    // 0.29.6: exec preflight now runs the UE service spec in a disposable
    // container. Non-zero exit surfaces LTE_UE_TOOLING_NOT_EXECUTABLE with a
    // bounded tail-preserving diagnostic. The DN SGi preflight has a
    // matching path; see verify_dn_tooling_executable.
    let [ue, dn] = certified_tooling_subjects(image_reference);
    verify_ue_tooling_executable(ue.0)?;
    verify_dn_tooling_executable(dn.0)
}

fn certified_tooling_subjects<'a>(
    ue_image_reference: &'a str,
) -> [(&'a str, &'static ContainerExecSpec); 2] {
    [
        (ue_image_reference, &UE_SERVICE_EXEC_SPEC),
        (CERTIFIED_DN_IMAGE_REFERENCE, &DN_SGI_SERVICE_EXEC_SPEC),
    ]
}

fn run_tooling_exec_preflight(
    image_reference: &str,
    spec: &ContainerExecSpec,
) -> Result<(), String> {
    let args = ue_tooling_exec_args(image_reference, spec);
    let output = Command::new("/usr/bin/timeout")
        .arg("15s")
        .arg("/usr/bin/docker")
        .args(args.iter().map(String::as_str))
        .output()
        .map_err(|_| match spec.role {
            "dn" => "LTE_DN_TOOLING_NOT_EXECUTABLE".to_string(),
            _ => "LTE_UE_TOOLING_NOT_EXECUTABLE".to_string(),
        })?;
    let exit = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    classify_tooling_exec(spec.role, exit, &stdout, &stderr).map_err(|(code, _diag)| code)
}

pub fn verify_ue_tooling_executable(image_reference: &str) -> Result<(), String> {
    run_tooling_exec_preflight(image_reference, &UE_SERVICE_EXEC_SPEC)
}

pub fn verify_dn_tooling_executable(image_reference: &str) -> Result<(), String> {
    run_tooling_exec_preflight(image_reference, &DN_SGI_SERVICE_EXEC_SPEC)
}

fn compose_config_args() -> [&'static str; 16] {
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
        "-f",
        COMPOSE_0298_OVERRIDE,
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
    fn verify_erab_established(
        &self,
    ) -> Result<ErabEstablishmentEvidence, (String, ErabEstablishmentEvidence)> {
        // Read full stdout+stderr for srsENB and SGW-C; delegate to the
        // pure classifier so unit tests exercise the exact same logic.
        let srsenb = self
            .resolve("srsenb")
            .ok()
            .flatten()
            .and_then(|c| self.run(&["logs", &c.id], 5).ok())
            .map(|out| format!("{}{}", out.stdout, out.stderr))
            .unwrap_or_default();
        let sgwc = self
            .resolve("sgwc")
            .ok()
            .flatten()
            .and_then(|c| self.run(&["logs", &c.id], 5).ok())
            .map(|out| format!("{}{}", out.stdout, out.stderr))
            .unwrap_or_default();
        evaluate_erab_establishment(&srsenb, &sgwc)
    }
    fn collect_terminal_evidence(
        &self,
        _run_id: &str,
        run_dir: &std::path::Path,
    ) -> TerminalEvidence {
        let _ = fs::create_dir_all(run_dir);
        let persist = |component: &'static str, container_name: &str| -> FullLogRecord {
            let Ok(Some(container)) = self.resolve(container_name) else {
                return FullLogRecord {
                    component: component.into(),
                    error_code: Some("LTE_TERMINAL_LOG_CONTAINER_ABSENT".into()),
                    ..FullLogRecord::default()
                };
            };
            let file_name = format!("/var/log/oiran/{component}.log");
            let read_script = format!(
                "for file in {file_name}*; do test -f \"$file\" && cat \"$file\"; done"
            );
            let direct = self
                .run(&["exec", &container.id, "/bin/sh", "-ec", &read_script], 5)
                .and_then(|output| {
                    (output.code == 0)
                        .then_some(output)
                        .ok_or_else(|| "LTE_DIRECT_LOG_READ_FAILED".into())
                });
            let raw = match direct.or_else(|_| self.run(&["logs", &container.id], 5)) {
                Ok(output) => format!("{}{}", output.stdout, output.stderr),
                Err(error) => {
                    return FullLogRecord {
                        component: component.into(),
                        error_code: Some(format!("LTE_TERMINAL_LOG_READ_FAILED:{error}")),
                        ..FullLogRecord::default()
                    };
                }
            };
            let sanitized_full = bounded_sanitized_log(&raw);
            let path = run_dir.join(format!("{component}.log"));
            let mut record =
                build_full_log_record(component, &path.display().to_string(), &sanitized_full);
            let rrc_extract = build_rrc_extract(&sanitized_full);
            let rrc_path = run_dir.join(format!("{component}-rrc.log"));
            let open_result = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(&path);
            match open_result.and_then(|mut file| file.write_all(sanitized_full.as_bytes())) {
                Ok(()) => {
                    record.persisted = true;
                    if OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .mode(0o600)
                        .open(&rrc_path)
                        .and_then(|mut file| file.write_all(rrc_extract.as_bytes()))
                        .is_ok()
                    {
                        record.rrc_path = rrc_path.display().to_string();
                        record.rrc_bytes = rrc_extract.len() as u64;
                        record.rrc_sha256 = format!("{:x}", Sha256::digest(rrc_extract.as_bytes()));
                    } else {
                        record.error_code = Some("LTE_RRC_EXTRACT_WRITE_FAILED".into());
                    }
                }
                Err(error) => {
                    record.error_code = Some(format!("LTE_TERMINAL_LOG_WRITE_FAILED:{error}"));
                }
            }
            record
        };
        let srsue_log = persist("srsue", "srsue");
        let srsenb_log = persist("srsenb", "srsenb");
        let enb_network = {
            let enb = self.resolve("srsenb").ok().flatten();
            let enb_neigh = match &enb {
                Some(c) => self.diagnostic(
                    &ip_neigh_args(&c.id)
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    3,
                ),
                None => failed_diagnostic("LTE_TERMINAL_LOG_CONTAINER_ABSENT"),
            };
            let enb_link = match &enb {
                Some(c) => self.diagnostic(
                    &ip_s_link_args(&c.id)
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    3,
                ),
                None => failed_diagnostic("LTE_TERMINAL_LOG_CONTAINER_ABSENT"),
            };
            let sgw_neigh = match self.resolve("sgwu").ok().flatten() {
                Some(c) => self.diagnostic(
                    &ip_neigh_args(&c.id)
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    3,
                ),
                None => failed_diagnostic("LTE_TERMINAL_SGWU_ABSENT"),
            };
            EnbNetworkDiagnostics {
                enb_ip_neigh: enb_neigh,
                enb_ip_s_link: enb_link,
                sgw_u_ip_neigh: sgw_neigh,
            }
        };
        // 0.29.8: build the per-component [RRC] extract (4 KiB tail,
        // sanitised). The extract reads the raw `docker logs` output
        // one more time (lightweight) to avoid round-trips through the
        // bounded srsue/srsenb_log records.
        let mut rrc_extracts: BTreeMap<String, String> = BTreeMap::new();
        for (component, container) in [("srsue", "srsue"), ("srsenb", "srsenb")] {
            if let Ok(Some(c)) = self.resolve(container) {
                if let Ok(output) = self.run(&["logs", &c.id], 5) {
                    let raw = format!("{}{}", output.stdout, output.stderr);
                    rrc_extracts.insert(component.into(), extract_rrc_lines(&raw, 4096));
                }
            }
        }
        TerminalEvidence {
            srsue_log,
            srsenb_log,
            enb_network,
            rrc_extracts,
        }
    }
    fn apply_run_ue_log_section(&self) -> LogSectionPatch {
        let path = std::path::Path::new(UE_CONFIG);
        let existing = match fs::read_to_string(path) {
            Ok(value) => value,
            Err(error) => {
                return LogSectionPatch {
                    path: UE_CONFIG.to_string(),
                    error_code: Some(format!("LTE_UE_CONF_READ_FAILED:{error}")),
                    ..LogSectionPatch::default()
                };
            }
        };
        let bytes_before = existing.len() as u64;
        let previous_sha256 = format!("{:x}", Sha256::digest(existing.as_bytes()));
        let patched = inject_log_section(&existing, "log", RUN_UE_LOG_SECTION);
        let bytes_after = patched.len() as u64;
        let new_sha256 = format!("{:x}", Sha256::digest(patched.as_bytes()));
        let applied = log_section_matches(&existing, "log", RUN_UE_LOG_SECTION);
        LogSectionPatch {
            path: UE_CONFIG.to_string(),
            previous_sha256,
            new_sha256,
            bytes_before,
            bytes_after,
            applied,
            error_code: (!applied).then(|| "LTE_UE_LOG_CONFIG_INVALID".into()),
        }
    }
    fn install_lte_ul_route(&self) -> RouteOperation {
        let peer = match configured_traffic_peer() {
            Ok(peer) => peer,
            Err(error) => {
                return RouteOperation {
                    error_code: Some(error),
                    ..RouteOperation::default()
                }
            }
        };
        let ue = match self.owned(Target::Ue) {
            Ok(ue) if ue.state == "running" => ue,
            Ok(_) => {
                return RouteOperation {
                    error_code: Some("LTE_UE_NOT_RUNNING".into()),
                    ..RouteOperation::default()
                }
            }
            Err(error) => {
                return RouteOperation {
                    error_code: Some(error),
                    ..RouteOperation::default()
                }
            }
        };
        let args = lte_ul_route_install_args(&ue.id, peer);
        match self.executor.run(&args, 3) {
            Ok(output) => classify_route_install(&output),
            Err(_) => RouteOperation {
                error_code: Some("LTE_UL_ROUTE_INSTALL_FAILED".into()),
                ..RouteOperation::default()
            },
        }
    }
    fn probe_traffic_route(&self, direction: &str) -> RouteOperation {
        let ue = match self.owned(Target::Ue) {
            Ok(ue) if ue.state == "running" => ue,
            _ => {
                return RouteOperation {
                    error_code: Some("LTE_UE_NOT_RUNNING".into()),
                    ..RouteOperation::default()
                }
            }
        };
        if direction == "dl" {
            let ue_ip = match self.ue_ip(Some(&ue)) {
                Some(ip) => ip,
                None => {
                    return RouteOperation {
                        error_code: Some("LTE_UE_IP_NOT_READY".into()),
                        ..RouteOperation::default()
                    }
                }
            };
            let dn = match configured_lte_dn_sender_container() {
                Ok(value) => value,
                Err(error) => {
                    return RouteOperation {
                        error_code: Some(error),
                        ..RouteOperation::default()
                    }
                }
            };
            return match self.run(&["exec", &dn, "ip", "route", "get", &ue_ip], 3) {
                Ok(output) => {
                    let code = if output.code == 0 {
                        configured_lte_dl_return_policy()
                            .and_then(|policy| {
                                evaluate_lte_dl_return_route(&output.stdout, &ue_ip, &policy)
                            })
                            .err()
                    } else {
                        Some("LTE_DL_RETURN_ROUTE_UNAVAILABLE".into())
                    };
                    RouteOperation {
                        diagnostic: bounded_diagnostic(&output),
                        error_code: code,
                    }
                }
                Err(_) => RouteOperation {
                    error_code: Some("LTE_DL_RETURN_ROUTE_UNAVAILABLE".into()),
                    ..RouteOperation::default()
                },
            };
        }
        if direction != "ul" {
            return RouteOperation {
                error_code: Some("LTE_TRAFFIC_PARAMETERS_INVALID".into()),
                ..RouteOperation::default()
            };
        }
        let peer = match configured_traffic_peer() {
            Ok(peer) => peer.to_string(),
            Err(error) => {
                return RouteOperation {
                    error_code: Some(error),
                    ..RouteOperation::default()
                }
            }
        };
        match self.run(&["exec", &ue.id, "ip", "route", "get", &peer], 3) {
            Ok(output) => {
                let mut code = (output.code != 0).then(|| "LTE_UL_ROUTE_PROBE_FAILED".to_string());
                if code.is_none() {
                    let preflight = evaluate_lte_ul_route(&output.stdout, &peer);
                    if !preflight.ok {
                        code = Some(
                            preflight
                                .code
                                .unwrap_or_else(|| "LTE_UL_ROUTE_NOT_VIA_UE_TUN".into()),
                        );
                    }
                }
                RouteOperation {
                    diagnostic: bounded_diagnostic(&output),
                    error_code: code,
                }
            }
            Err(_) => RouteOperation {
                error_code: Some("LTE_UL_ROUTE_PROBE_FAILED".into()),
                ..RouteOperation::default()
            },
        }
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
        Ok(
            event_at_epoch_ms.map(|event_at_epoch_ms| AttachProtocolEvidence {
                event_at_epoch_ms,
                observed_at_epoch_ms: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
                provenance: "OPEN5GS_MME_DOCKER_LOG_RFC3339",
            }),
        )
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
        let operation = self.execute_ping_with_evidence(direction, packets);
        operation.measurement.ok_or_else(|| {
            operation
                .error_code
                .unwrap_or_else(|| "LTE_PING_FAILED".into())
        })
    }
    fn ping_with_evidence(&self, direction: &str, packets: u32) -> PingOperation {
        self.execute_ping_with_evidence(direction, packets)
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
    if [
        "imsi",
        "supi",
        "suci",
        "guti",
        "tmsi",
        "imei",
        "imeisv",
        "msisdn",
        "opc",
        "auth key",
        "subscriber key",
        " ki=",
    ]
    .iter()
    .any(|m| lower.contains(m))
    {
        return Some("[REDACTED_SUBSCRIBER_MATERIAL]".into());
    }
    let value = line.trim();
    if value.len() >= 5
        && value.as_bytes().get(4) == Some(&b':')
        && value.as_bytes()[..4].iter().all(u8::is_ascii_hexdigit)
    {
        return None;
    }
    (!value.is_empty()).then(|| value.chars().take(500).collect())
}

fn sanitize_log_stream(raw: &str) -> String {
    raw.lines()
        .filter_map(sanitize_log_line)
        .collect::<Vec<_>>()
        .join("\n")
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
    /// 0.29.8: injectable ue.conf log-section patch result.
    pub ue_log_section_override: Arc<Mutex<Option<LogSectionPatch>>>,
    /// 0.29.7: injectable ERAB gate result. `Some(Ok(ev))` → gate PASS;
    /// `Some(Err((code, ev)))` → gate FAIL with the exact code; `None` →
    /// default pass with empty evidence.
    #[allow(clippy::type_complexity)]
    pub erab_gate_override:
        Arc<Mutex<Option<Result<ErabEstablishmentEvidence, (String, ErabEstablishmentEvidence)>>>>,
    /// 0.29.7: injectable terminal evidence returned by the mock.
    pub terminal_evidence_override: Arc<Mutex<Option<TerminalEvidence>>>,
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
            ue_log_section_override: Arc::new(Mutex::new(None)),
            erab_gate_override: Arc::new(Mutex::new(None)),
            terminal_evidence_override: Arc::new(Mutex::new(None)),
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
    fn verify_erab_established(
        &self,
    ) -> Result<ErabEstablishmentEvidence, (String, ErabEstablishmentEvidence)> {
        self.erab_gate_override
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| Ok(ErabEstablishmentEvidence::default()))
    }
    fn collect_terminal_evidence(
        &self,
        _run_id: &str,
        _run_dir: &std::path::Path,
    ) -> TerminalEvidence {
        self.terminal_evidence_override
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_default()
    }
    fn apply_run_ue_log_section(&self) -> LogSectionPatch {
        self.ue_log_section_override
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| LogSectionPatch {
                path: UE_CONFIG.to_string(),
                applied: true,
                ..LogSectionPatch::default()
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
    fn ping_evidence_diagnostics_are_complete_private_and_byte_bounded() {
        let diagnostic = bounded_diagnostic(&Output {
            code: 1,
            stdout: format!("IMEISV secret\n{}", "é".repeat(400)),
            stderr: "x".repeat(700),
        });
        assert!(diagnostic.stdout.len() <= 512 && diagnostic.stderr.len() <= 512);
        assert!(
            !diagnostic.stdout.contains("secret")
                && !diagnostic.stdout.to_ascii_lowercase().contains("imeisv")
        );
        let (gtp, s1c) =
            parse_enb_bind_config("gtp_bind_addr=10.77.11.20\ns1c_bind_addr=10.77.10.20");
        let networks = parse_docker_networks(r#"{"oiran-lab-s1u":{"IPAddress":"10.77.11.20"}}"#);
        let (ul, dl) = parse_enb_bitrates("UL bitrate=812000 bps\nDL bitrate=991000 bps");
        assert_eq!(gtp.as_deref(), Some("10.77.11.20"));
        assert_eq!(s1c.as_deref(), Some("10.77.10.20"));
        assert!(ul.is_some() && dl.is_some());
        let value = serde_json::to_value(PingRuntimeEvidence {
            ping: diagnostic.clone(),
            ue_link: diagnostic.clone(),
            ue_routes: diagnostic.clone(),
            srsue_log_tail: diagnostic.clone(),
            srsenb_log_tail: diagnostic,
            enb: EnbRuntimeEvidence {
                gtp_bind_addr: gtp,
                s1c_bind_addr: s1c,
                networks,
                s1u_network_present: true,
                ul_bitrate: ul,
                dl_bitrate: dl,
            },
            enb_link_counters: BTreeMap::new(),
            container_image_ids: BTreeMap::from([(
                "srsue".into(),
                format!("sha256:{}", "a".repeat(64)),
            )]),
        })
        .unwrap();
        for key in [
            "ping",
            "ue_link",
            "ue_routes",
            "srsue_log_tail",
            "srsenb_log_tail",
            "enb",
            "enb_link_counters",
            "container_image_ids",
        ] {
            assert!(value.get(key).is_some(), "missing {key}");
        }
    }
    #[test]
    fn filtered_log_evidence_keeps_the_end_not_the_beginning() {
        let output = Output {
            code: 1,
            stdout: format!("RRC FIRST_MARKER {}\nGTPU LAST_MARKER", "x".repeat(700)),
            stderr: String::new(),
        };
        let diagnostic = bounded_filtered_log_diagnostic(&output);
        assert!(diagnostic.stdout.as_bytes().len() <= 512);
        assert!(diagnostic.stdout.contains("GTPU LAST_MARKER"));
        assert!(!diagnostic.stdout.contains("FIRST_MARKER"));
    }
    #[test]
    fn enb_link_counter_interface_and_tail_are_preserved() {
        let addresses = "2: eth0    inet 10.77.11.20/24 brd 10.77.11.255 scope global eth0\n3: eth1    inet 10.77.17.20/24 brd 10.77.17.255 scope global eth1";
        assert_eq!(
            interface_for_ipv4(addresses, "10.77.11.20").as_deref(),
            Some("eth0")
        );
        assert_eq!(
            interface_for_ipv4(addresses, "10.77.17.20").as_deref(),
            Some("eth1")
        );
        let counters = bounded_diagnostic(&Output {
            code: 0,
            stdout: format!("RX OLD {}\nTX FINAL packets 42 bytes 4096", "x".repeat(700)),
            stderr: String::new(),
        });
        assert!(counters.stdout.as_bytes().len() <= 512);
        assert!(counters.stdout.contains("TX FINAL packets 42 bytes 4096"));
        assert!(!counters.stdout.contains("RX OLD"));
    }
    #[test]
    fn dl_ping_restores_missing_tooling_classification() {
        let output = Output {
            code: 127,
            stdout: String::new(),
            stderr: "ping: command not found".into(),
        };
        assert_eq!(
            classify_ping_output("dl", &output),
            Err("LTE_DN_SENDER_TOOLING_MISSING".into())
        );
        assert_eq!(classify_ping_output("ul", &output), Ok(()));
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
        assert_eq!(
            evidence.code.as_deref(),
            Some("LTE_UL_ROUTE_NOT_VIA_UE_TUN")
        );
        assert_eq!(evidence.actual_dev.as_deref(), Some("eth0"));

        // 5G uesimtun0 is not a valid LTE SGi outbound (keeps LTE vs 5G separate).
        let five_g = "10.77.16.30 dev uesimtun0 src 10.46.0.5 uid 0";
        let evidence = evaluate_lte_ul_route(five_g, "10.77.16.30");
        assert!(!evidence.ok);
        assert_eq!(
            evidence.code.as_deref(),
            Some("LTE_UL_ROUTE_NOT_VIA_UE_TUN")
        );
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
            evaluate_lte_dl_return_route("10.45.0.2 dev lo src 127.0.0.1", "10.45.0.2", &policy()),
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
        assert_eq!(
            configured_traffic_peer(),
            Ok("10.77.16.30".parse().unwrap())
        );
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
    fn lte_ul_route_install_command_is_exact_and_host_scoped() {
        assert_eq!(
            lte_ul_route_install_args("owned-ue", "10.77.16.30".parse().unwrap()),
            vec![
                "exec",
                "owned-ue",
                "ip",
                "route",
                "replace",
                "10.77.16.30/32",
                "dev",
                "tun_srsue",
            ]
        );
    }

    #[test]
    fn route_install_failure_has_dedicated_code_and_bounded_private_diagnostics() {
        let output = Output {
            code: 2,
            stdout: "x".repeat(700),
            stderr: "IMSI=001010123456789".into(),
        };
        let operation = classify_route_install(&output);
        assert_eq!(
            operation.error_code.as_deref(),
            Some("LTE_UL_ROUTE_INSTALL_FAILED")
        );
        assert_eq!(operation.diagnostic.exit_code, 2);
        assert!(operation.diagnostic.stdout.chars().count() <= 512);
        assert_eq!(
            operation.diagnostic.stderr,
            "[REDACTED_SUBSCRIBER_MATERIAL]"
        );
    }

    #[test]
    fn ue_tooling_exec_args_mirror_service_capabilities_and_run_real_binaries() {
        // 0.29.6: args carry --security-opt no-new-privileges + --read-only +
        // --user matching the service, cap_drop before cap_add, and the real
        // execution script (not just command -v).
        let args = ue_tooling_exec_args("example.invalid/srsran@sha256:abc", &UE_SERVICE_EXEC_SPEC);
        assert_eq!(&args[..4], ["run", "--rm", "--network", "none"]);
        assert!(args
            .windows(2)
            .any(|w| w == ["--security-opt", "no-new-privileges:true"]));
        assert!(args.iter().any(|a| a == "--read-only"));
        assert!(args.windows(2).any(|w| w == ["--user", "0:0"]));
        assert!(args.windows(2).any(|w| w == ["--cap-drop", "ALL"]));
        assert!(args.windows(2).any(|w| w == ["--cap-add", "NET_ADMIN"]));
        assert!(args.windows(2).any(|w| w == ["--cap-add", "SYS_NICE"]));
        assert!(args.windows(2).any(|w| w == ["--entrypoint", "/bin/sh"]));
        let script = args.last().unwrap();
        assert_eq!(script, EXEC_PREFLIGHT_SCRIPT);
        assert!(script.contains("ping -c1 -W1 127.0.0.1"));
        assert!(script.contains("iperf3 --version"));
    }

    #[test]
    fn dn_tooling_exec_args_mirror_sgi_sidecar_hardening() {
        // DN SGi sidecar runs non-root 65532:65532, cap_drop ALL, no cap_add,
        // read-only, no-new-privileges. The preflight must copy that exactly.
        let args = ue_tooling_exec_args(
            "example.invalid/srsran@sha256:abc",
            &DN_SGI_SERVICE_EXEC_SPEC,
        );
        assert!(args.windows(2).any(|w| w == ["--user", "65532:65532"]));
        assert!(args.windows(2).any(|w| w == ["--cap-drop", "ALL"]));
        assert!(!args.iter().any(|a| a == "--cap-add"));
        assert!(args.iter().any(|a| a == "--read-only"));
        assert!(args
            .windows(2)
            .any(|w| w == ["--security-opt", "no-new-privileges:true"]));
    }

    #[test]
    fn certified_preflight_contains_both_ue_and_dn_before_activation() {
        let subjects = certified_tooling_subjects(CERTIFIED_IMAGE_REFERENCE);
        assert_eq!(subjects.len(), 2);
        assert_eq!(subjects[0].0, CERTIFIED_IMAGE_REFERENCE);
        assert_eq!(subjects[0].1.role, "ue");
        assert_eq!(subjects[1].0, CERTIFIED_DN_IMAGE_REFERENCE);
        assert_eq!(subjects[1].1.role, "dn");
    }

    #[test]
    fn lte_0298_overlay_has_rt_limits_without_cpu_quota() {
        let overlay = include_str!(
            "../../../deployment/srsran-lte-0298/docker-compose.polaris-0.29.8.yml"
        );
        assert_eq!(overlay.matches("rtprio: 99").count(), 2);
        assert_eq!(overlay.matches("memlock: -1").count(), 2);
        assert_eq!(overlay.matches("cpus: 0.0").count(), 2);
        assert!(overlay.contains("cap_add: [\"SYS_NICE\"]"));
        assert!(!overlay.contains("driver: \"none\""));
        assert!(!overlay.contains("open5gs"));
        assert!(!overlay.contains("capture:"));
    }

    #[test]
    fn lte_0298_log_fragments_are_bounded_and_diagnostic() {
        let ue = include_str!(
            "../../../deployment/srsran-lte-0298/ue-log.conf.fragment"
        );
        let enb = include_str!(
            "../../../deployment/srsran-lte-0298/enb-log.conf.fragment"
        );
        for (component, fragment) in [("srsue", ue), ("srsenb", enb)] {
            for setting in [
                "phy_lib_level = none",
                "phy_level = warning",
                "rrc_level = debug",
                "pdcp_level = debug",
                "rlc_level = debug",
                "mac_level = info",
                "all_hex_limit = 64",
            ] {
                assert!(fragment.contains(setting), "{component}: {setting}");
            }
            assert!(fragment.contains("filename = stdout"), "{component}: stdout");
            assert!(!fragment.contains("file_max_size"), "{component}: no file bound on stdout");
        }
        assert!(ue.contains("nas_level = debug"));
        assert!(!enb.contains("nas_level"));
    }

    #[test]
    fn tooling_exec_preflight_passes_on_exit_zero_and_fails_otherwise() {
        // Exit 0 → PASS.
        assert_eq!(classify_tooling_exec("ue", 0, "iperf 3.17.1\n", ""), Ok(()));
        assert_eq!(classify_tooling_exec("dn", 0, "", ""), Ok(()));

        // EPERM scenario (ping fails because capabilities insufficient).
        let eperm_err =
            classify_tooling_exec("ue", 1, "", "ping: socket: Operation not permitted\n")
                .unwrap_err();
        assert_eq!(eperm_err.0, "LTE_UE_TOOLING_NOT_EXECUTABLE");
        assert!(eperm_err.1.stderr.contains("Operation not permitted"));
        assert!(eperm_err.1.stderr.len() <= 512);

        // Missing binary (shell exit 127).
        let missing_err =
            classify_tooling_exec("dn", 127, "", "/bin/sh: iperf3: not found\n").unwrap_err();
        assert_eq!(missing_err.0, "LTE_DN_TOOLING_NOT_EXECUTABLE");
        assert!(missing_err.1.stderr.contains("not found"));
    }

    #[test]
    fn tooling_exec_preflight_diagnostic_preserves_the_end_not_the_beginning() {
        // Stderr longer than 512 bytes: tail-512 must retain the final cause.
        let mut stderr = String::new();
        stderr.push_str("FIRST_MARKER unused warm-up noise\n");
        for _ in 0..40 {
            stderr.push_str("filler ping output line here\n");
        }
        stderr.push_str("LAST_MARKER_CAUSE Operation not permitted\n");
        assert!(stderr.len() > 512);
        let (code, diag) = classify_tooling_exec("ue", 1, "", &stderr).unwrap_err();
        assert_eq!(code, "LTE_UE_TOOLING_NOT_EXECUTABLE");
        assert!(diag.stderr.len() <= 512);
        assert!(diag.stderr.contains("LAST_MARKER_CAUSE"));
        assert!(!diag.stderr.contains("FIRST_MARKER"));
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
        let dropin = include_str!("../../../deployment/dn-sender/polaris-control-dl-sender.conf");
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
    fn certified_lte_sgi_dropin_sets_exact_confirmed_values() {
        let dropin =
            include_str!("../../../deployment/dn-sender/lte-sgi/polaris-control-lte-sgi.conf");
        for required in [
            "Environment=POLARIS_LTE_DN_SENDER_CONTAINER=polaris-lte-sgi-dn",
            "Environment=POLARIS_LTE_TRAFFIC_PEER_IP=10.77.16.30",
            "Environment=POLARIS_LTE_PGW_U_NEXT_HOP=10.77.16.15",
            "Environment=POLARIS_LTE_UE_SUBNET=10.45.0.0/16",
            "Environment=POLARIS_LTE_FORBIDDEN_RETURN_DEVS=lo,null0,blackhole,eth0,oiran-lab-n6",
        ] {
            assert!(
                dropin.lines().any(|line| line.trim() == required),
                "certified SGi drop-in must set {required} exactly"
            );
        }
    }

    #[test]
    fn candidate_lte_sgi_sidecar_pins_verified_image_digest_and_hardens_pod() {
        let compose = include_str!("../../../deployment/dn-sender/lte-sgi/compose.yaml");
        // The release gate replaces the placeholder with the exact offline
        // image digest. A zero or pending digest must never pass packaging.
        assert!(compose.contains(
            "polaris-lte-sgi-dn@sha256:e60eb72bf7619fd049f6bbbc45cf06927eb73ed7c613446678644f6742af31f3"
        ));
        assert!(!compose.contains("SIDE_CAR_IMAGE_DIGEST=PENDING"));
        assert!(!compose
            .contains("sha256:0000000000000000000000000000000000000000000000000000000000000000"));
        // Hardening gates — any removal of these breaks the test.
        for marker in [
            "cap_drop:",
            "- ALL",
            "no-new-privileges:true",
            "read_only: true",
            "user: \"65532:65532\"",
            "interface_name: sgi_lte",
            "polaris.sidecar.image_digest_state=OFFLINE_VERIFIED",
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
        assert!(calls[2]
            .windows(2)
            .any(|args| args == ["--timestamps", "--since"]));
        assert!(calls[2]
            .windows(2)
            .any(|args| args == ["--until", "1793534400.500"]));
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
    fn certification_subject_rejects_previous_image_id_after_0296_pin() {
        // 0.29.6: the certified image ID was rotated from 218e848b…4d04 to
        // aab719ff…db2a5 after ANR3 removed the ping file capability. The
        // previous ID must now fail-closed with LTE_CERTIFIED_IMAGE_MISMATCH
        // via the pinned CERTIFIED_IMAGE_REFERENCE, so an operator pointing
        // at the stale image gets a precise diagnostic.
        let previous = "oiran/srsran4g-ue-tools:0.29.4-rc1";
        assert_ne!(previous, CERTIFIED_IMAGE_REFERENCE);
        assert_eq!(
            validate_certified_release_subject(previous, CERTIFIED_COMPOSE_MODEL_SHA256),
            Err("LTE_CERTIFIED_IMAGE_MISMATCH".into())
        );
        // Pinned constants carry the real 0.29.6-rc1 reference + full 64-hex ID.
        assert_eq!(
            CERTIFIED_IMAGE_REFERENCE,
            "oiran/srsran4g-ue-tools:0.29.6-rc1"
        );
        assert_eq!(
            CERTIFIED_IMAGE_ID,
            "sha256:aab719ffdfa518777ed3d197ffe02cdcef02f78f578095d9abb1da9f327db2a5"
        );
        assert_eq!(CERTIFIED_IMAGE_ID.len(), 7 + 64, "sha256: prefix + 64 hex");
    }

    #[test]
    fn inject_log_section_replaces_body_without_touching_other_sections() {
        // Existing config has a noisy [log] block + three other sections.
        // Section patch must replace ONLY the [log] body with the required
        // pairs; the other sections stay byte-identical.
        let before = "\
[rat.eutra]
dl_earfcn = 2850
tx_gain = 50

[log]
phy_lib_level = info
rrc_level = info
all_hex_limit = 32
oldkey = oldvalue

[pcap]
enable = none

[expert]
some_option = 1
";
        let after = inject_log_section(before, "log", RUN_UE_LOG_SECTION);
        assert!(after.contains("[rat.eutra]\ndl_earfcn = 2850\ntx_gain = 50\n"));
        assert!(after.contains("[pcap]\nenable = none\n"));
        assert!(after.contains("[expert]\nsome_option = 1\n"));
        // Each of the nine required pairs is present in the new [log] body.
        for (key, value) in RUN_UE_LOG_SECTION {
            let line = format!("{key} = {value}");
            assert!(
                after.contains(&line),
                "patched config missing `{line}`:\n{after}"
            );
        }
        // Old [log] body is gone.
        assert!(!after.contains("phy_lib_level = info"));
        assert!(!after.contains("rrc_level = info"));
        assert!(!after.contains("all_hex_limit = 32"));
        assert!(!after.contains("oldkey = oldvalue"));
    }

    #[test]
    fn inject_log_section_appends_when_section_absent() {
        let before = "[rat.eutra]\ndl_earfcn = 2850\n";
        let after = inject_log_section(before, "log", RUN_UE_LOG_SECTION);
        assert!(after.starts_with("[rat.eutra]\ndl_earfcn = 2850\n"));
        assert!(after.contains("[log]\n"));
        for (key, value) in RUN_UE_LOG_SECTION {
            let line = format!("{key} = {value}");
            assert!(after.contains(&line), "appended [log] must include `{line}`");
        }
    }

    #[test]
    fn runtime_log_gate_requires_every_frozen_pair() {
        let valid = inject_log_section("[rat.eutra]\ndl_earfcn = 3350\n", "log", RUN_UE_LOG_SECTION);
        assert!(log_section_matches(&valid, "log", RUN_UE_LOG_SECTION));
        let invalid = valid.replace("phy_lib_level = none", "phy_lib_level = info");
        assert!(!log_section_matches(&invalid, "log", RUN_UE_LOG_SECTION));
        assert!(!log_section_matches("[rat.eutra]\ndl_earfcn = 3350\n", "log", RUN_UE_LOG_SECTION));
    }

    #[test]
    fn run_ue_log_section_lists_the_nine_frozen_pairs_in_order() {
        // Mission-mandated map; any drift is a regression.
        let expected: Vec<(&str, &str)> = vec![
            ("phy_lib_level", "none"),
            ("phy_level", "warning"),
            ("mac_level", "info"),
            ("rlc_level", "debug"),
            ("pdcp_level", "debug"),
            ("rrc_level", "debug"),
            ("nas_level", "debug"),
            ("usim_level", "warning"),
            ("all_hex_limit", "64"),
        ];
        assert_eq!(RUN_UE_LOG_SECTION.len(), 9);
        for ((ak, av), (ek, ev)) in RUN_UE_LOG_SECTION.iter().zip(expected.iter()) {
            assert_eq!(ak, ek);
            assert_eq!(av, ev);
        }
    }

    #[test]
    fn extract_rrc_lines_keeps_last_lines_and_drops_everything_else() {
        // 300 lines of PHY_LIB noise + 5 RRC lines interleaved + 300 more
        // PHY_LIB noise lines. 4 KiB tail must retain the five RRC lines
        // and NEVER retain a PHY_LIB line.
        let mut logs = String::new();
        for i in 0..300 {
            logs.push_str(&format!("[PHY_LIB] cell measurement {i}\n"));
        }
        for i in 1..=5 {
            logs.push_str(&format!("[RRC] marker {i}: setup complete\n"));
        }
        for i in 0..300 {
            logs.push_str(&format!("[PHY_LIB] later measurement {i}\n"));
        }
        let extract = extract_rrc_lines(&logs, 4096);
        assert!(extract.len() <= 4096);
        assert!(extract.contains("[RRC] marker 1"));
        assert!(extract.contains("[RRC] marker 5"));
        assert!(!extract.contains("[PHY_LIB]"));
    }

    #[test]
    fn extract_rrc_lines_sanitises_subscriber_material_and_preserves_tail() {
        // Three well-formed RRC lines + one subscriber-poisoned RRC line
        // + one noise line. The sanitiser replaces the poisoned RRC line
        // with the `[REDACTED_SUBSCRIBER_MATERIAL]` sentinel, which then
        // falls off the RRC filter (not an `[RRC]` line anymore). The two
        // benign RRC lines + non-poisoned noise exclusion must hold.
        let logs = "\
[RRC] UE Capability Enquiry received
[RRC] IMSI=001010123456789 attach request
[PHY_LIB] cell measurement 0
[RRC] RRC Reconfiguration no DRB ack
";
        let extract = extract_rrc_lines(logs, 4096);
        // IMSI must never surface — this is the mission's hard requirement.
        assert!(!extract.contains("IMSI="));
        // The two benign RRC lines must survive.
        assert!(extract.contains("UE Capability Enquiry received"));
        assert!(extract.contains("RRC Reconfiguration no DRB ack"));
        // PHY_LIB noise never surfaces either.
        assert!(!extract.contains("[PHY_LIB]"));
    }

    #[test]
    fn evaluate_erab_establishment_requires_both_ics_response_and_modify_bearer_response() {
        // Real srsRAN 25.10 + Open5GS SGW-C excerpts.
        // Response → evidence collected, Ok.
        let srsenb = "[S1AP] Tx S1AP SDU, InitialContextSetupResponse, rnti=0x46";
        let sgwc = "[sgwc] INFO: Modify Bearer Response";
        let ok = evaluate_erab_establishment(srsenb, sgwc).expect("both markers present");
        assert!(ok.ics_response_observed);
        assert!(ok.modify_bearer_response_observed);
        assert!(ok.ics_response_e_rab_markers >= 1);
        assert!(ok.modify_bearer_response_markers >= 1);

        // The exact d62245de pathology: eNB got ICS Request, never emitted
        // ICS Response; MME never sent Modify Bearer. Gate must fail with
        // LTE_ERAB_NOT_ESTABLISHED and the evidence must show what was seen.
        let srsenb_d62245de =
            "RRC: SetupComplete\nS1AP: InitialContextSetupRequest E-RAB=5\nUE context release";
        let mme_d62245de =
            "GTPv2 Create Session Response cause=16\nUE Context Release Command Cause=NAS Detach";
        let err =
            evaluate_erab_establishment(srsenb_d62245de, mme_d62245de).expect_err("gate must fail");
        assert_eq!(err.0, "LTE_ERAB_NOT_ESTABLISHED");
        assert!(!err.1.ics_response_observed);
        assert!(!err.1.modify_bearer_response_observed);
        assert!(err.1.summary.contains("ics_response_observed=false"));
        assert!(err
            .1
            .summary
            .contains("modify_bearer_response_observed=false"));

        // Partial: ICS Response observed but MBR missing → still FAIL.
        let srsenb_partial = "Tx S1AP SDU, InitialContextSetupResponse, rnti=0x46";
        let mme_partial = "nothing relevant";
        let err = evaluate_erab_establishment(srsenb_partial, mme_partial).expect_err("partial");
        assert_eq!(err.0, "LTE_ERAB_NOT_ESTABLISHED");
        assert!(err.1.ics_response_observed);
        assert!(!err.1.modify_bearer_response_observed);

        // Subscriber material in logs must be redacted by sanitize_log_line
        // before marker counting; the marker still fires if the token is on
        // another line.
        let srsenb_with_imsi =
            "IMSI=001010123456789\nTx S1AP SDU, InitialContextSetupResponse, rnti=0x46";
        let mme_with_tmsi = "TMSI=0xdeadbeef\nModify Bearer Response EBI=5";
        let ok = evaluate_erab_establishment(srsenb_with_imsi, mme_with_tmsi).expect("sanitised");
        assert!(ok.ics_response_observed && ok.modify_bearer_response_observed);

        // Approximate legacy strings must not create a false PASS.
        let legacy = evaluate_erab_establishment(
            "S1AP: InitialContextSetupResponse E-RAB=5",
            "MME GTPv2 message type 35",
        )
        .expect_err("unvalidated legacy markers rejected");
        assert_eq!(legacy.0, "LTE_ERAB_NOT_ESTABLISHED");
    }

    #[test]
    fn enb_network_diagnostic_args_mirror_ip_neigh_and_ip_s_link() {
        let neigh = ip_neigh_args("srsenb-id");
        assert_eq!(neigh, vec!["exec", "srsenb-id", "ip", "neigh"]);

        let link = ip_s_link_args("srsenb-id");
        assert_eq!(link, vec!["exec", "srsenb-id", "ip", "-s", "link"]);

        // Same args shape for the SGW-U sibling (read-only, no Open5GS
        // mutation implied by the command).
        let sgw_neigh = ip_neigh_args("sgwu-id");
        assert_eq!(sgw_neigh, vec!["exec", "sgwu-id", "ip", "neigh"]);
    }

    #[test]
    fn full_log_record_sanitises_and_bounds_tail_but_keeps_full_bytes_in_sha() {
        // Raw logs with subscriber material in the first line + 2000 bytes of
        // benign log content. The sanitised stream drops the IMSI line, the
        // tail is bounded 512, but the SHA256 covers the entire sanitised
        // stream (not the bounded tail).
        let mut raw = String::new();
        raw.push_str("IMSI=001010123456789 attach\n");
        for _ in 0..100 {
            raw.push_str("RRC: Measurement report ok\n");
        }
        raw.push_str("LAST_LINE_MARKER erab setup response\n");
        let record =
            build_full_log_record("srsenb", "/var/lib/polaris-control/runs/x/srsenb.log", &raw);
        assert_eq!(record.component, "srsenb");
        assert_eq!(record.path, "/var/lib/polaris-control/runs/x/srsenb.log");
        // Tail bounded ≤ 512 UTF-8 bytes.
        assert!(record.sanitized_tail.len() <= 512);
        // The LAST line survived the tail.
        assert!(record.sanitized_tail.contains("LAST_LINE_MARKER"));
        // The IMSI line was redacted (never surfaces).
        assert!(!record.sanitized_tail.contains("IMSI="));
        // SHA256 is 64 lowercase hex.
        assert_eq!(record.sha256.len(), 64);
        assert!(record.sha256.chars().all(|c| c.is_ascii_hexdigit()));
        // Bytes = length of sanitised stream (> 512 because many lines passed).
        assert!(record.bytes > 512);
    }

    #[test]
    fn private_log_bounds_and_rrc_extract_keep_tail_without_hex_material() {
        let mut raw = String::from("subscriber key follows\n0000: aa bb cc dd\n");
        for index in 0..300 {
            raw.push_str(&format!("[RRC] message-{index:03} {}\n", "x".repeat(20)));
        }
        raw.push_str("[RRC] LAST_RRC_MARKER\n");
        let bounded = bounded_sanitized_log(&raw);
        assert!(bounded.len() < 5 * 1024 * 1024);
        assert!(!bounded.contains("aa bb cc dd"));
        assert!(!bounded.to_ascii_lowercase().contains("subscriber key"));
        let extract = build_rrc_extract(&bounded);
        assert!(extract.len() <= 4096);
        assert!(extract.contains("LAST_RRC_MARKER"));
        assert!(!extract.contains("message-000"));
    }

    #[test]
    fn certification_subject_rejects_previous_compose_model_after_0296_pin() {
        // 0.29.8 rotates the compose model after adding the LTE-only
        // real-time overlay. Combining the current
        // pinned image reference with the stale compose model must now
        // fail-closed with LTE_CERTIFIED_COMPOSE_MODEL_MISMATCH so an
        // operator who kept an old compose render gets a precise diagnostic.
        let previous_model = "d0c80ea193272fc85b9afc8abc78d521ffc08e5581cf49894160c5bf78935f5d";
        assert_ne!(previous_model, CERTIFIED_COMPOSE_MODEL_SHA256);
        assert_eq!(
            validate_certified_release_subject(CERTIFIED_IMAGE_REFERENCE, previous_model),
            Err("LTE_CERTIFIED_COMPOSE_MODEL_MISMATCH".into())
        );
        // The pinned constant carries the new 64-hex compose model digest.
        assert_eq!(
            CERTIFIED_COMPOSE_MODEL_SHA256,
            "b25bc0137713697140aa96cb8e4964c844ce84754a1deb998387c2ed9595e560"
        );
        assert_eq!(CERTIFIED_COMPOSE_MODEL_SHA256.len(), 64);
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
