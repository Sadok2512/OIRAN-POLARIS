//! LTE E2E North Star mechanical verifier.
//!
//! Pure, offline verdict functions over a `pending-evidence/` folder.
//! A PASS is produced only when its proof is present; any missing field
//! fails closed with the exact gate code.

use serde::Deserialize;
use std::fs;
use std::io;
use std::path::Path;

pub const VERSION: &str = "0.1.0";

const UDP_RATE_CAP_BPS: u64 = 1_000_000;
const DUMPCAP_EXPECTED: usize = 12;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Each top-level gate.
pub const GATE_ORDER: &[&str] = &[
    "S1_SETUP",
    "ATTACH",
    "EPS_BEARER",
    "S1U_GTPU",
    "PING_UL",
    "PING_DL",
    "UDP_UL",
    "UDP_DL",
    "CLEANUP",
    "GRANT_REVOKED",
    "DUMPCAP",
];

/// Blocker priority order (operational, not declaration order).
///
/// The e0497 fixture must emit exactly:
///   PING_UL, S1U_GTPU, PING_DL, UDP_UL, UDP_DL
/// so this list places the UL path first, then user plane, then DL/UDP.
const BLOCKER_ORDER: &[&str] = &[
    "S1_SETUP",
    "ATTACH",
    "EPS_BEARER",
    "PING_UL",
    "S1U_GTPU",
    "PING_DL",
    "UDP_UL",
    "UDP_DL",
    "CLEANUP",
    "GRANT_REVOKED",
    "DUMPCAP",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    PassControlPlaneOnly,
    Fail(String),
}

impl Verdict {
    pub fn label(&self) -> String {
        match self {
            Verdict::Pass => "PASS".to_string(),
            Verdict::PassControlPlaneOnly => "PASS_CONTROL_PLANE_ONLY".to_string(),
            Verdict::Fail(_) => "FAIL".to_string(),
        }
    }

    pub fn passed(&self) -> bool {
        matches!(self, Verdict::Pass | Verdict::PassControlPlaneOnly)
    }
}

#[derive(Debug, Clone)]
pub struct Report {
    pub run_id: String,
    pub gates: Vec<(&'static str, Verdict)>,
}

impl Report {
    pub fn blockers(&self) -> Vec<&'static str> {
        let mut failed: Vec<&'static str> = self
            .gates
            .iter()
            .filter(|(_, v)| !v.passed())
            .map(|(name, _)| *name)
            .collect();
        failed.sort_by_key(|name| {
            BLOCKER_ORDER
                .iter()
                .position(|other| other == name)
                .unwrap_or(usize::MAX)
        });
        failed
    }

    pub fn final_verdict(&self) -> &'static str {
        if self.blockers().is_empty() {
            "REAL_PASS"
        } else {
            "NO_LTE_E2E_REAL_PASS"
        }
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("MISSION=LTE_E2E_NORTH_STAR\n");
        out.push_str(&format!("RUN_ID={}\n", self.run_id));
        for (name, verdict) in &self.gates {
            out.push_str(&format!("{}={}\n", name, verdict.label()));
        }
        let blockers = self.blockers();
        out.push_str(&format!("BLOCKERS={}\n", blockers.join(",")));
        out.push_str(&format!("FINAL_VERDICT={}\n", self.final_verdict()));
        out
    }
}

#[derive(Debug)]
pub enum VerifyError {
    Io(String),
    Parse(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Io(path) => write!(f, "io: {}", path),
            VerifyError::Parse(path) => write!(f, "parse: {}", path),
        }
    }
}

impl std::error::Error for VerifyError {}

pub fn verify(root: &Path) -> Result<Report, VerifyError> {
    let s1_mme = load_manifest(&root.join("manifests/S1_MME.json"))?;
    let s11 = load_manifest(&root.join("manifests/S11.json"))?;
    let s1_u = load_manifest(&root.join("manifests/S1_U.json"))?;
    let control = load_control(&root.join("sanitized-summaries/RUN.control-proof.json"))?;

    let run_id = control.run_id.clone();
    let mut gates: Vec<(&'static str, Verdict)> = Vec::new();
    gates.push(("S1_SETUP", verdict_s1_setup(&s1_mme)));
    gates.push(("ATTACH", verdict_attach(&s1_mme, &control)));
    gates.push(("EPS_BEARER", verdict_eps_bearer(&s11, &s1_mme, &s1_u)));
    gates.push(("S1U_GTPU", verdict_s1u_gtpu(&s1_u, &s11, &s1_mme)));
    gates.push(("PING_UL", verdict_ping(&control, "ul")));
    gates.push(("PING_DL", verdict_ping(&control, "dl")));
    gates.push(("UDP_UL", verdict_udp(&control, "ul")));
    gates.push(("UDP_DL", verdict_udp(&control, "dl")));
    gates.push(("CLEANUP", verdict_cleanup(&control)));
    gates.push(("GRANT_REVOKED", verdict_grant(&control)));
    gates.push(("DUMPCAP", verdict_dumpcap(&control)));

    Ok(Report { run_id, gates })
}

// ---------------------------------------------------------------------------
// Schema (shared with POLARIS srsran_controller.rs and the evidence envelope
// contract — see docs/api/lte-evidence-envelope.contract.md). The verifier
// deliberately treats every field as optional and emits FAIL with the gate's
// code if an expected value is absent.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    pub plane: String,
    pub packet_count: u64,
    #[serde(default)]
    pub first_packet_at: Option<String>,
    #[serde(default)]
    pub last_packet_at: Option<String>,
    #[serde(default)]
    pub source_sha256: Option<String>,
    #[serde(default)]
    pub s1ap_procedures: Vec<S1apEvent>,
    #[serde(default)]
    pub nas_eps: Vec<NasEvent>,
    #[serde(default)]
    pub gtpv2c: Vec<Gtpv2cEvent>,
    #[serde(default)]
    pub gtpu: Option<GtpuSummary>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct S1apEvent {
    pub procedure: u16,
    #[serde(default)]
    pub sctp_ppid: Option<u16>,
    #[serde(default)]
    pub e_rab_id: Option<u16>,
    #[serde(default)]
    pub s1_u_teid: Option<String>,
    #[serde(default)]
    pub s1_u_endpoint: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NasEvent {
    pub message_type: String,
    pub role: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Gtpv2cEvent {
    pub message_type: u16,
    pub role: String,
    #[serde(default)]
    pub cause: Option<u16>,
    #[serde(default)]
    pub ebi: Option<u16>,
    #[serde(default)]
    pub s1u_f_teid: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GtpuSummary {
    #[serde(default)]
    pub teid: Option<String>,
    #[serde(default)]
    pub octets: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ControlProof {
    pub run_id: String,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub ended_at: Option<String>,
    #[serde(default)]
    pub final_state: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub steps: Vec<Step>,
    #[serde(default)]
    pub ping: Option<PingSection>,
    #[serde(default)]
    pub udp: Option<UdpSection>,
    #[serde(default)]
    pub cleanup: Option<CleanupSection>,
    #[serde(default)]
    pub grant: Option<GrantSection>,
    #[serde(default)]
    pub dumpcap: Option<DumpcapSection>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Step {
    pub index: u32,
    pub name: String,
    pub state: String,
    #[serde(default)]
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PingSection {
    #[serde(default)]
    pub ul: Option<PingCounters>,
    #[serde(default)]
    pub dl: Option<PingCounters>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PingCounters {
    pub tx: u64,
    pub rx: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UdpSection {
    #[serde(default)]
    pub ul: Option<UdpCounters>,
    #[serde(default)]
    pub dl: Option<UdpCounters>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UdpCounters {
    pub bytes: u64,
    #[serde(default)]
    pub rate_bps: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CleanupSection {
    pub srsue_stopped: bool,
    pub srsenb_stopped: bool,
    pub sidecars_removed: bool,
    pub epc_healthy: bool,
    pub dumpcaps_preserved: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GrantSection {
    pub state: String,
    pub use_count: u32,
    #[serde(default)]
    pub run_state: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DumpcapSection {
    pub before_pids: Vec<u32>,
    pub after_pids: Vec<u32>,
}

fn load_manifest(path: &Path) -> Result<Manifest, VerifyError> {
    let bytes = fs::read(path).map_err(|_| VerifyError::Io(path.display().to_string()))?;
    serde_json::from_slice(&bytes).map_err(|_| VerifyError::Parse(path.display().to_string()))
}

fn load_control(path: &Path) -> Result<ControlProof, VerifyError> {
    let bytes = fs::read(path).map_err(|_| VerifyError::Io(path.display().to_string()))?;
    serde_json::from_slice(&bytes).map_err(|_| VerifyError::Parse(path.display().to_string()))
}

// ---------------------------------------------------------------------------
// Verdict logic — pure functions, testable in isolation.
// ---------------------------------------------------------------------------

/// S1_SETUP: at least one S1AP procedure 17 carried over SCTP PPID 18.
pub fn verdict_s1_setup(s1_mme: &Manifest) -> Verdict {
    let ok = s1_mme.s1ap_procedures.iter().any(|event| {
        event.procedure == 17 && event.sctp_ppid == Some(18)
    });
    if ok {
        Verdict::Pass
    } else {
        Verdict::Fail("S1_SETUP".into())
    }
}

/// ATTACH: NAS Attach Request/Complete + durable lte_attach step COMPLETED.
pub fn verdict_attach(s1_mme: &Manifest, control: &ControlProof) -> Verdict {
    let has_attach_request = s1_mme
        .nas_eps
        .iter()
        .any(|event| event.role.eq_ignore_ascii_case("attach_request"));
    let has_attach_complete = s1_mme
        .nas_eps
        .iter()
        .any(|event| event.role.eq_ignore_ascii_case("attach_complete"))
        || control
            .steps
            .iter()
            .any(|step| step.name == "lte_attach" && step.state == "COMPLETED");
    if has_attach_request && has_attach_complete {
        Verdict::Pass
    } else {
        Verdict::Fail("ATTACH".into())
    }
}

/// EPS_BEARER: S11 CSReq (type 32) + CSRsp (type 33) with cause 16 + S1AP
/// Initial Context Setup (procedure 9) carrying an E-RAB id. If S1-U has
/// zero packets the gate degrades to `PASS_CONTROL_PLANE_ONLY`.
pub fn verdict_eps_bearer(s11: &Manifest, s1_mme: &Manifest, s1_u: &Manifest) -> Verdict {
    let has_req = s11.gtpv2c.iter().any(|event| event.message_type == 32);
    let has_resp_ok = s11
        .gtpv2c
        .iter()
        .any(|event| event.message_type == 33 && event.cause == Some(16));
    let has_erab = s1_mme
        .s1ap_procedures
        .iter()
        .any(|event| event.procedure == 9 && event.e_rab_id.is_some());
    if !(has_req && has_resp_ok && has_erab) {
        return Verdict::Fail("EPS_BEARER".into());
    }
    if s1_u.packet_count == 0 {
        Verdict::PassControlPlaneOnly
    } else {
        Verdict::Pass
    }
}

/// S1U_GTPU: non-zero S1-U packet count AND identical TEID across S1-U,
/// S11 F-TEID and S1AP E-RAB TEID.
pub fn verdict_s1u_gtpu(s1_u: &Manifest, s11: &Manifest, s1_mme: &Manifest) -> Verdict {
    if s1_u.packet_count == 0 {
        return Verdict::Fail("S1U_GTPU".into());
    }
    let s1u_teid = s1_u.gtpu.as_ref().and_then(|g| g.teid.clone());
    let s11_teid = s11.gtpv2c.iter().find_map(|event| event.s1u_f_teid.clone());
    let s1ap_teid = s1_mme
        .s1ap_procedures
        .iter()
        .find_map(|event| event.s1_u_teid.clone());
    match (s1u_teid, s11_teid, s1ap_teid) {
        (Some(a), Some(b), Some(c)) if normalize_teid(&a) == normalize_teid(&b)
            && normalize_teid(&b) == normalize_teid(&c) =>
        {
            Verdict::Pass
        }
        _ => Verdict::Fail("S1U_GTPU".into()),
    }
}

fn normalize_teid(value: &str) -> String {
    let trimmed = value.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    stripped.trim_start_matches('0').to_ascii_lowercase()
}

/// PING: both tx and rx > 0 in the requested direction.
pub fn verdict_ping(control: &ControlProof, direction: &str) -> Verdict {
    let section = control.ping.as_ref().and_then(|section| {
        if direction == "ul" {
            section.ul.as_ref()
        } else {
            section.dl.as_ref()
        }
    });
    let gate = format!("PING_{}", direction.to_ascii_uppercase());
    match section {
        Some(c) if c.tx > 0 && c.rx > 0 => Verdict::Pass,
        _ => Verdict::Fail(gate),
    }
}

/// UDP: bytes > 0 AND rate ≤ 1 Mbit/s (Grant V2 cap) in the requested
/// direction. Missing rate is treated as unknown and fails closed.
pub fn verdict_udp(control: &ControlProof, direction: &str) -> Verdict {
    let section = control.udp.as_ref().and_then(|section| {
        if direction == "ul" {
            section.ul.as_ref()
        } else {
            section.dl.as_ref()
        }
    });
    let gate = format!("UDP_{}", direction.to_ascii_uppercase());
    match section {
        Some(c)
            if c.bytes > 0
                && c.rate_bps.is_some()
                && c.rate_bps.unwrap() <= UDP_RATE_CAP_BPS =>
        {
            Verdict::Pass
        }
        _ => Verdict::Fail(gate),
    }
}

/// CLEANUP: all five explicit observations are true.
pub fn verdict_cleanup(control: &ControlProof) -> Verdict {
    match control.cleanup.as_ref() {
        Some(c)
            if c.srsue_stopped
                && c.srsenb_stopped
                && c.sidecars_removed
                && c.epc_healthy
                && c.dumpcaps_preserved =>
        {
            Verdict::Pass
        }
        _ => Verdict::Fail("CLEANUP".into()),
    }
}

/// GRANT_REVOKED: grant state REVOKED and consumed at least once.
pub fn verdict_grant(control: &ControlProof) -> Verdict {
    match control.grant.as_ref() {
        Some(g)
            if g.state.eq_ignore_ascii_case("REVOKED")
                && g.use_count >= 1
                && g.run_state.as_deref().map(|v| v.eq_ignore_ascii_case("CLEAN")).unwrap_or(false) =>
        {
            Verdict::Pass
        }
        _ => Verdict::Fail("GRANT_REVOKED".into()),
    }
}

/// DUMPCAP: exactly 12 processes before/after with identical PID sets.
pub fn verdict_dumpcap(control: &ControlProof) -> Verdict {
    match control.dumpcap.as_ref() {
        Some(d)
            if d.before_pids.len() == DUMPCAP_EXPECTED
                && d.after_pids.len() == DUMPCAP_EXPECTED
                && pid_set(&d.before_pids) == pid_set(&d.after_pids) =>
        {
            Verdict::Pass
        }
        _ => Verdict::Fail("DUMPCAP".into()),
    }
}

fn pid_set(pids: &[u32]) -> Vec<u32> {
    let mut sorted = pids.to_vec();
    sorted.sort();
    sorted
}

// Shim for callers that only need the IO layer.
pub fn load_report_from_dir(path: &Path) -> io::Result<Report> {
    verify(path).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
}
