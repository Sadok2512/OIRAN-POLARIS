// 0.20.0 — Traffic Generator (#47) state machine + validation.
// 0.20.1 — Per-session samples ring buffer + GET
// `/traffic/sessions/:id/samples` endpoint feeding the simulator-control
// 0.13.1 live charts. The ring is bounded (SAMPLES_RING_MAX = 60), so
// the Analyzer-side memory bound mirrors the N3 aggregator one: no
// per-packet retention, only per-tick snapshots of the counters.
//
// HTTP contract:
//   POST   /api/v1/traffic/sessions          {ue_ids[], direction, protocol, rate_mbps, duration_s}
//   GET    /api/v1/traffic/sessions                                       → list + per-UE live counters
//   GET    /api/v1/traffic/sessions/:id                                    → one session
//   DELETE /api/v1/traffic/sessions/:id                                    → stop (always allowed)
//   GET    /api/v1/traffic/sessions/:id/samples                            → per-tick ring buffer (0.20.1)
//
// Rules (locked in tests):
//   - rate_mbps ∈ [1, 50] — the lab UDP sender guarantees ≤ 20 Mbit/s
//     without loss; the 50 Mbit/s upper bound is the hard rate ceiling.
//   - duration_s ∈ [1, 600].
//   - direction ∈ {UL, DL, BOTH}, protocol ∈ {TCP, UDP}.
//   - ue_ids non-empty, each must match `UE-NN` / `UE-NNNNN`.
//   - START requires `require_operator` + an active live grant covering
//     every UE in `ue_ids` (same gate as `POST /scenarios/start`).
//   - STOP is **always** allowed (even for a viewer re-opening the
//     session detail), mirroring the simulator's Stop-is-sacred rule.
//   - iperf3 is a measurement step; the per-session result reports the
//     counters + warning codes but never fails the session (0.19.8).
//
// Memory bound: one `TrafficSession` + one bounded `VecDeque<TrafficSample>`
// (SAMPLES_RING_MAX = 60) per POST. Fixed-size, no per-packet retention.
// Live counters come from the iperf3 driver that produces `IperfMeasurement`
// (0.19.8); we accumulate the counters, not the frames.
//
// The actual iperf3 spawn is wired to `UeRuntime::execute_iperf_ul` /
// `execute_iperf_dl` by the handler layer — those entry points are already
// in place in 0.19.8 and the integration site is a single
// `tokio::spawn` block per direction. Callers never block on an iperf3
// process; polling GET returns the latest snapshot.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Per-session rolling window of counter snapshots. 60 entries at 1 Hz
/// is one minute of history — enough for an at-a-glance live chart but
/// bounded so a long-running session cannot grow the API process RSS.
pub const SAMPLES_RING_MAX: usize = 60;

pub const RATE_MBPS_MIN: u32 = 1;
pub const RATE_MBPS_MAX: u32 = 50;
pub const DURATION_S_MIN: u32 = 1;
pub const DURATION_S_MAX: u32 = 600;

/// Backend contract for the per-lab UDP sender. The front shows this
/// value as "limite du labo affichée (UDP sans perte ≤ 20 Mbit/s)".
pub const UDP_LOSSLESS_CEILING_MBPS: u32 = 20;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Direction {
    Ul,
    Dl,
    Both,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionState {
    Requested,
    Running,
    Completed,
    Stopped,
    Failed,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SessionRequest {
    pub ue_ids: Vec<String>,
    pub direction: Direction,
    pub protocol: Protocol,
    pub rate_mbps: u32,
    pub duration_s: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct UeCounters {
    pub ue_id: String,
    pub packets_ul: u64,
    pub packets_dl: u64,
    pub bytes_ul: u64,
    pub bytes_dl: u64,
    pub rate_ul_bps: Option<u64>,
    pub rate_dl_bps: Option<u64>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TrafficSession {
    pub session_id: String,
    pub state: SessionState,
    pub request: SessionSnapshot,
    pub ue_counters: Vec<UeCounters>,
    pub started_at_epoch_s: u64,
    pub ended_at_epoch_s: Option<u64>,
    /// Last iperf3 warning codes (0.19.8 vocabulary). Empty when the
    /// session is running without surface-level anomalies.
    pub warnings: Vec<String>,
}

/// Request shape mirrored to the API so GET /traffic/sessions can show
/// the exact parameters the operator submitted (no derivation).
#[derive(Clone, Debug, Serialize)]
pub struct SessionSnapshot {
    pub ue_ids: Vec<String>,
    pub direction: Direction,
    pub protocol: Protocol,
    pub rate_mbps: u32,
    pub duration_s: u32,
}

/// A single tick snapshot of a traffic session's counters. The driver
/// pushes one of these per second (or per iperf3 result window); the
/// ring buffer is capped at `SAMPLES_RING_MAX` so an operator who leaves
/// a 10-minute session running cannot grow the API process RSS.
///
/// Byte counters are cumulative since the session started so the client
/// can draw either a cumulative line or diff two consecutive samples
/// for an instantaneous rate.
#[derive(Clone, Debug, Serialize)]
pub struct TrafficSample {
    pub epoch_s: u64,
    pub bytes_ul_cum: u64,
    pub bytes_dl_cum: u64,
    pub rate_ul_bps: Option<u64>,
    pub rate_dl_bps: Option<u64>,
}

/// Validation + state store. The HTTP handler layer plugs
/// `TrafficSessionManager` into AppState and uses `tokio::task::spawn`
/// to feed per-UE iperf3 drivers; the manager itself stays
/// synchronous and tiny so the test suite can lock the state machine
/// without a Tokio runtime.
#[derive(Default)]
pub struct TrafficSessionManager {
    sessions: Mutex<BTreeMap<String, TrafficSession>>,
    /// Per-session bounded ring of counter snapshots (0.20.1). Keyed by
    /// `session_id`. Separate map so the hot path for `get` / `list`
    /// never has to iterate the sample history.
    samples: Mutex<BTreeMap<String, VecDeque<TrafficSample>>>,
}

impl TrafficSessionManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate a POST body against the 0.20.0 contract. Returns a
    /// stable error code so the frontend can surface it verbatim
    /// (same vocabulary pattern as `scenarios/validate`).
    pub fn validate(request: &SessionRequest) -> Result<(), &'static str> {
        if request.ue_ids.is_empty() {
            return Err("TRAFFIC_SESSION_UE_IDS_REQUIRED");
        }
        for id in &request.ue_ids {
            if !is_ue_id_valid(id) {
                return Err("TRAFFIC_SESSION_UE_ID_INVALID");
            }
        }
        if request.rate_mbps < RATE_MBPS_MIN || request.rate_mbps > RATE_MBPS_MAX {
            return Err("TRAFFIC_SESSION_RATE_OUT_OF_RANGE");
        }
        if request.duration_s < DURATION_S_MIN || request.duration_s > DURATION_S_MAX {
            return Err("TRAFFIC_SESSION_DURATION_OUT_OF_RANGE");
        }
        Ok(())
    }

    /// Enqueue a session after validation + grant check. The caller is
    /// responsible for making sure every UE in `ue_ids` is covered by
    /// an active grant before this is reached; the manager only
    /// records the request + state.
    pub fn start(&self, request: SessionRequest) -> Result<TrafficSession, &'static str> {
        Self::validate(&request)?;
        let session_id = allocate_id();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let snapshot = SessionSnapshot {
            ue_ids: request.ue_ids.clone(),
            direction: request.direction,
            protocol: request.protocol,
            rate_mbps: request.rate_mbps,
            duration_s: request.duration_s,
        };
        let session = TrafficSession {
            session_id: session_id.clone(),
            state: SessionState::Requested,
            request: snapshot,
            ue_counters: request
                .ue_ids
                .iter()
                .map(|id| UeCounters {
                    ue_id: id.clone(),
                    packets_ul: 0,
                    packets_dl: 0,
                    bytes_ul: 0,
                    bytes_dl: 0,
                    rate_ul_bps: None,
                    rate_dl_bps: None,
                    warnings: Vec::new(),
                })
                .collect(),
            started_at_epoch_s: now,
            ended_at_epoch_s: None,
            warnings: Vec::new(),
        };
        self.sessions
            .lock()
            .unwrap()
            .insert(session_id.clone(), session.clone());
        self.samples.lock().unwrap().insert(
            session_id.clone(),
            VecDeque::with_capacity(SAMPLES_RING_MAX),
        );
        Ok(session)
    }

    pub fn transition_running(&self, session_id: &str) -> Result<(), &'static str> {
        let mut map = self.sessions.lock().unwrap();
        let session = map.get_mut(session_id).ok_or("TRAFFIC_SESSION_NOT_FOUND")?;
        if !matches!(session.state, SessionState::Requested) {
            return Err("TRAFFIC_SESSION_INVALID_TRANSITION");
        }
        session.state = SessionState::Running;
        Ok(())
    }

    /// Stop a session. Always allowed, even on a Failed state (idempotent).
    pub fn stop(&self, session_id: &str) -> Result<TrafficSession, &'static str> {
        let mut map = self.sessions.lock().unwrap();
        let session = map.get_mut(session_id).ok_or("TRAFFIC_SESSION_NOT_FOUND")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if matches!(
            session.state,
            SessionState::Running | SessionState::Requested
        ) {
            session.state = SessionState::Stopped;
            session.ended_at_epoch_s = Some(now);
        }
        Ok(session.clone())
    }

    pub fn fail(&self, session_id: &str, error: String) -> Result<(), &'static str> {
        let mut map = self.sessions.lock().unwrap();
        let session = map.get_mut(session_id).ok_or("TRAFFIC_SESSION_NOT_FOUND")?;
        session.state = SessionState::Failed;
        session.ended_at_epoch_s = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        if !session.warnings.contains(&error) {
            session.warnings.push(error);
        }
        Ok(())
    }

    /// Called by the per-UE iperf3 worker when the measurement window
    /// closes. The warnings vocabulary is the 0.19.8 string list
    /// (`IPERF3_SERVER_OUTPUT_MISSING`, `IPERF3_RECEIVER_SHORT`, …);
    /// anything in there is a warning, never a failure.
    pub fn record_measurement(
        &self,
        session_id: &str,
        ue_id: &str,
        bytes_ul: u64,
        bytes_dl: u64,
        rate_ul_bps: Option<u64>,
        rate_dl_bps: Option<u64>,
        warnings: Vec<String>,
    ) -> Result<(), &'static str> {
        let mut map = self.sessions.lock().unwrap();
        let session = map.get_mut(session_id).ok_or("TRAFFIC_SESSION_NOT_FOUND")?;
        let counters = session
            .ue_counters
            .iter_mut()
            .find(|c| c.ue_id == ue_id)
            .ok_or("TRAFFIC_SESSION_UE_NOT_IN_SESSION")?;
        counters.bytes_ul = counters.bytes_ul.saturating_add(bytes_ul);
        counters.bytes_dl = counters.bytes_dl.saturating_add(bytes_dl);
        if let Some(rate) = rate_ul_bps {
            counters.rate_ul_bps = Some(rate);
        }
        if let Some(rate) = rate_dl_bps {
            counters.rate_dl_bps = Some(rate);
        }
        for warning in warnings {
            if !counters.warnings.contains(&warning) {
                counters.warnings.push(warning.clone());
            }
            if !session.warnings.contains(&warning) {
                session.warnings.push(warning);
            }
        }
        Ok(())
    }

    pub fn get(&self, session_id: &str) -> Option<TrafficSession> {
        self.sessions.lock().unwrap().get(session_id).cloned()
    }

    pub fn list(&self) -> Vec<TrafficSession> {
        self.sessions.lock().unwrap().values().cloned().collect()
    }

    /// 0.20.1 — Append a tick snapshot to the per-session ring. Capped at
    /// `SAMPLES_RING_MAX`; older ticks fall off the front. Returns an
    /// error only when the session_id is unknown (so the driver can log
    /// and keep going without panicking).
    pub fn push_sample(&self, session_id: &str, sample: TrafficSample) -> Result<(), &'static str> {
        let mut map = self.samples.lock().unwrap();
        let ring = map.get_mut(session_id).ok_or("TRAFFIC_SESSION_NOT_FOUND")?;
        if ring.len() == SAMPLES_RING_MAX {
            ring.pop_front();
        }
        ring.push_back(sample);
        Ok(())
    }

    /// 0.20.1 — Snapshot of the ring buffer for GET `/samples`.
    pub fn samples(&self, session_id: &str) -> Option<Vec<TrafficSample>> {
        self.samples
            .lock()
            .unwrap()
            .get(session_id)
            .map(|ring| ring.iter().cloned().collect())
    }

    /// 0.20.1 — Flip a session to COMPLETED when the driver's duration
    /// window closes naturally (as opposed to an operator STOP). No-op
    /// if the session is already in a terminal state.
    pub fn complete(&self, session_id: &str) -> Result<(), &'static str> {
        let mut map = self.sessions.lock().unwrap();
        let session = map.get_mut(session_id).ok_or("TRAFFIC_SESSION_NOT_FOUND")?;
        if matches!(
            session.state,
            SessionState::Completed | SessionState::Stopped | SessionState::Failed
        ) {
            return Ok(());
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        session.state = SessionState::Completed;
        session.ended_at_epoch_s = Some(now);
        Ok(())
    }
}

fn is_ue_id_valid(id: &str) -> bool {
    if id == "LTE-UE-01" {
        return true;
    }
    if !id.starts_with("UE-") {
        return false;
    }
    let digits = &id[3..];
    (digits.len() == 2 || digits.len() == 5) && digits.chars().all(|c| c.is_ascii_digit())
}

fn allocate_id() -> String {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("traffic-{hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> SessionRequest {
        SessionRequest {
            ue_ids: vec!["UE-01".into(), "UE-02".into()],
            direction: Direction::Both,
            protocol: Protocol::Udp,
            rate_mbps: 5,
            duration_s: 10,
        }
    }

    #[test]
    fn validate_rejects_empty_ue_ids() {
        let mut r = req();
        r.ue_ids.clear();
        assert_eq!(
            TrafficSessionManager::validate(&r).unwrap_err(),
            "TRAFFIC_SESSION_UE_IDS_REQUIRED"
        );
    }

    #[test]
    fn validate_accepts_only_the_allowlisted_lte_ue_shape() {
        let mut r = req();
        r.ue_ids = vec!["LTE-UE-01".into()];
        assert_eq!(TrafficSessionManager::validate(&r), Ok(()));
        r.ue_ids = vec!["LTE-UE-99".into()];
        assert_eq!(
            TrafficSessionManager::validate(&r),
            Err("TRAFFIC_SESSION_UE_ID_INVALID")
        );
    }

    #[test]
    fn validate_rejects_bad_ue_id_shape() {
        let mut r = req();
        r.ue_ids = vec!["UE-1".into()];
        assert_eq!(
            TrafficSessionManager::validate(&r).unwrap_err(),
            "TRAFFIC_SESSION_UE_ID_INVALID"
        );
    }

    #[test]
    fn validate_rate_window() {
        let mut r = req();
        r.rate_mbps = 51;
        assert_eq!(
            TrafficSessionManager::validate(&r).unwrap_err(),
            "TRAFFIC_SESSION_RATE_OUT_OF_RANGE"
        );
        r.rate_mbps = 0;
        assert_eq!(
            TrafficSessionManager::validate(&r).unwrap_err(),
            "TRAFFIC_SESSION_RATE_OUT_OF_RANGE"
        );
        r.rate_mbps = 50;
        assert!(TrafficSessionManager::validate(&r).is_ok());
    }

    #[test]
    fn validate_duration_window() {
        let mut r = req();
        r.duration_s = 601;
        assert_eq!(
            TrafficSessionManager::validate(&r).unwrap_err(),
            "TRAFFIC_SESSION_DURATION_OUT_OF_RANGE"
        );
        r.duration_s = 0;
        assert_eq!(
            TrafficSessionManager::validate(&r).unwrap_err(),
            "TRAFFIC_SESSION_DURATION_OUT_OF_RANGE"
        );
        r.duration_s = 600;
        assert!(TrafficSessionManager::validate(&r).is_ok());
    }

    #[test]
    fn start_then_running_then_stop_is_the_happy_path() {
        let mgr = TrafficSessionManager::new();
        let session = mgr.start(req()).unwrap();
        assert_eq!(session.state, SessionState::Requested);
        mgr.transition_running(&session.session_id).unwrap();
        assert!(matches!(
            mgr.get(&session.session_id).unwrap().state,
            SessionState::Running
        ));
        let stopped = mgr.stop(&session.session_id).unwrap();
        assert_eq!(stopped.state, SessionState::Stopped);
        assert!(stopped.ended_at_epoch_s.is_some());
    }

    #[test]
    fn stop_is_always_allowed_on_unknown_session_returns_not_found() {
        let mgr = TrafficSessionManager::new();
        assert_eq!(
            mgr.stop("traffic-ffffffffffffffff").unwrap_err(),
            "TRAFFIC_SESSION_NOT_FOUND"
        );
    }

    #[test]
    fn stop_is_idempotent_on_already_stopped_session() {
        let mgr = TrafficSessionManager::new();
        let s = mgr.start(req()).unwrap();
        mgr.stop(&s.session_id).unwrap();
        let again = mgr.stop(&s.session_id).unwrap();
        assert_eq!(again.state, SessionState::Stopped);
    }

    #[test]
    fn record_measurement_dedupes_warnings_and_accumulates_bytes() {
        let mgr = TrafficSessionManager::new();
        let s = mgr.start(req()).unwrap();
        mgr.record_measurement(
            &s.session_id,
            "UE-01",
            1_000,
            500,
            Some(1_000_000),
            Some(500_000),
            vec!["IPERF3_SERVER_OUTPUT_MISSING".into()],
        )
        .unwrap();
        mgr.record_measurement(
            &s.session_id,
            "UE-01",
            1_000,
            500,
            Some(2_000_000),
            Some(1_000_000),
            vec![
                "IPERF3_SERVER_OUTPUT_MISSING".into(),
                "IPERF3_RECEIVER_SHORT".into(),
            ],
        )
        .unwrap();
        let got = mgr.get(&s.session_id).unwrap();
        let ue01 = got.ue_counters.iter().find(|c| c.ue_id == "UE-01").unwrap();
        assert_eq!(ue01.bytes_ul, 2_000);
        assert_eq!(ue01.bytes_dl, 1_000);
        assert_eq!(ue01.rate_ul_bps, Some(2_000_000));
        assert_eq!(ue01.rate_dl_bps, Some(1_000_000));
        assert_eq!(ue01.warnings.len(), 2);
        assert!(ue01
            .warnings
            .contains(&"IPERF3_SERVER_OUTPUT_MISSING".to_string()));
        assert!(ue01.warnings.contains(&"IPERF3_RECEIVER_SHORT".to_string()));
        // Session-level warnings dedupe too.
        assert_eq!(got.warnings.len(), 2);
    }

    #[test]
    fn record_measurement_rejects_ue_not_in_session() {
        let mgr = TrafficSessionManager::new();
        let s = mgr.start(req()).unwrap();
        assert_eq!(
            mgr.record_measurement(&s.session_id, "UE-99", 0, 0, None, None, vec![])
                .unwrap_err(),
            "TRAFFIC_SESSION_UE_NOT_IN_SESSION"
        );
    }

    #[test]
    fn ceiling_constant_matches_lab_lossless_udp_contract() {
        assert_eq!(UDP_LOSSLESS_CEILING_MBPS, 20);
        assert_eq!(RATE_MBPS_MAX, 50);
        assert_eq!(DURATION_S_MAX, 600);
    }

    #[test]
    fn samples_ring_is_created_on_start_and_queryable_empty() {
        let mgr = TrafficSessionManager::new();
        let s = mgr.start(req()).unwrap();
        let got = mgr.samples(&s.session_id).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn samples_evict_oldest_when_cap_reached() {
        let mgr = TrafficSessionManager::new();
        let s = mgr.start(req()).unwrap();
        // Push 1.5× the cap; only the last `SAMPLES_RING_MAX` must remain
        // and the earliest sample must be the (SAMPLES_RING_MAX / 2)-th
        // one we pushed.
        for i in 0..(SAMPLES_RING_MAX + SAMPLES_RING_MAX / 2) as u64 {
            mgr.push_sample(
                &s.session_id,
                TrafficSample {
                    epoch_s: 1_000_000 + i,
                    bytes_ul_cum: i * 1_000,
                    bytes_dl_cum: i * 500,
                    rate_ul_bps: Some(1_000_000),
                    rate_dl_bps: Some(500_000),
                },
            )
            .unwrap();
        }
        let got = mgr.samples(&s.session_id).unwrap();
        assert_eq!(got.len(), SAMPLES_RING_MAX);
        assert_eq!(
            got.first().unwrap().epoch_s,
            1_000_000 + (SAMPLES_RING_MAX / 2) as u64
        );
        assert_eq!(
            got.last().unwrap().epoch_s,
            1_000_000 + (SAMPLES_RING_MAX + SAMPLES_RING_MAX / 2 - 1) as u64
        );
    }

    #[test]
    fn push_sample_rejects_unknown_session_without_panicking() {
        let mgr = TrafficSessionManager::new();
        let err = mgr
            .push_sample(
                "traffic-ffffffffffffffff",
                TrafficSample {
                    epoch_s: 0,
                    bytes_ul_cum: 0,
                    bytes_dl_cum: 0,
                    rate_ul_bps: None,
                    rate_dl_bps: None,
                },
            )
            .unwrap_err();
        assert_eq!(err, "TRAFFIC_SESSION_NOT_FOUND");
    }

    #[test]
    fn complete_transitions_running_to_completed_once() {
        let mgr = TrafficSessionManager::new();
        let s = mgr.start(req()).unwrap();
        mgr.transition_running(&s.session_id).unwrap();
        mgr.complete(&s.session_id).unwrap();
        let got = mgr.get(&s.session_id).unwrap();
        assert_eq!(got.state, SessionState::Completed);
        assert!(got.ended_at_epoch_s.is_some());
        // Idempotent — a second `complete` on an already-COMPLETED session is a no-op.
        mgr.complete(&s.session_id).unwrap();
        assert_eq!(
            mgr.get(&s.session_id).unwrap().state,
            SessionState::Completed
        );
    }

    #[test]
    fn complete_does_not_downgrade_a_stopped_session() {
        let mgr = TrafficSessionManager::new();
        let s = mgr.start(req()).unwrap();
        mgr.stop(&s.session_id).unwrap();
        mgr.complete(&s.session_id).unwrap();
        // STOPPED stays STOPPED — an operator stop beats a natural completion.
        assert_eq!(mgr.get(&s.session_id).unwrap().state, SessionState::Stopped);
    }
}
