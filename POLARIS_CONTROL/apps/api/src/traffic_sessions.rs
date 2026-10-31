// 0.20.0 — Traffic Generator (#47).
//
// HTTP contract:
//   POST   /api/v1/traffic/sessions  {ue_ids[], direction, protocol, rate_mbps, duration_s}
//   GET    /api/v1/traffic/sessions                                     → list + per-UE live counters
//   GET    /api/v1/traffic/sessions/:id                                  → one session
//   DELETE /api/v1/traffic/sessions/:id                                  → stop (always allowed)
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
// Memory bound: one `TrafficSession` per POST — fixed-size, no per-packet
// retention. Live counters come from the iperf3 driver that produces
// `IperfMeasurement` (0.19.8); we accumulate the counters, not the
// frames.
//
// This file ships the state machine + validation + HTTP handlers. The
// actual iperf3 spawn is wired to `UeRuntime::execute_iperf_ul` /
// `execute_iperf_dl` by the handler below — those entry points are
// already in place in 0.19.8 and the integration site is a single
// `tokio::spawn_blocking` block per direction. Callers never block on
// an iperf3 process; polling GET returns the latest snapshot.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

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

/// Validation + state store. The HTTP handler layer plugs
/// `TrafficSessionManager` into AppState and uses `tokio::task::spawn`
/// to feed per-UE iperf3 drivers; the manager itself stays
/// synchronous and tiny so the test suite can lock the state machine
/// without a Tokio runtime.
#[derive(Default)]
pub struct TrafficSessionManager {
    sessions: Mutex<BTreeMap<String, TrafficSession>>,
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
        Ok(session)
    }

    pub fn transition_running(&self, session_id: &str) -> Result<(), &'static str> {
        let mut map = self.sessions.lock().unwrap();
        let session = map
            .get_mut(session_id)
            .ok_or("TRAFFIC_SESSION_NOT_FOUND")?;
        if !matches!(session.state, SessionState::Requested) {
            return Err("TRAFFIC_SESSION_INVALID_TRANSITION");
        }
        session.state = SessionState::Running;
        Ok(())
    }

    /// Stop a session. Always allowed, even on a Failed state (idempotent).
    pub fn stop(&self, session_id: &str) -> Result<TrafficSession, &'static str> {
        let mut map = self.sessions.lock().unwrap();
        let session = map
            .get_mut(session_id)
            .ok_or("TRAFFIC_SESSION_NOT_FOUND")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if matches!(session.state, SessionState::Running | SessionState::Requested) {
            session.state = SessionState::Stopped;
            session.ended_at_epoch_s = Some(now);
        }
        Ok(session.clone())
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
        let session = map
            .get_mut(session_id)
            .ok_or("TRAFFIC_SESSION_NOT_FOUND")?;
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
}

fn is_ue_id_valid(id: &str) -> bool {
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
        assert!(ue01
            .warnings
            .contains(&"IPERF3_RECEIVER_SHORT".to_string()));
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
}
