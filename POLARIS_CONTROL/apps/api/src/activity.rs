// 0.19.0 (#37) — Per-UE Activity surface.
//
// Scope:
//   * GET /ues/:id/activity              — one-shot snapshot
//   * GET /ues/:id/activity/stream       — SSE, same payload every 2 s
//
// The surface is read-only and intentionally NOT gated by any live
// grant or server flag: an operator (or anyone with session) must be
// able to see what a UE is doing without first obtaining an elevation.
//
// Hard-filter rules enforced by `filter_identity_fields`:
//   * SUCI, GUTI and TMSI tokens are stripped from every stringified
//     payload we touch — the Activity surface MUST NOT echo them.
//   * Authentication key / OPc material is stripped the same way.
//   * IMSI is returned only when the caller is operator or
//     administrator. Viewer sees the solid mask.
//
// UE stopped (no live job, no container) → `{"running": false, …}`
// with a short reason string. We never surface a 5xx from this
// endpoint; a broken Docker exec yields a safe empty payload instead.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use serde_json::{json, Value};

/// Hard cap: the activity ring buffer never grows past this per UE.
pub const MAX_EVENTS_PER_UE: usize = 20;

/// Structured event appended to the per-UE ring. The frontend renders
/// them as the "last 20 events" timeline.
#[derive(Clone, Debug, Serialize)]
pub struct ActivityEvent {
    pub epoch_s: u64,
    pub kind: String,
    pub outcome: String,
    pub detail: Value,
}

impl ActivityEvent {
    pub fn new(kind: impl Into<String>, outcome: impl Into<String>, detail: Value) -> Self {
        Self {
            epoch_s: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|value| value.as_secs())
                .unwrap_or(0),
            kind: kind.into(),
            outcome: outcome.into(),
            detail,
        }
    }
}

/// Per-UE ring of recent events. Lookup is case-sensitive on `ue_id`.
#[derive(Default)]
pub struct ActivityEventStore {
    inner: Mutex<BTreeMap<String, VecDeque<ActivityEvent>>>,
}

impl ActivityEventStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, ue_id: &str, event: ActivityEvent) {
        if ue_id.is_empty() {
            return;
        }
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        let ring = guard.entry(ue_id.to_string()).or_default();
        if ring.len() >= MAX_EVENTS_PER_UE {
            ring.pop_front();
        }
        ring.push_back(event);
    }

    pub fn snapshot(&self, ue_id: &str) -> Vec<ActivityEvent> {
        self.inner
            .lock()
            .ok()
            .and_then(|guard| guard.get(ue_id).map(|ring| ring.iter().cloned().collect()))
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub fn clear(&self, ue_id: &str) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.remove(ue_id);
        }
    }
}

/// 0.19.0 — Scrub a free-form string of identity tokens we must never
/// echo back on the Activity surface. Case-insensitive. The replacement
/// token is the same literal used elsewhere in POLARIS for secrets so
/// a reader cannot distinguish "field removed" from "field never set".
pub fn filter_identity_fields(input: &str) -> String {
    const TOKENS: &[&str] = &[
        "suci", "guti", "5g-guti", "tmsi", "5g-tmsi", "s-tmsi", "ptmsi",
        "key", "opc", "op-c", "op_c", "authentication_key",
    ];
    let mut out = String::with_capacity(input.len());
    for line in input.lines() {
        let lower = line.to_ascii_lowercase();
        let mut skip = false;
        for token in TOKENS {
            // Match "<token>: " or "<token>=" or "<token> =" at any
            // whitespace-separated position. We never want to leak the
            // value, so the whole line is dropped and a redaction note
            // is inserted in its place.
            if lower.contains(&format!("{token}:"))
                || lower.contains(&format!("{token} :"))
                || lower.contains(&format!("{token}="))
                || lower.contains(&format!("{token} ="))
            {
                skip = true;
                out.push_str("[redacted — identity material]\n");
                break;
            }
        }
        if !skip {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// 0.19.0 — Role-aware IMSI projection. Operators see the raw IMSI;
/// viewers see a mask. `None` becomes `None` regardless of role.
pub fn imsi_for_role(imsi: Option<&str>, role: &str) -> Option<String> {
    let value = imsi?.trim();
    if value.is_empty() {
        return None;
    }
    match role {
        "operator" | "administrator" => Some(value.into()),
        _ => Some("•••••••••••••••".into()),
    }
}

/// 0.19.0 — Compose the final payload. `nr_cli_status`, `pdu`,
/// `counters`, `job_step` and `events` are supplied by the caller so
/// this function stays unit-testable without hitting Docker or state.
#[allow(clippy::too_many_arguments)]
pub fn compose_activity_payload(
    ue_id: &str,
    running: bool,
    reason_when_stopped: Option<&str>,
    imsi_projection: Option<String>,
    nr_cli_states: NrCliStates,
    pdu: Option<PduSnapshot>,
    counters: Option<CountersSnapshot>,
    job_step: Option<Value>,
    events: Vec<ActivityEvent>,
) -> Value {
    if !running {
        return json!({
            "ue_id": ue_id,
            "running": false,
            "reason": reason_when_stopped.unwrap_or("UE_NOT_RUNNING"),
            "voice": { "available": false, "reason": "IMS_NOT_AVAILABLE" },
            "events": events,
        });
    }
    json!({
        "ue_id": ue_id,
        "running": true,
        "imsi": imsi_projection,
        "states": {
            "rm_state": nr_cli_states.rm_state,
            "cm_state": nr_cli_states.cm_state,
            "rrc_state": nr_cli_states.rrc_state,
            "mm_5g_state": nr_cli_states.mm_5g_state,
        },
        "pdu": pdu,
        "counters": counters,
        "job_step": job_step,
        "events": events,
        "voice": { "available": false, "reason": "IMS_NOT_AVAILABLE" },
    })
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct NrCliStates {
    pub rm_state: Option<String>,
    pub cm_state: Option<String>,
    pub rrc_state: Option<String>,
    pub mm_5g_state: Option<String>,
}

/// Parse the four state lines out of `nr-cli … -e status` output. The
/// parser is deliberately permissive — unknown lines are ignored —
/// because UERANSIM minor versions reshuffle the key order between
/// releases.
pub fn parse_nr_cli_states(stdout: &str) -> NrCliStates {
    let filtered = filter_identity_fields(stdout);
    let mut states = NrCliStates::default();
    for line in filtered.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key_lc = key.trim().to_ascii_lowercase();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key_lc.as_str() {
            "rm-state" | "rm_state" => states.rm_state = Some(value.into()),
            "cm-state" | "cm_state" => states.cm_state = Some(value.into()),
            "rrc-state" | "rrc_state" => states.rrc_state = Some(value.into()),
            "mm-state" | "5gmm-state" | "mm5g-state" | "5gmm_state" => {
                states.mm_5g_state = Some(value.into())
            }
            _ => {}
        }
    }
    states
}

#[derive(Clone, Debug, Serialize)]
pub struct PduSnapshot {
    pub psi: Option<u32>,
    pub dnn: Option<String>,
    pub state: Option<String>,
    pub address: Option<String>,
}

/// Parse the first PDU session block out of `nr-cli … -e ps-list`.
pub fn parse_ps_list(stdout: &str) -> Option<PduSnapshot> {
    let filtered = filter_identity_fields(stdout);
    let mut psi = None;
    let mut dnn = None;
    let mut state = None;
    let mut address = None;
    let mut inside = false;
    for raw in filtered.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("PDU Session") || line.starts_with("Session") {
            if inside {
                break;
            }
            inside = true;
            if let Some(number) = line.split_whitespace().last() {
                psi = number.trim_end_matches(':').parse::<u32>().ok();
            }
            continue;
        }
        if !inside {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key_lc = key.trim().to_ascii_lowercase();
        let value = value.trim();
        match key_lc.as_str() {
            "apn" | "dnn" => dnn = Some(value.into()),
            "state" => state = Some(value.into()),
            "address" | "ue-address" => address = Some(value.into()),
            _ => {}
        }
    }
    if psi.is_none() && dnn.is_none() && state.is_none() && address.is_none() {
        None
    } else {
        Some(PduSnapshot {
            psi,
            dnn,
            state,
            address,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct CountersSnapshot {
    pub interface: Option<String>,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    /// Bytes-per-second rate computed from the previous sample. `None`
    /// when the caller does not have a prior sample yet.
    pub rx_bps: Option<f64>,
    pub tx_bps: Option<f64>,
}

/// Parse the `/proc/net/dev` snapshot and return the first interface
/// matching `uesimtun[0-9]*`. The interface is where UERANSIM punches
/// the UE-plane traffic; its RX / TX counters are the ground truth for
/// uplink / downlink accounting.
///
/// `/proc/net/dev` columns we care about:
///   name:  rx_bytes  rx_packets  …  tx_bytes  tx_packets  …
pub fn parse_uesimtun_counters(proc_net_dev: &str) -> Option<CountersSnapshot> {
    for raw in proc_net_dev.lines() {
        let line = raw.trim();
        if !line.starts_with("uesimtun") {
            continue;
        }
        let Some((head, tail)) = line.split_once(':') else {
            continue;
        };
        let name = head.trim();
        let numbers: Vec<&str> = tail.split_whitespace().collect();
        if numbers.len() < 16 {
            continue;
        }
        let parse = |index: usize| numbers.get(index).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        return Some(CountersSnapshot {
            interface: Some(name.into()),
            rx_bytes: parse(0),
            rx_packets: parse(1),
            tx_bytes: parse(8),
            tx_packets: parse(9),
            rx_bps: None,
            tx_bps: None,
        });
    }
    None
}

/// Apply bps rates against a previous sample. The samples must be
/// taken at least 50 ms apart; otherwise the rate stays `None` to
/// avoid an arithmetic spike on the frontend sparkline.
pub fn attach_rates(
    current: &mut CountersSnapshot,
    previous: Option<&CountersSnapshot>,
    elapsed_ms: u128,
) {
    let Some(prev) = previous else {
        return;
    };
    if elapsed_ms < 50 {
        return;
    }
    let elapsed_s = (elapsed_ms as f64) / 1_000.0;
    current.rx_bps = Some((current.rx_bytes.saturating_sub(prev.rx_bytes) as f64) / elapsed_s);
    current.tx_bps = Some((current.tx_bytes.saturating_sub(prev.tx_bytes) as f64) / elapsed_s);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_filter_scrubs_suci_guti_tmsi_and_keys() {
        let raw = "\
rm-state: RM-REGISTERED\n\
suci: 0-999-01-0-0-0-0000000042\n\
5G-GUTI: {plmn: 00101, tmsi: 00:00:00:42}\n\
mm-state: MM-REGISTERED\n\
authentication_key: ff00112233445566778899aabbccddee\n\
opc = eeddccbbaa998877665544332211ff00\n\
rrc-state: RRC-CONNECTED\n\
";
        let filtered = filter_identity_fields(raw);
        for banned in &[
            "999-01-0-0-0-0000000042",
            "ff00112233445566778899aabbccddee",
            "eeddccbbaa998877665544332211ff00",
            "tmsi: 00:00:00:42",
        ] {
            assert!(
                !filtered.contains(banned),
                "filtered output must not contain {banned}: {filtered}",
            );
        }
        assert!(filtered.contains("RM-REGISTERED"));
        assert!(filtered.contains("MM-REGISTERED"));
        assert!(filtered.contains("RRC-CONNECTED"));
        assert!(filtered.contains("[redacted — identity material]"));
    }

    #[test]
    fn imsi_projection_mask_viewer_but_reveal_operator() {
        assert_eq!(
            imsi_for_role(Some("imsi-001010000000042"), "operator").as_deref(),
            Some("imsi-001010000000042"),
        );
        assert_eq!(
            imsi_for_role(Some("imsi-001010000000042"), "administrator").as_deref(),
            Some("imsi-001010000000042"),
        );
        let masked = imsi_for_role(Some("imsi-001010000000042"), "viewer").unwrap();
        assert!(masked.chars().all(|c| c == '•'));
        assert_eq!(masked.chars().count(), 15);
        assert_eq!(imsi_for_role(None, "operator"), None);
        assert_eq!(imsi_for_role(Some("   "), "operator"), None);
    }

    #[test]
    fn parse_states_reads_rm_cm_rrc_and_mm5g() {
        let stdout = "\
cm-state: CM-CONNECTED\n\
rm-state: RM-REGISTERED\n\
mm-state: MM-REGISTERED-NORMAL-SERVICE\n\
rrc-state: RRC-CONNECTED\n\
sim-inserted: true\n\
";
        let states = parse_nr_cli_states(stdout);
        assert_eq!(states.rm_state.as_deref(), Some("RM-REGISTERED"));
        assert_eq!(states.cm_state.as_deref(), Some("CM-CONNECTED"));
        assert_eq!(states.rrc_state.as_deref(), Some("RRC-CONNECTED"));
        assert_eq!(
            states.mm_5g_state.as_deref(),
            Some("MM-REGISTERED-NORMAL-SERVICE"),
        );
    }

    #[test]
    fn parse_ps_list_returns_first_pdu_block() {
        let stdout = "\
PDU Session 1:\n\
  state: PS-ACTIVE\n\
  apn: internet\n\
  address: 10.46.0.5\n\
  qos-flows: [1]\n\
";
        let pdu = parse_ps_list(stdout).expect("pdu block");
        assert_eq!(pdu.psi, Some(1));
        assert_eq!(pdu.dnn.as_deref(), Some("internet"));
        assert_eq!(pdu.state.as_deref(), Some("PS-ACTIVE"));
        assert_eq!(pdu.address.as_deref(), Some("10.46.0.5"));
    }

    #[test]
    fn parse_counters_pulls_uesimtun_lines_only() {
        let proc_net_dev = "\
Inter-|   Receive                                                |  Transmit\n\
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
    lo: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n\
uesimtun0: 123456 42 0 0 0 0 0 0 654321 55 0 0 0 0 0 0\n\
eth0: 9999 9 0 0 0 0 0 0 8888 8 0 0 0 0 0 0\n\
";
        let counters = parse_uesimtun_counters(proc_net_dev).expect("uesimtun counters");
        assert_eq!(counters.interface.as_deref(), Some("uesimtun0"));
        assert_eq!(counters.rx_bytes, 123_456);
        assert_eq!(counters.rx_packets, 42);
        assert_eq!(counters.tx_bytes, 654_321);
        assert_eq!(counters.tx_packets, 55);
    }

    #[test]
    fn attach_rates_computes_bps_from_a_two_second_window() {
        let previous = CountersSnapshot {
            interface: Some("uesimtun0".into()),
            rx_bytes: 1_000,
            rx_packets: 10,
            tx_bytes: 2_000,
            tx_packets: 20,
            rx_bps: None,
            tx_bps: None,
        };
        let mut current = CountersSnapshot {
            interface: Some("uesimtun0".into()),
            rx_bytes: 3_000,
            rx_packets: 15,
            tx_bytes: 6_000,
            tx_packets: 30,
            rx_bps: None,
            tx_bps: None,
        };
        attach_rates(&mut current, Some(&previous), 2_000);
        assert_eq!(current.rx_bps, Some(1_000.0));
        assert_eq!(current.tx_bps, Some(2_000.0));
    }

    #[test]
    fn compose_running_false_returns_safe_payload_with_voice_block() {
        let payload = compose_activity_payload(
            "UE-01",
            false,
            Some("UE_NOT_PROVISIONED"),
            None,
            NrCliStates::default(),
            None,
            None,
            None,
            vec![],
        );
        assert_eq!(payload["running"], Value::Bool(false));
        assert_eq!(payload["ue_id"], Value::String("UE-01".into()));
        assert_eq!(payload["reason"], Value::String("UE_NOT_PROVISIONED".into()));
        assert_eq!(payload["voice"]["available"], Value::Bool(false));
        assert_eq!(
            payload["voice"]["reason"],
            Value::String("IMS_NOT_AVAILABLE".into()),
        );
    }

    #[test]
    fn event_store_rings_at_twenty_items_per_ue() {
        let store = ActivityEventStore::new();
        for index in 0..30 {
            store.record(
                "UE-01",
                ActivityEvent::new(
                    format!("step-{index}"),
                    "OK",
                    json!({ "index": index }),
                ),
            );
        }
        let kept = store.snapshot("UE-01");
        assert_eq!(kept.len(), MAX_EVENTS_PER_UE);
        // Oldest 10 must have been evicted; last entry is step-29.
        assert_eq!(kept.first().unwrap().kind, "step-10");
        assert_eq!(kept.last().unwrap().kind, "step-29");
    }

    #[test]
    fn event_store_ignores_empty_ue_id() {
        let store = ActivityEventStore::new();
        store.record("", ActivityEvent::new("noop", "OK", json!({})));
        assert!(store.snapshot("").is_empty());
    }
}
