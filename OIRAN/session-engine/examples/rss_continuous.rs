//! Standalone harness: measure VmRSS/VmPeak of a process that
//!   (1) holds a synthetic 25 537-event / 8-session continuous dataset
//!       loaded via `session_engine::load_path`;
//!   (2) runs `discover_sessions` on it (the same call `process_capture_into`
//!       makes on the import thread at `live-probe/src/lib.rs:2704`).
//!
//! Build: inside OIRAN/apps/api/ run
//!     cargo run --release --example rss-continuous -- <events.jsonl>
//! or compile this file as a stand-alone bin with session-engine added as
//! a dep (see `02-generate-synthetic-events.py` for the fixture builder).
//!
//! Output (one line, parseable):
//!     stage=<name> vmrss_kb=<n> vmpeak_kb=<n>

use session_engine::{discover_sessions, load_path};
use std::{env, fs, path::PathBuf};

fn read_status(key: &str) -> u64 {
    let s = fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{key}:")) {
            let n = rest.trim().split_whitespace().next().unwrap_or("0");
            return n.parse().unwrap_or(0);
        }
    }
    0
}

fn report(stage: &str) {
    println!(
        "stage={stage} vmrss_kb={} vmpeak_kb={}",
        read_status("VmRSS"),
        read_status("VmPeak"),
    );
}

fn main() {
    let path = PathBuf::from(
        env::args()
            .nth(1)
            .expect("usage: rss-continuous <events.jsonl>"),
    );
    report("baseline");
    let mut events = load_path(&path).expect("load_path");
    report("after-load-path");
    let discovery = discover_sessions(&mut events);
    report("after-discover-sessions");
    println!(
        "summary events={} ue_contexts={} pdu_sessions={} pfcp={} gtpu={}",
        events.len(),
        discovery.ue_contexts.len(),
        discovery.pdu_sessions.len(),
        discovery.pfcp_sessions.len(),
        discovery.gtpu_tunnels.len(),
    );
    drop(events);
    drop(discovery);
    report("after-drop");
}
