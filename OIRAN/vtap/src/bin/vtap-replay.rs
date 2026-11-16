//! `vtap-replay` — rejoue des records TLS en clair (JSONL) en pcap vTAP.
//! Outil hors ligne (recette, debug) : aucune dépendance eBPF ni /proc.
//!
//! Ligne JSONL : `{"ts_ns":…,"local":"ip:port","remote":"ip:port",
//! "op":"ssl_write"|"ssl_read","comm":"open5gs-amfd","data_hex":"…"}`
//!
//! usage: vtap-replay --input FILE.jsonl --output FILE.pcap [--probe-id ID]

use std::io::BufRead;

use polaris_vtap::conn::ConnTuple;
use polaris_vtap::pcap::{global_header, record, FileManifest};
use polaris_vtap::record::SslOp;
use polaris_vtap::synth::{Synthesizer, DEFAULT_SERVER_PORTS};

#[derive(serde::Deserialize)]
struct Line {
    ts_ns: u64,
    local: String,
    remote: String,
    op: String,
    comm: String,
    data_hex: String,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{}", serde_json::json!({"event":"VTAP_REPLAY_FAILED","error":e}));
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let get = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1).cloned())
    };
    let input = get("--input").ok_or("--input is required")?;
    let output = get("--output").ok_or("--output is required")?;
    let probe_id = get("--probe-id").unwrap_or_else(|| "lab-vtap".into());
    let reader = std::io::BufReader::new(std::fs::File::open(&input).map_err(|e| e.to_string())?);
    let mut synth = Synthesizer::new(DEFAULT_SERVER_PORTS);
    let mut bytes = global_header().to_vec();
    for (n, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let l: Line = serde_json::from_str(&line).map_err(|e| format!("line {}: {e}", n + 1))?;
        let op = match l.op.as_str() {
            "ssl_write" => SslOp::Write,
            "ssl_read" => SslOp::Read,
            other => return Err(format!("line {}: unknown op {other}", n + 1)),
        };
        let tuple = ConnTuple {
            local: l.local.parse().map_err(|_| format!("line {}: bad local", n + 1))?,
            remote: l.remote.parse().map_err(|_| format!("line {}: bad remote", n + 1))?,
        };
        let data = hex(&l.data_hex).ok_or(format!("line {}: bad data_hex", n + 1))?;
        for p in synth.push(l.ts_ns, tuple, op, &l.comm, false, &data) {
            bytes.extend_from_slice(&record(&p));
        }
    }
    std::fs::write(&output, &bytes).map_err(|e| e.to_string())?;
    let manifest = FileManifest {
        schema: "polaris.vtap.manifest.v1",
        agent_version: polaris_vtap::VERSION,
        probe_id: &probe_id,
        probe_type: polaris_vtap::PROBE_TYPE,
        interface: polaris_vtap::INTERFACE,
        timestamp_source: "replay",
        pcap: output.clone(),
        counters: &synth.counters,
        connections: synth.manifest(),
        open_items: polaris_vtap::open_items(&synth),
    };
    let json = serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?;
    std::fs::write(format!("{output}.vtap.json"), &json).map_err(|e| e.to_string())?;
    println!("{json}");
    Ok(())
}

fn hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
