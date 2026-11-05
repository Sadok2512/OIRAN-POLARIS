//! 2.7.23 publication-RSS harness.
//!
//! Builds a continuous-import `<base>/` with a pre-populated
//! `dataset/oiran_events.jsonl` containing `--history` events, then
//! calls `process_continuous_capture` with one new N3 pcap so the
//! merge and per-session callflow generation runs. Reads
//! `/proc/self/status` before, after each phase, and after drop.

use live_probe::{interface_specs, CaptureManager, CONTINUOUS_CAPTURE_ID};
use std::{env, fs, io::Write, path::PathBuf};

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
    let history_size: usize = env::args()
        .nth(1)
        .expect("usage: rss_publication <history-size>")
        .parse()
        .expect("history-size integer");
    let root = env::temp_dir().join(format!(
        "oiran-rss-publication-{}-{}",
        history_size,
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let base = root.join(CONTINUOUS_CAPTURE_ID);
    fs::create_dir_all(base.join("pcap")).unwrap();
    fs::create_dir_all(base.join("dataset/callflows")).unwrap();

    let history_path = base.join("dataset/oiran_events.jsonl");
    {
        let mut writer =
            std::io::BufWriter::with_capacity(1 << 20, fs::File::create(&history_path).unwrap());
        for i in 0..history_size {
            let session = (i / 500) + 1;
            let ts_ns = 1_792_872_462_000_000_000u64 + (i as u64) * 1000;
            let ts_s = ts_ns / 1_000_000_000;
            let ns = ts_ns % 1_000_000_000;
            let iface = match i % 3 {
                0 => "N2",
                1 => "N3",
                _ => "N4",
            };
            let proto = match iface {
                "N2" => "NGAP",
                "N3" => "GTP-U",
                _ => "PFCP",
            };
            let event = serde_json::json!({
                "event_id": format!("evt-stub-{i:08}"),
                "capture_id": format!("sha256:stub-{session:04}"),
                "capture_point_id": iface,
                "interface": iface,
                "protocol": proto,
                "message_name": "SyntheticMessage",
                "message_type": 0,
                "procedure_code": 0,
                "source_endpoint": {"address": "10.0.0.1", "network_function": "gNB"},
                "destination_endpoint": {"address": "10.0.0.2", "network_function": "AMF"},
                "direction": "RAN_TO_CORE",
                "session_identifiers": [
                    {"name": "ran_ue_ngap_id", "value": session.to_string(), "pseudonymized": false},
                    {"name": "amf_ue_ngap_id", "value": session.to_string(), "pseudonymized": false},
                    {"name": "pdu_session_id", "value": "1", "pseudonymized": false},
                ],
                "information_elements": [
                    {"id": 85, "name": "RAN-UE-NGAP-ID",
                     "value": format!("ran_ue_ngap_id={session}"),
                     "raw_sha256": "c".repeat(64), "status": "DECODED"},
                    {"id": 38, "name": "NAS-PDU",
                     "value": "nas_protected=true,pseudonym=psn-".to_string() + &"a".repeat(16),
                     "raw_sha256": "d".repeat(64), "status": "ENCRYPTED_OR_PROTECTED"},
                ],
                "decoder_name": "stub",
                "decoder_version": "0",
                "schema_version": "1.2.0",
                "decoding_status": "DECODED",
                "errors": [],
                "raw_payload_reference": "sha256:".to_string() + &"b".repeat(64),
                "evidence_references": [],
                "packet_references": [{
                    "source_file": format!("/captures/history/{iface}.pcapng"),
                    "packet_number": (i + 1) as u64,
                    "byte_offset": 0,
                    "interface_id": 0,
                    "captured_length": 100,
                    "original_length": 100,
                }],
                "timestamp": {
                    "seconds": ts_s,
                    "nanoseconds": ns,
                    "raw_ticks": ts_ns,
                    "resolution_base": 10,
                    "resolution_exponent": 9,
                    "display": format!("{ts_s}.{ns:09}Z"),
                }
            });
            writeln!(writer, "{}", event).unwrap();
        }
        writer.flush().unwrap();
    }
    let manifest = serde_json::json!({
        "dataset_id": "dataset-continuous-lab-import",
        "capture_id": "continuous-lab-import",
        "path": "runtime/live-captures/continuous-lab-import/dataset",
        "event_count": history_size,
        "session_ids": [],
        "decode_reports": {},
        "checksums": {},
        "state": "COMPLETED",
        "discovery": null,
        "capture_started_epoch_ms": null,
        "last_packet_epoch_ms": null,
        "fresh_packet_count": 0,
        "active_ue_ips": [],
        "active_pdu_contexts": [],
    });
    fs::write(
        base.join("dataset/dataset_manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
    fs::copy(fixture.join("N3.pcapng"), base.join("pcap/N3.pcapng")).unwrap();

    report("baseline");

    let manager = CaptureManager::with_pseudonym_key_path(
        root.clone(),
        false,
        root.join(".oiran-pseudonym.key"),
    )
    .unwrap();
    report("after-manager");

    // Drive process_capture_into directly (into a scratch "next"
    // directory). This bypasses the production
    // `MAX_CONTINUOUS_DERIVED_BYTES` ceiling (64 MiB) which is sized
    // for the ring and does not accommodate 30k / 100k pre-built
    // histories; the memory invariant we are measuring here is the
    // same regardless.
    let next_dir = base.join(".dataset-next");
    let _ = fs::remove_dir_all(&next_dir);
    let dataset = manager
        .process_capture_into(
            CONTINUOUS_CAPTURE_ID,
            "dataset-continuous-lab-import".into(),
            &base.join("pcap"),
            &next_dir,
            format!("runtime/live-captures/{CONTINUOUS_CAPTURE_ID}/dataset"),
            &interface_specs(),
        )
        .unwrap();
    report("after-process_capture_into");

    println!(
        "summary history_size={history_size} final_events={} sessions={}",
        dataset.event_count,
        dataset.session_ids.len()
    );

    drop(dataset);
    drop(manager);
    report("after-drop");

    let _ = fs::remove_dir_all(&root);
}
