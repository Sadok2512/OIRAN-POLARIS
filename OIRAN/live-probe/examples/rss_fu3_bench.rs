//! 2.9.18-fu3 RSS bench — reproduit la reconstruction continue à
//! l'échelle ANR2 (production) sous un budget mémoire de 256 MiB.
//!
//! ## Utilisation
//!
//! ```bash
//! # Build en debug (production = release ; debug suffit pour le
//! # bench mémoire, l'allocateur est le même).
//! cargo build -p live-probe --example rss_fu3_bench --release
//!
//! # Sous cgroup 256 MiB — échoue en SIGKILL/OOM si on dépasse.
//! systemd-run --user --scope -p MemoryMax=256M \
//!     ./target/release/examples/rss_fu3_bench 500000 1300
//!
//! # Fallback sans systemd — ulimit -Sv exprime une borne vsize
//! # (kiB) qui déclenche ENOMEM et non pas SIGKILL, et donc produit
//! # un rapport lisible dans la sortie stderr.
//! ( ulimit -Sv 262144 ; ./target/release/examples/rss_fu3_bench 500000 1300 ) 2>&1
//! ```
//!
//! Le binaire imprime `stage=... vmrss_kb=... vmhwm_kb=...` à
//! chaque phase (baseline, prior-written, pcapng-written,
//! after-process_capture_into, after-drop). Le `vmhwm_kb` final
//! est la haute-eau mémoire du processus.

use live_probe::{interface_specs, CaptureManager, CONTINUOUS_CAPTURE_ID};
use std::{env, fs, io::Write};

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
    eprintln!(
        "FU3_RSS stage={stage} vmrss_kb={} vmhwm_kb={} vmpeak_kb={}",
        read_status("VmRSS"),
        read_status("VmHWM"),
        read_status("VmPeak"),
    );
}

fn main() {
    let mut args = env::args().skip(1);
    let history_size: usize = args
        .next()
        .expect("usage: rss_fu3_bench <history-events> <ring-segments>")
        .parse()
        .expect("history-events integer");
    let ring_segments: usize = args
        .next()
        .expect("usage: rss_fu3_bench <history-events> <ring-segments>")
        .parse()
        .expect("ring-segments integer");

    let root = env::temp_dir().join(format!(
        "oiran-fu3-bench-{}-{}-{}",
        history_size,
        ring_segments,
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let base = root.join(CONTINUOUS_CAPTURE_ID);
    fs::create_dir_all(base.join("pcap")).unwrap();
    fs::create_dir_all(base.join("dataset/callflows")).unwrap();

    report("baseline");

    // 1. Prior dataset : history_size events avec capture_ids
    // répartis sur ring_segments.
    let history_path = base.join("dataset/oiran_events.jsonl");
    {
        let mut writer =
            std::io::BufWriter::with_capacity(1 << 20, fs::File::create(&history_path).unwrap());
        for i in 0..history_size {
            let segment = i % ring_segments;
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
            // event_id en format "evt-<16hex>" — stress-test du
            // path hot SpillingEventIdSet (parse u64 direct).
            let event_id = format!("evt-{:016x}", i as u64 ^ 0x1234_5678_9abc_def0);
            let event = serde_json::json!({
                "event_id": event_id,
                "capture_id": format!("sha256:{:064x}", segment as u128),
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
                ],
                "decoder_name": "stub",
                "decoder_version": "0",
                "schema_version": "1.2.0",
                "decoding_status": "DECODED",
                "errors": [],
                "raw_payload_reference": format!("sha256:{:064x}", (i as u128) + 1),
                "evidence_references": [],
                "packet_references": [{
                    "source_file": format!("/captures/history/{iface}-{segment:04}.pcapng"),
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
    report("prior-written");

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

    // 2. Ring pcapng : `ring_segments` fichiers pcapng synthétiques
    // vides (SHB + IDB, aucun EPB) → le décodeur produit 0 event par
    // fichier, ce qui laisse le chemin merge-prior comme unique
    // source de pression mémoire (c'est exactement le scénario
    // ANR2 : la reconstruction PART du dataset prior déjà volumineux).
    let empty_pcapng: [u8; 52] = [
        // SHB (Section Header Block)
        0x0a, 0x0d, 0x0d, 0x0a, // block type
        0x1c, 0x00, 0x00, 0x00, // block total length = 28
        0x4d, 0x3c, 0x2b, 0x1a, // byte-order magic
        0x01, 0x00, 0x00, 0x00, // version major/minor
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // section length (unknown)
        0x1c, 0x00, 0x00, 0x00, // block total length
        // IDB (Interface Description Block)
        0x01, 0x00, 0x00, 0x00, // block type
        0x18, 0x00, 0x00, 0x00, // block total length = 24
        0xe4, 0x00, 0x00, 0x00, // link type SCTP (228) — accepté par le loader OIRAN
        0x00, 0x00, 0x00, 0x00, // reserved
        0xff, 0xff, 0x00, 0x00, // snaplen
        0x18, 0x00, 0x00, 0x00, // block total length
    ];
    for iface in ["N2", "N3", "N4"] {
        for s in 0..(ring_segments / 3).max(1) {
            let path = base.join(format!("pcap/{iface}.pcapng-{s:04}"));
            fs::write(&path, empty_pcapng).unwrap();
        }
    }
    report("pcapng-written");

    // 3. Bench proprement dit : `process_capture_into` fusionne
    // prior + spool (vide) vers `.dataset-next/`. C'est le chemin
    // qui OOM-ait sous pre-fu3.
    let manager = CaptureManager::with_pseudonym_key_path(
        root.clone(),
        false,
        root.join(".oiran-pseudonym.key"),
    )
    .unwrap();
    report("after-manager");

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
        .expect("process_capture_into must succeed under 256 MiB cgroup (ANR2 #9 comment 6750859966)");
    report("after-process_capture_into");

    eprintln!(
        "FU3_RSS summary history_events={history_size} ring_segments={ring_segments} final_events={} sessions={}",
        dataset.event_count,
        dataset.session_ids.len()
    );

    drop(dataset);
    drop(manager);
    report("after-drop");

    let _ = fs::remove_dir_all(&root);
    let hwm_kb = read_status("VmHWM");
    let hwm_mib = hwm_kb as f64 / 1024.0;
    eprintln!(
        "FU3_RSS verdict vmhwm_mib={hwm_mib:.1} cap_mib=200.0 pass={}",
        if hwm_mib < 200.0 { "YES" } else { "NO" }
    );
    if hwm_mib >= 200.0 {
        std::process::exit(2);
    }
}
