//! 2.7.27 integration test for the `dataset-restore` binary:
//! idempotent reinjection of archived events, no event_id lost,
//! canonical order preserved.

use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    process::Command,
};

fn target_bin() -> PathBuf {
    let candidates = [
        "OIRAN/target/release/dataset-restore",
        "target/release/dataset-restore",
        "../target/release/dataset-restore",
    ];
    for candidate in candidates {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return path;
        }
    }
    panic!("dataset-restore binary not found; run `cargo build --release -p live-probe --bin dataset-restore` first");
}

fn jsonl_line(event_id: &str, capture_id: &str, packet_number: u64) -> String {
    serde_json::json!({
        "event_id": event_id,
        "capture_id": capture_id,
        "timestamp": {"seconds": packet_number, "nanoseconds": 0, "raw_ticks": packet_number * 1_000_000_000, "display": ""},
        "packet_references": [{"source_file": "x", "packet_number": packet_number, "byte_offset": 0, "interface_id": 0, "captured_length": 1, "original_length": 1}],
    })
    .to_string()
}

fn write_jsonl(path: &Path, lines: &[String]) {
    let mut writer = BufWriter::new(fs::File::create(path).unwrap());
    for line in lines {
        writer.write_all(line.as_bytes()).unwrap();
        writer.write_all(b"\n").unwrap();
    }
    writer.flush().unwrap();
}

fn read_event_ids(path: &Path) -> BTreeSet<String> {
    BufReader::new(fs::File::open(path).unwrap())
        .lines()
        .filter_map(Result::ok)
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let v: serde_json::Value = serde_json::from_str(&line).unwrap();
            v["event_id"].as_str().unwrap().to_string()
        })
        .collect()
}

fn sha256_of(path: &Path) -> String {
    // Shell out to avoid pulling event_schema into the integration test.
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .expect("sha256sum available");
    let line = String::from_utf8_lossy(&output.stdout).into_owned();
    line.split_whitespace().next().unwrap_or("").to_string()
}

#[test]
fn dataset_restore_reinjects_archived_events_idempotently() {
    let base = std::env::temp_dir().join(format!("oiran-dataset-restore-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let dataset_dir = base.join("dataset");
    let archive_segment = base.join("archive/seg-001");
    fs::create_dir_all(&dataset_dir).unwrap();
    fs::create_dir_all(&archive_segment).unwrap();
    // Current hot view: 3 events of a fresh capture.
    let hot_events = dataset_dir.join("oiran_events.jsonl");
    write_jsonl(
        &hot_events,
        &[
            jsonl_line("evt-fresh-1", "sha256:fresh", 10_001),
            jsonl_line("evt-fresh-2", "sha256:fresh", 10_002),
            jsonl_line("evt-fresh-3", "sha256:fresh", 10_003),
        ],
    );
    // Archive segment: 2 717 "stale" events under a single capture.
    // These are the events ANR2 observed lost when per-event
    // retention ran on the 7-day window.
    let archive_events = archive_segment.join("events.jsonl");
    let archived_lines: Vec<String> = (0..2_717)
        .map(|i| jsonl_line(&format!("evt-stale-{i:04}"), "sha256:stale", 1_000 + i as u64))
        .collect();
    write_jsonl(&archive_events, &archived_lines);
    let archive_sha = sha256_of(&archive_events);
    // Minimal manifest with the computed sha so the restore validates it.
    fs::write(
        archive_segment.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "archive_id": "seg-001",
            "created_epoch_s": 1_792_872_462u64,
            "cutoff_epoch_s": 5_000u64,
            "retention_days": 7u64,
            "captures": ["sha256:stale"],
            "event_count": 2_717,
            "events_sha256": archive_sha,
            "schema_version": "2.7.27",
        }))
        .unwrap(),
    )
    .unwrap();
    // First restore.
    let status = Command::new(target_bin())
        .arg(&dataset_dir)
        .arg(&archive_segment)
        .status()
        .expect("spawn dataset-restore");
    assert!(status.success(), "first restore must succeed");
    let after_first = read_event_ids(&hot_events);
    let total_expected = 3 + 2_717;
    assert_eq!(
        after_first.len(),
        total_expected,
        "every event_id must be in the hot view after restore"
    );
    for i in 0..2_717 {
        assert!(after_first.contains(&format!("evt-stale-{i:04}")));
    }
    for i in 1..=3 {
        assert!(after_first.contains(&format!("evt-fresh-{i}")));
    }
    let sha_after_first = sha256_of(&hot_events);
    // Second restore on the same inputs: output byte-identical
    // (idempotency).
    let status = Command::new(target_bin())
        .arg(&dataset_dir)
        .arg(&archive_segment)
        .status()
        .expect("spawn dataset-restore");
    assert!(status.success(), "second restore must succeed");
    let sha_after_second = sha256_of(&hot_events);
    assert_eq!(
        sha_after_first, sha_after_second,
        "dataset-restore is idempotent: same inputs → same SHA-256"
    );
    // Canonical order: output sorted by (capture_id, packet_number, event_id).
    let on_disk_order: Vec<String> = BufReader::new(fs::File::open(&hot_events).unwrap())
        .lines()
        .filter_map(Result::ok)
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let v: serde_json::Value = serde_json::from_str(&line).unwrap();
            format!(
                "{}|{}|{}",
                v["capture_id"].as_str().unwrap(),
                v["packet_references"][0]["packet_number"].as_u64().unwrap(),
                v["event_id"].as_str().unwrap(),
            )
        })
        .collect();
    let mut sorted = on_disk_order.clone();
    sorted.sort();
    assert_eq!(
        on_disk_order, sorted,
        "restore output must be in canonical (capture_id, packet_number, event_id) order"
    );
    fs::remove_dir_all(&base).unwrap();
}
