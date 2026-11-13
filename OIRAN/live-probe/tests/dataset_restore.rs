//! 2.7.28 integration test for `dataset-restore`:
//! restore routes through the full publication path — manifest,
//! callflows and session registry are coherent with the restored
//! events.jsonl after the call, and a second run on the same inputs
//! leaves every artifact byte-identical (idempotency).

use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    process::Command,
};

/// 2.14.6 (ANR1 #10) : le test construit lui-même le binaire release
/// `dataset-restore` au lieu d'exiger qu'un `cargo build --release`
/// préalable ait eu lieu. Cargo sérialise les accès au `target/` via son
/// propre fichier de verrou, donc une exécution parallèle d'autres
/// `cargo test` dans le même workspace reste sûre.
///
/// L'ancien comportement (trois candidats fixes + `panic!("…binary not
/// found; run cargo build…")`) rendait le test environnementalement
/// dépendant : qui lançait `cargo test` sans avoir fait un build release
/// préalable voyait un `FAILED` opaque dans le résumé. « Un garde qui se
/// saute ne garde rien » (ANR1).
fn target_bin() -> PathBuf {
    // Fast path : le binaire peut déjà être présent (release build préalable
    // manuel pour le pipeline 2.14.x ; re-utilisation du cache cargo entre
    // runs). Évite de payer le coût d'un cargo-build à chaque invocation.
    let fast_candidates = [
        "OIRAN/target/release/dataset-restore",
        "target/release/dataset-restore",
        "../target/release/dataset-restore",
    ];
    for candidate in fast_candidates {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return path;
        }
    }

    // Chemin lent : construire le binaire via la CLI cargo courante. Cargo
    // positionne `CARGO` sur son propre chemin pendant `cargo test`, donc on
    // réutilise la même toolchain que le runner. `--locked` interdit toute
    // modification du Cargo.lock (règle projet).
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let build = Command::new(&cargo)
        .args([
            "build",
            "--release",
            "--locked",
            "-p",
            "live-probe",
            "--bin",
            "dataset-restore",
        ])
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "failed to spawn `{cargo} build --release --locked -p live-probe --bin dataset-restore`: {error}"
            )
        });
    if !build.status.success() {
        panic!(
            "cargo build --release -p live-probe --bin dataset-restore failed (status={:?}); stderr:\n{}",
            build.status.code(),
            String::from_utf8_lossy(&build.stderr)
        );
    }

    // Re-chercher après build. Le `target/` est positionné par cargo via
    // `CARGO_TARGET_DIR` (quand défini) ou à défaut `<workspace>/target`.
    for candidate in fast_candidates {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return path;
        }
    }
    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        let path = PathBuf::from(target_dir).join("release").join("dataset-restore");
        if path.is_file() {
            return path;
        }
    }
    panic!(
        "dataset-restore binary not found after `cargo build --release --locked -p live-probe --bin dataset-restore` succeeded; searched {fast_candidates:?} and $CARGO_TARGET_DIR/release/"
    );
}

fn jsonl_line(event_id: &str, capture_id: &str, packet_number: u64) -> String {
    serde_json::json!({
        "event_id": event_id,
        "capture_id": capture_id,
        "capture_point_id": "N2",
        "timestamp": {
            "seconds": packet_number,
            "nanoseconds": 0,
            "raw_ticks": packet_number as i128 * 1_000_000_000i128,
            "display": "",
        },
        "interface": "N2",
        "protocol": "NGAP",
        "message_name": "InitialUEMessage",
        "source_endpoint": {"address": "10.0.0.1", "network_function": "gNB"},
        "destination_endpoint": {"address": "10.0.0.2", "network_function": "AMF"},
        "direction": "RAN_TO_CORE",
        "session_identifiers": [],
        "information_elements": [],
        "decoding_status": "DECODED",
        "decoder_name": "test",
        "decoder_version": "1",
        "raw_payload_reference": "sha256:test",
        "packet_references": [{
            "source_file": "x",
            "packet_number": packet_number,
            "byte_offset": 0,
            "interface_id": 0,
            "captured_length": 1,
            "original_length": 1,
        }],
        "errors": [],
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
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .expect("sha256sum available");
    let line = String::from_utf8_lossy(&output.stdout).into_owned();
    line.split_whitespace().next().unwrap_or("").to_string()
}

#[test]
fn dataset_restore_reinjects_archived_events_idempotently() {
    let base = std::env::temp_dir().join(format!(
        "oiran-dataset-restore-2.7.28-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let capture_root = base.join("captures");
    fs::create_dir_all(&capture_root).unwrap();
    // Pseudonym key under the test tree so CaptureManager::new() does
    // not touch /var/lib/oiran. On the first restore, PseudonymKey::
    // load_or_generate creates a fresh 32-byte key with mode 0o600;
    // the second restore reads it back — this is the same persistence
    // production uses to keep event_ids stable across restarts.
    let key_path = base.join("pseudonym.key");
    let continuous = capture_root.join("continuous-lab-import");
    let dataset_dir = continuous.join("dataset");
    let callflows_dir = dataset_dir.join("callflows");
    let archive_segment = continuous.join("archive/seg-001");
    fs::create_dir_all(&callflows_dir).unwrap();
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
    // First restore via the binary — goes through CaptureManager →
    // publish_events_to_dataset_dir (full session + manifest rebuild).
    let status = Command::new(target_bin())
        .arg(&capture_root)
        .arg(&archive_segment)
        .env("OIRAN_PSEUDONYM_KEY_PATH", &key_path)
        .status()
        .expect("spawn dataset-restore");
    assert!(status.success(), "first restore must succeed");
    let manifest_path = dataset_dir.join("dataset_manifest.json");
    assert!(
        manifest_path.is_file(),
        "restore must leave dataset_manifest.json next to events.jsonl"
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let on_disk_count = read_event_ids(&hot_events).len();
    let manifest_count = manifest["event_count"].as_u64().unwrap() as usize;
    assert_eq!(
        on_disk_count, manifest_count,
        "manifest event_count must match the on-disk JSONL — this is the 2.7.27 defect regression guard"
    );
    let after_first = read_event_ids(&hot_events);
    let total_expected = 3 + 2_717;
    assert_eq!(after_first.len(), total_expected);
    for i in 0..2_717 {
        assert!(after_first.contains(&format!("evt-stale-{i:04}")));
    }
    for i in 1..=3 {
        assert!(after_first.contains(&format!("evt-fresh-{i}")));
    }
    let sha_events_after_first = sha256_of(&hot_events);
    let sha_manifest_after_first = sha256_of(&manifest_path);
    // Second restore: every output artifact byte-identical.
    let status = Command::new(target_bin())
        .arg(&capture_root)
        .arg(&archive_segment)
        .env("OIRAN_PSEUDONYM_KEY_PATH", &key_path)
        .status()
        .expect("spawn dataset-restore");
    assert!(status.success(), "second restore must succeed");
    let sha_events_after_second = sha256_of(&hot_events);
    let sha_manifest_after_second = sha256_of(&manifest_path);
    assert_eq!(
        sha_events_after_first, sha_events_after_second,
        "events.jsonl must be byte-identical across two restores"
    );
    assert_eq!(
        sha_manifest_after_first, sha_manifest_after_second,
        "dataset_manifest.json must be byte-identical across two restores"
    );
    // Canonical order: (capture_id, packet_number, event_id).
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
