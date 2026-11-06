//! 2.7.27 `dataset-restore` — re-inject previously archived events
//! back into the live dataset.
//!
//! Semantics
//!
//! - **Dedup by `event_id`**: the archive segment and the current
//!   `oiran_events.jsonl` can overlap (the archive was written from
//!   events that were ALSO still in the dataset at the time of
//!   archiving, and the dataset may already have been re-ingested
//!   since). Only the first occurrence of each `event_id` is kept.
//! - **Canonical order**: output is sorted by
//!   `(capture_id, packet_number, event_id)` — session-engine's
//!   `canonical_sort_key` — never by timestamp.
//! - **Idempotent**: a second run on the same inputs produces an
//!   identical `oiran_events.jsonl` (same SHA-256).
//! - **Session rediscovery** happens on the NEXT continuous
//!   publication cycle: the worker reads the restored jsonl through
//!   `load_path_streaming_index` and rebuilds sessions + callflows
//!   without reloading the entire history into RAM. This binary does
//!   NOT regenerate callflows itself.
//!
//! Usage
//!
//!     dataset-restore <dataset-dir> <archive-segment-dir> [--dry-run]
//!
//! `<dataset-dir>` is the `continuous-lab-import/dataset/` directory
//! containing `oiran_events.jsonl`.
//! `<archive-segment-dir>` is one `<archive>/<id>/` directory
//! produced by `archive_stale_captures` and MUST contain
//! `events.jsonl` + `manifest.json`.

use event_schema::{sha256_hex, Sha256Hasher};
use std::{
    collections::BTreeSet,
    env, fs,
    io::{BufRead, BufReader, BufWriter, Write},
    path::PathBuf,
    process::ExitCode,
};

const STREAM_CHUNK_BYTES: usize = 1 << 20;

fn main() -> ExitCode {
    match run() {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::json!({
                    "event": "DATASET_RESTORE_FAILED",
                    "reason": error,
                })
            );
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<String, String> {
    let mut args = env::args().skip(1);
    let dataset_dir = args
        .next()
        .ok_or("usage: dataset-restore <dataset-dir> <archive-segment-dir> [--dry-run]")?;
    let archive_dir = args
        .next()
        .ok_or("usage: dataset-restore <dataset-dir> <archive-segment-dir> [--dry-run]")?;
    let dry_run = args.any(|arg| arg == "--dry-run");
    let dataset_dir = PathBuf::from(dataset_dir);
    let archive_dir = PathBuf::from(archive_dir);
    let events_path = dataset_dir.join("oiran_events.jsonl");
    let archive_events = archive_dir.join("events.jsonl");
    let archive_manifest = archive_dir.join("manifest.json");
    if !events_path.is_file() {
        return Err(format!(
            "DATASET_RESTORE_MISSING: {}",
            events_path.display()
        ));
    }
    if !archive_events.is_file() {
        return Err(format!(
            "DATASET_RESTORE_MISSING: {}",
            archive_events.display()
        ));
    }
    // Validate the archive segment: manifest.events_sha256 must match
    // the on-disk events.jsonl.
    if archive_manifest.is_file() {
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&archive_manifest).map_err(stringify)?)
                .map_err(stringify)?;
        if let Some(expected) = manifest
            .get("events_sha256")
            .and_then(serde_json::Value::as_str)
        {
            let actual = sha256_hex(&fs::read(&archive_events).map_err(stringify)?);
            if actual != expected {
                return Err(format!(
                    "DATASET_RESTORE_ARCHIVE_TAMPERED: manifest sha {expected} != actual {actual}"
                ));
            }
        }
    }
    // Pass 1: collect every (sort_key, event_id, raw_line) across the
    // archive + live dataset. Dedup by event_id (first occurrence
    // wins), sort by canonical key. Memory peak = O(events in the
    // restored union), which is itself bounded by the on-disk file.
    let mut records: Vec<(String, u64, String, String)> = Vec::new(); // (capture_id, packet_number, event_id, raw_line)
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for source in [&events_path, &archive_events] {
        let reader = BufReader::with_capacity(STREAM_CHUNK_BYTES, fs::File::open(source).map_err(stringify)?);
        for line in reader.lines() {
            let line = line.map_err(stringify)?;
            if line.trim().is_empty() {
                continue;
            }
            let value: serde_json::Value = serde_json::from_str(&line).map_err(stringify)?;
            let event_id = value
                .get("event_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| format!("DATASET_RESTORE_MALFORMED: missing event_id in {}", source.display()))?
                .to_string();
            if !seen.insert(event_id.clone()) {
                continue;
            }
            let capture_id = value
                .get("capture_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            let packet_number = value
                .get("packet_references")
                .and_then(serde_json::Value::as_array)
                .and_then(|refs| refs.first())
                .and_then(|r| r.get("packet_number"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            records.push((capture_id, packet_number, event_id, line));
        }
    }
    // Canonical sort: (capture_id, packet_number, event_id).
    records.sort_by(|a, b| (a.0.as_str(), a.1, a.2.as_str()).cmp(&(b.0.as_str(), b.1, b.2.as_str())));
    let event_count = records.len();
    if dry_run {
        return Ok(serde_json::json!({
            "event": "DATASET_RESTORE_DRY_RUN",
            "dataset_dir": dataset_dir.display().to_string(),
            "archive_segment": archive_dir.display().to_string(),
            "event_count": event_count,
        })
        .to_string());
    }
    // Write the restored jsonl atomically and compute its SHA-256 for
    // the idempotency guarantee.
    let tmp = events_path.with_extension("jsonl.restore-tmp");
    let mut hasher = Sha256Hasher::new();
    {
        let file = fs::File::create(&tmp).map_err(stringify)?;
        let mut writer = BufWriter::with_capacity(STREAM_CHUNK_BYTES, file);
        for (_, _, _, line) in &records {
            writer.write_all(line.as_bytes()).map_err(stringify)?;
            writer.write_all(b"\n").map_err(stringify)?;
            hasher.update(line.as_bytes());
            hasher.update(b"\n");
        }
        writer.flush().map_err(stringify)?;
        writer.get_ref().sync_all().map_err(stringify)?;
    }
    fs::rename(&tmp, &events_path).map_err(stringify)?;
    let restored_sha256 = hasher.finish_hex();
    Ok(serde_json::json!({
        "event": "DATASET_RESTORE_COMPLETED",
        "dataset_dir": dataset_dir.display().to_string(),
        "archive_segment": archive_dir.display().to_string(),
        "event_count": event_count,
        "events_sha256": restored_sha256,
    })
    .to_string())
}

fn stringify<E: std::fmt::Display>(error: E) -> String {
    format!("{error}")
}
