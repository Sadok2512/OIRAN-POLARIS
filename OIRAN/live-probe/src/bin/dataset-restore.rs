//! 2.7.28 `dataset-restore` — re-inject previously archived events
//! back into the live dataset through the SAME publication path the
//! continuous import worker uses (dataset-next → sessions +
//! correlation + callflows + manifest + registration → atomic swap),
//! under the same `flock` publication lock. Never writes
//! `oiran_events.jsonl` directly.
//!
//! Semantics
//!
//! - **Dedup by `event_id`**: the archive segment and the current hot
//!   view can overlap. First occurrence from the current view wins.
//!   Overlap `event_id`s are returned in the report.
//! - **Canonical order**: output is sorted by
//!   `(capture_id, packet_number, event_id)` — session-engine's
//!   `canonical_sort_key` — never by timestamp.
//! - **Publication lock**: `flock(LOCK_EX | LOCK_NB)` on
//!   `<capture-root>/<continuous-capture-id>/.publication.lock`. If
//!   the import worker holds the lock the call fails with
//!   `RESTORE_REQUIRES_PUBLICATION_LOCK` — stop the service first.
//! - **Idempotent**: two runs on the same inputs produce an identical
//!   `oiran_events.jsonl` (same SHA-256) and therefore identical
//!   downstream artifacts.
//!
//! Usage
//!
//!     dataset-restore <capture-root> <archive-segment-dir>
//!
//! `<capture-root>` is `/var/lib/oiran/captures` in the production
//! deployment — the `CaptureManager` root, parent of the
//! `continuous-lab-import/` directory that owns the hot dataset.
//! `<archive-segment-dir>` is one `<archive>/<id>/` directory produced
//! by `archive_stale_captures` and MUST contain `events.jsonl` +
//! `manifest.json`.

use live_probe::CaptureManager;
use std::{env, path::PathBuf, process::ExitCode};

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
    let capture_root = args
        .next()
        .ok_or("usage: dataset-restore <capture-root> <archive-segment-dir>")?;
    let archive_segment_dir = args
        .next()
        .ok_or("usage: dataset-restore <capture-root> <archive-segment-dir>")?;
    if args.next().is_some() {
        return Err("usage: dataset-restore <capture-root> <archive-segment-dir>".into());
    }
    let capture_root = PathBuf::from(capture_root);
    let archive_segment_dir = PathBuf::from(archive_segment_dir);
    let manager = CaptureManager::new(capture_root, false)
        .map_err(|error| format!("MANAGER_INIT: {error}"))?;
    let report = manager.restore_from_archive_segment(&archive_segment_dir)?;
    let payload = serde_json::json!({
        "event": "DATASET_RESTORE_COMPLETED",
        "schema_version": report.schema_version,
        "dataset_dir": report.dataset_dir,
        "archive_segment": report.archive_segment_dir,
        "event_count_before": report.event_count_before,
        "archive_event_count": report.archive_event_count,
        "overlap_event_count": report.overlap_event_count,
        "overlap_event_ids": report.overlap_event_ids,
        "event_count_after": report.event_count_after,
        "session_ids": report.session_ids,
        "events_sha256": report.events_sha256,
    });
    Ok(payload.to_string())
}
