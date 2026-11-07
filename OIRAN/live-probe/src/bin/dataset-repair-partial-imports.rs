//! 2.8.3 `dataset-repair-partial-imports` — heal a published dataset
//! that imported an active dumpcap segment multiple times at different
//! sizes (ANR2 phantom, issue #9 comment 6704872754). Uses the SAME
//! publication path as `dataset-restore` under the SAME `flock`
//! lock, so nothing else may be touching the dataset while it runs.
//!
//! Usage
//!
//!     dataset-repair-partial-imports <capture-root> [--dry-run]
//!
//! Exit codes
//!   0   repair (or dry-run) completed
//!   >0  the publication lock was held OR a structural invariant was
//!       broken; the stderr JSON carries the reason.
//!
//! Semantics mirror `restore_from_archive_segment`:
//!   * output JSONL is sorted canonically by
//!     `(capture_id, packet_number, event_id)` — never by timestamp;
//!   * idempotent: the second run on the same inputs produces an
//!     identical `oiran_events.jsonl` (same SHA-256);
//!   * manifest `event_count` equals the number of JSONL lines;
//!   * every removed event is listed with its reason
//!     (`partial-import-superseded-by-final-owned-file=…`).

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
                    "event": "DATASET_REPAIR_PARTIAL_IMPORTS_FAILED",
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
        .ok_or("usage: dataset-repair-partial-imports <capture-root> [--dry-run]")?;
    let mut dry_run = false;
    for extra in args {
        match extra.as_str() {
            "--dry-run" => dry_run = true,
            other => {
                return Err(format!(
                    "usage: dataset-repair-partial-imports <capture-root> [--dry-run] (unknown arg {other})"
                ));
            }
        }
    }
    let capture_root = PathBuf::from(capture_root);
    let manager = CaptureManager::new(capture_root, false)
        .map_err(|error| format!("MANAGER_INIT: {error}"))?;
    let report = manager.repair_partial_imports(dry_run)?;
    let payload = serde_json::json!({
        "event": if report.dry_run {
            "DATASET_REPAIR_PARTIAL_IMPORTS_DRY_RUN"
        } else {
            "DATASET_REPAIR_PARTIAL_IMPORTS_COMPLETED"
        },
        "schema_version": report.schema_version,
        "dataset_dir": report.dataset_dir,
        "dry_run": report.dry_run,
        "event_count_before": report.event_count_before,
        "event_count_after": report.event_count_after,
        "partial_import_groups": report.partial_import_groups,
        "removed_events": report.removed_events,
        "events_sha256": report.events_sha256,
    });
    Ok(payload.to_string())
}
