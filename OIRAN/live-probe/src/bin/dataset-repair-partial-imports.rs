//! 2.8.4 `dataset-repair-partial-imports` — heal a published dataset
//! that imported an active dumpcap segment multiple times at different
//! sizes (ANR2 phantom, #9 comments 6704872754 + 6705466743). The
//! grouping is now driven by the CONTENT of the dataset
//! (`oiran_events.jsonl`) so a `state.segments` that evicted history
//! still produces the full historical repair plan.
//!
//! Usage
//!
//!     dataset-repair-partial-imports <capture-root>
//!         [--dry-run]
//!         [--source-root <path>]
//!
//! The optional `--source-root` points at the production source tree
//! where the live rotation watcher writes segments (e.g.
//! `/var/lib/docker/volumes/oiran_lab_pcap/_data`). When provided, the
//! repair SHA-256-hashes every closed segment under
//! `<source-root>/<interface-lowercase>/` and matches those SHAs
//! against the snapshot `capture_id`s observed in events — the
//! authoritative evidence for picking the FINAL snapshot per group.
//! Without `--source-root` the repair falls back to `state.segments`
//! (largest `size_bytes` ⇒ FINAL); the fallback is correct ONLY when
//! `state.segments` carries the full history, which 2.8.4 guarantees
//! for every import from 2.8.4 onwards (no more count/byte eviction).
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
//!     (`partial-import-superseded-by-final-capture-id=sha256:…`);
//!   * unresolved groups (no `--source-root`, no `state.segments`
//!     history) are LISTED without touching their events.

use live_probe::{CaptureManager, recover_repair_staging};
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
        .ok_or("usage: dataset-repair-partial-imports <capture-root> [--dry-run|--recover] [--source-root <path>]")?;
    let mut dry_run = false;
    let mut recover = false;
    let mut source_root: Option<PathBuf> = None;
    while let Some(extra) = args.next() {
        match extra.as_str() {
            "--dry-run" => dry_run = true,
            // 2.9.17 (#9 comment 6739207609) : mode de reprise
            // après OOM. Supprime `.dataset-next/` et son
            // staging `.repair-staging/` orphelin, laisse
            // `dataset/` et `import_state.json` strictement
            // inchangés. Sans suppression sans preuve : log les
            // chemins et tailles supprimées.
            "--recover" => recover = true,
            "--source-root" => {
                let value = args.next().ok_or(
                    "usage: dataset-repair-partial-imports <capture-root> [--dry-run|--recover] [--source-root <path>] (missing --source-root value)",
                )?;
                source_root = Some(PathBuf::from(value));
            }
            other => {
                return Err(format!(
                    "usage: dataset-repair-partial-imports <capture-root> [--dry-run|--recover] [--source-root <path>] (unknown arg {other})"
                ));
            }
        }
    }
    if recover {
        if dry_run {
            return Err("--recover and --dry-run are mutually exclusive".into());
        }
        let capture_root = PathBuf::from(&capture_root);
        let report = recover_repair_staging(&capture_root)?;
        return Ok(serde_json::json!({
            "event": "DATASET_REPAIR_RECOVERY_COMPLETED",
            "schema_version": "2.9.17",
            "capture_root": capture_root.display().to_string(),
            "removed_paths": report.removed_paths,
            "removed_bytes": report.removed_bytes,
            "dataset_untouched": true,
            "import_state_untouched": true,
        })
        .to_string());
    }
    let capture_root = PathBuf::from(capture_root);
    let manager = CaptureManager::new(capture_root, false)
        .map_err(|error| format!("MANAGER_INIT: {error}"))?;
    let report = manager.repair_partial_imports(dry_run, source_root.as_deref())?;
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
        "unresolved_groups": report.unresolved_groups,
        "removed_events": report.removed_events,
        "events_sha256": report.events_sha256,
    });
    Ok(payload.to_string())
}
