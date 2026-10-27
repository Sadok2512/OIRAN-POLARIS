# S5.5.1 freshness blocker result

Date: 2026-10-27 UTC

Status: the single verified cached-activity blocker was fixed and targeted offline checks pass. This report does not claim certification. `integration-result.md` remains unchanged as prior context.

## Scoped change

- `live-probe/src/lib.rs:759-814` applies a read-time activity view to capture jobs and datasets, so an idle import loop cannot keep cached packet/runtime credits active.
- `live-probe/src/lib.rs:2692-2725` expires packet credit from `last_packet_epoch_ms` and runtime-context credit from each context's evidence `observed_epoch_ms`. Expired runtime-only session IDs are omitted from the returned view; historical session IDs, events, callflows, timestamps, and persisted provenance are retained.
- `live-probe/src/lib.rs:3478-3597` adds the deterministic regression. It starts with three fresh contexts, advances the explicit observation time beyond the 60-second TTL without sleeping, exercises packet and evidence expiry independently, and verifies dataset/session-ID/job-metric reads no longer expose fresh activity.

No host actions, process restarts, live capture, traffic generation, commits, history rewriting, or other worktrees were used. No previously approved recovery, Forget, ring-processing, authorization, or retention behavior was reopened.

## Fail-first evidence

Command:

```text
cargo test -p live-probe aged_cached_activity_is_not_reported_without_new_ingestion -- --nocapture
```

Before the fix, the new regression failed at the first stale read with `left: 3`, `right: 0` for `fresh_packet_count`.

## Final targeted checks

All of these passed:

```text
cargo test -p live-probe aged_cached_activity_is_not_reported_without_new_ingestion -- --nocapture
cargo test -p live-probe runtime_evidence_binds_three_fresh_gpdus_to_three_real_pdu_callflows -- --nocapture
cargo test -p live-probe production_pipeline_decodes_three_pcap_gpdus_into_three_bound_pdu_callflows -- --nocapture
cargo test -p live-probe continuous_import_is_incremental_deduplicated_stoppable_and_restart_safe -- --nocapture
cargo test -p live-probe full_ring_ingests_three_interface_batches_across_rotations -- --nocapture
cargo test -p live-probe atomic_temp_budget_failure_preserves_previous_dataset -- --nocapture
cargo test -p oiran-api continuous_capture_state_and_incremental_sessions_are_truthful -- --nocapture
cargo fmt --all -- --check
git diff --check
```

The supervisor's previously reported 79-test run, including host Unix IPC, was not rerun for this narrow fix.

## Matched release artifacts

Built from this dedicated worktree with release Cargo builds:

```text
/root/OIRAN_VPROBE/.worktrees/continuous_certification/target/release/oiran-api
SHA-256 e3daa282e3d4208863f72595327d6484c27fbcf7a6a696e9354de4d374b32e77

/root/OIRAN_VPROBE/.worktrees/continuous_certification/target/release/oiran-capture-helper
SHA-256 051d2ab9605a262957b676a43996b04fec6c349aa1a822b819c40303ec35c892
```
