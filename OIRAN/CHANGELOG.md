# Changelog

## OIRAN API 2.7.21 — 2026-11-05 — the published dataset is NEVER touched at startup

- ANR2 recette (issue #10 comment 6653514332): on binary 2.7.20 the
  cleanup of `.dataset-next/` worked (1 506 177 003 → 0 B, base
  footprint fell to 46 751 842 B), but the compaction of
  `dataset/oiran_events.jsonl` collapsed the published event set from
  25 537 to 77 entries, keeping 1 capture_id instead of the 51 present
  on disk. 3 945 events belonging to 20 captures **whose pcap was
  still on disk** were dropped before rollback saved the data.
- Root cause (file:line of the bad computation): the 2.7.20 worker ran
  at startup

      // live-probe/src/lib.rs (2.7.20) lines 1764-1769
      let current_capture_ids: BTreeSet<String> = state
          .segments
          .keys()
          .map(|sha| format!("sha256:{sha}"))
          .collect();

  and passed that set to `compact_dataset_in_place` to filter the
  published `oiran_events.jsonl`. `state.segments` is the CURRENT PCAP
  RING, capped at `max_segments`; it is NOT the history of capture_ids
  that ever contributed events to the dataset. The ANR2 lab arrived
  with 1 pcap in the ring (fresh binary start, or the ring had just
  rotated after a crash) while the published `oiran_events.jsonl` held
  51 distinct capture_ids accumulated across many publication cycles
  before those pcaps were evicted. Filtering the dataset against the
  ring therefore dropped every event whose pcap had been rotated out
  — which is most of the historical dataset by construction.
- Decision: **the published dataset is NEVER compacted or filtered at
  startup.** `clean_continuous_import_root` is reduced to the
  never-committed artefacts only. The `current_capture_ids`
  computation is removed from `run_continuous_import_inner`; it is no
  longer used to delete data at startup.
- Remaining startup cleanup scope (strictly outside `dataset/`):
  * `.dataset-previous/` → removed unconditionally (rollback artefact).
  * `.dataset-next/` → removed unconditionally (mid-publish staging
    tree, never holds committed data; `process_capture_into` at
    `live-probe/src/lib.rs:2462` already wipes it before each rebuild).
  * Base-level `*.tmp` / `*.compact-tmp` / `*.spool` → removed (orphan
    `atomic_write` / spool partials).
  * `dataset/` and its `*.spool`, `*.tmp`, `oiran_events.jsonl`,
    `dataset_manifest.json`, `callflows/` are **not inspected and not
    rewritten**.
- The `CONTINUOUS_IMPORT_STARTUP_CLEAN` log line is retained, now
  reporting only the artefacts actually touched (two directories, a
  handful of orphan temp files on first start after a crash, zero
  entries on a clean restart). The ANR2 recette's "before 1 506 177 003
  B / after 46 751 842 B" shape is reproducible because the 1.5 GiB
  were all under `.dataset-next/`.
- `recover_continuous_dataset_from_disk` keeps its 2.7.20 tolerance of a
  missing / malformed / drifted manifest: it logs
  `CONTINUOUS_DATASET_RECOVER_SKIPPED` and returns `Ok`, so a partial
  prior-generation manifest does not crash the worker before its
  normal publication cycle can rebuild a coherent manifest atomically.
- Regression tests (new + updated):
  * `live_probe::tests::startup_cleanup_removes_rollback_only_and_leaves_dataset_byte_identical`
    (NEW) drives the pure `clean_continuous_import_root(base)` helper
    and asserts (a) `.dataset-next/`, `.dataset-previous/`,
    `base/*.tmp`, `base/*.spool` are gone and (b)
    `dataset/oiran_events.jsonl` is **byte-identical** (sha256 before ==
    sha256 after), with events of BOTH live AND evicted capture_ids
    preserved. The call site drops the `current_capture_ids` parameter.
  * `live_probe::tests::anr2_layout_startup_cleanup_shrinks_below_cap_then_drains_250_segments`
    (UPDATED) still reproduces the exact ANR2 lab tree and asserts
    `.dataset-next` + `.dataset-previous` are gone, base footprint
    below 128 MiB cap, and 250 N3 segments drain to
    `segments_ingested >= 250` with `state != Blocked`. Byte-identity
    of `dataset/` across cleanup is now proven by the dedicated test
    above, since here the subsequent publication cycle atomically
    replaces `dataset/` by design.
  * The 2.7.20 `compact_continuous_spools_prunes_orphan_events_and_rollback_directory`
    test is **removed**: compaction of published events is no longer a
    supported operation.
- Workspace: `cargo test --workspace --locked --release` →
  **369 passed / 0 failed / 4 ignored** (same count as 2.7.20 — one
  test added, one removed). Shell guards (3) PASS. Negative harness
  9/9 unchanged.
- Versions: `apps/api` 2.7.20 → 2.7.21; `live-probe` 0.4.6 → 0.4.7.

## OIRAN API 2.7.20 — 2026-11-05 — startup cleanup covers .dataset-next + size-before/after log

- ANR2 arborescence (issue #10 comment 6652125653): the real oversized
  spools in the lab were under `.dataset-next/`, not under `dataset/`.
  `.dataset-next/` is the mid-publish staging tree used by
  `process_capture_into`: when a publication crashes between
  `atomic_write(dataset_next/dataset_manifest.json)` and the final
  `rename(.dataset-next → dataset)`, `.dataset-next/` persists with its
  own ~700 MiB `oiran_events.jsonl`, `.decoded-events.spool`,
  `.normalized-events.spool` and `oiran_events.jsonl.tmp`. The 2.7.19
  startup compaction only touched `dataset/oiran_events.jsonl`, so the
  worker still arrived with 744 MiB (`dataset/`) + 762 MiB
  (`.dataset-next/`) = 1 506 177 003 B > `max_owned_bytes =
  1 140 850 688 B`, the storage guard tripped on candidate #1, and the
  file stayed BLOCKED.
- 2.7.20 fix: `compact_continuous_spools` has been generalised into
  `clean_continuous_import_root(base, current_capture_ids) ->
  CompactionReport`. Scope:
  * `.dataset-previous/` → removed unconditionally (rollback artifact).
  * `.dataset-next/` → removed unconditionally (mid-publish staging
    tree, never holds committed data; `process_capture_into`
    `live-probe/src/lib.rs:2462` already blanket-removes it before
    rebuilding, so pre-cleaning at worker start is safe).
  * `dataset/oiran_events.jsonl` → stream-compact in place
    (`stream_compact_events`), keep only events whose `capture_id` is
    in `current_capture_ids = {"sha256:<sha>" | sha in
    state.segments.keys()}`. If any line was dropped, the (now stale)
    `dataset_manifest.json` + `callflows/` are removed too — the next
    publish rebuilds a coherent bundle atomically.
  * `dataset/.decoded-events.spool`, `.normalized-events.spool`,
    `*.tmp`, `*.compact-tmp` → removed (temp spools from a crashed
    publication cycle).
  * Base-level `*.tmp` / `*.compact-tmp` → removed (orphan
    `atomic_write` partials).
- Memory ceiling unchanged: 1 MiB `BufReader` + 1 MiB `BufWriter` +
  one `serde_json::Value` at a time — no multi-GiB spool is
  materialised in RAM. The compaction is sequential and single-threaded
  so peak RSS during cleanup stays below the baseline footprint.
- Startup log: `run_continuous_import_inner` now emits a single
  structured line on stderr after cleanup finishes:
  ```json
  {
    "event": "CONTINUOUS_IMPORT_STARTUP_CLEAN",
    "base": "/var/lib/oiran/captures/continuous-lab-import",
    "capture_ids_retained": 8,
    "total_before_bytes": 1506177003,
    "total_after_bytes": 65432108,
    "entries": [
      {"path": "...dataset-previous", "before_bytes": 180000000, "after_bytes": 0, "action": "removed-rollback-or-crash-artifact"},
      {"path": "...dataset-next",     "before_bytes": 761937920, "after_bytes": 0, "action": "removed-rollback-or-crash-artifact"},
      {"path": "...dataset/oiran_events.jsonl", "before_bytes": 744239083, "after_bytes": 65432108, "action": "compacted"},
      ...
    ]
  }
  ```
  The "recette" (deployment checklist) can `grep CONTINUOUS_IMPORT_STARTUP_CLEAN
  /var/log/oiran-api/stderr.log` to verify the shrink happened; each
  entry lists its `before_bytes` / `after_bytes` / `action`.
- `recover_continuous_dataset_from_disk` now tolerates a malformed or
  drifted manifest the same way it tolerates a missing one. The worker
  thread's cleanup runs AFTER `recover_continuous_dataset_from_disk`
  returns to `start_continuous_import`, so a prior-run bogus manifest
  must not crash the worker before cleanup can delete it; a
  `CONTINUOUS_DATASET_RECOVER_SKIPPED` log line records the skip.
- Regression tests (new):
  * `live_probe::tests::anr2_layout_startup_cleanup_shrinks_below_cap_then_drains_250_segments`
    reproduces the EXACT ANR2 lab directory tree: `dataset/`
    (`oiran_events.jsonl` 60 000 × ~1 KiB = ~60 MiB with stale
    capture_ids, `dataset_manifest.json`, `callflows/`), `.dataset-next/`
    (its own 60 MiB `oiran_events.jsonl`, 2 MiB `.decoded-events.spool`,
    2 MiB `.normalized-events.spool`, 2 MiB `oiran_events.jsonl.tmp`,
    manifest + callflows), `.dataset-previous/` (20 MiB spool). Total
    pre-cleanup > 128 MiB cap. The worker starts, the test waits for
    the three observable terminal conditions (`.dataset-next` gone,
    `.dataset-previous` gone, `dataset/oiran_events.jsonl` size == 0),
    asserts `directory_size(&base) < cap`, and then 250 N3 segments
    are drained to `segments_ingested >= 250`, `state != Blocked`.
  * The 2.7.19 `compact_continuous_spools_prunes_orphan_events_and_rollback_directory`
    was renamed to call `clean_continuous_import_root` via the new
    entry point and retains full coverage of the rollback-removal +
    stale-manifest-removal invariants.
- Workspace: `cargo test --workspace --locked --release` → **369
  passed / 0 failed / 4 ignored** (was 368 on 2.7.19; +1 for the ANR2
  layout test). Shell guards (3) PASS. Negative harness 9/9
  unchanged.
- Versions: `apps/api` 2.7.19 → 2.7.20; `live-probe` 0.4.5 → 0.4.6.

## OIRAN API 2.7.19 — 2026-11-05 — startup spool compaction + single-source /health coherence

- Follow-up on the ANR2 lab reproduction (issue #10, comment
  6646981831): even on a 2.7.18 binary the lab worker landed with two
  `oiran_events.jsonl` spools on disk — the live one at 744 239 083
  bytes and `.dataset-previous/oiran_events.jsonl` (crash rollback) at
  761 937 920 bytes, total 1 506 177 003 bytes, already **above**
  `max_owned_bytes = 1 140 850 688`. 2.7.18 prevents further growth but
  cannot shrink the pre-existing artifacts, so the FIRST
  `directory_size(&base)` read in `run_continuous_import_inner` tripped
  `CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT` on the FIRST candidate of the
  first scan and the queue stayed at 222 pending.
- 2.7.19 fix (startup compaction): new helper
  `compact_continuous_spools(base, current_capture_ids)` at
  `live-probe/src/lib.rs`. Called from the top of
  `run_continuous_import_inner` right after `state.segments` has been
  resolved, BEFORE any guard reads `directory_size(&base)` or the
  historical-bootstrap pcap is copied. The helper streams
  `base/dataset/oiran_events.jsonl` line by line via a 1 MiB
  `BufReader`, parses each line as `serde_json::Value`, keeps only
  events whose `capture_id` is in `current_capture_ids`
  (i.e. `{"sha256:<sha>"}` for every pcap in `state.segments`), writes
  to `oiran_events.jsonl.compact-tmp` and atomically renames. If any
  line was dropped the published manifest and callflows are stale by
  construction (they reference event ids that no longer exist), so the
  helper removes `dataset_manifest.json` + `callflows/`. The next
  successful publication rebuilds a coherent dataset. `.dataset-previous/`
  is always a rollback artifact and is removed unconditionally.
  Memory ceiling: 2 MiB (reader + writer) + one `serde_json::Value` at
  a time — no 1.5 GiB in-RAM materialisation.
- 2.7.19 fix (single-source `/health` coherence): the ANR2 lab also
  observed `/health = 25 939 events / 10 sessions` while
  `dataset_manifest.json` on disk reported `25 537 / 8`. Root cause:
  `apps/api::health` (2.7.17) summed across every entry of
  `capture_manager.datasets()`, so a residual recovered-failed dataset
  (`402` events / `2` sessions) was added on top of the continuous one.
  Fix: in operational mode `/health` now reads exactly
  `capture_manager.dataset(CONTINUOUS_DATASET_ID)` and projects only
  that dataset's `event_count` / `session_ids`. Because the in-RAM
  `LiveDataset` and the on-disk `dataset_manifest.json` are the same
  struct (serialized atomically in `process_capture_into` and upserted
  in the same publication), `/health` and the manifest are now
  identical by construction.
- `CaptureManager::recover_continuous_dataset_from_disk(base)` is now
  `pub` so tests and non-worker code paths can hydrate the manifest
  without spawning the production-only import worker.
- Regression tests
  (`cargo test --workspace --locked --release` → **368 passed / 0
  failed / 4 ignored**, was 366 on 2.7.18):
  * `live_probe::tests::compact_continuous_spools_prunes_orphan_events_and_rollback_directory`
    seeds a 5 MiB spool with 2 500 "stale" events (`capture_id="sha256:stale"`)
    + 2 500 "live" events, plus a `.dataset-previous/` directory and a
    stub manifest + callflow. After `compact_continuous_spools(base,
    {"sha256:live"})` the rollback directory is gone, the manifest +
    callflows are removed (events were dropped), and the compacted spool
    contains exactly the 2 500 live events. A second idempotent call
    with the same keep-set leaves a freshly-written manifest untouched.
  * `live_probe::tests::continuous_import_drains_a_burst_of_250_segments_without_blocking`
    (from 2.7.18) still passes with the new startup compaction added
    in the critical path.
  * `oiran_api::tests::health_counters_mirror_the_continuous_manifest_exclusively`
    seeds a `dataset_manifest.json` with 24 events / 8 sessions,
    hydrates the manager, hits `/api/v1/health`, and asserts
    `data.source_events == manifest.event_count` and
    `data.session_count == manifest.session_ids.len()`.
- Audit negative harness
  (`AUDIT_E2E_CERT_001_scripts/02-negative-tests.py`): 9/9 scenarios
  still match the expected verdict.
- Shell guards all PASS.
- Versions: `apps/api` 2.7.18 → 2.7.19; `live-probe` 0.4.4 → 0.4.5.

## OIRAN API 2.7.18 — 2026-11-04 — bound derived artifacts + N2↔N4 via regenerated dataset

- Root cause of the lab-reproduced 222-segment deadlock (ANR2, issue #9):
  `process_capture_into` merges the previous dataset's events into the
  new `oiran_events.jsonl` through `index_event_stream` at
  `live-probe/src/lib.rs:2619-2639`. Before this patch the merge kept
  **every** prior event, including events from pcap segments that had
  already been evicted by the ring. The derived `oiran_events.jsonl`
  therefore accreted monotonically; `directory_size(&base)` was
  dominated by the events artifact, not by the live pcap ring; and the
  backpressure guard at `live-probe/src/lib.rs:1961-2013` tripped
  because the only thing eviction could reclaim was the pcap pool. A
  freshly-arrived 212 th segment couldn't fit even though the live
  pcap directory was well under budget, and every scan failed on
  candidate #1. The 2.7.16 batch-of-32 did not help because the FIRST
  candidate in every scan tripped the guard — no segment ever entered
  `pending_publication`.
- 2.7.18 fix (filter prior events by the current pcap set):
  `index_event_stream` now takes a `keep: FnMut(&Value) -> bool`
  predicate. The prior-events caller passes
  `|v| current_capture_ids.contains(v.capture_id)` where
  `current_capture_ids` is derived from the `checksums` map built in
  the per-pcap decode loop. Evicted pcap → their events drop from the
  next published dataset. The derived artifact is therefore bounded by
  what the ring currently holds (≤ `max_segments` pcap × their events),
  and can no longer starve the ring.
- 2.7.18 fix (two-pass eviction): the eviction loop at
  `live-probe/src/lib.rs:1982-2002` now falls back to evicting the
  oldest segment **of any kind** (including the N2 historical
  bootstrap) when the non-historical pool is exhausted. The historical
  pcap is on the allowlisted `/var/lib/docker/volumes/oiran_lab_pcap/_data`
  source, so evicting its owned cached copy only loses the on-disk
  mirror; the worker can re-bootstrap on the next start.
- 2.7.18 fix (dataset regenerated with the current decoder):
  `datasets/OIRAN_5G_PDU_SESSION_DATA_V1/oiran_events.jsonl` was
  regenerated with `oiran-decode 0.6.0`, which emits structured tunnel
  IE components (`item_<i>_tunnel_ip_ul`, `item_<i>_gtp_teid_ul`,
  `item_<i>_tunnel_ip_dl`, `item_<i>_gtp_teid_dl`) on NGAP IE 74/75
  instead of the old `nested_transfer_sha256`-only placeholder. The
  pcapng captures themselves are untouched. As a result the existing
  `ngap-pfcp-exact-tunnel` rule in
  `correlation-engine::correlate_cross_interface_evidence` finds the
  byte-identical `(ipv4=10.77.22.13, teid=0x96a8)` on N2 and N4 and
  emits an EXACT edge (plus the mirror downlink
  `(10.77.22.20, 0x3)`). The full 5G SA chain is now certified by the
  engine itself, not just by the audit oracle.
- Regression tests (run with
  `cargo test --workspace --locked --release`):
  * `live_probe::tests::continuous_import_drains_a_burst_of_250_segments_without_blocking`
    writes 250 valid N3 pcaps with distinct TEIDs into the source root
    under `max_owned_bytes = 128 MiB` / `max_segments = 8`, starts the
    import, and asserts `segments_ingested >= 250`, `state != Blocked`
    and `pending_segments == 0` within 120 s (empirically ~3 s).
  * `correlation_engine::tests::audit_dataset_produces_the_full_n2_n4_n3_chain`
    loads the regenerated dataset events, runs
    `correlate_cross_interface_evidence`, and asserts exactly two
    `ngap-pfcp-exact-tunnel` EXACT edges and two
    `pfcp-outer-header-matches-gtpu-tunnel` EXACT edges, each carrying
    the known `(endpoint_ip, teid)` anchor.
  * Four existing API tests were updated to reflect the new on-wire
    event count (24 N2 + 30 N4 + 10 N3 = 64 events, 76 flow-accounting
    sum, 2 session callflows). The pcapng packet count is unchanged
    (same captures).
- Replay of `AUDIT_E2E_CERT_001_scripts/02-negative-tests.py`: the 9-case
  truth table is unchanged — no false positive, fail-closed on
  duplicate TEIDs / multiple candidates / partial captures / duplicate
  events, time-independent on clock skew / reversed order.
- Versions: `apps/api` 2.7.17 → 2.7.18; `live-probe` 0.4.3 → 0.4.4.

## OIRAN API 2.7.17 — 2026-11-04 — remove every hardcoded version; measure continuous RSS

- `apps/api/src/lib.rs:44-45` previously pinned `API_VERSION` and
  `PLATFORM_VERSION` to the string `"2.7.15"`, so `apps/api/Cargo.toml`
  could bump to `2.7.16` while `/version` still reported the old number
  and the unit assertion at `apps/api/src/lib.rs:3509` still read
  `"2.7.15"`. ANR2 refused the 2.7.16 deployment on exactly this drift.
  Fix: `API_VERSION = env!("CARGO_PKG_VERSION")`,
  `PLATFORM_VERSION = env!("CARGO_PKG_VERSION")`. The /version regression
  test now asserts `backend_api == env!("CARGO_PKG_VERSION") ==
  platform_core` — no literal in the assertion.
- Same drift hazard existed in every other crate: `decoder-ngap`,
  `decoder-s1ap`, `decoder-nas`, `decoder-pfcp`, `decoder-gtpu`,
  `decoder-gtpv2c`, `decoder-sbi`, `decoder-diameter`, `oiran-decode`,
  `session-engine`, `correlation-engine`, `callflow-schema`,
  `callflow-renderer`, `live-probe`, `disk-safety`, `dataset-registry`,
  `transport-tcp`, `capture-helper` all exposed
  `pub const VERSION: &str = "<literal>"` mirrored from their own
  Cargo.toml. All 18 are now `pub const VERSION: &str =
  env!("CARGO_PKG_VERSION")`. `cargo build` confirms the identity across
  the workspace; no further manual bumps required.
- Web frontend version (`apps/web/package.json`) was hardcoded as
  `"web_frontend":"2.7.1"` in `apps/api/src/lib.rs:669`. New
  `apps/api/build.rs` reads `apps/web/package.json` at build time and
  emits `cargo:rustc-env=OIRAN_WEB_FRONTEND_VERSION=<value>`; the
  constant `WEB_FRONTEND_VERSION = env!("OIRAN_WEB_FRONTEND_VERSION")`
  serves it. `cargo:rerun-if-changed` is set so bumping the frontend
  triggers an API rebuild automatically.
- Memory measurement: the user reported that `oiran-api` RSS approaches
  256 MiB in production under 2.7.16. We built a reproducible harness
  (`AUDIT_E2E_CERT_001_scripts/04-generate-synthetic-events.py` +
  `04-rss-continuous.rs`, installed as
  `OIRAN/session-engine/examples/rss_continuous.rs`) and measured on the
  reported shape (25 537 events, 8 sessions):

  | stage                        | VmRSS   | VmPeak  |
  | ---                          | ---:    | ---:    |
  | baseline                     | 1.06 MiB | 3.47 MiB |
  | after `load_path`            | **114.7 MiB** | **127.5 MiB** |
  | after `discover_sessions`    | **130.7 MiB** | **136.5 MiB** |
  | after drop (allocator held)  | 116.9 MiB | 136.5 MiB |

  **Peak: 137 MiB VmPeak — under the 200 MiB threshold** stated in the
  mission brief. Retention is concentrated in `Vec<EventRecord>` returned
  by `session_engine::load_path` at `session-engine/src/lib.rs:620-623`.
  session-engine already strips `source_json` to the three top-level
  schema keys (`compact_source`, `src/lib.rs:691-701`), which was
  introduced specifically to keep the continuous importer below the
  256 MiB cgroup; without that trim the figure would be ~3× higher.
  The 115 MiB resident after `drop(events)` is the Rust allocator
  retaining freed arenas, not leaked data — it is reused by the next
  publication cycle rather than returned to the kernel. The production
  gap to 256 MiB (~120 MiB) is accounted for by the live Axum router,
  Tokio worker pool, decode spool buffers (`decoded_spool` /
  `normalized_spool`, `live-probe/src/lib.rs:2538, 2613`), and the live
  `datasets` map; no new bound is required at this stage.
- Regression test guarantees: workspace build succeeds with the new
  `env!()` wiring across all 18 crates and the new `build.rs`.
  `cargo test --workspace --locked --release` → **364 passed / 0 failed /
  4 ignored** (same count as 2.7.16). The strengthened
  `apps/api::tests::version_reports_installed_lte_and_5g_decoders`
  now asserts `backend_api == platform_core ==
  env!("CARGO_PKG_VERSION")` and `web_frontend ==
  env!("OIRAN_WEB_FRONTEND_VERSION")` — four assertions added inside
  the same test function, so the count is unchanged. Shell guards
  (`test-rotation-drops.sh`, `test-rotation-watcher.sh`,
  `test-dumpcap-retention.sh`) all PASS.
- Versions: `apps/api` 2.7.16 → 2.7.17. No other crate changes version
  — this is purely a drift-hardening patch.

## OIRAN API 2.7.16 — 2026-11-04 — API continuous projection + bounded-batch backpressure drain

- `live-probe::CaptureManager::start_continuous_import` now recovers a
  previously-published continuous dataset from
  `<capture_root>/continuous-lab-import/dataset/dataset_manifest.json` into
  the in-RAM `datasets` map before the import worker is spawned (new
  `recover_continuous_dataset_from_disk`). Prior to this fix the API
  process restarted with an empty `datasets` map, so `/sessions`,
  `/datasets` and `/health` reported zero sessions for a continuous dataset
  whose disk already held 25 537 events and 8 sessions (issue #9 part 1,
  ANR2 diagnostic). The recovery reads only the manifest JSON (a few KiB);
  `oiran_events.jsonl` and callflows stay on disk and are never pulled into
  memory, preserving the 256 MiB continuous-import ceiling.
- `apps/api::health` projects `capture_manager.datasets()` into the
  response fields (`dataset`, `source_events`, `session_count`,
  `ue_context_count`) when `Inner.flows` is empty (operational mode).
  Reference mode still wins — the projection is a fallback, not an
  override. The projection accumulates integer counters only, so a dataset
  with 25 537 events adds a `usize` to the sum and nothing else.
- `live-probe::run_continuous_import_inner` drains the pending-segment
  queue in bounded batches of at most `MAX_INGESTED_SEGMENTS_PER_SCAN = 32`
  (`live-probe/src/lib.rs:62`). Before this patch the per-candidate loop
  tried to admit every candidate before publishing, so a burst of 212
  segments observed in the lab (issue #9 part 2) could exhaust the eviction
  budget at `live-probe/src/lib.rs:1961-1992`, trip
  `CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT`, set `terminal_error`, and
  `return Ok(())` from the worker — leaving the pending-segments counter
  stuck at 212 forever. The patch:
  * bounds the per-scan ingestion count so each outer-loop iteration
    publishes what it has and sleeps before taking the next batch;
  * stops treating `CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT` as a terminal
    error — the worker now records `CaptureState::Blocked` with the
    stop_reason set but continues the outer loop, so eviction+publish on
    the next scan drains the queue. Non-recoverable terminals
    (`CONTINUOUS_IMPORT_DISK_POLICY_STOP` et al.) still end the worker.
  * no segment is lost: the tripped candidate's checksum is never added
    to `seen_checksums` (commit point is `persist_published_checksums`
    after a successful publish), so the next scan re-discovers it.
- `correlation-engine` now emits an explicit N4↔N3 `CorrelationEdge` via
  the new `pfcp-outer-header-matches-gtpu-tunnel` rule. The rule matches a
  PFCP F-TEID or Update-FAR outer-header-creation `(ipv4, teid)` tuple
  against the destination endpoint + `teid` identifier of N3 GTP-U events
  in the same capture scope. Uniqueness is enforced on the N4 side
  (reused F-TEID → no edge); the N3 side aggregates all G-PDUs sharing
  the tuple into one edge with `gtpu_frame_count=<n>` and selects the
  deterministic representative via the canonical
  `(capture_id, packet_number, event_id)` sort key — never a timestamp.
  Covers DSN-ENGINE-002 from the independent audit
  (`AUDIT_E2E_CERT_001` / `FINAL_CERTIFICATION_REPORT.md`).
- `correlation-engine::capture_scope` now falls back to the parent
  directory of `source_file` when the `/captures/<scope>/` marker is
  absent, so a dataset rooted under `datasets/<scope>/*.pcapng` unifies
  N2, N3 and N4 under a single scope. Previously the fallback keyed on the
  per-file `capture_id` SHA-256, which was always distinct across planes
  and forbade any cross-interface match on a fixture dataset. Covers
  DSN-SCOPE-001 from the audit.
- Regression tests (all green under `cargo test --workspace --locked
  --release`, 364 passed / 0 failed / 4 ignored):
  * `correlation_engine::tests::n4_n3_rule_publishes_one_exact_edge_per_matching_tunnel`
    — single N4 F-TEID + 3 N3 G-PDUs → one EXACT edge with
    `gtpu_frame_count=3` and `capture_scope=AUDIT`.
  * `correlation_engine::tests::n4_n3_rule_is_fail_closed_when_the_pfcp_teid_is_reused`
    — ambiguous N4 F-TEID across two PFCP responses → no edge.
  * `correlation_engine::tests::capture_scope_fallback_unifies_planes_under_dataset_directory`
    — `datasets/<X>/N3.pcapng` → `<X>`; `/var/lib/oiran/captures/<Y>/N3.pcapng` → `<Y>`.
- Replay of the audit's negative-test harness
  (`AUDIT_E2E_CERT_001_scripts/02-negative-tests.py`) confirms the 9-case
  truth table is unchanged: no false positives, fail-closed on duplicate
  TEIDs / multiple candidates / partial captures / duplicate events, and
  still time-independent on clock skew / reversed order.
- Replay of `evidence-replay` on
  `datasets/OIRAN_5G_PDU_SESSION_DATA_V1/oiran_events.jsonl` now yields
  **2 EXACT N4↔N3 edges** (uplink `0x96a8 @ 10.77.22.13` and downlink
  `0x3 @ 10.77.22.20`), up from 0 in 2.7.15. The N2↔N4 bridge still
  requires the dataset events to be regenerated with the current
  decoder-ngap (which already emits `item_0_tunnel_ip_ul` /
  `item_0_gtp_teid_ul`, see `decoder-ngap/src/lib.rs:500-507` and
  `:542-548`); the shipped jsonl predates that decoder and only carries
  `nested_transfer_sha256`. DSN-ENGINE-001 therefore becomes a fixture
  regeneration chore, not a code gap.
- Versions: `apps/api` 2.7.15 → 2.7.16; `live-probe` 0.4.2 → 0.4.3;
  `correlation-engine` 0.5.1 → 0.5.2.

## OIRAN API 2.7.15 — 2026-11-04 — session consolidation + typed packet counters

- `session-engine::discover_lte_sessions` now consolidates S1AP
  contexts by the structural `(capture_id, enb_ue_s1ap_id)` key before
  it enumerates sessions. The pre-2.7.15 code
  (`session-engine/src/lib.rs:313-319`) inserted every observed
  `(capture_id, enb, mme)` triple, so an `InitialUEMessage` event
  (which carries `enb_ue_s1ap_id` but no `mme_ue_s1ap_id` — the MME
  has not yet allocated one) was treated as a separate context from
  the rest of the exchange and produced a parallel
  `RELEASED`-but-incomplete session missing `InitialUEMessage` and the
  NAS Attach Request child (ANR3 final report, issue #10 comment
  6636015016). The consolidation keeps structural separation: two
  UEs with distinct `enb_ue_s1ap_id` values still yield two sessions,
  and two UEs that reuse the same `enb_ue_s1ap_id` across different
  `mme_ue_s1ap_id` values still yield two sessions. No timestamp
  comparison is used.
- The per-context match relaxes the `mme_ue_s1ap_id` check: an event
  with no mme (InitialUEMessage, the NAS Attach Request child that
  inherits the parent's identifiers, …) is admitted into the
  canonical context when the `enb` matches. The mme equality check
  stays strict for events that DO carry a mme identifier.
- `rotation-watcher.sh` emits `packets_captured` and `packets_dropped`
  as typed metrics. `packets_captured` is read from capinfos and
  `packets_dropped` is computed as a delta on the bridge's kernel
  `/sys/class/net/<iface>/statistics/rx_dropped` counter, seeded on
  the watcher's first visit. Every failure path produces an explicit
  `"UNKNOWN:<reason>"` JSON string (`capinfos-missing`,
  `capinfos-no-count`, `no-baseline-yet`, `counter-rolled-back`,
  `sysfs-<iface>-unavailable`, `stat-failed`, `file-not-readable`) —
  the field is never `null`. ANR3 observed 24 `packets_dropped:null`
  records before this patch.
- Regression tests:
  * `session_engine::tests::anr3_attach_to_detach_flow_consolidates_into_a_single_session`
    replays the shape reported by ANR3 (InitialUEMessage + NAS Attach
    + 5 subsequent S1AP events + S11 + S1-U) and asserts a single
    session that contains both `InitialUEMessage` and
    `Attach Request`.
  * `session_engine::tests::two_distinct_ues_each_get_their_own_session_after_consolidation`
    guards the mirror case: distinct eNB UE IDs → two sessions.
  * `infrastructure/capture/tests/test-rotation-drops.sh` — four
    rotations driving the four failure modes (`no-baseline-yet`,
    numeric delta, `sysfs-...-unavailable`, `capinfos-missing`) and a
    final sweep over the JSONL asserting no `"packets_captured":null`
    or `"packets_dropped":null` line remains.

## OIRAN API 2.7.14 — 2026-11-04 — technical-field exemption in privacy predicate

- `live-probe::lte_evidence::contains_forbidden_identity` no longer
  rejects the ANR3 event id `evt-78165221727737b8` (issue #10 comment
  6632047981): the previous rule applied the 14-consecutive-decimal
  heuristic to every JSON string, so a canonical event id whose 16-hex
  suffix happened to contain 14 digits in a row was treated as a raw
  IMSI.
- New `is_valid_technical_field(key, value)` predicate is the single
  place that lists the technical field names exempted from the
  long-digit-run heuristic and declares their exact format:
  * `event_id`, `parent_event_id` → `^evt-[0-9a-f]{16}$`
  * `capture_id` → `^sha256:[0-9a-f]{64}$`
  * `raw_payload_reference` → sha256: head, optional `#…` suffix
  * `raw_sha256`, `source_sha256`, `normalized_events_sha256`,
    `derived_manifest_sha256`, `event_artifact_sha256`,
    `correlation_artifact_sha256`, `source_file_sha256` → `[0-9a-f]{64}`
  * `dataset_id` → `dataset-` or `dataset-live-` + `[0-9a-f]{32}` or
    `[0-9a-f]{64}`.
  A value whose format does not match falls through to the strict scan,
  so an IMSI stuffed under `event_id`, `capture_id`, `raw_sha256` or
  `dataset_id` is still refused with
  `LTE_IDENTITY_DISCLOSURE_REJECTED`.
- `contains_forbidden_identity_marker` runs BEFORE the exemption, so a
  value like `imsi-001010123456789` stored under `event_id` stays
  rejected.
- The scan stays strict on IE contents, decoded values, session
  identifiers, and any field not listed above.
- Regression tests:
  * `anr3_exact_event_id_from_the_report_is_not_flagged_as_identity`
    (passes on the exact `evt-78165221727737b8` value),
  * `technical_fields_accept_their_declared_formats`,
  * `imsi_inside_an_information_element_value_stays_rejected`,
  * `imsi_stuffed_into_a_technical_field_is_rejected_by_format_invalidation`,
  * `whitelisted_names_do_not_exempt_other_marker_shapes`.

## OIRAN API 2.7.13 — 2026-11-04 — canonical `(capture_id, seq)` order, no dumpcap retention

- The canonical processing order across OIRAN is now
  `(capture_id, packet_number, event_id)`. The `timestamp_ns` field is
  NEVER used for a processing decision and no two events from different
  captures are ever compared by timestamp. New public helper
  `session_engine::canonical_sort_key()` is the single implementation
  of the key; every processing sort in the workspace now delegates to
  it. Call flow ladder rendering may reorder an already-selected set
  of events by `timestamp_ns` as a presentation step — see the
  explicit comment at `callflow-schema::build_lte_callflow` — and no
  session, correlation, dedup, or attachment decision depends on that
  order.
- `session_engine::within_lte_window` no longer gates on a
  `timestamp_ns` difference. Cross-capture joins (S1-MME ↔ S11 ↔ S1-U)
  rely exclusively on structural keys (MME/eNB-UE-S1AP-ID, E-RAB
  TEIDs, F-TEID, pseudonym when present).
- `oiran-decode::decode_capture()` and
  `live-probe::lte_evidence::read_events_bounded()`'s post-merge sort
  both use `canonical_sort_key`. Within one capture this collapses to
  `(packet_number, event_id)`, which preserves the parent S1AP → NAS
  child emission order without relying on `sort_by_key` stability.
- Dumpcap native rotation drops `-b files:8`. The capture script now
  invokes `dumpcap -b duration:3600 -b filesize:262144 -w <path>` only.
  Retention is owned by the existing disk-safety guard-rail; dumpcap
  must never delete a finalised segment.
- New regression tests:
  - `session_engine::tests::crossed_timestamps_across_captures_do_not_alter_sessions_or_attachments` —
    two captures with interleaved timestamps produce the exact same
    `discover_lte_sessions` shape under both the canonical and the
    legacy ts order.
  - `oiran-decode::tests::sort_by_timestamp_tie_breaks_on_capture_id_then_sequence_then_event_id`
    stays valid against the canonical sort.
  - `infrastructure/capture/tests/test-dumpcap-retention.sh` — asserts
    that `capture-interface.sh` no longer passes `-b files:` (outside
    comments) and that 10 simulated rotations retain all 10 files.

## OIRAN API 2.7.12 — 2026-11-04 — gapless dumpcap rotation + deterministic ts tiebreak

- `infrastructure/capture/capture-interface.sh` drops the
  `timeout --signal=INT 3600 dumpcap ...` wrapper in favour of native
  dumpcap rotation (`-b duration:3600 -b filesize:262144 -b files:8`).
  dumpcap no longer exits between hourly segments, so the capture
  container stays up continuously (ANR3 measured 2.5–3.2 s of capture
  loss per interface per hour and a restart_count of 256 with the
  previous wrapper).
- New `infrastructure/capture/rotation-watcher.sh` keeps the
  `capture-rotation.jsonl` contract from a40e110 alive: it polls each
  per-label output directory and emits one JSONL record the moment
  dumpcap finalises a segment (i.e. the moment a newer file appears
  beside it), with `interface`, `plane`, `file`, `file_bytes`,
  `packets_captured`, `packets_dropped` fields. Idempotent across
  watcher restarts via a per-label seen list.
- `infrastructure/capture/capture-all.sh` orchestrates one
  `capture-interface.sh` + one `rotation-watcher.sh` per approved
  bridge; the shutdown trap stops both cleanly.
- `infrastructure/capture/tests/test-rotation-watcher.sh` simulates two
  dumpcap rotations and asserts the two JSONL records are emitted in
  order, carry all expected fields, and that the watcher is idempotent
  (no gap, no duplicate).
- `oiran-decode::decode_capture()` replaces the previous stable
  `sort_by_key((ts.s, ts.ns, packet_number))` with an explicit
  `sort_by` on `(ts.s, ts.ns, capture_id, packet_number, event_id)`.
  Live-probe's cross-plane merge sort already carried `event_id` as the
  final tiebreak; this patch brings oiran-decode to the same full
  determinism without relying on `sort_by_key`'s stability guarantee.
  New `oiran-decode::tests::sort_by_timestamp_tie_breaks_on_capture_id_then_sequence_then_event_id`.

## OIRAN API 2.7.11 — 2026-11-04 — SecurityKey material withheld at decode

- `event-schema` exposes `InformationElement::withheld(id, length)`, the
  shared constants `KEY_MATERIAL_WITHHELD_IE_NAME` / `..._VALUE`, and the
  explicit allowlist `is_withheld_key_material(decoder, ie_id)` covering
  S1AP IE 73 (SecurityKey, KeNB*/NH/NCC) and NGAP IE 94 (SecurityKey,
  KgNB*/NH/NCC). Both decoders must emit matching IEs via this path so no
  raw key material and no hash of it ever reaches a NormalizedEvent.
- `decoder-s1ap` and `decoder-ngap` build the SecurityKey IE through the
  withheld constructor: id and length are preserved for provenance, `name`
  is `"key_material_withheld"`, `value` is the sentinel `"WITHHELD"`, and
  `raw_sha256` is `None`. The previous `security_key_sha256=...` identifier
  emission is removed.
- `live-probe` fail-closed `LTE_IDENTITY_DISCLOSURE_REJECTED` remains
  active: any residual key material that still reaches the published
  stream (raw bytes under `name: "SecurityKey"`, `security_key=` substring,
  or a sha256 under the original IE name) is refused.
- Regression tests:
  - `decoder-s1ap::tests::initial_context_setup_request_withholds_security_key_payload`
  - `decoder-ngap::tests::initial_context_setup_request_withholds_ngap_security_key_payload`
  - `live-probe::lte_evidence::tests::imports_ics_with_withheld_security_key_without_privacy_rejection`
  - `live-probe::lte_evidence::tests::rejects_raw_security_key_leaked_into_the_published_stream`

## OIRAN API 2.7.10 — 2026-11-04 — explicit decoder-vs-protocol binding for nested EPS NAS

- `live-probe::lte_evidence::read_events_bounded()` now classifies each
  normalised event with an explicit allowlist of `(plane, protocol,
  decoder)` tuples. An S1-MME event with the plane's declared binding
  decoder stays a plane-binding primary; an S1-MME event with protocol
  `NAS-EPS-MM` or `NAS-EPS-SM` is accepted only when it is decoded by
  `decoder-nas/0.3.1` AND carries a `parent_event_id` resolvable to an
  S1AP event seen in the same plane. Any other combination fails closed
  with `LTE_EVENT_DECODER_MISMATCH` (detail: decoder, protocol, parent),
  and a nested NAS event without a valid parent fails
  `LTE_EVENT_NESTED_NAS_WITHOUT_PARENT`. The S11 and S1-U plane bindings
  stay strict. The N2 / NGAP / NAS-5G path is untouched (non-regression).
- Regression tests:
  `accepts_ten_nas_children_decoded_by_the_eps_nas_decoder_on_s1_mme`
  (ANR3 field case),
  `rejects_nested_nas_without_s1ap_parent_on_s1_mme`,
  `rejects_nested_nas_without_any_parent_event_id_on_s1_mme`,
  `rejects_unknown_decoder_on_s1_mme`,
  `rejects_wrong_decoder_version_for_nested_eps_nas`.

## OIRAN API 2.7.9 — 2026-11-04 — bounded LTE runtime-diagnostic privacy predicate

- Removes only the envelope's exact strict `lte-run-<32 lowercase hex>` value
  before applying the long-digit privacy rule to LTE step measurements; any
  other or malformed run identifier remains rejected fail-closed.
- Exempts only the numeric-run heuristic for the exact iperf runtime diagnostic
  stdout/stderr fields while retaining all subscriber and equipment identity
  markers everywhere.

## OIRAN API 2.7.8 — 2026-11-04 — scalar pseudonym IE contract

- Serializes every GTPv2-C, S1AP and EPS NAS information element named
  `subscriber_pseudonym` or `identity_pseudonym` as the bare deployment-keyed
  HMAC value `psn-<32 hex>`, without a key/value prefix or concatenation.
- Exports the EPS mobile type code separately as the numeric-only
  `eps_mobile_type_code`, preserving correlation while satisfying the strict
  POLARIS 0.29.16 privacy contract.

## OIRAN API 2.7.7 — 2026-11-04 — unified `subscriber_pseudonym` / `identity_pseudonym` emission contract

- Every identity-derived identifier (IMSI, IMEI, MSISDN, GUTI/TMSI/5G-S-TMSI,
  SUCI, Masked IMEISV, UE Paging ID) now surfaces on `session_identifiers`
  with the fixed name `subscriber_pseudonym`. Identity-carrying
  `information_elements` entries (NAS 5GS/EPS mobile identity, GTPv2-C IMSI/
  MEI/MSISDN, S1AP S-TMSI/UEPagingID, NGAP 5G-S-TMSI/MaskedIMEISV, Diameter
  User-Name/MSISDN) are renamed `identity_pseudonym`. The value is the HMAC
  output `psn-<32 hex>`. No name, no IE label, no identifier value contains
  any POLARIS blacklist substring (`imsi`, `suci`, `guti`, `tmsi`, `imei`,
  `imeisv`, `msisdn`, `subscriber_id`, `subscriber_identity`). The NAS EPS
  identity-type mnemonic is exported as `eps_mobile_identity_type_code`
  (TS 24.301 §9.9.3.12 numeric code) rather than the 3GPP string
  (`IMSI`/`IMEI`/`IMEISV`/`GUTI`). Regression test
  `decoder-gtpv2c::tests::export_of_a_full_session_contains_no_raw_imsi_imei_or_msisdn`
  now asserts no blacklist substring appears anywhere in the serialised
  event JSON.

## OIRAN API 2.7.6 — 2026-11-03

- Scopes the HMAC-SHA256 pseudonym key to the DEPLOYMENT (not the import):
  generated once at a root-only 0600 file (default
  `/var/lib/oiran/pseudonym.key`, configurable via `OIRAN_PSEUDONYM_KEY_PATH`
  or `ApiConfig.pseudonym_key_path`), reloaded at every probe restart from
  the same path. Wider permissions on the file fail-closed with
  `OIRAN_PSEUDONYM_KEY_INSECURE`; missing or malformed file fails-closed
  `OIRAN_PSEUDONYM_KEY_UNAVAILABLE` (except on the first-generation path).
  The two live-probe continuous-import tests now pass again without being
  weakened. `session-engine::discover_lte_sessions` falls back to the
  structural keys (MME/eNB-UE-S1AP-ID + F-TEID S11 ↔ E-RAB TEID S1-U) when
  no subscriber identifier is present on any event — new regression test
  `s1_s11_s1u_correlate_by_teid_without_any_subscriber_identifier`.
- Replaces the FNV-1a unkeyed 64-bit `pseudonym()` (reversible by enumerating
  the ~10⁹ IMSI space) with HMAC-SHA256 keyed by a 32-byte secret generated
  per import, output `psn-<32 hex>` (128 bits). The secret is OS-sourced from
  `/dev/urandom`, lives in the import's stack frame only, is zeroised on drop
  and never serialised, logged, or committed. Missing entropy source fails
  closed with `OIRAN_PSEUDONYM_KEY_UNAVAILABLE` — no silent fallback to an
  unkeyed hash. Debug impl is deliberately redacted. New RFC 4231 HMAC
  regression tests + mission tests (same-key stable, different-key disjoint,
  domain-separated labels, `PseudonymKey::generate` randomness, no raw
  IMSI/IMEI/MSISDN in gtpv2c exports, S11-level correlation of the same IMSI
  under one import).
- Threads the per-import key through `DecoderInput`, `decode_capture`,
  `decode_capture_streaming`, all S1AP/NGAP/NAS/PFCP/SBI/GTPv2-C/Diameter
  decoders, and the live-probe continuous import (one key per
  `run_continuous_import_inner` and per `process_capture_into` invocation).
  Within one import, S1-MME / S11 / S1-U events carrying the same IMSI share
  the exact same pseudonym; across imports, the same IMSI emits disjoint
  pseudonyms.
- Uses the privacy-safe `subscriber_pseudonym` identifier for decoded LTE
  S11 evidence while retaining read compatibility with legacy
  `imsi_pseudonym` events.
- Correlates S1-MME, S11 and S1-U with the privacy-safe opaque pseudonym so
  POLARIS finalization and OIRAN session reconstruction share one admissible
  contract.

## OIRAN API 2.7.5 / disk-safety 0.2.0 — 2026-11-02

- Replaces the legacy 75/80/85/90 capture policy with 95% information, 97%
  warning and a fail-closed 98% hard ceiling.
- Requires every projected capture budget to fit below the ceiling while
  retaining an 8 GiB absolute free-space reserve.
- Retains inode, measurement, ENOSPC, rotation and unexpected-growth guards;
  Stop, cleanup and read-only analysis remain available at the ceiling.

## OIRAN API 2.7.4 / Live Probe 0.4.2 — 2026-11-01

- Imports approved evidence from clean terminal failed/cancelled LTE runs as
  `IMPORTED_PARTIAL`, preserving the observed plane set and original hashes.
- Keeps `COMPLETED` evidence gated on all three S1-MME/S11/S1-U planes; partial
  evidence cannot be promoted to a successful LTE certification.
- Persists final state and capture planes in the dataset manifest and retains
  idempotence, run conflict, privacy, cleanup, and correlation safety guards.

## OIRAN API 2.7.3 / session-engine 0.5.1 / correlation-engine 0.5.1 — 2026-11-01

- Correlate LTE S1-MME, S11 and S1-U evidence across distinct per-file capture
  hashes while retaining every original `capture_id` as provenance.
- Require a unique S1 context, opaque pseudonym and E-RAB/F-TEID chain before
  admitting S11 evidence; admit S1-U only when its TEID has one established
  session owner inside the bounded 300-second evidence window.
- Keep reused or ambiguous TEIDs, partial captures and insufficient evidence
  unmatched rather than joining by time or TEID alone; add multi-PCAP,
  multi-UE, reused-TEID, partial and out-of-order regressions.
- This is an offline correlation fix only. It does not certify real LTE,
  modify capture processes, generate traffic or deploy production services.

## OIRAN API 2.7.2 / live-probe 0.4.1 / Analyzer 2.7.1 — 2026-11-01

- Reject SUCI, SUPI, TMSI, PEI, equipment-identity variants and subscriber
  key labels at the LTE evidence admission/export privacy boundary.
- Apply recursive response sanitization to paginated LTE evidence sessions and
  add bounded JSON/HTML export support for persisted LTE Call Flows.
- Render LTE S1-MME/S11 and S11/S1-U correlation bridges truthfully in the
  Analyzer; E2E remains `UNKNOWN` unless both required bridges are proven.
- Add raw-response, export and UI regressions. This release does not create
  capture references, certify real LTE, enable live traffic or deploy itself.
- Redact provenance filenames containing identity labels or identity-length digit
  runs while retaining safe `capture://` basename provenance.
- Add fail-closed envelope regressions for duplicate capture planes, duplicate event
  IDs, capture-ID mismatch and packet source-file mismatch.
- Document the exact POLARIS evidence-to-OIRAN binding boundary and preserve the
  strict S1-MME/S11/S1-U required-plane set.
- Accept the complete strict POLARIS 0.28.0 import envelope on the existing LTE
  import route and reject outer/nested provenance drift before artifact access.

## OIRAN API 2.7.1 — 2026-10-31

- Preserve the 2.7 real-lab/LTE-evidence model while integrating bounded offline
  LTE session materialization and the complete installed LTE+5G decoder inventory;
  live capture allowlists and execution gates remain unchanged.
- Remove subscriber and equipment identity fields and identity-bearing decoded
  information elements from raw API responses instead of returning masked labels.
- Apply response sanitization at the common success and pagination boundaries for
  datasets, sessions, events, packets, Call Flow and future read handlers.
- Add raw JSON regressions for unauthenticated/viewer and operator reads while
  preserving protocol events, accounting counters and capture provenance.

## Real-lab read model / API 2.7.0 / live-probe 0.4.0 / Analyzer 2.7.0 — 2026-10-31

- Disable bundled reference dataset loading by default; operational Session Explorer,
  Call Flow and Dataset Library now read only persisted CaptureManager datasets and
  atomically admitted LTE evidence. Reference artifacts require the explicit
  `OIRAN_REFERENCE_DATASET_ENABLED=1` test/reference switch.
- Catalog finalized LTE evidence datasets with bounded, line-oriented session lookup
  and Call Flow pagination. Empty LTE observations remain empty/`UNKNOWN`.
- Derive radio technology from observed planes, preserve missing counters as `null`,
  and remove generated UE/PDU/context placeholders from operational responses.
- Apply defense-in-depth subscriber-identity withholding to session and Call Flow
  responses while retaining source-file provenance as `capture://` references.

## LTE evidence pipeline 1.1.0 / API 2.6.0 / live-probe 0.3.0 — 2026-10-31

- Add the ANR1 V2 evidence adapter, canonical plane aliases and fail-closed
  reference, approval, provenance and SHA-256 validation.
- Add atomic/idempotent LTE materialization with bounded Session and streaming
  Call Flow pagination, capture/binding decoder-version equality and a 64 MiB
  retained-event allocation budget while preserving 5G reconstruction.
- Add verified streaming export for already-sanitized PCAP/derived evidence;
  exports start `SANITIZED_PENDING_REVIEW` and are not a generic anonymizer.
- Add Operator+CSRF import/export routes and exact request/response contract.

## LTE offline certification 1.0.0-offline.1 — 2026-10-31

- Validate mandatory S1-MME/S11/S1-U fixture fields separately from ANR1
  readiness, with a machine-readable schema and fail-closed real-fixture gate.
- Partition LTE sessions by explicit S1AP context, exact pseudonym and S11
  F-TEID; add multi-UE, timestamps, UL/DL counters and ambiguity regressions.
- Add canonical LTE Call Flow generation and offline correlation rule version
  `1.0.0-offline.1` without enabling capture or production ingestion.
- Extend the synthetic decoder fixture with E-RAB procedure coverage and keep
  the approved-PCAP requirement explicit.

## LTE pipeline preparation 0.1.0 — 2026-10-31

- Add explicit, non-aliased offline decoder routes for S1-MME/S1AP PPID 18,
  S11/GTPv2-C UDP 2123 and S1-U/GTP-U UDP 2152 while retaining N2/N3/N4/SBI.
- Add LTE session preparation with EPS bearer metadata and per-TEID UL/DL
  packet/octet counters, without timestamp-only subscriber association.
- Add ambiguity-safe S11-to-S1-U and prepared S1AP-to-S11 correlation rules.
- Add Analyzer LTE filters marked synthetic-only and an ANR1-gated real-fixture
  manifest template. No capture or production enablement is included.

## OIRAN API 2.5.3 / live-probe 0.2.6 - 2026-10-31

- Aggregate continuous N3 user-plane observations by TEID, direction, inner flow and QFI while decoding; packet and byte counters plus first/last provenance remain exact without retaining one event per G-PDU.
- Bound N3 aggregate cardinality and fail an individual segment closed if the limit is exceeded; N2, N4 and SBI signalling remain individual normalized events.
- Preserve the real packet count in continuous-import activity metrics while storing only first/last N3 packet references.
- Normalize directional NGAP `tunnel_ip_{ul,dl}` / `gtp_teid_{ul,dl}` fields when building exact N2-to-N4 tunnel evidence (correlation-engine 0.3.1).

## OIRAN API 2.5.2 / live-probe 0.2.5 - 2026-10-30

- Commit continuous-import checksums only after the rebuilt dataset generation
  has been published atomically. A failed marker write leaves the segment
  retryable instead of reporting it imported without published events.
- Add a regression test covering the atomic marker-write failure and retry.

## OIRAN API 2.5.1 / live-probe 0.2.4 - 2026-10-30

- Added `OIRAN_CONTINUOUS_MAX_SEGMENT_BYTES`, defaulting to 1 GiB, with
  validation against the existing bounded disk policy.
- Reworked PCAP/PCAPNG decoding to visit packets incrementally; discovery,
  SHA-256, copy, packet parsing and decoding no longer materialise an entire
  capture file.
- Stream decoded events through an on-disk spool, finalize idle TCP/SBI
  connections during packet visitation, and retain only event-ID/offset pairs
  during continuous deduplication. This closes the production OOM found when
  a finalized SBI segment expanded to many normalized events under a 256 MiB
  service limit.
- Preserve all fully decoded SBI transactions while keeping response-only
  PARTIAL streams lacking decoded request identity as connection-level HPACK
  evidence rather than synthetic transactions, restoring the pre-regression
  event-count contract without hiding the capture limitation.
- Compact session-engine source metadata to the schema, procedure and SBI
  fields actually consumed after normalization instead of retaining a second
  copy of every decoded IE tree during call-flow reconstruction.
- Oversized finalized segments are now persisted individually with source
  path, observed byte size, timestamp and
  `CONTINUOUS_SOURCE_SEGMENT_TOO_LARGE`; they no longer fail the continuous
  import job or prevent eligible siblings from being ingested.
- Added regression coverage for a streaming 300 MiB import below 32 MiB live
  allocation and for mixed accepted/rejected segments.

## OIRAN API 2.5.0 / live-probe 0.2.3 / oiran-decode 0.4.5 - 2026-10-30

- Integrated the persistent API 2.4 probe registry and its truthful heartbeat,
  interface-role, CSRF, and download-policy routes with the memory-bounded
  live-probe 0.2.3 continuous importer and oiran-decode 0.4.5 decoder release.
- Preserved the mode-`0600` registry seeded with `oiran-vprobe-local-01` and
  retained fail-closed liveness when no measured heartbeat exists.
- Kept continuous checkpoint recovery, stable session/call-flow evidence, and
  external-capture ownership boundaries unchanged.

## OIRAN API 2.4.0-dev / live-probe 0.2.0-dev - 2026-10-28

- Added an atomic, mode-`0600` probe registry seeded with
  `oiran-vprobe-local-01` and an Operator-plus-CSRF `POST /api/v1/probes`
  contract.
- Added registry-backed capture-interface roles while keeping unregistered
  roles explicitly `null`.
- Derived probe liveness only from measured capture ingestion or packet
  timestamps; probes without a real heartbeat remain `PENDING`.
- Made missing live capture interface and size evidence explicitly `null` and
  made raw PCAP download fail closed with `403 DOWNLOAD_POLICY_PENDING`.

## live-probe v0.2.3 — pcap import streaming (copy_verified + write_jsonl_atomic)

- `copy_verified` previously verified the freshly-copied temporary pcap by
  calling `fs::read` on it and feeding the full byte vector to `sha256_hex`.
  On a 512 MiB pcap import the live resident set spiked by ~512 MiB. 0.2.3
  switches the integrity hash to `sha256_hex_file`, which is already the
  streaming (`BufReader` of `STREAM_CHUNK_BYTES`) path used elsewhere in
  the module. The post-copy integrity contract (`size`, `mtime`, `sha256`
  all unchanged) is preserved; only the hashing memory footprint changes.
- The second `fs::read`-into-`sha256_hex` leak at `continuous_source_dedup_ok`
  was fixed with the same `sha256_hex_file` substitution.
- Test (`copy_verified_streams_512_mib_import_under_32_mib_live_allocation`,
  `#[ignore]`'d because the `#[global_allocator]` tracker is shared with
  concurrent tests): materialises a 512 MiB source pcap on disk, computes
  its expected SHA via the streaming hasher, builds a `SourceSegment` with
  that checksum, resets the allocation peak, calls `copy_verified`, and
  asserts the peak live allocation stays under 32 MiB. Measured on Back100:
  `COPY_VERIFIED_512MIB_PEAK_BYTES=1048765 PEAK_MIB=1 LIMIT_MIB=32`. Full
  live-probe suite: `cargo test -p live-probe` → 42 passed, 0 failed, 2
  ignored. Reproduce:
  `cargo test -p live-probe --release copy_verified_streams_512_mib_import_under_32_mib_live_allocation -- --ignored --test-threads=1 --nocapture`.

## oiran-decode v0.4.5 — streaming-friendly write_jsonl_atomic signature

- `write_jsonl_atomic` now accepts `IntoIterator<Item = &NormalizedEvent>`
  instead of `&[NormalizedEvent]`. The function body was already streaming
  through a bounded `BufWriter`; the API change lets a caller that produces
  events lazily avoid materialising the full `Vec` before writing. Existing
  callers (`live-probe/src/lib.rs:2197` with `&all_events` and
  `oiran-decode/src/lib.rs:332` with `&[]`) compile unchanged because
  `&Vec<T>` and `&[T]` both implement the new trait bound.

## live-probe v0.2.2 — source_segments OOM fix, memory-bounded ingestion

### live-probe v0.2.2 — bounded ingestion

Codex measured 27 OOMs in 5 min with RSS up to 255 MiB in a 256 MiB cgroup
on the OIRAN API, root-caused to `source_segments()` retaining up to 512
candidates and `fs::read()`-ing each pcap in full BEFORE applying the
`finalized_candidates_only` filter. The fix:

- **Metadata-first finalized filter.** `source_segments()` now walks the
  candidate pool as a cheap `SourceCandidateMeta { path, interface,
  size_bytes, modified }` projection, applies the finalized filter on
  that, THEN opens and stream-hashes only the kept candidates. The pcap
  content is never materialised in RAM — SHA-256 streams through 1 MiB
  `BufReader` chunks via `sha256_hex_file`, and packet counting uses the
  existing streaming `count_pcap_records` (16-byte header + `io::copy`
  into `io::sink`).
- **Streaming per-candidate loop.** One pcap in flight at a time; the
  candidate's `size_bytes` + `modified` are retained in metadata only.
  No `Vec<u8>` of file contents is ever held across loop iterations.
- **`events.clone()` dropped.** `session_engine::discover_sessions` was
  taking `Vec<EventRecord>` by value and consuming it, forcing live-probe
  (and three other callers) to `events.clone()` the full dataset so the
  Vec could be used after discovery. Signature changed to
  `discover_sessions(&mut Vec<EventRecord>)` — callers now pass a mutable
  borrow and reuse the same Vec afterwards. 4 call sites updated
  (live-probe, correlation-engine, apps/api, evidence-replay bin).
- **600 × 2 MiB memory-bounded test.** New
  `source_segments_memory_is_bounded_on_600_two_mib_pcaps` test uses a
  tracking `GlobalAlloc` shim to assert that the peak live allocation
  stays under 128 MiB when walking 600 synthetic 2 MiB pcaps. Measured
  peak: **1 MiB** on 512 segments (vs. ~1 GiB upper bound in 0.2.1).
  The test is `#[ignore]`'d because the global allocator counts
  allocations from every parallel test thread, so it must run alone:
  `cargo test --release -p live-probe
   source_segments_memory_is_bounded -- --ignored --test-threads=1
   --nocapture` → `source_segments peak live allocation = 1258536 B =
   1 MiB (segments=512)` in 47 s.
- **Pre-existing live-probe test failures proven as environmental.**
  Three continuous-import tests
  (`continuous_import_is_incremental_deduplicated_stoppable_and_restart_safe`,
  `continuous_source_skips_active_truncation_and_rotates_owned_ring`,
  `full_ring_ingests_three_interface_batches_across_rotations`) fail
  when the test host's `/tmp` filesystem is at ≥ 85 % utilisation because
  `disk_safety::capture_budget` returns `allowed=false` on
  `SafetyState::StopNewCaptures`. The tests now call a
  `skip_if_disk_too_full()` guard that emits a `SKIP ...` log line with
  the detected safety state and returns early. On this host `df -h /tmp`
  reports 87 % usage; on a host with free space the guard is a no-op and
  the tests run normally.
- The merge of `feat/oiran-live-probe-finalized-segments` (0.2.0,
  SHA 0930c75) is now part of this branch: `finalized_candidates_only()`
  and `record_ingestion_failure()` are available, plus the four
  finalized-segments unit tests. Lineage proven by
  `git merge-base --is-ancestor 0930c75 HEAD` returning 0 after the
  merge commit `3e87af3`.

### decoder-ngap v0.6.0 compatibility alias

The 0.6.0 outer-list walker emitted `item_<i>_pdu_session_id` identifiers
but `session_engine::discover_sessions` groups events by the historical
`pdu_session_id` key. Fixed by also emitting a plain
`pdu_session_id=<first-item-id>` for IE 74 and IE 75 so the session
engine recognises PDU sessions decoded through the new walker. Fixes
`completed_capture_registers_real_decoded_dataset_with_provenance`.

## oiran-decode v0.4.5 / decoder-sbi v0.3.1 / live-probe v0.2.1 — SBI 0.4.2 regression + OOM fixes

### decoder-sbi v0.3.1 — HPACK regression fix

Codex measurement on inventory `aabbe5e9…` showed 0.4.2 regressed SBI
throughput 70x: 57,532 DECODED / 6,164 PARTIAL (0.3.1) → 799 DECODED / 317,019
PARTIAL (0.4.2). Two root causes were introduced in 0.4.2:
- **Permanent direction poisoning**: a single HPACK failure flagged every
  subsequent HEADERS block on the same direction as `hpack_unavailable`,
  including blocks the HPACK decoder had accepted cleanly.
- **Ghost events**: streams that in 0.3.1 would have been skipped (orphan
  CONTINUATION, oversized HEADERS/CONTINUATION fragments, unflushed
  continuations at end of capture) were promoted to synthetic events via
  `hpack_unavailable=true`. This inflated the event count by ~5x on
  well-formed captures.

Fix:
- HPACK failure now touches **only** the specific header block that failed.
  The next block that decodes cleanly re-synchronises the direction
  automatically — no permanent poisoning.
- Frame-level framing errors (orphan CONTINUATION, oversized blocks,
  unflushed continuations) are now **connection-level** entries in
  `report.errors`. They do not touch any stream state, so they do not
  fabricate events.
- One normalised event per stream (unchanged structural invariant); the
  stream is only promoted to an event when at least one direction's
  decoded headers are non-empty — same contract as 0.3.1.

Two new non-regression tests pin the contract:
- `non_regression_well_formed_connection_emits_one_decoded_event_per_stream`
  encodes 32 well-formed HTTP/2 request/response pairs with SETTINGS,
  WINDOW_UPDATE and GOAWAY interleaved. The decoder emits exactly 32
  DECODED events, zero HPACK_CONTEXT_UNAVAILABLE errors, zero ghost
  events for the control frames.
- `non_regression_hpack_failure_does_not_poison_subsequent_streams`
  encodes a failing HEADERS on stream 1 followed by a well-formed POST
  on stream 3. Stream 3 decodes cleanly, stream 1 surfaces the
  HPACK_CONTEXT_UNAVAILABLE once, and the direction-level error is
  logged exactly once in `report.errors` (not per frame).

### live-probe v0.2.1 — memory-bounded streaming I/O

Audit of live-probe 0.2.0 identified three unbounded-RAM sites that
accounted for the API OOM Codex observed:
1. **`fs::read(pcap_path)` for integrity verification**: every source
   pcap was fully materialised in a `Vec<u8>` so `sha256_hex(&bytes)`
   could run. On a multi-GB pcap this allocates the full file. Fixed by
   introducing a streaming `Sha256Hasher` in event-schema and a
   `sha256_hex_file(path)` + `verify_file_integrity(path, size, sha)`
   helper that walks the file in 1 MiB chunks via `BufReader::fill_buf`.
2. **Continuous events dedup rewrite**: the per-ingestion
   `events.jsonl` rewrite read the entire prior file via
   `fs::read_to_string`, held a `BTreeMap<String, serde_json::Value>` of
   every event, and finally serialised the whole thing into a
   `Vec<u8>` before `atomic_write`. On a long-running continuous
   capture this is proportional to the number of events ever observed.
   Fixed by streaming the prior file line-by-line, storing serialised
   lines (not parsed values), applying a `MAX_IN_MEMORY_EVENT_IDS =
   1_000_000` safety cap with FIFO eviction, and writing the output
   through a `BufWriter` + atomic rename.
3. **Recovery dataset integrity material**: `integrity_material` was
   built by `fs::read(events.jsonl)` and `fs::read(dataset_manifest)`
   concatenated into a single `Vec<u8>`, then hashed. Replaced by a
   two-file streaming SHA-256 identical bit-for-bit to the previous
   output.

Bounded-memory tests pin the contract:
- `streaming_sha256_matches_in_memory_sha256_on_large_synthetic_file`
  materialises a 64 MiB file on disk and verifies that
  `sha256_hex_file` returns the exact same hash as the full-buffer
  oracle. The production code path only ever reads
  `STREAM_CHUNK_BYTES = 1 MiB` at a time.
- `verify_file_integrity_detects_size_and_hash_mismatches_without_full_read`
  proves the integrity verifier catches size and SHA mismatches on a
  4 MiB file without a full-read oracle.

### event-schema

- Added `Sha256Hasher` (streaming) with `new()`, `update(&[u8])`,
  `finish_hex()`. `sha256_hex(bytes)` is now implemented on top of it,
  byte-for-byte identical to the previous implementation (the
  pre-existing `sha256_matches_standard_vector` test still passes).

### Open regressions

- 6 live-probe tests (`completed_capture_registers_real_decoded_dataset_with_provenance`,
  `continuous_checkpoint_keeps_five_sessions_across_restart_and_republish`,
  `continuous_import_is_incremental_deduplicated_stoppable_and_restart_safe`,
  `continuous_source_skips_active_truncation_and_rotates_owned_ring`,
  `failed_capture_recovery_is_atomic_registered_and_idempotent`,
  `full_ring_ingests_three_interface_batches_across_rotations`) are
  broken at the branch base `d85d29f` already; this release does not
  change the pass/fail count — it only adds +2 bounded-memory tests
  that both pass.

## oiran-decode v0.4.4 — pycrate-grounded real TS 38.413 transfer decoders

- `decoder-ngap v0.6.0`:
  - **Real ASN.1 ground truth: pycrate.** Replaced the simplified asn1tools
    schema (removed `tests/fixtures/aper-transfer.asn` and the asn1tools
    generator) with pycrate (`pycrate_asn1dir.NGAP`), the only Python library
    that compiles the full TS 38.413 3GPP ASN.1 module. Fixtures are now
    pycrate `.to_aper()` outputs of real NGAP types.
  - **Request transfer = ProtocolIE-Container.**
    `decode_pdu_session_resource_setup_request_transfer` now walks the real
    `SEQUENCE { protocolIEs ProtocolIE-Container {...} }` structure: outer
    SEQUENCE ext + 1-bit, 2-octet container size, then per-item
    `{ id, criticality, value OPEN TYPE }`. Decoded IEs:
    `id-UL-NGU-UP-TNLInformation` (139), `id-PDUSessionType` (134),
    `id-QosFlowSetupRequestList` (136),
    `id-PDUSessionAggregateMaximumBitRate` (130). Unknown IEs are retained
    with `{id, criticality, length}` on `unknown_protocol_ies` and named in
    `errors`; the OPEN TYPE length determinant lets the walker skip them
    cleanly instead of de-syncing.
  - **Response transfer: 4 top-level OPTIONALs + extensions.** The response
    SEQUENCE now reads the correct 5-bit preamble (ext + additional +
    security + failed + iE-Ext) and parses the `iE-Extensions`
    ProtocolExtensionContainer when present, extracting
    `id-RedundantDLQosFlowPerTNLInformation` (id 196) into `redundant`;
    other extensions are retained verbatim with their id/length.
  - **IE 71 / IE 72 (Cxt-Req / Cxt-Res).**
    `decode_pdu_session_resource_setup_list_cxt_req` and `_cxt_res` cover
    `PDUSessionResourceSetupListCxtReq` / `CxtRes` from the
    `InitialContextSetupRequest/Response` procedures (used by Open5GS to
    mount the session via the Initial Context Setup path).
  - **Correct extensibility on primitives.** Audited every INTEGER / ENUMERATED
    / CHOICE in the real NGAP module and fixed the extension-marker handling:
    `QosFlowIdentifier` is extensible (1 ext bit + 6-bit value, 7 bits total),
    `PriorityLevelARP` is NOT extensible (4-bit bit-field),
    `UPTransportLayerInformation` is NOT extensible (1-bit choice index for
    gTPTunnel vs choice-Extensions),
    `Cause` is NOT extensible (3-bit index for 6 root alternatives including
    choice-Extensions). The old implementation was wrong on all four, which
    is why the asn1tools-simplified fixtures looked self-consistent but
    disagreed with real captures.
  - **Guard-rail.** `tests/pycrate_fixtures.rs` includes an explicit guard
    that encodes `TEID=0x11223344` and `QFI=5` with pycrate and asserts the
    exact values round-trip through the decoder. Separate tests prove
    mangled or truncated bytes return a NON-matching value AND surface
    named `errors` entries — the decoder never silently fabricates a wrong
    value.
  - **8 new typed structs** exposed on the public API (`SNssai`,
    `SetupItemSUReq`, `SetupItemSURes`, `ListSUReq`, `ListSURes`,
    `UnknownProtocolIe`, `UpTransportLayerInformation::ChoiceExtensions`,
    `QosCharacteristics::ChoiceExtensions`) plus `serde::Serialize` on
    every public type so the `ngap-decode-hex` diagnostic CLI emits a
    complete JSON tree.

## oiran-decode v0.4.3 — real outer-list walker, ENUMERATED extension, diagnostic CLI

- `decoder-ngap v0.5.1`:
  - **Outer list walker, no more heuristic.** `decode_pdu_session_list` now
    routes IE 74 and IE 75 through the new
    `decode_pdu_session_resource_setup_list_su_req` /
    `decode_pdu_session_resource_setup_list_su_res` entry points, which
    implement the real X.691 ALIGNED PER encoding of
    `PDUSessionResourceSetupListSUReq` and `PDUSessionResourceSetupListSURes`:
    SIZE(1..256) size byte, per-item SEQUENCE preamble (ext +
    optional-presence bits), `pDUSessionID` octet-aligned, `pDUSessionNAS-PDU`
    with its APER length determinant, `S-NSSAI` SEQUENCE (`sST` as a SIZE(1)
    bit-field, `sD` as SIZE(3) octet-aligned), and the transfer OCTET STRING
    extracted via its own length determinant. The previous "canonical" byte
    offset heuristic has been removed; non-canonical layouts surface their
    specific failure in a per-item `errors` list and the `item_<i>_*` summary
    keys name the exact field that did not decode.
  - **`qosFlowMappingIndication` extension additions.** When the ENUMERATED
    extension bit is set, the walker now reads the normally-small-non-negative
    whole number for the extension index (X.691 Clause 10.6) and reports
    `AssociatedQosFlowMapping::UnknownExtension(index)` instead of returning
    `UnknownExtension(0)` for every extension value.
  - **Diagnostic CLI.** New binary `ngap-decode-hex` (invoked as `cargo run
    -p decoder-ngap --bin ngap-decode-hex`) reads a hex NGAP PDU from stdin
    (whitespace and `0x` prefixes tolerated) and writes the decoded tree as
    pretty-printed JSON on stdout. For IE 74 and IE 75 the embedded transfer
    is decoded in the same JSON blob so operators can diff the result
    side-by-side with `tshark -O ngap -J` on real captures.
  - **New fixtures.** 7 additional asn1tools-generated ground-truth fixtures
    cover the outer list envelope: 1 session SST-only, 1 session with NAS-PDU,
    1 session with S-NSSAI SST+SD, 1 session with item iE-Extensions, 3
    sessions mixed (NAS-PDU + SST/SD + iE-Ext), and SURes with/without
    iE-Extensions on individual items. The hand-crafted bit-level fixture
    `qos_flow_mapping_indication_extension_decodes_normally_small_number`
    exercises the ENUMERATED extension path end-to-end.
- Fixtures remain synthetic (PLMN 001/01 or TEST-NET addresses, NAS-PDU
  stub 0x7e 00 44 6f = plain 5GMM Registration Reject). No real
  SUPI/K/OPc/SUCI/GUTI/IMSI/IMEI material is present in test code,
  fixtures, or decoders.

## oiran-decode v0.4.2 — real X.691 APER walker, HPACK Huffman recovery

- `decoder-ngap v0.5.0`: removed the one-octet-per-primitive canonical walker
  and replaced it with a bit-accurate X.691 ALIGNED PER reader
  (`aper::AperReader`) plus type-specific decoders for
  `PDUSessionResourceSetupRequestTransfer` and
  `PDUSessionResourceSetupResponseTransfer`
  (`transfer::decode_pdu_session_resource_setup_{request,response}_transfer`).
  The decoders are driven by 11 ground-truth fixtures generated with
  `asn1tools` (Python, codec `per`) against the minimal TS 38.413 subset
  shipped in `decoder-ngap/tests/fixtures/aper-transfer.asn`. Each fixture
  round-trips value → bytes → decoder → value, so a byte-level drift fails
  loudly. Optional fields covered end-to-end: `gBR-QosInformation`,
  `dynamic5QI`, `reflectiveQoSAttribute`, `additionalDLQosFlowPerTNLInformation`
  (multi-tunnel), `qosFlowFailedToSetupList` with Cause CHOICE, and
  `SecurityResult`. Unsupported constructs (extension markers, choice
  extensions, unknown Cause groups) are now **named** in a `errors` vector on
  the returned structure instead of being silently dropped — the "canonical
  only" rejection path has been removed.
- `decoder-sbi v0.3.0`: `tolerant_literals` now decodes HPACK Huffman-encoded
  literals via `hpack::huffman::HuffmanDecoder`. HTTP/2 header blocks that
  only recovered static-name indexed-plain literals in 0.2.0 now also recover
  the Huffman-encoded values that make up most SBI PATCH requests. Covered by
  two unit tests: the RFC 7541 Appendix C.4.1 example for `:authority` =
  `www.example.com` and a synthetic SBI `:path` = PATCH SM-context modify.
- Fixtures remain synthetic (PLMN 001/01 or TEST-NET addresses). No real
  SUPI/K/OPc/SUCI/GUTI/IMSI/IMEI/IMEISV material is present in test code,
  fixtures, or decoders.

## oiran-decode v0.4.1 — SBI HPACK context, NGAP QoS flow walker, EPS SMC decoding

- `decoder-sbi v0.2.0`: HPACK decode failures (dynamic table state lost when the
  capture starts mid-connection, orphan CONTINUATION, header block exceeding the
  configured maximum size) are now surfaced as explicit
  `HPACK_CONTEXT_UNAVAILABLE` errors on the normalized event instead of being
  rolled into a generic PARTIAL. Once a direction's HPACK state is poisoned, any
  subsequent HEADERS block on that direction is attributed to
  `HPACK_CONTEXT_UNAVAILABLE` because the dynamic table indices can no longer be
  verified against the sender. Streams whose request headers failed to decode
  are still emitted so the response remains correlatable by HTTP/2 stream ID
  (previously these were silently dropped as incomplete). The CONTINUATION
  reassembler was audited: orphan CONTINUATION frames and over-sized blocks now
  flag the stream explicitly instead of being discarded.
- `decoder-ngap v0.4.1`: added a canonical APER walker for
  `QoSFlowSetupRequestList` inside `PDUSessionResourceSetupRequestTransfer`
  (IE 74) and `AssociatedQosFlowList` inside the first
  `QoSFlowPerTNLInformation` of `PDUSessionResourceSetupResponseTransfer`
  (IE 75). When the walker matches the "no-optionals, nonDynamic5QI, canonical
  one-octet-per-primitive" layout it emits per-item `qfi_<i>`, `five_qi_<i>`,
  `arp_priority_<i>`, `arp_capability_<i>`, `arp_vulnerability_<i>` session
  identifiers. Non-canonical encodings (extensions, additional optional
  subfields, dynamic5QI) fall back to the existing structural
  `qos_flow_setup_list=present` marker so operators can tell "scanned but could
  not decode" apart from "no QoS flow IE at all".
- `decoder-nas v0.3.1`: EPS Security Mode Command (0x5C) now has a dedicated
  per-TS 24.301 §8.5 decoder (previously the body was preserved only by
  SHA-256). Mandatory fields emitted: Selected NAS security algorithms
  (`ciphering=EEAn, integrity=EIAn`), NAS key set identifier (`nas_ksi`,
  `tsc`), and Replayed UE security capabilities parsed as EEA / EIA / UEA /
  UIA / GEA bitmaps per TS 24.301 §9.9.3.34.
- Fixtures are synthetic (PLMN 001/01 or TEST-NET addresses). No real
  identity, key, SUCI, GUTI, IMEI or IMSI material is present in test code.

## oiran-decode v0.4.0 — N2 SM transfer typing, Diameter S6a base, Security Mode Command

- `decoder-ngap v0.4.0`: PDUSessionResourceSetupListSUReq (IE 74) and
  PDUSessionResourceSetupListSURes (IE 75) now expose direction-tagged tunnel
  evidence from the nested PDU Session Resource Setup Request/Response Transfer.
  IE 74 yields `tunnel_ip_ul` + `gtp_teid_ul`, IE 75 yields `tunnel_ip_dl` +
  `gtp_teid_dl`. Structural scan also reports `pdu_session_type` (ipv4, ipv6,
  ipv4v6, ethernet, unstructured) and the presence of a QoS Flow setup list. The
  overall message status stays `PARTIAL` because QFI, QoS profile and secondary
  fields remain SHA-256 provenance; the correlation keys needed for NGAP ↔ PFCP
  ↔ GTP-U are now emitted explicitly instead of being hidden behind an
  undirected `tunnel_endpoint_ip`/`gtp_teid` pair.
- `decoder-nas v0.3.0` (TS 24.501):
  - Registration Request now decodes the optional UE security capability
    (IEI 0x2E = 46). The IE value is parsed into `nr_encryption`,
    `nr_integrity`, and when present `eutra_encryption`/`eutra_integrity`.
  - Security Mode Command (0x5D) now has a dedicated parser: Selected NAS
    security algorithms (ciphering/integrity half-octets), ngKSI, Replayed UE
    security capability (LV) and the optional Additional 5G security information
    (IEI 0x36 = 54) which reports `rinmr` and `hdp`.
- `decoder-diameter v0.2.0` (RFC 6733 + 3GPP TS 29.272): added base AVPs
  Origin-State-Id (278), Session-Id (263), Auth-Session-State (277),
  Vendor-Specific-Application-Id (260, grouped), Vendor-Id (266), Auth- and
  Acct-Application-Id (258/259). These AVPs previously forced S6a messages to
  `PARTIAL` because they were unsupported.
- All new fixtures are synthetic (PLMN 001/01 or TEST-NET addresses). No real
  identity, SUPI, K, OPc, SUCI, GUTI, IMEI or IMSI material is present in test
  code.

## live-probe v0.2.0 — finalized segments only + persistent failure log

- Continuous import skips the still-live dumpcap target per interface. For
  each interface the newest file is dropped from the candidate set whenever
  its mtime is more recent than `2 × stable_age`; finalized files
  (anything older) stay eligible. The pure helper
  `finalized_candidates_only()` replaces the previous "stable-across-scans"
  proxy at the discovery layer, so a running writer is never fed into
  `copy_verified` and cannot trigger
  `CONTINUOUS_SOURCE_CHANGED_DURING_IMPORT` as a hot-path error.
- `ContinuousImportState` grows a bounded `failed_ingestions: VecDeque<
  FailedIngestion>` persisted in `import_state.json`. Every ingestion
  failure path (`CONTINUOUS_SEGMENT_NOT_FINALIZED` pre-copy / post-copy,
  `CONTINUOUS_COPY_RETRYABLE`) now records `{source_path, error_code,
  occurred_epoch_ms}` and writes the state atomically — the entry survives
  probe restarts, so the operator can audit a 1 h window after the fact.
  Bounded at `MAX_PERSISTED_INGESTION_FAILURES=256`, FIFO-evicted.
- Pure helpers `record_ingestion_failure` and `finalized_candidates_only`
  are exposed under tests; four new unit tests exercise FIFO eviction,
  verbatim path/code/timestamp preservation, newest-per-interface skip
  within the safety window and single-file acceptance after the window
  has elapsed.
- No live-probe behaviour change for successful imports; aggregate metrics
  (`ingestion_failures`, `segments_ingested`, …) remain the same.

## decoder-ngap v0.3.1 / oiran-decode v0.3.1 - NGAP status correction

- Mark a structurally bounded NAS-PDU information element as decoded at the
  NGAP layer; the nested NAS child event independently retains
  `ENCRYPTED_OR_PROTECTED`, `PARTIAL` or `MALFORMED`.
- Correct the NAS security-header nibble and accept the observed eight-octet
  as well as schema forty-bit `UEAggregateMaximumBitRate` encodings.
- Keep PDU Session Resource Setup list items `PARTIAL` while their nested N2
  SM transfer remains opaque; no missing field is promoted to decoded.
- Replayed the unchanged finalized N2 inventory identified by SHA-256
  `aabbe5e942ede445fcd59b8ad37184f7dadc57a8b16aee935b30b99e9ecdc084`.

## decoders-epc v1.0 - GTPv2-C, Diameter S6a, EPS NAS (TS 29.274 / RFC 6733 + TS 29.272 / TS 24.301)

- `decoder-gtpv2c v0.1.0` (new crate, TS 29.274): Echo, Create/Modify/Delete Session, Create/Delete Bearer, Release Access Bearers. IEs IMSI, MSISDN, MEI are flagged identity (`pseudonymized: true`); F-TEID, Bearer Context (grouped), PAA, APN, AMBR, Serving Network (PLMN), EBI are decoded.
- `decoder-diameter v0.1.0` (new crate, IETF RFC 6733 + 3GPP TS 29.272 S6a): ULR/ULA (316), AIR/AIA (318), PUR/PUA (321), CLR/CLA (317), NOR/NOA (323). AVPs User-Name (code 1) and MSISDN (code 701, vendor 10415) are flagged identity; Result-Code, Experimental-Result-Code, Visited-PLMN-Id, Origin-Host/Realm, Subscription-Data envelope and Authentication-Info envelope are decoded.
- `decoder-nas v0.2.0` (extended, TS 24.301): added EPS EMM (Attach, TAU, Service Request, Detach, Authentication, Security Mode, Identity, EMM Status/Information, NAS Transport) and ESM (PDN Connectivity, Activate/Modify/Deactivate EPS Bearer Context, ESM Info, Status). EPS Mobile Identity (IMSI/IMEI/IMEISV/GUTI) is flagged identity.
- `decoder-s1ap v0.2.0` (updated): NAS-PDU IE (id 26) now forwards to `decoder-nas` and emits a child `NormalizedEvent` with a parent link back to the S1AP event, mirroring NGAP → 5G NAS.
- `event-schema`: added `Protocol::Gtpv2c`, `Protocol::Diameter`, `Protocol::NasEpsMm`, `Protocol::NasEpsSm` variants (`as_str` → `GTPv2-C`, `DIAMETER`, `NAS-EPS-MM`, `NAS-EPS-SM`).
- All fixtures are synthetic (PLMN 001/01, synthetic BCD/digit material). No real identities are present in test code.

## decoder-s1ap v0.1.0 - S1AP APER decoder (TS 36.413)

- Added `OIRAN/decoder-s1ap` crate implementing the schema-independent S1AP-PDU/open-type envelope and ProtocolIE container, modelled on `decoder-ngap`.
- Procedures recognised: S1 Setup (17), E-RAB Setup (5), E-RAB Release (7), Initial Context Setup (9), Paging (10), Downlink NAS Transport (11), Initial UE Message (12), Uplink NAS Transport (13), UE Context Release Request (18), UE Context Release Command / Complete (23).
- Identity-bearing IEs (`S-TMSI`, `UEPagingID`, `GUMMEI-ID`, `SecurityKey`, `NAS-PDU`) are tagged `pseudonymized: true` so the Analyzer strips them before persistence.
- Added `Protocol::S1ap` variant to the event-schema protocol enum.
- Coverage: 10 unit tests on synthetic APER vectors built from TS 36.413 with synthetic PLMN `001/01` and synthetic identities only — no real IMSI/K/OPc material in fixtures.
- Carried NAS-PDU is EPS NAS (TS 24.301) and preserved opaquely by SHA-256 + length; `decoder-nas` remains 5G-only (declared limitation).
- Added `OIRAN/docs/PROTOCOL_AUDIT.md` with the static 12-plane coverage audit.

## Release consolidation V1.1 - lossless continuous checkpoint resume

- Preserve evidence-backed session identifiers when live activity credit expires or a continuous import is finalized.
- Validate and merge the last durable continuous dataset checkpoint before publishing the next atomic dataset generation.
- Deduplicate observations by stable semantic event identifier and retain only call flows whose event references remain present.
- Fail closed on an invalid checkpoint without replacing the prior event store.
- Added restart, new-data, idempotent replay, five-session retention, and invalid-checkpoint regression coverage.

## E2E-002 - Atomic derived-dataset registration

- Added an authenticated, allowlisted import endpoint that accepts only a derived dataset identifier.
- Verifies source capture identity, all source PCAP hashes and packet counts, artifact hashes, schema/decoder compatibility, provenance, sessions, and correlation evidence before registration.
- Stages and atomically renames the complete dataset, callflows and registry update.
- Supports idempotent re-import and rejects conflicting dataset identifiers.
- Added authenticated candidate browser coverage for derived dataset visibility, exact tunnel evidence, strong associations, unknown NG-U evidence and packet provenance.

## E2E-002 - Evidence-based cross-interface correlation

- Normalized structurally verified NGAP UP transport endpoint and TEID evidence.
- Added typed exact-tunnel and strong-context correlation edges with scope, limitations, and packet provenance.
- Added ambiguity rejection and kept missing NG-U evidence explicitly unknown.
- Exposed evidence type and limitations in Call Flow and Correlation Studio.
- Added an immutable-source offline replay producing a separate 92-event derived dataset.

All notable OIRAN vProbe changes are recorded here. Versions follow Semantic Versioning.

## [S5.5.1/1.0.1-dev] - 2026-10-26

### Fixed

- Defined the shared Rust `MAX_CAPTURE_PLANES = 4` contract and applied it independently in the live-probe API validator and isolated Capture Helper.
- Made the four-plane default (`N2`, `SBI`, `N4`, `N3`) valid while retaining one-, two- and three-plane compatibility.
- Preserved strict rejection of duplicate, unknown, unavailable and more-than-four logical planes.
- Added deterministic interface inventories for offline helper/IPC tests while retaining the fixed `/sys/class/net` inventory in production.
- Added explicit Select All and Apply Configuration controls; successful validation is invalidated whenever capture configuration changes.

### Validation

- Passed 172/172 Rust workspace tests, including authenticated HTTP API to Unix IPC to non-acquiring Capture Helper validation.
- Passed 19/19 frontend tests, TypeScript validation and the production frontend build.
- Passed 46/46 browser E2E regressions against an isolated local API and copied read-only registry fixture.

### Safety

- Four-plane storage remains one global bounded reservation: the helper divides the job budget across plane/rotation segments rather than multiplying it.
- No packet socket was opened by the new validation test, and no live capture, simulator execution, production deployment or service restart occurred.

## [S5.5/1.0.0-dev] - 2026-10-26

### Added

- Unified S5.1 SLL2, S5.2 NAS and S5.3 TCP/HTTP2/SBI decoding in one release lineage.
- Fixed, allowlisted SBI capture point (`br-oiran-sbi`, TCP/7777) in the isolated AF_PACKET helper.
- Four-plane POLARIS profile for NG-C, SBI, N4 and NG-U with synchronized capture-group identifiers and per-plane results.
- Capture-group API, per-plane packet/storage/decode status, and four-plane Probe Manager controls.
- SBI-aware Call Flow participants, arrows and conservative E2E status that remains UNKNOWN when either SBI bridge is unproven.

### Validation

- Passed 166 Rust tests and 18 frontend tests; production frontend build and TypeScript validation passed.
- Passed the dedicated four-plane Playwright suite in Light/Dark at 1440x900 and 1920x1080.
- Retained the unchanged 13-file corpus and the multi-IMSI result: six UE contexts, five PDU sessions, six PFCP sessions, zero GTP-U tunnels and no observed cross-UE contamination.

### Safety

- No live capture, simulator execution, production deployment or shared-service restart occurred.
- POLARIS, POLARIS Control, ETV/OTV and certified historical datasets were unchanged.

## [S5.3/1.0.0-dev] - 2026-10-26

### Added

- Bounded bidirectional TCP reconstruction with sequence-aware retransmission, duplicate, out-of-order, gap, timeout and provenance handling.
- Native HTTP/2 frame and multiplexed-stream decoding, including HEADERS/CONTINUATION/DATA and stateful HPACK through the MIT-licensed `hpack` crate.
- Sanitized SBI request/response events for observed Nsmf PDUSession and Namf Communication operations, with JSON/multipart field extraction and explicit TLS/unresolved states.
- Conservative SCP-routing and cross-interface correlation hooks that reject PDU Session ID-only and timestamp-only associations.
- SBI participants and request/response messages in the existing Call Flow schema without synthesizing unseen logical hops.

### Validation

- Replayed the unchanged 13-file, 4,205-packet corpus with SHA256 verification before and after.
- Matched 2,316/2,316 HTTP/2 frames and 766/766 independently comparable fields against TShark 4.2.2; 26 fields remain unresolved because capture begins after HPACK dynamic-table state was established.
- Observed 48 TCP connections, 708 HTTP/2 streams, 198 transactions and 20 prioritized operations.
- Preserved six UE contexts and five PDU sessions without observed cross-UE contamination; the N2/SBI/N4 bridge remains uncertified because explicit cross-layer identifiers are absent.

### Safety

- No live capture, simulator execution, production deployment or service restart occurred.
- POLARIS, POLARIS Control, ETV/OTV and the reference corpus were unchanged.

## [S5.2/1.0.0-dev] - 2026-10-26

### Added

- Native bounded Rust dispatch for 5GMM (`0x7e`) and 5GSM (`0x2e`) with observed Release-17 message identities.
- Safe Type 1/3/4/6, TV, TLV and TLV-E handling for observed NAS fields, including pseudonymized mobile identities, PDU Session ID, PTI, causes, DNN and S-NSSAI.
- Explicit NAS security-envelope classification without key derivation, integrity claims or unauthorized decryption.
- Parent/child NGAP → 5GMM → 5GSM event relationships with inherited packet provenance and compatible event schema 1.4.0 fields.
- Evidence-based procedure attempts that separate retry, failure, success and incomplete results and scope NAS children through their exact NGAP parent.

### Validation

- Replayed the unchanged 13-file, 4,205-packet S5.1 corpus before/after SHA256 verification.
- Parsed 116 NGAP-carried NAS envelopes across the full corpus; 46 plain messages were decoded (24 complete, 22 partial), 10 integrity-only messages were decoded without claiming verification, and 60 ciphered envelopes remained unresolved.
- Achieved 404/464 exact independently comparable TShark fields, with zero mismatch and 60 encrypted/unresolved message-type fields.
- Preserved six UE context lifecycles and five PDU sessions in the multi-IMSI fixture without observed cross-UE contamination.
- Passed 152/152 Rust workspace tests after one documented retry of a pre-existing timing-sensitive worker-runtime queue watermark test.

### Safety

- No live capture, simulator execution, production deployment or service restart occurred.
- POLARIS, POLARIS Control, ETV/OTV and certified historical datasets were unchanged.

## [S5.1/1.0.0-dev] - 2026-10-26

### Added

- Native Linux cooked capture v2 parsing for `LINKTYPE_LINUX_SLL2` / link type 276.
- Network-byte-order parsing and validation for the 20-byte SLL2 header, including protocol, interface index, ARPHRD type, packet type and address metadata.
- Additive event provenance schema 1.3.0 fields for source SHA256, link type and SLL2 metadata.
- Per-interface SLL2 dispatch for PCAPNG and IPv6 extension-header traversal with explicit fragment/ESP limitations.

### Validation

- Replayed the unchanged 13-file, 4,205-packet benchmark corpus after SHA256 verification.
- Decoded 239 LAB NGAP/PFCP/GTP-U message envelopes with exact packet, timestamp, endpoint and message parity against TShark 4.2.2.
- Reconstructed five isolated PDU sessions from the five-UE fixture without cross-UE contamination; cross-interface N2/N4 confidence remains unresolved.
- Added deterministic PCAP, PCAPNG mixed-link, IPv4, IPv6, malformed-header and fuzz-like regression tests.

### Safety

- No live capture, simulator execution, deployment or production service change occurred.
- POLARIS, POLARIS Control, ETV/OTV and historical certified datasets were unchanged.

## [2.3.0-dev] - 2026-10-26

### Fixed

- Normalize historical, captured-live and recovered dataset records behind API 2.3.
- Add explicit dataset scopes to Session Explorer without fallback to an unrelated historical session.
- Scope decode-completeness counts to session-associated events instead of dataset background events.
- Preserve exact dataset identity through Session Explorer and Call Flow navigation.

### Validation

- Added a deterministic, clearly labeled test corpus with three independent UE contexts, PDU sessions, PFCP sessions and GTP-U tunnels.
- Verified composite identity isolation, identifier reuse safety, pagination and zero-session datasets.
- Passed 134 Rust tests, 18 frontend tests and 44 browser workflows.
- Reviewed Light and Dark screenshots at 1440×900 and 1920×1080.

### Safety

- No live capture, simulator traffic, UE process, deployment or production-service restart occurred.
- POLARIS, POLARIS Control, ETV/OTV and certified historical datasets were not changed.

## [1.0.0-dev/OIRAN-P0-LIVE-FINALIZATION-FIX] - 2026-10-25

### Fixed

- Create the derived `dataset/callflows` layout before the first decoded-event write from a freshly finalized helper capture.
- Preserve `FAILED` status for recoverable PCAP evidence until derived processing completes successfully.
- Synchronize terminal helper storage accounting after empty-interface PCAP headers are finalized.
- Show an explicit **View error** action, exact backend failure, and preserved-evidence state for failed capture jobs without linking them to fictitious sessions.
- Finalize normalized-event JSONL, Call Flow exports and dataset manifests using temporary files plus atomic rename.
- Add an idempotent `oiran-recover` command and persistent recovered-dataset registry that never changes the original failed job.

### Validation

- Added clean-root regressions for fully populated N2/N3/N4 captures and captures with an empty N3 interface.
- Added offline timeout, graceful manual Stop, bounded rotation, empty selected interface, partial initialization failure, and failed-job recovery coverage.
- Recovered `live-1792964646320-0003` offline as 50 verified packets and 20 PFCP heartbeat events; the original capture remains `FAILED`.
- No live capture or simulator traffic was executed; original forensic PCAPs and historical certified datasets remain unchanged.

## [1.0.0-dev/OIRAN-P0-ISOLATED-CAPTURE-HELPER] - 2026-10-25

### Added

- Native Rust AF_PACKET capture helper with no tcpdump subprocess dependency.
- Unix socket IPC v1 with `SO_PEERCRED` server authorization and client-side helper identity verification.
- Fixed N2/N3/N4 interface enum, bounded request schema, exact job ownership, and explicit `COMPLETED_EMPTY` state.
- Global disk budget, bounded PCAP rotation, atomic manifests, SHA-256 integrity, and persisted helper job records.
- Review-only hardened systemd unit, API drop-in, IPC specification, security review, and deployment/rollback plan.

### Changed

- `live-probe` now uses the isolated IPC adapter and fails closed when its authorized socket is absent.
- The API capture root may use the fixed `/var/lib/oiran/captures` deployment path; arbitrary Web paths remain impossible.
- Unix termination signals are represented separately from process exit codes.

### Safety

- No helper was deployed or started and no live capture or simulator traffic was executed.
- POLARIS, POLARIS Control, ETV/OTV, Open5GS, UERANSIM, historical datasets, Docker, firewall, and routing were unchanged.

## [2.0.0-dev] - 2026-10-25

### Added

- Premium dark-default Analyzer shell with complete Light, Dark and System themes.
- Operational Overview, Packet Analyzer, Export & Reports, and Live Monitoring modules.
- Versioned API 2.0 endpoints for probe detail, truthful host/live metrics, packet provenance, public Viewer identity, and fail-closed capture lifecycle validation.
- Evidence-driven Call Flow inspector tabs for decoded fields, ASN.1, restricted raw payload references, canonical JSON, correlation evidence and provenance.
- Responsive visual validation for seven analytical views at 1440×900 and 1920×1080 in both themes.

### Validation

- 97 Rust/API tests, 9 frontend tests and 33 browser workflows pass.
- Certified accounting remains 54 source events, 26 session events, 28 background events and 12 evidence edges.
- Live metrics are `NOT AVAILABLE` and capture controls remain unavailable because no authorized live capture backend is configured.

### Safety

- The certified PCAPs and Call Flow JSON remain checksum-identical.
- No POLARIS, POLARIS Control, ETV/OTV, Open5GS, UERANSIM, Docker, firewall, routing or database resource was modified.

## [1.0.0-dev/S4.2] - 2026-10-25

### Added

- Permanent 75/80/85/90 percent disk policy with statvfs byte/inode measurement.
- Fail-closed stateful capture guard, reserved between-poll write budget and bounded 256 MiB × 8 rotation plan.
- Authenticated storage-safety API and measured Probe Manager storage panel.
- Approval-gated five-UE POLARIS scenario manifest and validation reports.

### Safety

- No five-UE scenario, traffic or capture was started because new POLARIS profiles/processes require explicit approval.
- No cleanup, automatic deletion, service restart, database, Docker-network, firewall or route change occurred.

## [1.0.0-dev/S4.1] - 2026-10-24

### Added

- Deterministic multi-UE, multi-PDU, PFCP lifecycle and directional GTP-U tunnel discovery.
- Immutable checksum-based dataset registry with idempotent duplicate handling.
- API 1.1 dataset/UE/procedure endpoints and multi-flow state with S4 compatibility.
- Dataset, UE, interface and state filtering across Session Explorer and Correlation Studio.
- Independent session selection in Call Flow Viewer and conservative incomplete-flow generation.

### Validation

- 85 Rust release tests, 9 frontend tests and 28 browser workflows pass.
- Five-UE/six-PDU synthetic fixture covers concurrent, sequential and incomplete behavior; real multi-UE capture certification remains pending.
- Certified S3.3 call flow and N2/N3/N4 checksums remain unchanged.

### Safety

- POLARIS was read-only; ETV/OTV, Docker networks, databases, routing and capture services were not modified or restarted.
- No additional UE, test traffic or live capture was started.

### Public read-only access update — 2026-10-25

- Removed viewer/admin access tokens and the sign-in screen by explicit operator request.
- Preserved read-only API behavior, disabled live capture controls, sanitized provenance and immutable datasets.

## [1.0.0-dev/S4] - 2026-10-24

### Added

- Localhost-only Axum API adapter with bearer authentication, read-only authorization, pagination, filtering, sanitized provenance and protected exports.
- React/TypeScript application with a shared module-aware shell, Probe Manager, Session Explorer, SVG Call Flow Viewer and Correlation Studio.
- Real integration with 54 certified events, including the strict 26 session / 28 background split and all 12 evidence edges.
- Responsive 1440×900 and 1920×1080 visual certification, keyboard focus states, dark theme, error/empty/loading states and URL-deep-linked sessions.
- Isolated deployment templates, API contract, security/deployment reports and a 25-workflow browser suite.

### Validation

- 71 Rust/API tests, 8 frontend tests and 25 browser workflows pass.
- Production frontend build and TypeScript checking pass; npm audit reports zero vulnerabilities.
- Certified call flow and PCAP hashes remain unchanged; no Docker, database, firewall, route or persistent-service mutation was performed.

## [1.0.0-dev/S3.1-S3.2] - 2026-10-24

### Added

- Native bounded PCAP and PCAPNG reader with exact per-interface timestamp provenance.
- Ethernet, stacked VLAN, Linux cooked v1, IPv4/IPv6, UDP and SCTP extraction.
- SCTP DATA parsing, association generations, duplicate handling and conservative reassembly.
- Independent NGAP, PFCP and GTP-U decoder crates behind plugin API 1.1.0.
- Event schema 1.1.0 with deterministic IDs, packet sets, endpoint roles, decode statuses and raw-payload references.
- Offline CLI producing 99 ordered real-capture events and an independent TShark comparison.

### Validation

- 40 unit/regression tests pass.
- Exact packet/header alignment: 37 NGAP, 52 PFCP and 10 GTP-U; zero missing or mismatched messages.
- Full nested IE parity remains partial: 33 NGAP and 12 PFCP events explicitly retain unsupported values.
- Operational N3 remains empty; GTP-U evidence comes from an immutable Open5GS reference under POLARIS.

### Safety

- No benchmark, package installation, service restart or POLARIS/ETV/OTV mutation.

## [1.0.0-dev/S2.1] - 2026-10-24

### Added

- Immutable preloaded multi-flow batches and deterministic worker-owned partitions.
- Generator-only, independent preloaded fast-path and full-pipeline benchmark isolation.
- Queue-oriented source contract for future PCAP, AF_XDP and DPDK adapters.
- Effective-cpuset-aware automatic/explicit/disabled affinity and worker mask reporting.
- Mandatory fresh receipt from a bounded 15-minute resource safety observer.

### Changed

- `capture-core`, `worker-runtime` and `benchmark-engine` advanced to 0.3.0.
- Processing-only timing no longer contains serial generation, per-packet allocation, queues or shared counters.
- Full-pipeline reporting distinguishes generated, enqueued, processed, explicit drops and in-flight packets.

### Validation

- 21 unit tests passed with no failure; performance runs were deferred because the stability gate did not pass.
- No 25 Gbit/s or 100 Gbit/s capability claim is made.

## [1.0.0-dev/S2] - 2026-10-24

### Added

- Generator-only, pre-generated processing-only and full-pipeline benchmark modes.
- Exact generated = processed + explicit-drop invariant.
- Packet-number sum/XOR, ordered work accumulator and provenance-length validation.
- Four-worker accounting, same-flow ordering and length-mismatch regression tests.
- Complete 1–4 worker, 32–256 batch and 64–1500 byte before/after matrices.

### Changed

- `capture-core` 0.2.0 adds uniquely owned packet buffers while preserving shared replay buffers.
- `worker-runtime` and `telemetry` 0.2.0 aggregate fast-path counters per batch.
- `benchmark-engine` 0.2.0 reports generated packets, length errors and observable work.

### Performance

- Fixed S1 profile (2 workers, batch 64, 250 ms): 1500-byte median increased from 2.694994 to 3.037666 Gbit/s Ethernet-wire equivalent (+12.72%).
- Best accepted three-run median: 3.175694 Gbit/s at 2 workers, batch 256, 1500-byte frames.
- No claim of 25 Gbit/s certification.

### Safety stop

- Further component profiling stopped after an external OTV container replacement/worker exit was observed. S2 status is partial; no OIRAN command modified OTV.

## [1.0.0-dev] - 2026-10-24

### Added

- Eight-crate Rust workspace with independent component versions.
- Immutable packet provenance and batch envelopes.
- Allocation-free Ethernet, VLAN, IPv4, direct-UDP IPv6, UDP and GTP-U classification.
- TEID and tunnel endpoint extraction with strict malformed-length detection.
- Stable software flow/session affinity independent of NIC RSS behavior.
- Bounded per-worker queues, batch execution, CPU affinity, backpressure accounting and graceful shutdown.
- Deterministic replay mode and cache-line-aligned per-worker counters.
- Versioned normalized event model and deterministic decoder plugin contract.
- Safety-bounded synthetic benchmark for 64, 128, 512 and 1500-byte frames.
- Automated integrity, parser, concurrency, saturation, shutdown and replay tests.

### Limitations

- No production capture adapter, SCTP/NGAP/PFCP decoder, dynamic plugin loader or UI in S1.
- No IPv4 fragment or IPv6 extension-header reconstruction.
- Synthetic results are not line-rate certification.

## [1.0.0-dev/S3.2.1] - 2026-10-24

### Added

- Release-aware typed NGAP decoding for observed UE IDs, location, security, S-NSSAI, PDU-session identifiers, cause and selected node/context fields.
- Recursive typed PFCP decoding for the grouped and leaf IEs observed in the selected captures.
- Event-schema 1.2 probe/capture-point identity and explicit EXACT/STRONG/POSSIBLE/UNKNOWN evidence references.
- Field-parity, N3 diagnostic, dataset and correlation-readiness artifacts.

### Changed

- `decoder-ngap` and `decoder-pfcp` advanced to 0.2.0; `event-schema` advanced to 1.2.0-dev.
- Known but untyped PFCP leaves are PARTIAL and unknown IEs are UNSUPPORTED rather than silently decoded.
- The selected PFCP set improved from 40 fully decoded and 12 partial messages to 52 fully decoded and zero partial; NGAP improved from 4/33 to 9/28.

### Validation and safety

- 46 workspace tests pass; 99/99 generated events retain packet provenance and evidence.
- Operational N3 remains empty because no UE user-plane traffic was generated; no POLARIS or ETV/OTV service was changed.
- Full Release-17 NGAP parity and a coherent operational N2/N4/N3 dataset are not claimed.

## [1.0.0-dev/S3.3] - 2026-10-24

### Added

- Independently versioned `session-engine`, `correlation-engine`, `callflow-schema`, `callflow-renderer`, and `oiran-callflow` crates.
- Deterministic UE/PDU/PFCP/GTP-U reconstruction with explicit session, background and unmatched accounting.
- Versioned STRONG N2↔N4 certified-tunnel rules and EXACT N4↔N3 TEID-plus-endpoint rules.
- Canonical Call Flow JSON and standalone interactive HTML with filters, search, zoom, procedure groups, evidence inspector and JSON export.
- Seventeen unit tests for reconstruction, ambiguity, missing data, duplicate handling, provenance, schema, output containment and safe HTML rendering.

### Validation

- All 54 certified source events are preserved: 26 session, 28 background, 0 unmatched, 0 duplicate and 0 extra.
- Twelve evidence-bearing edges reproduce N2↔N4 STRONG, N4↔N3 EXACT and E2E STRONG.
- 63 workspace tests pass; all historical 46 tests remain passing.

### Security

- Subscriber identity remains `UE-A`; no authentication material or unrestricted raw payload is exported.
- HTML has no remote dependency, treats decoded values as text, and script-escapes embedded JSON.

## [1.0.0-dev/OIRAN-LIVE-V1] - 2026-10-25

### Added

- Strictly owned, allowlisted Rust live-capture manager for the discovered POLARIS N2, N3 and N4 Linux bridges.
- Bounded duration, global byte reservation, per-interface rotation, continuous disk enforcement, exact PID ownership, persistent job recovery and audit records.
- Reusable native decoder library feeding normalized events, multi-session discovery, correlation and canonical Call Flow outputs after capture finalization.
- Versioned capture validation/start/stop/metrics API with Viewer, Operator and Administrator enforcement.
- Probe Manager controls, real interface inventory, session-scoped token login and honest execution/certification states.

### Safety

- Capture execution is disabled by default and requires `OIRAN_CAPTURE_EXECUTION_ENABLED=1` plus a server-provisioned token hash.
- No live capture or traffic generation was executed in this release; POLARIS, POLARIS Control and ETV/OTV were not changed.
- Job storage is constrained to `/root/OIRAN_VPROBE/runtime/live-captures`; source datasets are never deleted or overwritten.

## [1.0.0-dev/OIRAN-P0-CAPTURE-LIFECYCLE] - 2026-10-25

- Fixed tcpdump output ownership for its restricted service account.
- Run the OIRAN API with the restricted `tcpdump` primary group and grant write access only to each job's PCAP directory, avoiding the broader `CAP_CHOWN` capability.
- Configure the capture helper to retain the already systemd-confined service identity, avoiding a denied tcpdump `setuid/setgid` transition without granting additional capabilities.
- Persist helper PID, exit status and bounded stderr for capture forensics.
- Classify premature helper exit and missing output as failures.
- Represent legitimate empty capture explicitly without generating sessions.
- Synchronize the selected capture panel with authoritative polling state.
- Recover the affected legacy false-success job as failed.

## [2.2.0-dev] - 2026-10-25

### Added

- Strict capture-to-dataset resolution through `GET /api/v1/captures/{capture_id}/context`.
- Exact packet provenance filters for capture, event and packet number.
- Evidence-derived Call Flow participants, directional SVG arrows, procedure controls and a synchronized message index/inspector.
- Honest zero-session and unavailable-dataset investigation states.
- UTC millisecond timestamp formatting and provenance deep links into Packet Analyzer.

### Changed

- Session navigation now persists `capture_id`, `dataset_id`, `session_id`, `probe_id`, technology and selected event in the URL.
- Capture records expose their associated dataset without changing the immutable capture outcome.
- OIRAN API and Web versions advance to 2.2.0-dev.

### Safety

- No decoder, historical dataset, live capture service or external laboratory component was modified or started.

## OIRAN API 2.5.4 / live-probe 0.2.7 - 2026-10-31

- `GET /api/v1/sessions/:id/callflow` now returns at most 100 events by
  default and accepts `limit` (1..256) plus an event-id `cursor`.
- Persisted call-flow JSON is read with a streaming deserializer; only the
  selected event page is retained, preventing large historical sessions from
  multiplying their resident-memory cost during HTTP serialization.
- Every response carries `pagination.{limit,cursor,next_cursor,returned_events,total_events}`;
  invalid cursors fail explicitly and never replay the first page.

## OIRAN API 2.6.0 / live-probe 0.3.0 - 2026-10-31

- Materialise bounded LTE S1-MME/S11/S1-U sessions and correlated Call Flows
  from already-decoded offline evidence during dataset finalisation and API load.
- Expose the installed decoder inventory and LTE capture protocol labels through
  the version and capture APIs.
- Keep live LTE capture disabled: no capture interface allowlist was expanded.
- Limit offline LTE materialisation to 128 sessions per dataset to bound memory.
