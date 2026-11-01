# ANR3 Hermes P0 final-delivery result

Date: 2026-11-01 UTC

Verdict: **SOURCE RESOLUTION COMPLETE; POST-MERGE TEST/REAL-PCAP/RELEASE GATES OPEN**

This worktree contains a source-only resolution for parent review. No Git index
or common-directory write, build, service, receiver, live operation, capture,
dataset, deployment, or external collector action was performed.

## 1. Ancestry and active merge evidence

| Evidence | Value |
|---|---|
| Isolated branch | `hermes/final-anr3-20261101` |
| `HEAD` / privacy parent | `523524fd44b6bc2b6a4535bb093290f26b8135f4` |
| `MERGE_HEAD` / LTE parent | `b011432b17235d85a08aa21bf4afe1c65fa6eeba` |
| Merge base | `2c67fe6b2cbb450fefaa789c76f947678388953c` |
| `merge-base --is-ancestor b011432 HEAD` | exit `1`: not already integrated |
| `merge-base --is-ancestor 7f84c49 HEAD` | exit `0`: real-lab integration retained |
| Git common directory | `/root/OIRAN_POLARIS_FOUNDATION/.git` |

The inherited `--no-ff --no-commit` merge is still active. The index continues
to show the five conflict paths as unmerged because this sandbox cannot write
the common Git directory. The working files themselves contain no conflict
markers. The merge was not aborted, reset, replaced with an older tree, or
reconstructed by cherry-pick.

## 2. Pre-edit source checkpoint

Before editing, the nine inherited changed/conflicted files were copied to:

`/root/.hermes/cache/scratch/oiran-polaris-final-delivery-20261101/anr3-source-checkpoint-pre-resolution-523524f-b011432`

The SHA-256 aggregate of the sorted checkpoint hash list is:

`4c704dc3d56309ee616b4b6def398d6501f1c96d87f51b3b3fa876782067bf6b`

| Checkpoint file | SHA-256 before resolution |
|---|---|
| `ANR3_FINAL_OIRAN_LTE_REPORT.md` | `709ea86adf1b671af18450fc255e490f0b14653e832e264890c745b8cc442804` |
| `OIRAN/CHANGELOG.md` | `a57d4d4d2cf3482e43afddd0d82d5b42321f57d636e998e62081f051608ae805` |
| `OIRAN/Cargo.lock` | `ae59f4684a275ecf33fa4adcc00d8ddff494e1033cf18fff142bd79734d4152b` |
| `OIRAN/apps/api/Cargo.toml` | `5cd338b56f788da4e0f5b92103513c48cc40bda31047dffb4e80ee121aa900ff` |
| `OIRAN/apps/api/src/lib.rs` | `85c0c1388bd69d33e8e9616efbc168cb814358758ddbce8ba50f861ebaeb1861` |
| `OIRAN/live-probe/Cargo.toml` | `8498ece0e7bc7d2dbdc1774764fb27b6a4fcb6a6a1677d96ded846ee18dbda99` |
| `OIRAN/live-probe/src/lib.rs` | `c16e37bda004beab08f1b16bc2e7a2451192f34211c6b4bec7d2ba65343720ef` |
| `OIRAN/oiran-decode/Cargo.toml` | `042c1e35d93215ffab61dd100cdbf762f356ea79b6b7e4abbc52fc89fcbb1107` |
| `OIRAN/oiran-decode/src/lib.rs` | `4937833800af34122b6e25e89241662f1ec586114ca6fed7b72aba77db98757d` |

No source worktree named in the mission was modified.

## 3. Exact conflict resolutions

| Path/hunk | Resolution |
|---|---|
| `ANR3_FINAL_OIRAN_LTE_REPORT.md` add/add | Replaced the contradictory parent versions with one integrated report that distinguishes inherited test evidence from this untested post-merge source and retains privacy, LTE/5G, real-data and rollback gates. |
| `OIRAN/Cargo.lock`, `live-probe` package | Kept newer `0.4.0`; rejected `0.3.0`. |
| `OIRAN/Cargo.lock`, `oiran-api` package | Kept newer `2.7.1`; rejected `2.6.0`. |
| `OIRAN/apps/api/Cargo.toml:3` | Kept API `2.7.1`. |
| `OIRAN/live-probe/Cargo.toml:3` | Kept Live Probe `0.4.0`. |
| `OIRAN/apps/api/src/lib.rs:17-24` import hunk | Unioned privacy `lte_evidence::{...}` exports with LTE `offline_lte_callflows`; neither side was dropped. |
| `OIRAN/apps/api/src/lib.rs:44-45` constants | Kept API `2.7.1` and Platform `2.7.0`. |
| `OIRAN/apps/api/src/lib.rs:638-647` version response | Kept Platform/Analyzer `2.7.0` and optional empty-flow safety; took `correlation_engine::VERSION` and the complete installed LTE+5G decoder inventory. |

Semantic follow-ups required by those resolutions:

- `OIRAN/apps/api/src/lib.rs:3350` now expects API `2.7.1` in
  `version_reports_installed_lte_and_5g_decoders`, rather than the rejected
  `2.6.0` value.
- `OIRAN/live-probe/src/lib.rs:42` now reports `VERSION = "0.4.0"`, matching
  its newer manifest, lockfile and changelog.
- `OIRAN/CHANGELOG.md:5-7` records that the 2.7 read model/privacy release
  includes bounded offline LTE materialization and the full decoder inventory
  without changing capture gates.

The resolved source SHA-256 aggregate, over the eight OIRAN source/manifest
paths in sorted command order, is:

`6800db89f84ec8253eebd057b70cd8763d6189b6dc871ec1cff9daf346e59203`

Key resolved SHA-256 values:

| File | SHA-256 after resolution |
|---|---|
| `OIRAN/CHANGELOG.md` | `caade09e91e6823848c551a55194d56245141775fe164b8602d9c1e22f915076` |
| `OIRAN/Cargo.lock` | `2aab075c7be109f5ee5a09327b5dfbc8da82d759087fdffecc7ccab63ad7faca` |
| `OIRAN/apps/api/Cargo.toml` | `4aa62f4ffc5f89c1c491d2e3e866ed7853273c020a31120788647d57b70f2252` |
| `OIRAN/apps/api/src/lib.rs` | `8398db0b6bf70b8b3b878108eb12921975a98f54a44ee36aa31c484c3f087973` |
| `OIRAN/live-probe/Cargo.toml` | `236e19521e7da9f34f91bd6f0dd1d30348243df8d2d39c8c5d1022257ac05771` |
| `OIRAN/live-probe/src/lib.rs` | `301148e2bdfdd01ab305a60f848572fa4291e8e9d43f6daed15c2b90d0ffdc9a` |
| `OIRAN/oiran-decode/Cargo.toml` | `042c1e35d93215ffab61dd100cdbf762f356ea79b6b7e4abbc52fc89fcbb1107` |
| `OIRAN/oiran-decode/src/lib.rs` | `4937833800af34122b6e25e89241662f1ec586114ca6fed7b72aba77db98757d` |
| `ANR3_FINAL_OIRAN_LTE_REPORT.md` | `78afc8ecbe1231e167c45284a8019c92906ecceff6a9404eed95b03703de64aa` |

## 4. Preserved behavior and named tests

Privacy is retained at the common JSON boundaries and the HTML export:

- sanitized HTML/JSON export: `OIRAN/apps/api/src/lib.rs:2729`;
- common pagination and success sanitization: lines `2840` and `2855`;
- recursive identity removal: line `2910`;
- raw viewer/operator route regression:
  `raw_read_routes_remove_identity_material_for_viewer_and_operator` at line
  `3149`.

LTE and 5G are retained together:

- installed inventory includes S1AP, NAS-EPS-MM/SM, GTPv2-C, GTP-U, NGAP,
  NAS-5GMM/SM, PFCP and SBI-HTTP2 in
  `OIRAN/oiran-decode/src/lib.rs:29-44`;
- bounded offline LTE materialization is in
  `OIRAN/live-probe/src/lib.rs:62` and is called by API reference loading at
  `OIRAN/apps/api/src/lib.rs:326`;
- `offline_lte_materialisation_is_bounded_and_correlates_planes` remains at
  `OIRAN/live-probe/src/lib.rs:4501`;
- `api_load_materialises_synthetic_lte_session_without_live_capture` remains at
  `OIRAN/apps/api/src/lib.rs:3423`.

Operational truthfulness is preserved: reference artifacts require the explicit
`reference_dataset_enabled` gate (`OIRAN/apps/api/src/lib.rs:94,135,202`), while
the operational loader begins with empty flow maps (`:405,445`) and only admits
persisted CaptureManager or fail-closed LTE evidence-store data. Synthetic
fixtures therefore remain offline test/reference inputs and do not populate an
operational UI.

## 5. Validation actually run

| Check run in this worktree | Result |
|---|---|
| Conflict-marker scan over all touched source/report files | PASS: no matches (ripgrep exit `1`) |
| `git diff --check` after final edits | PASS, exit `0` |
| `cargo metadata --offline --locked --no-deps --format-version 1` | PASS, exit `0` |
| Metadata versions | API `2.7.1`; Live Probe `0.4.0`; decoder `0.6.0`; session/correlation `0.5.0` |
| Rust parser via `rustfmt --edition 2021 --emit stdout ... >/dev/null` for API and Live Probe | PASS for both, exit `0` |
| Final resources after lightweight checks | memory used about 15 GiB, available 4.5 GiB; disk 55% |

The first `git diff --check` found three Markdown hard-break trailing spaces in
the newly composed report. They were removed; the recorded final rerun passes.

Not run in this worktree:

- no `cargo check`, `cargo test`, compiler, linker or heavy ignored test;
- no npm install/CI, TypeScript, Vitest, Vite or Playwright;
- no real or synthetic capture decode/import;
- no service, loopback API, Docker, receiver, live traffic or deployment.

Those are intentionally not reported as post-merge PASS because the parent did
not grant a build/test lease. Parent-branch results are preserved, explicitly
labelled as inherited evidence, in `ANR3_FINAL_OIRAN_LTE_REPORT.md`.

## 6. Approved real-PCAP verification path

Status: **PREPARED, NOT EXECUTED; BLOCKED ON PARENT SAFE MANIFEST**.

Only the parent's existing approved read-only captures may be used. The
verification must use the existing
`OIRAN/docs/LTE_EVIDENCE_INGESTION_CONTRACT.md` contract and must not modify,
rename, relabel or re-sanitize a source capture.

Required parent inputs:

1. a safe bundle/manifest using schema `oiran.lte-evidence-ingestion.v1` and
   evidence schema `oiran-polaris.lte-e2e-evidence.v1`;
2. exactly one `S1_MME`, one `S11` and one `S1_U` capture binding;
3. relative regular-file paths only, no symlinks/traversal;
4. `SANITIZED_APPROVED`, SHA-256, frame bounds, event-schema `1.5.0`, exact
   decoder versions and endpoint roles for every plane;
5. completed run/cleanup evidence and no clear subscriber/equipment identity.

After the parent supplies that manifest and grants the build/test resource
lease, the bounded offline sequence is:

1. read-only preflight of the manifest and `sha256sum` verification of each
   existing capture; stop on any mismatch or missing plane;
2. create only a disposable verification directory with
   `mktemp -d /tmp/anr3-real-pcap-verify.XXXXXX`;
3. run the existing `oiran-decode` binary once per plane, writing normalized
   JSONL only under that disposable directory:

   ```text
   oiran-decode --input <approved-S1_MME> --capture-id sha256:<manifest-sha> --interface S1-MME --output <tmp>/s1_mme.events.jsonl --endpoint <manifest-role>...
   oiran-decode --input <approved-S11>    --capture-id sha256:<manifest-sha> --interface S11    --output <tmp>/s11.events.jsonl    --endpoint <manifest-role>...
   oiran-decode --input <approved-S1_U>   --capture-id sha256:<manifest-sha> --interface S1-U   --output <tmp>/s1_u.events.jsonl   --endpoint <manifest-role>...
   ```

4. compare normalized-event hashes and provenance to the manifest, then invoke
   the existing fail-closed LTE evidence adapter with both evidence and output
   roots redirected to the disposable directory; do not point it at production
   runtime/dataset paths;
5. inspect only anonymized session/call-flow/provenance output and measured
   UE/session/bearer/TEID/UL/DL counts; absent data stays `null`/`UNKNOWN`;
6. scan all JSON/HTML output for forbidden identity keys/values and long digit
   runs, and retain hashes/counts plus decoder versions in the review artifact;
7. stop with BLOCKED/FAIL on identity disclosure, missing/ambiguous correlation,
   checksum/version mismatch, missing plane, unsupported path, or unapproved
   classification.

This is an offline verification path, not live certification. No manifest was
supplied here, so no capture was opened and no dataset was created or changed.

## 7. Parent Git commands

Run only from this worktree after reviewing the files:

```bash
cd /root/HERMES_FINAL_ANR3_20261101
git add -- \
  ANR3_FINAL_OIRAN_LTE_REPORT.md \
  ANR3_RESULT.md \
  OIRAN/CHANGELOG.md \
  OIRAN/Cargo.lock \
  OIRAN/apps/api/Cargo.toml \
  OIRAN/apps/api/src/lib.rs \
  OIRAN/live-probe/Cargo.toml \
  OIRAN/live-probe/src/lib.rs \
  OIRAN/oiran-decode/Cargo.toml \
  OIRAN/oiran-decode/src/lib.rs
git diff --cached --check
git diff --cached --name-status
test "$(git rev-parse MERGE_HEAD)" = b011432b17235d85a08aa21bf4afe1c65fa6eeba
git commit -m "merge(oiran): integrate LTE pipeline with API privacy 2.7.1"
git rev-list --parents -n 1 HEAD
git merge-base --is-ancestor 523524fd44b6bc2b6a4535bb093290f26b8135f4 HEAD
git merge-base --is-ancestor b011432b17235d85a08aa21bf4afe1c65fa6eeba HEAD
```

The committed revision must show two parents. Do not use `git commit` until the
parent has run the leased targeted validation below.

## 8. Staged release and rollback

1. **Source gate:** parent stages the explicit files, checks the combined diff,
   and verifies both merge parents.
2. **Build/test gate:** after measuring RAM/disk and granting the lease, use one
   compiler worker and at most two test threads. Run the two named privacy tests,
   the version inventory test, LTE API materialization test, Live Probe LTE test,
   then the bounded API/Live Probe/decoder/session/correlation suites. No npm
   install is needed for this source-only backend merge.
3. **Real-data gate:** run the approved-manifest path above in disposable
   storage. A missing manifest leaves the release `REAL_DATA_BLOCKED`.
4. **Artifact stage:** record candidate hashes and current deployed
   version/artifact/config hashes; place the candidate at a distinct versioned
   path without changing active symlinks/processes.
5. **Authorization gate:** obtain specific user authorization before any
   deployment. Grant V2/live authorization does not imply deployment approval.
6. **Readback gate:** after an authorized swap, verify `/version`, empty-state
   truthfulness, raw viewer/operator privacy routes, sanitized JSON/HTML export,
   and approved LTE/5G evidence. Never set `LTE_E2E_CERTIFIED` without real proof.
7. **Rollback:** on a critical component readback failure, restore only the
   previously active OIRAN artifact/config from recorded hashes. Do not alter
   captures, datasets, the 12 external collectors, Open5GS, POLARIS or unrelated
   services. Preserve the failed candidate and logs for review.

Final status for this worktree: **READY FOR PARENT SOURCE REVIEW; NOT READY FOR
BUILD CLAIM, REAL CERTIFICATION, MERGE COMMIT, OR DEPLOYMENT CLAIM**.
