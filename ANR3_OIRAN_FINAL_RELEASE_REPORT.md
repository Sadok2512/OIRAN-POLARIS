# ANR3 — OIRAN final release review

Date: 2026-11-01 UTC
Mode: offline only; production unchanged

## Candidate and lineage

- Required base: `92c1b08cd63202272986b64702ee97a334f010a3`
  (`origin/hermes/final-anr3-20261101`).
- Review branch: `anr3/oiran-final-release-271`.
- Production reports API/platform `2.5.4`; the exact source commit carrying those
  constants is `e33515d551eae0f3de44b1b7d525a33a9365a478` and is an ancestor of the
  candidate. Binary-to-source reproducibility is not proven by the version string
  alone. Running binary SHA-256:
  `7a9c5711ed1827dc9ed8fef1c34ff63816a86deccc70fadf4219643153cfd657`.
- Reviewed target after hardening: API `2.7.2`, live-probe `0.4.1`, Analyzer
  `2.7.0`.

Commands:

```text
git fetch origin hermes/final-anr3-20261101
git rev-parse origin/hermes/final-anr3-20261101
# 92c1b08cd63202272986b64702ee97a334f010a3
git merge-base --is-ancestor e33515d... 92c1b08...; echo $?
# 0
curl http://127.0.0.1:49152/api/v1/version
# HTTP 200; backend_api/platform_core 2.5.4
sha256sum /opt/oiran/bin/oiran-api /proc/1262927/exe
# identical 7a9c5711...657
```

## Exact POLARIS/OIRAN contract

ANR2 confirmed that POLARIS 0.28.0 returns this outer envelope:

```text
polaris-oiran.lte-import-envelope.v1
  provenance
  oiran_import:
    oiran.lte-evidence-ingestion.v1
      bundle_id
      evidence: oiran-polaris.lte-e2e-evidence.v1
      capture_bindings[]
```

The existing `POST /api/v1/lte/evidence/import` now accepts either the nested
direct request or that complete strict outer envelope. For the outer form it
validates source/RAT/session-reference state, exact run/profile/scenario/time
equality, unique planes and exact SHA256-derived capture IDs before opening any
artifact. Unknown fields remain fail-closed.

The evidence is terminal `CLEAN`/`COMPLETED`; plans are exactly unique
`S1_MME`, `S11`, `S1_U`; every reference is `SANITIZED_APPROVED`. Bindings carry
relative artifact paths, source/event SHA-256, decoder and event-schema versions,
endpoint roles and the capture-ref index. RAT/provenance/session references remain
inside bounded step measurements. Unknown fields fail deserialization.

OIRAN validates required planes, reference uniqueness/resolution, hashes, decoder
metadata equality, frame ranges, event capture ID, packet source and range, event-ID
deduplication, cleanup proof and identity absence before atomic publication. S5 and
5G planes are intentionally rejected by this LTE endpoint. N2/N3/N4 remain on the
existing CaptureManager atomic dataset path; the two sources merge only at the read
model.

Contract: `OIRAN/docs/LTE_EVIDENCE_INGESTION_CONTRACT.md`.

## Changes in this review

- API provenance filenames carrying an identity label or an identity-length digit
  run are now returned as `capture://REDACTED.pcapng`.
- Added fail-closed regressions for duplicate planes, duplicate event IDs, capture-ID
  mismatch and packet-source mismatch.
- Added exact POLARIS 0.28.0 outer-envelope admission with strict outer/nested
  provenance equality and a POLARIS-shaped regression.
- Updated SemVer/changelog and documented the exact adapter boundary. No
  `deny_unknown_fields`, required-plane or approval check was weakened.

## Privacy review

The 2.7.1 tree removes identity-bearing keys and IE objects at the common JSON
success/pagination boundaries and regenerates HTML from a sanitized CallFlow. The
covered routes include datasets, sessions, events, packets, Call Flow, JSON export
and HTML export for viewer and operator. Useful protocol events, technical TEIDs,
accounting and sanitized capture provenance remain.

No repository real capture has an explicit current `SANITIZED_APPROVED` release
manifest suitable for this mission. Therefore no real PCAP was opened. Synthetic
anonymized fixtures are the only approved test source; the real-capture gate remains
closed.

## Validation status

Completed before the final envelope adjustment:

```text
CARGO_BUILD_JOBS=1 cargo check --offline -p oiran-api -p live-probe
# PASS at the preceding hardening revision; API 2.7.2 and live-probe 0.4.1
git diff --check
# PASS after removal of one Markdown trailing space
```

Final-envelope targeted execution:

```text
CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 cargo test --offline -p live-probe \
  accepts_exact_polaris_outer_envelope_and_rejects_provenance_drift -- --nocapture
# PASS: 1 passed, 0 failed
```

The matching API route/auth regression was started in a single worker, then
interrupted when `MemAvailable` fell to `4,273,061,888` bytes, below the 4 GiB
gate. It is **NOT EXECUTED** and the final API adjustment is therefore not
claimed fully compiled/tested.

The candidate's committed evidence records these prior commands/results on the exact
92c1b08 tree:

- integrated Rust/API suite: 136 passed, 0 failed, 4 ignored;
- protocol decoders: 82 passed, 0 failed;
- frontend: 75/75, typecheck/build/leak scan PASS;
- bounded Call Flow: 8,192 events, 100-event cursor pages, peak RSS 12,595,200 B.

The broader targeted replay was not completed because the resource gate crossed
below 4 GiB twice while other single-worker builds were active. The new
fail-closed provenance regression passed; the remaining API/privacy targeted
tests and full suite remain **NOT EXECUTED** on the final tree. A release verdict
cannot treat them as PASS.

Ignored stress tests remain explicit:

- continuous 300 MiB segment / 32 MiB allocation;
- continuous N3 500 MiB / 64 MiB allocation;
- verified 512 MiB copy / 32 MiB allocation;
- 600 × 2 MiB source-segment bound (about 1.2 GiB input).

Repository-wide `cargo fmt --all -- --check` debt is inherited (candidate report:
1,463 proposed diff lines across unrelated crates). It was not bulk-applied or rerun
under the resource stop.

## Read-only resource and capture evidence

```text
df -h / /var/lib/oiran/captures
# /dev/sda1 387G, 215G used, 172G available, 56% (later 57%)
pgrep -x dumpcap | wc -l
# 12
systemctl show oiran-api.service -p MainPID -p MemoryCurrent -p MemoryPeak -p MemoryMax
# MainPID=1262927, MemoryCurrent=61,321,216, MemoryPeak=268,435,456,
# MemoryMax=268,435,456
```

The 12 dumpcap PIDs were inspected only; no process was signalled or interrupted.

## Deployment and rollback recipe (not executed)

1. Re-open the memory gate (stable `MemAvailable >= 4 GiB`), disk `<85%`, and record
   all 12 dumpcap PIDs/start times.
2. Execute the targeted tests plus the full locked single-worker suites and frontend
   build/leak scan; generate SHA-256 manifest for API, decoder and web assets.
3. Back up/hash the running API, web assets, systemd units/drop-ins, capture/dataset
   registries and configuration. Do not copy or log secrets.
4. Replace only reviewed OIRAN artifacts atomically; restart only `oiran-api` if
   separately authorized. Capture Helper and external dumpcaps remain untouched.
5. Verify `/health`, `/version`, auth, datasets/sessions/callflow, raw privacy routes,
   bounded pagination, RSS below 256 MiB and unchanged dumpcap identities.
6. On any failure, atomically restore the prior API/assets, restart only `oiran-api`,
   verify running SHA `7a9c5711...657`, registry integrity and all dumpcap PIDs.

## Verdict

`PARTIAL / RESOURCE-GATED`

The live-probe contract implementation and exact POLARIS envelope test pass.
Production remains unchanged. Promotion is blocked until the final API tree,
remaining targeted tests and release artifact build/hash execute above the
resource gate. Real LTE certification remains separately blocked by absence of an
explicitly approved real-capture manifest.

— ANR3
