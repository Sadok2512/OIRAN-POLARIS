# ANR2 — POLARIS final release report

Date: 2026-11-01 UTC  
Mode: offline/staging only; production unchanged

## Candidate

- Branch: `release/oiran-polaris-final-p0-anr2-report`
- Base reviewed: `ac8748c1713cb039686ad42f6549ca0a55dff5ba`
- Release code SHA: `8cb356a7e4264b80fb82e2f1c90b9511f581df41`
- POLARIS API: `0.28.1`
- Simulator Control UI: `0.20.0`
- Production observed read-only: API `0.26.0`, platform `3.2.1`, OIRAN API `2.5.4`.

Lineage commands:

```text
git merge-base --is-ancestor 2dd98d70... ac8748c...  # 0
git merge-base --is-ancestor 4669de8b... ac8748c...  # 0
git merge-base --is-ancestor 70faacb5... ac8748c...  # 0
```

The final SHA retains those ancestries. No `merge -s ours` was used.

## Final evidence boundary

`POST /api/v1/lte/runs/:run_id/evidence-envelope` requires Operator or
Administrator authentication plus CSRF. The browser supplies only an opaque
bundle ID. The OIRAN finalizer owns a private server-staged manifest and files.

POLARIS now:

- requires a terminal `CLEAN`/`COMPLETED` run and all cleanup observations;
- binds the staged manifest to the exact run, controller-owned profile and
  certification scenario;
- accepts exactly one `SANITIZED_APPROVED` reference for each of `S1_MME`,
  `S11` and `S1_U`;
- confines regular files below the canonical bundle directory and rejects
  traversal, symlinks, missing files and SHA256 drift;
- recalculates capture and normalized-event hashes rather than trusting HTTP
  metadata;
- persists the admitted bundle ID and capture references atomically; exact
  replay is idempotent and changed evidence returns a conflict;
- emits the exact `oiran.lte-evidence-ingestion.v1` request. RAT, observation
  timestamps, provenance and pseudonymous session refs are carried in bounded
  evidence measurements; no OIRAN session ID is invented;
- never changes `POLARIS_LTE_E2E_CERTIFIED`.

Contract: `POLARIS_CONTROL/docs/api/lte-evidence-envelope.contract.md`.

## Security and functional review

- Grant V2: persistent ownership, exact subject/digests, Operator session,
  CSRF, nonce, expiry, revocation and one-time consumption remain enforced.
- Temporary activation remains restricted to `LTE-SRSUE-TEST-01`, one UE and
  `CERTIFICATION_RUN`; `LIVE_OPERATIONAL` remains locked while uncertified.
- Stop/emergency cleanup remains grant-independent and idempotent.
- UI regression covers LTE/5G Topology, UE Manager RAT/simulator, 13 templates,
  bounded LTE certification controls and measured Traffic Sessions.
- IMSI role tests pass: Operator sees the API identity, Viewer receives the
  protected form; K/OPc are never serialized.
- No DEMO source was added and no live process, grant or traffic was started.

## Manual tests

Backend binary provenance for base `ac8748c`: source mtimes precede the compiled
test binary. Direct execution avoided Cargo cross-worktree cache ambiguity.

```text
target/debug/deps/polaris_control_api-dbd657a6f78b88e1 --test-threads=1
# 248 passed; 0 failed; 3 ignored; 394.24 s

/root/.cache/anr2-node20/bin/node node_modules/typescript/bin/tsc -b --pretty false
# PASS, no diagnostics; Node v20.20.0

/root/.cache/anr2-node20/bin/node node_modules/vitest/vitest.mjs run \
  --maxWorkers=1 --minWorkers=1
# 38 files; 235 passed; 0 failed; 96.53 s

/root/.cache/anr2-node20/bin/node node_modules/vite/bin/vite.js build
# PASS; 1,708 modules; JS 542.29 kB (gzip 152.87 kB)

playwright test lte-integration topology ue-manager traffic
# 24 passed; 0 failed; 1280/1440/1920, light/dark; 39.8 s
```

The final 0.28.1 test binary was then executed directly, single-threaded:

```text
target/debug/deps/polaris_control_api-0e958ab517ad3494 --test-threads=1
# 249 passed; 0 failed; 3 ignored; 369.87 s
```

Before the full run, the three new scope/replay/HTTP tests each passed in
isolation. One fixture first failed because it omitted the run ID suffix; the
fixture was corrected and the targeted test was rerun GREEN before regression.

Three ignored Rust tests are explicit manual high-volume persistence/benchmark
tests, not silent failures. Vitest emits inherited React `act(...)` warnings but
exits zero.

## Artifacts and resources

- Deterministic UI `dist` tar SHA256:
  `bd749ab68cd57803d21f43b73baaf0693b3c0487686238d595dde870703cb06d`.
- Final 0.28.1 test binary SHA256:
  `3a04dadc055e72d714203aab93cebc404af7e503843dfbbde1cea727962554f1`.
- Final source archive SHA256:
  `231ab3f5e4d93a87fb64c886c55d92a626e2b946c0ef59d2ba1e43e5157dfdbf`.
- Final API release binary: not built; the local release link would cross the
  mandatory 4 GiB available-RAM reserve. This remains a release blocker.

Final read-only resource sample: `4,554,108,928` bytes available RAM; disk
`59%`. The lowest sampled available RAM during final test compilation was
`4,326,772,736` bytes, still above the `4,294,967,296`-byte stop threshold.

The external collector count remained 12, but supervisor rotation changed all
PIDs at approximately 09:15 UTC (from the 08:14 set to the 09:14 set). ANR2 did
not signal or restart them. Because packet-level handoff evidence was not
available, continuity without loss is **not claimed**.

## Deployment and rollback

Deployment was not authorized and was not attempted. Fresh backups were not
created because they belong inside the separately authorized deployment window.
The prepared procedure is:

1. Recheck final remote SHA/lineage, RAM, disk and all collector PIDs/start times.
2. Back up and SHA256 the running API, UI assets, environment/configuration and
   POLARIS systemd unit/drop-ins into a root-only timestamped directory.
3. Verify backup readability and build/hash the final API release artifact.
4. Atomically stage API and UI, switch them as one release, restart only POLARIS.
5. Run version/health, real-data routes, RBAC/CSRF/privacy and read-only browser
   recipe; any failure restores all API/UI/config assets and the previous unit.
6. Revalidate API `0.26.0`, UI `0.19.0`, services, resources and collectors after
   rollback.

## Verdict

`BLOCKED`

Code and offline UI/backend regression are strong, but release promotion is
blocked by the missing final API release artifact/hash, unproven collector
rotation continuity, absent deployment authorization and absent real LTE E2E
evidence/import/Call Flow certification.

— ANR2

