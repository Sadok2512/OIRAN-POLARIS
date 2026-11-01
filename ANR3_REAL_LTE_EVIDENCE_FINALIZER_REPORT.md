# ANR3 — Real LTE evidence finalizer

Date: 2026-11-01 UTC  
Project: Sadok2512/OIRAN-POLARIS  
Base: `880c493f6bba5c760722e22b20d15bad3cfe4b78`  
Branch: `feat/anr3-real-lte-evidence-finalizer-p0`

## Verdict

```text
ROOT_CAUSE = CONFIRMED — POLARIS 0.28.3 could validate a prebuilt private bundle but no production code created that bundle.
FINALIZER = PASS — POLARIS 0.29.0 creates an immutable verified bundle from a server-owned authorized release.
MANIFEST = PASS — polaris.oiran-lte-capture-release.v1 binds release/run/profile/scenario/RAT/start/end/outcome/interface/hashes.
CAPTURE_REFS = PASS OFFLINE — only remeasured SANITIZED_APPROVED S1_MME/S11/S1_U proofs are published.
IMPORT = PASS OFFLINE CONTRACT — generated envelope uses oiran.lte-evidence-ingestion.v1; OIRAN 2.7.4 import/API tests pass.
PARTIAL = PASS — FAILED and CANCELLED preserve a non-empty observed subset; COMPLETED requires all three planes.
PRIVACY = PASS — identity labels, 14–16 digit identity values, 32-hex secrets, unsafe paths and unapproved releases fail closed.
TESTS = PASS — POLARIS Rust 270 passed/0 failed/3 manual ignored; OIRAN 13 passed/0 failed; frontend 5 passed/typecheck/build PASS.
SOURCE_SHA = 5d4c7ecca8fc12ecc1f3c64e3c054864551df273
VERDICT = READY
BLOCKERS = Real run lte-run-b12f8f56374b06af8dc4678908f4834b still has no authorized sanitized release manifest; no real capture was opened or retroactively fabricated. Production deployment is not authorized by this mission.
```

`READY` means ready for review/integration and an explicitly authorized
sanitized release. It is not LTE `REAL_PASS` and does not claim that the
historical run has acquired evidence.

## Implementation

New protected route:

```text
POST /api/v1/lte/runs/:run_id/evidence-finalize
body: {"release_id":"<opaque-server-release-id>"}
```

The route requires the existing Operator/Administrator session and CSRF
middleware. The client cannot provide paths, hashes, frames, provenance or
capture references. POLARIS resolves the opaque ID only below the private
`POLARIS_LTE_EVIDENCE_RELEASE_ROOT`.

The finalizer performs the following fail-closed sequence:

1. Confine and parse `oiran-lte-capture-release.json` with unknown fields
   denied and a 1 MiB manifest limit.
2. Require exact run, profile, scenario, RAT, start/end timestamps, terminal
   outcome and `SANITIZED_APPROVED` authorization.
3. Confine regular source/event files, reject symlinks/traversal/duplicates,
   and recompute both SHA256 values.
4. Parse normalized JSONL with a 64 MiB retained-input bound and reject
   subscriber/equipment identity labels, identity-shaped values and secret
   material.
5. Copy verified files as 0600 into a 0700 staging directory, write the private
   proof manifest, fsync, and atomically rename it below the bundle root.
6. Reload and re-hash the immutable bundle through the existing POLARIS/OIRAN
   contract before persisting capture refs.

The stable bundle ID is derived from `SHA256(run_id:release_id)`. An exact retry
is idempotent. Manifest or capture drift cannot replace an existing bundle and
returns HTTP 409.

No collector path is read by the HTTP request. No capture, decoded event,
session, TEID, E-RAB or Call Flow is synthesized.

## Terminal and partial behavior

| Run outcome | Required evidence | Publication state expected in OIRAN |
|---|---|---|
| `COMPLETED` | S1-MME + S11 + S1-U | complete import |
| `FAILED` | non-empty observed subset only | `IMPORTED_PARTIAL` when incomplete |
| `CANCELLED` | non-empty observed subset only | `IMPORTED_PARTIAL` when incomplete |
| empty/unapproved/non-clean | rejected | no import |

Cleanup does not delete the release or finalized bundle. The durable run store
persists the admitted bundle ID and capture refs after validation.

## Manual tests and actual results

### POLARIS API/Rust

```bash
CARGO_BUILD_JOBS=1 cargo test -p polaris-control-api
```

```text
270 passed; 0 failed; 3 ignored
```

The ignored tests are the pre-existing manual 100,000-profile persistence and
pagination benchmarks plus restored MongoDB validation; none is related to the
LTE finalizer. New coverage includes complete, failed, cancelled, empty,
partial, hash drift, privacy rejection, immutable replay, Operator/CSRF and
HTTP 409.

After the final privacy hardening, the directly affected test was replayed:

```bash
CARGO_BUILD_JOBS=1 cargo test -p polaris-control-api \
  lte_orchestrator::tests::real_finalizer_rejects_empty_privacy_leaks_hash_drift_and_conflicts
```

```text
1 passed; 0 failed
```

### OIRAN import, privacy, pagination and Call Flow

```bash
CARGO_BUILD_JOBS=1 cargo test -p live-probe lte_evidence::tests -- --nocapture
CARGO_BUILD_JOBS=1 cargo test -p oiran-api lte_evidence -- --nocapture
```

```text
live-probe LTE evidence = 10 passed; 0 failed
OIRAN LTE API = 3 passed; 0 failed
```

These tests verify exact POLARIS envelope admission, atomic import,
idempotence/conflict, `IMPORTED_PARTIAL`, S1-MME/S11/S1-U materialization,
session/Call Flow creation, ambiguous TEID isolation, bounded pagination,
RBAC/CSRF and JSON/HTML export privacy.

### POLARIS frontend regression

```bash
npm ci --no-audit --no-fund
npm run typecheck
npm test
npm run build
```

```text
TypeScript = PASS
Vitest = 1 file, 5 tests passed
Vite production build = PASS, 23 modules
```

No frontend source changed; this is a regression check of the existing client.

### Formatting and leak checks

```bash
git diff --check
rg -n -i '<identity/secret patterns>' <changed source and documentation>
```

```text
git diff --check = PASS
new clear subscriber/equipment identities = none
```

The repository has pre-existing `cargo fmt --check` drift in unrelated API
modules. Only the modified finalizer module was formatted; unrelated formatting
was not committed.

## Resource and collector safety

```text
disk = 80% (<85% stop threshold)
available RAM after builds = approximately 9 GiB
dumpcap process count = 12
live/grant/traffic/deployment/import = none
real PCAP opened or decoded = none
```

The current 12-process dumpcap snapshot differs from the earlier diagnostic
snapshot because their PIDs/output filenames changed outside this worktree.
This task did not signal, restart or modify them; uninterrupted collector
continuity is therefore not claimed.

## Required integration step

An authorized capture-release process must create the private release directory
and manifest from approved anonymized S1-MME/S11/S1-U material, then invoke the
finalizer. Only the returned envelope may be posted to OIRAN. Without that
release, the historical run remains truthfully empty and Call Flow remains
unavailable.

— ANR3
