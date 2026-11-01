# OIRAN LTE evidence publication fix P0

Date UTC: 2026-11-01  
Agent: ANR3  
Scope: offline code and synthetic anonymized fixtures only. No live operation, capture, collector change, deployment, grant, or production-data write.

## Verdict

```text
VERDICT = READY
POLARIS_API = 0.28.3
OIRAN_API = 2.7.4
LIVE_PROBE = 0.4.2
PRODUCTION = UNCHANGED (OIRAN API 2.7.3)
```

`READY` means ready for review and controlled release. It is not a real LTE E2E certification and does not claim that the incident run has been recovered.

## Git isolation

```text
BASE_RELEASE = 7e5e43b512c4066971d2761ee7265c92214f7cc0
INTEGRATED_POLARIS_0_28_2_FIX = d22b24ffc0b4fea792310084dbc7b5020aafbbff
BRANCH = fix/anr3-lte-evidence-publication-p0
WORKTREE = /root/ANR3_LTE_EVIDENCE_PUBLICATION_FIX
```

The shared worktree `/root/OIRAN_POLARIS_FOUNDATION` was dirty and unmerged before this task and was not modified.

## Real publication path

```text
external dumpcap S1-MME/S11/S1-U
  -> OIRAN capture finalizer
  -> private sanitized bundle + polaris-evidence-proof.json
  -> POLARIS POLARIS_LTE_EVIDENCE_BUNDLE_ROOT
  -> POST /api/v1/lte/runs/:run_id/evidence-envelope
  -> server re-hash + scope/provenance validation
  -> persistent RunStore capture_refs + evidence_bundle_id
  -> OIRAN POST /api/v1/lte/evidence/import
  -> atomic dataset, sessions, correlation edges and Call Flow
```

The caller supplies only an opaque `bundle_id`. Capture paths, SHA256, frame bounds, decoder versions, RAT, timestamps, endpoint roles, and session references come from the server-owned finalizer manifest. No reference is derived from run timestamps or state.

## Root cause

The timeout path itself preserved the run:

1. `orchestrate_lte_run_with_timeout` marked the active step `LTE_GLOBAL_TIMEOUT`;
2. `cleanup_lte_run` stopped owned components, verified cleanup, and finalized the run as `CLEAN/FAILED`;
3. temporary activation/grant state was then cleared.

Publication was lost at two fail-closed guards:

- `RunStore::publish_capture_refs` required `state=CLEAN` **and** `outcome=COMPLETED`;
- `build_oiran_evidence_envelope` imposed the same condition and always emitted `final_state=COMPLETED`;
- OIRAN admission rejected every final state other than `COMPLETED` and required all three planes.

Therefore an approved S1-MME proof observed before timeout could not be persisted after cleanup. `capture_refs` stayed empty even though the private bundle remained available.

## Fix

### POLARIS

- Clean terminal outcomes `COMPLETED`, `FAILED`, and `CANCELLED` may publish observed evidence.
- `COMPLETED` still requires all three unique approved planes: S1-MME, S11, S1-U.
- `FAILED`/`CANCELLED` may publish a non-empty subset containing only observed planes.
- Empty, unsupported, duplicate, raw, hash-invalid, path-escaping, or changed evidence remains rejected.
- Step `evidence_refs` are added only for planes actually present; missing S11/S1-U refs are never invented.
- `final_state` is emitted from the durable run outcome.
- `capture_refs` and `evidence_bundle_id` remain atomically persisted, replay-idempotent, and conflict-protected after reload/revocation.

### OIRAN

- Admission accepts only terminal `COMPLETED`, `FAILED`, or `CANCELLED` evidence with fully proven cleanup.
- Completed evidence still requires all three planes.
- Failed/cancelled evidence requires at least one observed approved plane and is stored as `IMPORTED_PARTIAL`.
- Dataset manifests now persist `final_state` and the exact `capture_planes` list.
- Existing atomic staging/rename, request hash idempotence, run conflict, deduplication, privacy scan, session partitioning, TEID ambiguity, pagination, and export guards remain active.
- Partial S1-only evidence can reconstruct the proven S1 context and Call Flow, but contains no invented S11/S1-U event or correlation edge.

## Provenance fields verified

| Field | Enforcement |
|---|---|
| `run_id` | exact manifest/run equality; OIRAN run conflict on changed request |
| RAT | exactly `LTE` in each observed proof |
| SHA256 | source PCAP and normalized JSONL re-hashed server-side |
| timestamps | UTC observation plus run start/end persisted |
| session ID | only safe `lte-session-*` pseudonymous references; reconstructed OIRAN session IDs remain derived |
| planes | unique allowlist `S1_MME`, `S11`, `S1_U` |
| cleanup | all five observations must be true before any terminal import |
| confidentiality | approved sanitization plus recursive identity rejection |

## Tests executed manually

### POLARIS Rust

```bash
CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/tmp/anr3-polaris-evidence-target \
  cargo test -p polaris-control-api lte_orchestrator::tests:: -- --nocapture
```

First run: `17 passed, 1 failed`. The failure showed that absent S11/S1-U planes were still added to step references (`LTE_EVIDENCE_REF_UNRESOLVED`). This was corrected; the failure was not hidden.

Final run after correction and formatting:

```text
18 passed; 0 failed; 0 ignored; 243 filtered out
```

Coverage includes SUCCESS, TIMEOUT, CANCELLED/PARTIAL, CLEANUP, persistent reload, exact replay, conflict, missing/duplicate/unsupported planes, frame bounds, and server-side re-hashing.

### OIRAN evidence store and API

```bash
CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/tmp/anr3-oiran-evidence-target \
  cargo test -p live-probe lte_evidence::tests:: -- --nocapture

CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/tmp/anr3-oiran-evidence-target \
  cargo test -p oiran-api lte_evidence -- --nocapture
```

Results:

```text
live-probe LTE evidence: 10 passed; 0 failed
OIRAN API LTE evidence: 3 passed; 0 failed
```

Verified: atomic import, `IMPORTED_PARTIAL`, replay idempotence, changed-run conflict, cleanup rejection, RBAC/CSRF, privacy, bounded views, JSON/HTML export, session reconstruction, pagination and Call Flow.

### Correlation and isolation

```bash
cargo test -p correlation-engine lte_ -- --nocapture
cargo test -p session-engine cross_plane -- --nocapture
cargo test -p session-engine reused_teid_across_two_contexts -- --nocapture
```

Results:

```text
correlation-engine LTE: 3 passed; 0 failed
partial/out-of-order: 1 passed; 0 failed
reused TEID isolation: 1 passed; 0 failed
```

The complete synthetic bundle uses three distinct PCAP hashes for S1-MME/S11/S1-U. Multi-UE and reused-TEID tests prove that time or TEID alone does not merge sessions.

### Analyzer frontend

```bash
npm test -- --run src/test/lte-offline-ui.test.ts \
  src/test/callflow-viewer.test.tsx \
  src/test/packet-analyzer-identity.test.tsx
npm run typecheck
npm run build
```

Results:

```text
Vitest: 3 files, 16 tests passed
TypeScript: PASS
Vite build: PASS, 1,636 modules
check-dist-leaks: clean, 3 files scanned, 2 prohibited marker families
```

No frontend asset changed.

### Format and repository checks

```bash
rustfmt --edition 2021 --check \
  POLARIS_CONTROL/apps/api/src/lte_orchestrator.rs \
  OIRAN/live-probe/src/lte_evidence.rs
git diff --check
```

Result: PASS. The initial workspace-wide `cargo fmt --check` exposed pre-existing formatting debt in unrelated POLARIS files; only the changed source files were formatted and verified.

## Resource and safety evidence

Final read-only check:

```text
RAM available = 8,452,108,288 bytes
RAM used = 12,518,473,728 bytes
disk / = 70%
dumpcap count = 12
```

Builds ran sequentially with `CARGO_BUILD_JOBS=1`. No collector signal, live traffic, grant, capture, service restart, or deployment occurred.

## Remaining blockers

- The incident run can be recovered only if its server-owned sanitized bundle still exists with valid hashes; this patch will not synthesize missing files or references.
- Production remains OIRAN 2.7.3 and does not contain this fix.
- Deployment and any real-data import require separate explicit authorization and release review.
- Real LTE E2E remains uncertified until an approved run proves the required planes and complete chain.

— ANR3
