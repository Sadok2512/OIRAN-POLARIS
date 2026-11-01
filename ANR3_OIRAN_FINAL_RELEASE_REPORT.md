# ANR3 — OIRAN final release report

Date UTC: 2026-11-01  
Base: `hermes/final-anr3-20261101` at `92c1b08cd63202272986b64702ee97a334f010a3`  
Working branch: `release/anr3-oiran-final-p0`  
Scope: offline development and read-only production observations. No deployment,
capture action, grant, UE start, traffic generation, or service restart.

## Release delta

Prepared versions:

- OIRAN API/platform `2.7.2` (from candidate API `2.7.1`).
- live-probe `0.4.1`.
- Analyzer `2.7.1`.

Corrections:

1. LTE evidence admission rejects SUCI, SUPI, GUTI/TMSI, PEI,
   IMEI/IMEISV variants and subscriber/authentication/security key labels and
   identity-shaped values. Opaque pseudonyms remain supported.
2. The paginated LTE session response now crosses the common recursive privacy
   boundary.
3. Persisted LTE Call Flows can be exported through the existing JSON/HTML
   route. Catalog/session resolution is fail-closed and the input artifact is
   capped at 64 MiB before allocation.
4. Analyzer renders `S1-MME ↔ S11` and `S11 ↔ S1-U`; LTE E2E remains
   `UNKNOWN` unless both mandatory bridges are `EXACT` or `STRONG`. Existing
   N2/SBI/N4/N3 rendering is preserved.

No DEMO dataset, generated counter, capture reference, or live state was added.

## Contract and real-evidence finding

OIRAN provides `POST /api/v1/lte/evidence/import`, requires Operator plus CSRF,
and validates:

- envelope `oiran.lte-evidence-ingestion.v1`;
- evidence `oiran-polaris.lte-e2e-evidence.v1`;
- exactly `S1_MME`, `S11`, `S1_U`;
- capture/event SHA-256, frame bounds, decoder/event versions and confined
  bundle paths;
- `SANITIZED_APPROVED`, event packet provenance, deduplicated event IDs,
  idempotent request hash and atomic publication.

The POLARIS `70faacb5...` candidate does **not** publish real capture references:
the only `set_capture_refs` occurrence is its method definition and every new
run starts with an empty vector. It also contains no OIRAN import client,
`capture_bindings`, or versioned ingestion envelope. Therefore no real
POLARIS-to-OIRAN import can be certified from the supplied candidates. No
capture reference was invented to bypass this blocker.

The shared canonical schema is byte-identical between the two candidate trees;
SHA-256:
`4eb2a8c124845e6ebfadc32b3ad5459142b24c523e86697178b7fb2395cc1e14`.
Wire compatibility remains partial until POLARIS implements an explicit
adapter which emits only canonical fields and OIRAN-owned bundle bindings.

## Validation

Completed before this delta, on the exact `92c1b08...` base:

- 14 targeted Rust/API tests PASS: privacy, LTE import/materialization,
  correlation, provenance, bounded pagination and fail-closed memory cases.
- Large Call Flow test: 8,192 events, peak RSS `13,082,624` bytes, PASS.

Completed after the frontend delta:

```text
npm test -- src/test/callflow-viewer.test.tsx
Test Files 1 passed; Tests 10 passed

npm run typecheck
PASS

git diff --check
PASS
```

Post-delta Rust/API, full frontend, build, Playwright and release artifact
results are recorded in the final committed revision of this report after the
resource-gated execution. A first Rust compilation attempt was stopped and is
not counted because `MemAvailable` crossed below 4 GiB. Repository-wide
`cargo fmt --all -- --check` still reports the documented pre-existing
formatting debt; no mass reformat was performed.

## Read-only laboratory evidence

Production remained OIRAN API `2.5.4`. Read-only requests observed:

- 11 datasets and 11 reconstructed sessions, all reported as 5G SA;
- one selected historical session with 54 chronological events;
- observed interfaces N2/N3/N4 and protocols NGAP/PFCP/GTP-U;
- correlation `N2_N4=STRONG`, `N4_N3=EXACT`, `E2E=STRONG`.

This proves an existing historical 5G Call Flow in the current production data
model. It does not prove candidate deployment, current live continuity, or LTE
E2E. No new 5G operation was run.

## Resource/capture safety

Initial gate: RAM available `5,062,410,240` bytes, RAM used
`15,908,171,776` bytes, disk `57%`, 12 dumpcap. Initial PID/start-time snapshot
SHA-256: `4fe9f419d92e43bd68cdf78cf7e36d15e7fed415245bc36bff072f23084cf9e5`.

All build/test starts are conditional on available RAM >=4 GiB, used RAM <=16
GiB and disk <85%. The 12 external dumpcap processes were not signalled,
reconfigured or restarted. A future deployment must compare PID/start-time and
capture rotation manifests immediately before and after; this review cannot
certify lossless continuity across an operation that has not happened.

## Verdict

OIRAN_RELEASE = pending final post-delta test/build results.  
REAL_LTE_IMPORT = BLOCKED.  
LTE_E2E = BLOCKED — no approved real three-plane LTE bundle and no POLARIS
capture-reference publisher.  
5G_E2E = PARTIAL — existing historical read-only evidence, no new live test.  
DEPLOYMENT = NOT_AUTHORIZED / NOT_PERFORMED.

— ANR3
