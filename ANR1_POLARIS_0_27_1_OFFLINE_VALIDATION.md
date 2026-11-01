# ANR1 — POLARIS API 0.27.1 offline validation

Date: 2026-11-01 UTC

Base: `a6c34e1d17d8ad2980c385bf689312e29cc0e5a2`

Scope: source-only LTE controller hardening. No deployment, grant, UE, traffic,
capture, Open5GS, OIRAN or service mutation was performed.

## Integrated corrections

- Administrator disable revokes the Certification Grant V2 before clearing the
  temporary LTE activation.
- An idempotent activation request cannot reactivate a revoked grant.
- UDP iperf execution applies the certified `-l 1200` payload bound while TCP
  remains unchanged.
- Existing controller protections retained by the base include serialized
  start/cleanup, deadline rechecks, exact consumed-grant ping/UDP constraints,
  the 4 GiB available-memory reserve, the 16 GiB used-memory ceiling and
  grant-independent emergency cleanup.

## Manual test evidence

```text
CARGO_BUILD_JOBS=1 cargo test -p polaris-control-api \
  temporary_activation_requires_operator_csrf_nonce_and_is_revoked_with_grant \
  -- --nocapture --test-threads=1
PASS — 1 passed, 0 failed

CARGO_BUILD_JOBS=1 cargo test -p polaris-control-api -- --test-threads=1
PASS — 244 passed, 0 failed, 3 ignored
```

The ignored tests are the declared manual 100,000-profile and isolated MongoDB
resource tests. The UDP production-boundary module regression also passed, as
did all 12 tests in `srsran_controller`.

Admission before compilation: `MemAvailable=5,109,919,744` bytes; root disk
55%. Compilation used one worker and completed without OOM.

## Remaining gates

- Production still runs API 0.26.0; 0.27.1 is not deployed.
- Real LTE S1 Setup, Attach, IP and bounded UL/DL remain unexecuted.
- External collector continuity is not certified by a count-only assertion;
  the separately proven hourly `timeout` rotation still creates a short blind
  interval and remains an infrastructure blocker for lossless certification.
- Deployment and the bounded LTE run require their distinct operator gates.

Verdict: `OFFLINE_PASS / DEPLOYMENT_NOT_AUTHORIZED / REAL_E2E_NOT_RUN`.

— ANR1
