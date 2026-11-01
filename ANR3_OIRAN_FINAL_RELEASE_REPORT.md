# ANR3 — OIRAN final release report

Date: 2026-11-01 UTC
Branch: `release/anr3-oiran-final-p0`
Base: `92c1b08cd63202272986b64702ee97a334f010a3`

## Release

OIRAN API/platform `2.7.2`, live-probe `0.4.1` and Analyzer `2.7.1` integrate the strict POLARIS LTE envelope adapter, provenance/deduplication checks, S1AP/S11/S1-U session and Call Flow materialization, recursive API/export privacy, bounded pagination and LTE bridge rendering. N2/N3/N4 behavior is preserved. No dataset, counter, capture reference or state is fabricated.

POLARIS `0.28.1` at `8cb356a7e4264b80fb82e2f1c90b9511f581df41` produces the direct `oiran.lte-evidence-ingestion.v1` body from server-staged, rehashed `SANITIZED_APPROVED` S1-MME/S11/S1-U artifacts. OIRAN accepts this body and the stricter `polaris-oiran.lte-import-envelope.v1` wrapper. Both paths fail closed on provenance drift. No real bundle was imported.

Privacy admission and response boundaries reject IMSI/SUPI/SUCI/GUTI/TMSI, IMEI/IMEISV/PEI/MSISDN and K/OPc/authentication/subscriber/security keys. Canonical SHA-256 evidence identifiers remain accepted; opaque pseudonyms are not exposed as subscriber identities.

## Manual validation

```text
CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_INCREMENTAL=false cargo test --locked -p live-probe --lib
# 56 passed; 0 failed; 4 ignored
CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_INCREMENTAL=false cargo test --locked -p oiran-api --lib
# 41 passed; 0 failed; 0 ignored
npm test
# 77 passed; 0 failed
npm run typecheck
# PASS
npm run build
# PASS; JS 360.39 kB
playwright test v2_3_session_explorer.spec.ts --grep 'dataset inventory|explicit scopes|historical selection'
# 3 passed; isolated read-only preview
```

The first post-merge Rust run found one provenance fixture rejected earlier by the stronger privacy boundary; SHA-256 identifiers were explicitly exempted and the complete suite then passed. The first API compile exposed one missing test-only import after the envelope merge; it was restored and the complete API suite passed. Four ignored live-probe tests are documented high-volume memory tests. Repository-wide inherited `rustfmt` debt remains; both modified Rust packages and `git diff --check` pass.

Frontend artifact SHA-256: JS `a5604ec9da2b3b62ceeb570c6591d39f4e398d0674731c90727eec4719704538`, CSS `481e6c7cd2a0a229b3904b1c416f4177bd0e727da9756cff9bea3b492b8dd031`, HTML `ecd5a0129418abe86043b836276c29ceb65bdc0b3f654ca1f77fde6065b6de4e`. Final release API binary SHA-256: `8c99a76d037d6dc731f6c16349505f1f1b26e1381874c70f12d9baff450a28e1`.

## Laboratory and safety

Read-only production observation found 11 historical 5G SA sessions. One selected session contained 54 chronological NGAP/PFCP/GTP-U events over N2/N4/N3 with `N2_N4=STRONG`, `N4_N3=EXACT`, `E2E=STRONG`. This is historical evidence, not a new 5G certification. No approved real LTE three-plane bundle was available, so LTE remains uncertified.

The 12 external dumpcap processes were never signalled or reconfigured. Their supervisor rotated all PIDs around 09:15 UTC; the final PID/start snapshot is `b6f5a7771f9b013b9052f7eaf810693523f62937fe9b61970355ecfddb0cb8b9`. Packet-level continuity across that external rotation is not proven. Disk was 59%; all builds started above the 4 GiB available-RAM gate.

## Verdict

OIRAN_OFFLINE_RELEASE = READY_FOR_REVIEW.
DEPLOYMENT = NOT AUTHORIZED / NOT PERFORMED.
LTE_E2E = BLOCKED without approved real capture bundle and deployed releases.
5G_E2E = PARTIAL historical evidence only.
OVERALL = BLOCKED; no `FINAL_PASS` or `REAL_PASS` is claimed.

— ANR3
