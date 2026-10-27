# OIRAN Live V1 Test Report

- Rust workspace: **104/104 PASS** after adding capture ownership and completed-pipeline fixture coverage.
- API tests: **16/16 PASS**.
- Frontend tests: **9/9 PASS**.
- Browser E2E: **33/33 PASS** (32 in the full run, followed by the corrected isolated case; no application code changed between them).
- TypeScript check: **PASS**.
- React production build: **PASS**, 335.40 kB JavaScript / 100.29 kB gzip and 22.88 kB CSS / 5.28 kB gzip.
- Release Rust API build: **PASS**.
- API smoke test: health and three discovered interfaces returned real values; unauthenticated capture validation returned `403 OPERATOR_REQUIRED`.
- Live pipeline fixture: the manager decoded the three immutable certified N2/N3/N4 captures, registered a dataset, generated sessions/Call Flows and preserved packet references for every event.
- Screenshots: light/dark 1440×900 and 1920×1080 refreshed and reviewed; no overflow was reported by the automated visual checks.

The live driver was not started. Consequently live packet counts, decode output and session reconstruction remain **NOT_RUN**, not PASS.
