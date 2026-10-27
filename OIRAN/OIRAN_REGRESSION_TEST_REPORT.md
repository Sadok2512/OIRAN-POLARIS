# OIRAN Dataset Fix Regression Test Report

## Results

- Rust workspace: **131/131 PASS**.
- API unit/integration tests: **16/16 PASS** (included in the Rust total).
- Frontend unit tests: **10/10 PASS**.
- Browser E2E tests: **34/34 PASS**.
- TypeScript validation: **PASS**.
- Vite production build: **PASS**.

The suite covers missing dataset directories, empty PCAPs, unsupported traffic, supported PFCP traffic, permission failures, decoder failure, atomic finalization, registration rejection, failed-capture recovery, idempotent recovery, authorization, dataset visibility, empty-session behavior, historical analysis, Session Explorer, and Call Flow rendering.

The E2E expectations were updated from the pre-recovery fixed counts to the deployed evidence: six captures, two datasets, the recovered dataset with 20 events and zero sessions, and original capture `live-1792964646320-0003` remaining `FAILED`.

Historical dataset checksum inventory before and after deployment is identical.

