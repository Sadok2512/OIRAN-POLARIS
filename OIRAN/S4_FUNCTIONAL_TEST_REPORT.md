# S4 Functional Test Report

## Automated results

| Suite | Result | Count |
|---|---|---:|
| Rust workspace regression + API | PASS | 71/71 |
| Frontend unit/component | PASS | 8/8 |
| Browser end-to-end matrix | PASS | 25/25 |
| TypeScript type check | PASS | 0 errors |
| React production build | PASS | 1,633 modules transformed |
| npm security audit | PASS | 0 vulnerabilities |

All `WEB-001` through `WEB-025` tests passed in 30.6 seconds. `tests/e2e/results.json` records 25 expected, 0 unexpected, 0 skipped and 0 flaky. The suite authenticates against the real Rust API and certified dataset, validates the exact event/edge counts, exercises NGAP/PFCP/GTP-U inspection, tests filters/deep links/exports/errors, and captures eight real screenshots.

## Acceptance gates

| Gate | Result | Evidence |
|---|---|---|
| A Build | PASS | Rust release, TypeScript and Vite production build |
| B Real data | PASS | 54 source / 26 session / 28 background / 12 edges / 54 provenance |
| C Probe Manager | PASS | Real probe, interfaces, checksums; live control disabled |
| D Session Explorer | PASS | One actual session, filters, paging, background separation |
| E Call Flow | PASS | Canonical events, directions, statuses, IE/provenance/evidence and exports |
| F Correlation Studio | PASS | 12 backend edges, 2 STRONG and 10 EXACT, no inflation |
| G UI/UX | PASS | Eight screenshots and two no-overflow checks |
| H Security | PASS | Authenticated read-only API, RBAC roles, localhost bind, sanitized output |
| I Protection | PASS | Baseline artifact hashes unchanged; no mission lifecycle mutation |

No test was reported PASS without execution. Early test-development failures were corrected and the final complete run is the recorded certification run.
