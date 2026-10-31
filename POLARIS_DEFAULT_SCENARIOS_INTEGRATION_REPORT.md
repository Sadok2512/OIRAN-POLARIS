# POLARIS Default Scenarios — Integration Report

Date: 2026-10-31 UTC

Agent: ANR1

Verdict: **PASS (offline integration only)**

## Source and integration provenance

| Item | Evidence |
|---|---|
| Common base | `87daa3445e3058352d21efeba21d05fefe3029d4` |
| Integration branch | `integ/polaris-default-scenarios-v1` |
| Backend source | `a2a9d10adbb1e098a3dd49ba0af525dbddbd652c` |
| Frontend source | `0a226bf9f9d7740e8f325f1687ae5fe2b25a6735` |
| Validated contract | `ff748ef26af67325e896de0dfed53434f762410c` |
| Backend merge | `2e87a04` (`ort`, no `ours`) |
| Frontend merge | `60c66ba` (`ort`, no `ours`) |
| Integration correction | `ff5ce47c7fe2e78150bfc6a15bc5a9970924f2b3` |

Both `git merge-base --is-ancestor <source> HEAD` checks returned status 0. No conflict was hidden and neither source branch was overwritten.

## Integrated contract

- API catalogue: 13 immutable system templates: 6 LTE/srsRAN and 7 5G SA/UERANSIM.
- Honest support distribution: 3 `SUPPORTED`, 2 `CERTIFICATION_REQUIRED`, 8 `BACKEND_REQUIRED`.
- Source templates are read-only; customization creates a durable user-owned clone.
- Operator/RBAC and mutation gates remain server-enforced; no scenario was executed.
- Existing user scenarios remain in the durable definition store.
- Integration correction: frontend 0.17.1 now preserves RAT, simulator, description, provenance, support status and fixed string/boolean parameters (`dnn`, `protocol`, etc.) across clone/save round trips.

## Manual validation

| Command | Result |
|---|---|
| `cargo test -p polaris-control-api` | PASS — 228 passed, 0 failed; 3 documented manual benchmark/Mongo tests ignored |
| `npm run test -- --run` | PASS — 36 files, 224 tests |
| `npx tsc --noEmit` | PASS |
| `npm run build` | PASS — `index-CRWd4Vuh.js` |
| `npm audit --omit=dev --json` | PASS — 0 production vulnerabilities |
| `npx playwright test e2e/default-scenarios.spec.ts` | PASS — 6/6; catalogue/filter/load/customize/clone/save, 1280/1440/1920 light/dark |
| read-only preview Playwright spec | PASS — 6/6; 13 templates, exact 3/2/8 distribution, mutation rejected with HTTP 423 |

The Rust catalogue tests cover immutable templates, exact defaults/status counts, cloneability and operator/RBAC failure paths. The frontend suite also preserves the existing UE Manager and 5G behavior. React test `act(...)` warnings remain non-failing test-harness warnings; no assertion failed.

## Preview and captures

The isolated preview is bound to loopback only:

`http://127.0.0.1:4332/simulator/`

It serves the built catalogue and rejects every POST/PUT/PATCH/DELETE under `/polaris-api/` with HTTP `423 READ_ONLY_PREVIEW`. The integration test environment on port 4330 used intercepted API fixtures solely to exercise clone and save; it was stopped after validation. The shared preview and production were not touched.

Eighteen screenshots are stored under `apps/simulator-control/docs/screenshots/default-scenarios/`: LTE, 5G and read-only preview at 1280, 1440 and 1920 in light and dark themes.

Build integrity:

- `dist/index.html`: `fe176f77030c5344196fe3c990df40ca30bab5ef589102ac32eba3512d197d92`
- JS: `8587617a83fa3aeda80adc25179f810574faa056211c3bfb4e565e2b3f41b228`
- CSS: `26ad08d7aa8dd96aa3972d1a90755e223b7047d51f4bebe8cc6d390451425d1c`

## Safety evidence

- `df -h /`: 48% used (below 85%).
- `/proc/meminfo`: 4,370,936 kB available at final validation (above 4 GiB).
- `pgrep -x dumpcap | wc -l`: 12 before and after validation.
- No live execution, production deployment, historical-data mutation or subscriber identity exposure occurred.

## Open items

None blocking this offline integration. Production deployment and any live LTE/5G execution remain separately gated and unauthorized.

— ANR1
