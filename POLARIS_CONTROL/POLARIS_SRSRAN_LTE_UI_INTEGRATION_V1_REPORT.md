# POLARIS srsRAN LTE UI Integration V1 — ANR2

Date: 2026-10-31  
Scope: POLARIS backend and existing Simulator Control frontend only  
Deployment: **not performed**  
Live LTE/5G execution: **not performed**

## Delivery

- API: `0.21.0`
- Frontend: `0.14.0`
- Branch: `feat/polaris-srsran-lte-ui-v1`
- Base API candidate: `a483e0a9e0e0031c42b0e805eaf29ea052dbe746` (`0.20.2`)
- Integrated frontend lineage: `a39e692` (`0.13.1`), imported without downgrading the API line

## Architecture and behavior

- One POLARIS application: no duplicate UE Manager or Scenario Builder.
- Backend module `srsran_controller` observes exact allowlisted containers for `ENB-01`, `LTE-UE-01`, and EPC; commands use direct argv, never a shell.
- Typed endpoints: `GET /lte/status`, `GET /lte/logs`, `POST /lte/components/start`, `POST /lte/components/stop`.
- Live start is fail-closed behind operator RBAC, CSRF, execution mode, valid grant, resource gate, `POLARIS_SRSRAN_LIVE_ENABLED=true`, and `POLARIS_LTE_E2E_CERTIFIED=true`.
- Stop is bounded, idempotent, operator-only, and deliberately remains grant-exempt for cleanup safety.
- Logs redact subscriber/authentication material. IMSI is never added by the LTE integration.
- UE inventory is extended only when an LTE/EPC component is actually observed, preserving existing 5G counts otherwise.
- Existing UI gains a shared technology selector, LTE status/control/logs, LTE scenario steps, and LTE traffic selection. LTE traffic/start stays disabled before certification.

## Tests executed manually

- `CARGO_TARGET_DIR=/dev/shm/anr2-polaris-target cargo check --manifest-path POLARIS_CONTROL/apps/api/Cargo.toml --locked --offline`
  - PASS; 5 pre-existing dead-code warnings.
- `CARGO_TARGET_DIR=/dev/shm/anr2-polaris-target cargo test --manifest-path POLARIS_CONTROL/apps/api/Cargo.toml --locked --offline srsran_controller -- --nocapture`
  - PASS: 3 passed, 0 failed.
- Same command filtered on `lte_api_is_observable_but_start_stays_locked_without_certification`.
  - PASS: status remains observable, live start returns 423, mock runtime starts nothing.
- Full backend suite, same tmpfs target and offline/locked options.
  - Initial run: 194 passed, 4 failed, 3 ignored; failures identified artificial unobserved LTE inventory/capability exposure.
  - Corrected targeted regressions: PASS.
  - Final rerun: PASS — 198 passed, 0 failed, 3 ignored (explicit manual benchmarks), 47.81 s.
- `node_modules/.bin/tsc -p tsconfig.json --noEmit`
  - PASS.
- `node_modules/.bin/vitest run`
  - PASS: 35 files, 215 tests; pre-existing React `act(...)` warnings only.
- `node_modules/.bin/playwright test e2e/lte-integration.spec.ts`
  - PASS after correcting a test locator: 1280/1440/1920, light/dark, API fully mocked.
  - No live srsRAN, UERANSIM, UE, scenario, or traffic was started.

## Safety and release gates

- Production was not modified, restarted, or deployed.
- Open5GS, OIRAN, gNB, external capture, and dumpcap were untouched.
- Live LTE remains disabled by default and requires ANR1 LTE E2E certification plus explicit deployment authorization.
- Final disk check: 71.5759% used (`df` displays 72%), below the 85% limit. Build artifacts were nevertheless redirected to `/dev/shm` throughout the audit to avoid pressure.

## Rollback

Revert the delivery commits on this branch. No runtime data or production configuration requires rollback because no deployment or live execution occurred.

— ANR2
