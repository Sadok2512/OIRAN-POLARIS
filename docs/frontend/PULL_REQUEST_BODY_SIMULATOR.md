# PR body — `feat(simulator): advanced mobile scenario builder V1 — integrated`

> Paste below as the PR body
> `feat/polaris-advanced-scenario-builder → main`.

## Final integration update

Added the missing POLARIS surface so `apps/simulator-control` is a
drop-in replacement for the legacy preview served at `/simulator/`:
Network Nodes page (`/nodes`), Traffic Generator page (`/traffic`),
Operator Login with CSRF handling, and a header identity badge. **No
second Simulator Control app** — the Scenario Builder is now inside the
single app that owns UE Manager, gNB Manager, Operator Login, Traffic
and History. Backend untouched.

## Scope

- **New app**: `apps/simulator-control` (`@telecom/simulator-control` 0.1.0)
- **Docs**: `docs/frontend/SIMULATOR_SCENARIO_BUILDER.md`

No file under `OIRAN/`, `POLARIS_CONTROL/`, `services/`,
`infrastructure/`, `apps/{oiran-analyzer, probe-manager, portal}` or
`packages/ui` is touched. No Rust change. No deploy.

## Delivered

### P0 — Scenario Library + Builder

- Dedicated `/scenarios` page: create, edit, duplicate, delete,
  search/filter, scenario version counter, assigned-UE count, last
  update timestamp. Reusable scenario definitions separated from
  execution history.
- Scenario Builder (`/scenarios/:id/edit`): step palette with 14 kinds
  (UE_START, REGISTER_5G, WAIT_REGISTRATION, PDU_ESTABLISH,
  UDP_TRAFFIC, TCP_TRAFFIC, ICMP_TRAFFIC, HTTP_TRAFFIC, IDLE,
  WAIT_RRC_CONNECTED, WAIT_RRC_IDLE, PDU_RELEASE, DEREGISTER, UE_STOP).
  Add / remove / duplicate / move up / down. Steps declare
  `backendCertified` — unsupported steps are saveable but surface a
  visible **"Backend support required"** notice and warning in
  validation.
- Every numeric parameter supports `Fixed` or `Random (min, max)`:
  duration, idle, traffic duration, packet count, packet size, packet
  interval, target bitrate, delay before action, retry interval,
  timeout. Validation enforces positive values, integer-only fields,
  min ≤ max, and backend-safe bounds.
- Timeline preview reuses the committed scenario model and highlights
  the current step when fed one.

### Loop engine

Once / 50 / 100 / Custom / Random (min, max) / Infinite — each with
inline validation. **Infinite emits a WARNING** (saveable but Run
Scenario stays disabled) with explicit text that server-side
execution limits and cancellation are required. Random cycle count is
sampled **once per scenario run**; random step values are sampled on
**each execution of that step** — enforced by `sampleParam` /
`sampleLoopCount` and tested.

### UE Manager + assignment

- `/ues` lists POLARIS UEs from `/ues` and adds an **Assigned Scenario**
  column with a scenario picker + auto-run checkbox (auto-run requires
  a backend endpoint, documented).
- `Start UE` → `/ues/start`. `Run Scenario` → `/scenarios/start` with
  the certified `scenario_type` derived from the scenario shape. `Stop`
  → `/scenarios/stop` targeting only the controller-owned job owned by
  that UE. Shared UEs are protected (buttons disabled).
- No request is sent when the scenario shape doesn't match a certified
  profile — a visible warning explains why.

### Execution Monitor

Polls `/scenarios/status`, `/scenarios/history`, `/traffic/status`
every 2 seconds. Shows scenario_id, job_id, UE target, started_at,
duration, traffic state, packets requested/sent/received, bytes,
CPU/RAM budget, terminal result, state. The user's local scenario
definition is reused for a **Timeline projection** — clearly labeled
"Frontend projection — not a backend execution log". Per-step live
status needs `GET /scenarios/:id/steps` (documented).

### Backend contracts

Reused:
- `GET /auth/me`, `GET /capabilities`, `GET /scenario-capabilities`
- `GET /lab`, `GET /system/health`
- `GET /ues`, `POST /ues/start`, `POST /ues/stop`
- `GET /scenarios/status`, `GET /scenarios/history`
- `POST /scenarios/validate`, `POST /scenarios/start`,
  `POST /scenarios/stop`
- `GET /traffic/status`

Documented missing contracts (surfaced as `Not available` or
`Backend support required`):
- Scenario catalog CRUD (`/scenarios/definitions`)
- UE ↔ scenario assignment (`/ues/:id/assigned-scenario`) + auto-run
- Per-step live status (`/scenarios/:id/steps`)
- Scenario-level cancellation + CPU/RAM safety for infinite loops
- TCP / ICMP / HTTP `scenario_type` support
- `rrc_state` on `/ues`

## Honesty policy

- Catalog + assignments live in `localStorage` until the backend
  contract exists.
- `Run Scenario` only fires when the scenario shape matches a
  certified profile (today: `bounded-controller-ue-udp-v1`).
- Infinite loops are never spawned client-side.
- RRC Idle / Connected waits are flagged `OBSERVATION` + warning.
- Shared UE Start/Run/Stop stays disabled.

## Tests

- `apps/simulator-control`: tsc PASS · Vitest 30/30 · vite build PASS
  (278 kB JS gzip 84 kB)
- Scenario model: 18 cases cover sampleParam, sampleLoopCount
  (including the "once per run" contract), validation (name required,
  random min > max, out-of-range bounds, backend-pending warning),
  certified profile mapping (UDP maps, TCP/HTTP refused, tolerates
  IDLE/WAIT_REGISTRATION).
- Store: 8 cases cover CRUD + duplicate + cascade delete + multi-UE
  assignment.
- Routing: 4 cases cover default route, nav links, library → builder,
  unknown-route redirect.
- Playwright not extended (shared `e2e/mock-api.ts` currently only
  routes OIRAN); tracked as follow-up.

## Not changed

- No Rust change, no `OIRAN/`, no `POLARIS_CONTROL/`
- No `apps/{oiran-analyzer, probe-manager, portal}` change
- No `packages/ui` change

## Checklist

- [x] Branched from latest `origin/main`
- [x] No backend / production change
- [x] No live UE Start/Stop or live traffic executed
- [x] Scenario shape honestly mapped to certified backend profile
- [x] Random cycle sampled once per run, step values once per step
- [x] Shared UE protected
