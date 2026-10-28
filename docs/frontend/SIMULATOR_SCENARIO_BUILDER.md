# POLARIS Simulator Control — Advanced Mobile Scenario Builder V1

Branch: `feat/polaris-advanced-scenario-builder`
Dev base path: `/simulator/` (BrowserRouter basename)
Vite dev port: `4330`

## Scope

Introduces a new frontend app at `apps/simulator-control` that layers a
professional Scenario Library + Builder + UE Assignment + Execution
Monitor on top of the existing POLARIS Control v1 API. The POLARIS Rust
backend is **not modified**.

## Pages (single unified Simulator Control)

| Route                                   | Component              | Purpose                                                  |
| --------------------------------------- | ---------------------- | -------------------------------------------------------- |
| `/console`                              | `ConsolePage`          | Lab state tiles, scenario mode, approved destinations    |
| `/nodes`                                | `NetworkNodesPage`     | gNB / eNB inventory (POLARIS `/nodes`), controller vs shared |
| `/ues`                                  | `UeManagerPage`        | POLARIS UEs + Assigned Scenario column + Run / Stop      |
| `/traffic`                              | `TrafficPage`          | Live `/traffic/status` + approved destinations           |
| `/scenarios`                            | `ScenariosLibraryPage` | TanStack-style library with Create/Edit/Duplicate/Delete |
| `/scenarios/new` + `/scenarios/:id/edit`| `ScenarioBuilderPage`  | Step palette, Fixed/Random params, loop config, timeline |
| `/scenarios/monitor`                    | `ExecutionMonitorPage` | Backend-reported scenario runtime + traffic + timeline   |
| `/history`                              | `HistoryPage`          | POLARIS `/scenarios/history` table                       |
| `/settings`                             | `SettingsPage`         | Operator Login (CSRF) + scenario policy + local-catalog diagnostics |

**This app is the single Simulator Control** — it integrates the
Scenario Builder into the existing POLARIS surface (UE Manager + gNB
Manager + Traffic + Operator Login + History). No parallel application
is introduced; the preview at `/simulator/` can swap the legacy
single-file `POLARIS_CONTROL/apps/web` for `apps/simulator-control/dist`
without exposing any new backend port.

## Scenario model

Single source of truth: `src/scenarios/model.ts`.

- 14 step kinds covering UE lifecycle (`UE_START`, `REGISTER_5G`,
  `WAIT_REGISTRATION`, `PDU_ESTABLISH`, `UDP_TRAFFIC`, `TCP_TRAFFIC`,
  `ICMP_TRAFFIC`, `HTTP_TRAFFIC`, `IDLE`, `WAIT_RRC_CONNECTED`,
  `WAIT_RRC_IDLE`, `PDU_RELEASE`, `DEREGISTER`, `UE_STOP`).
- Each step kind declares `family: 'ACTION' | 'WAIT' | 'OBSERVATION'` and
  a `backendCertified` boolean. Steps that depend on backend work the
  real POLARIS does not yet expose render an explicit
  **"Backend support required"** notice and surface a warning in the
  validation report.
- Numerical parameters support `{mode: 'fixed', value}` and
  `{mode: 'random', min, max}` — one shape used everywhere. Per the
  brief:
  - **Random cycle count is sampled ONCE per scenario run.**
  - **Random step values are sampled on each execution of that step.**
  Both samplers live in `sampleParam` / `sampleLoopCount` and are
  tested.
- Loop configuration: `ONCE`, `FIXED(cycles)`, `RANDOM(min, max)`,
  `INFINITE`. Infinite emits a WARNING (not an error) so the UI can
  save the scenario, but Run Scenario is disabled until the backend
  owns execution limits + cancellation (contract documented below).
- Identifier fields (`IMSI / SUPI / PDU Session ID / IP`) are **never**
  randomized by this UI — Section 5 of the brief.

## Local persistence

`src/scenarios/store.ts` keeps the catalog + UE assignments in
`localStorage` keys `polaris.scenarios.v1` and `polaris.assignments.v1`.
This is a deliberate honesty choice: the real POLARIS backend does not
expose a scenario CRUD today. The hooks are shaped so they can be
swapped for TanStack-Query mutations when the matching endpoints
appear, with no change to the UI components.

## Mapping to the certified backend

`certifiedProfileFor(scenario)` maps a user-defined scenario onto one of
POLARIS's certified scenario profiles when the shape matches. Today the
only match is **`bounded-controller-ue-udp-v1`** — a single UDP traffic
step on an already-running registered controller-owned UE, with
tolerance for surrounding `IDLE`/`WAIT_REGISTRATION` steps.

Scenarios that do not match a certified profile stay saveable but the
**Run Scenario** button in UE Manager is disabled, with a visible
"Backend support required" hint. No capture or traffic is issued when
no profile matches.

## Execution

- `UE Manager → Start UE` → POST `/ues/start` with `ue_id`.
- `UE Manager → Run Scenario` → when a certified profile exists:
  POST `/scenarios/start` with
  `{ scenario_id, scenario_type, target_ue_id }`.
- `UE Manager / Monitor → Stop` → POST `/scenarios/stop` with the
  active backend-reported `job_id`. **Never stops a shared UE** and
  never releases a PDU session unless the scenario explicitly contains
  the matching step AND the backend authorizes it.
- All reads are polled via `@tanstack/react-query` under
  `authScope: 'polaris'` + `base: '/polaris-api/v1'` so the shared API
  client can only attach a POLARIS token.

## Execution Monitor honesty

- Numeric fields (packets requested/sent, PDU sessions, CPU/RAM, state)
  are **backend-reported** — no client-side sampling.
- A `Local timeline projection` panel reuses the user's own scenario
  definition to show the expected step order, clearly labeled
  "Frontend projection — not a backend execution log".
- Per-step `PENDING/RUNNING/WAITING/PASS/FAIL/SKIPPED/STOPPED` status
  needs a dedicated backend endpoint (`GET /scenarios/:id/steps`).
  Until that exists the Monitor renders every step as `PENDING` to
  avoid fabricating execution progress — this is documented in-page.

## Required backend contracts (missing today)

| Capability                                          | Proposed contract                                                    |
| --------------------------------------------------- | -------------------------------------------------------------------- |
| Scenario catalog CRUD                               | `GET/POST/PUT/DELETE /scenarios/definitions`                         |
| UE ↔ scenario assignment (incl. auto-run)           | `GET/PUT/DELETE /ues/:id/assigned-scenario`                          |
| Auto-run on UE start                                | `start_assigned_on_registration: bool` field on the UE profile      |
| Per-step live status                                | `GET /scenarios/:id/steps` + SSE/short-poll                          |
| Loop/scenario cancellation + CPU/RAM-safe budgets   | Already partially exposed by `/scenarios/stop`; needs infinite-loop safety |
| TCP / ICMP / HTTP traffic generators                | Extend `/scenarios/start` to accept new `scenario_type` values       |
| RRC-state observation                               | Extend `/ues` with `rrc_state` (currently returned by some simulators but not propagated by POLARIS) |
| Random-seed audit                                   | Return the sampled random values alongside `ScenarioState` for auditability |

Each gap is reflected in the UI as a warning or disabled control — no
fake success is ever reported.

## Tests

| File                                   | Suite                                     | Cases |
| -------------------------------------- | ----------------------------------------- | ----- |
| `src/scenarios/model.test.ts`          | `sampleParam`, `sampleLoopCount`, `validateScenario`, `certifiedProfileFor` | 18 |
| `src/scenarios/store.test.ts`          | CRUD, duplicate, cascade delete, multi-UE assignments | 8 |
| `src/app/App.test.tsx`                 | Routing, nav links, library → builder, Network Nodes nav, Traffic nav, Operator Login form, header identity, unknown-route redirect | 8 |

**Total: 34/34 passing** · `npm run typecheck` clean · `npm run build`
succeeds (289 kB JS gzip 86 kB).

Playwright is not yet extended to this app because the shared
`e2e/mock-api.ts` currently only routes OIRAN endpoints — adding a
POLARIS mock surface is tracked as a follow-up to keep this PR focused
on scenario modeling and UE assignment logic.

## Integration with the current Simulator Control preview

The current preview deployment at `https://151.242.147.49:8020/simulator/`
serves the legacy single-file `POLARIS_CONTROL/apps/web/main.tsx`. This
app (`apps/simulator-control/dist`) is a **drop-in replacement** that:

1. Reuses every public POLARIS v1 route (`/auth/*`, `/capabilities`,
   `/scenario-capabilities`, `/lab`, `/system/health`, `/nodes`, `/ues`,
   `/ues/start`, `/ues/stop`, `/traffic/status`, `/scenarios/*`).
2. Adds the Scenario Library + Builder + Execution Monitor without
   touching any Rust file.
3. Stays mounted at the same `/simulator/` base path thanks to the
   `base: '/simulator/'` option in `vite.config.ts`.
4. Preserves Enterprise Precision design tokens via `packages/ui`.

Preview swap:

```bash
# On the preview host:
cd apps/simulator-control
npm install && npm run build
# Point the preview reverse-proxy /simulator/ at apps/simulator-control/dist
```

No new backend port is exposed. Operator Login writes `polaris.csrf_token`
to sessionStorage (per-scope key); the shared client attaches the token
only to writes against `/polaris-api/v1/*`.

## Operator Login contract

- `POST /auth/login { username, password }` → `{ authenticated, username,
  role, csrf_token, expires_at_epoch_s }`. The CSRF token is stored and
  automatically attached to every subsequent write (POST / PUT / DELETE /
  PATCH).
- `POST /auth/logout` clears the stored CSRF.
- The login form in `/settings` refuses to submit when the browser is
  neither HTTPS nor localhost — the message is shown inline.

## Dev / test commands

```bash
cd apps/simulator-control
npm install
npm run dev            # http://127.0.0.1:4330/simulator/
npm run typecheck
npm run test
npm run build
```
