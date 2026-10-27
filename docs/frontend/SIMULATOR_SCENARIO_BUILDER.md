# POLARIS Simulator Control — Advanced Mobile Scenario Builder V1

Branch: `feat/polaris-advanced-scenario-builder`
Dev base path: `/simulator/` (BrowserRouter basename)
Vite dev port: `4330`

## Scope

Introduces a new frontend app at `apps/simulator-control` that layers a
professional Scenario Library + Builder + UE Assignment + Execution
Monitor on top of the existing POLARIS Control v1 API. The POLARIS Rust
backend is **not modified**.

## Pages

| Route                                   | Component              | Purpose                                                  |
| --------------------------------------- | ---------------------- | -------------------------------------------------------- |
| `/console`                              | `ConsolePage`          | Lab state tiles, scenario mode, approved destinations    |
| `/ues`                                  | `UeManagerPage`        | POLARIS UEs + Assigned Scenario column + Run / Stop      |
| `/scenarios`                            | `ScenariosLibraryPage` | TanStack-style library with Create/Edit/Duplicate/Delete |
| `/scenarios/new` + `/scenarios/:id/edit`| `ScenarioBuilderPage`  | Step palette, Fixed/Random params, loop config, timeline |
| `/scenarios/monitor`                    | `ExecutionMonitorPage` | Backend-reported scenario runtime + traffic + timeline   |
| `/history`                              | `HistoryPage`          | POLARIS `/scenarios/history` table                       |
| `/settings`                             | `SettingsPage`         | Operator + scenario policy + local-catalog diagnostics   |

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
| `src/app/App.test.tsx`                 | Routing, nav links, library → builder, unknown-route redirect | 4 |

**Total: 30/30 passing** · `npm run typecheck` clean · `npm run build`
succeeds (278 kB JS gzip 84 kB).

Playwright is not yet extended to this app because the shared
`e2e/mock-api.ts` currently only routes OIRAN endpoints — adding a
POLARIS mock surface is tracked as a follow-up to keep this PR focused
on scenario modeling and UE assignment logic.

## Dev / test commands

```bash
cd apps/simulator-control
npm install
npm run dev            # http://127.0.0.1:4330/simulator/
npm run typecheck
npm run test
npm run build
```
