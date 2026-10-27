# Simulator Control

**Responsibility (foundation guidance):** UE/gNB simulation lifecycle
and bounded traffic generation. This directory must not implement a
simulator or carry production configuration — it only drives the
POLARIS Rust backend through its public `/polaris-api/v1/*` surface.

Initialized on `feat/polaris-advanced-scenario-builder` with the
Enterprise Precision V1 implementation of the Advanced Mobile Scenario
Builder.

## Routes (single unified Simulator Control)

- `/console` — lab tiles, scenario mode, approved destinations
- `/nodes` — gNB / eNB inventory from POLARIS `/nodes`
- `/ues` — POLARIS UE inventory with Assigned Scenario column
- `/traffic` — live `/traffic/status` observability
- `/scenarios` — scenario library (TanStack-table)
- `/scenarios/new` + `/scenarios/:id/edit` — step palette, Fixed/Random
  parameters, loop editor, timeline preview, validation
- `/scenarios/monitor` — backend scenario runtime + traffic + local
  timeline projection (labeled as a projection, not a backend log)
- `/history` — POLARIS `/scenarios/history`
- `/settings` — Operator Login (CSRF-aware) + scenario policy + local-catalog diagnostics

## Scope boundaries

- No simulator / Rust change. Reads/writes go through
  `/polaris-api/v1/*` under `authScope: 'polaris'` — the shared client
  only attaches a POLARIS token to its allowlisted base.
- No fabricated execution. Only backend-reported counters are shown.
- Scenario catalog + UE assignment persisted in `localStorage` until a
  dedicated backend contract exists. See
  [`docs/frontend/SIMULATOR_SCENARIO_BUILDER.md`](../../docs/frontend/SIMULATOR_SCENARIO_BUILDER.md).
- Run Scenario only dispatches when the scenario shape maps to a
  certified backend profile (today: `bounded-controller-ue-udp-v1`).
- Shared UEs are protected: Start / Run / Stop stay disabled on them.

## Dev / test commands

```bash
npm install
npm run dev            # http://127.0.0.1:4330/simulator/
npm run typecheck
npm run test
npm run build
```

## Delivered artifacts

- 34 Vitest tests (scenario model 18, store 8, routing + login 8)
- Full implementation report:
  [`docs/frontend/SIMULATOR_SCENARIO_BUILDER.md`](../../docs/frontend/SIMULATOR_SCENARIO_BUILDER.md)
