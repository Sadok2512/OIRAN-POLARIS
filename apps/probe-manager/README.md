# Probe Manager

**Responsibility (foundation guidance):** probe inventory, interface
visibility, capture lifecycle, and PCAP management. Contains no capture
implementation and no privileged configuration — this is a frontend only.

Initialized on `feat/frontend-portal-probe-manager` with the premium
Enterprise Precision implementation.

## Routes

- `/overview` — probe fleet counters, storage safety, inventory, honest empty states
- `/topology` — React Flow (`@xyflow/react` 12) telecom topology with evidence tags
- `/probes` + `/probes/:id` — fleet table + `ProbeInspector`
- `/interfaces` + `/interfaces/:id` — interface table + `InterfaceInspector`
- `/live-captures` — per-job cards with every mandated counter
- `/capture-library` — TanStack Table with filters + Analyzer deep-link
- `/settings` — authentication + operational boundaries (read-only)

## Backend wiring

Consumes the OIRAN v1 API through `@shared/api`. All GETs are polled via
`@tanstack/react-query`; writes (`/captures/validate|start|:id/stop`) are
built but deliberately not dispatched during review — see the brief:
`LIVE_CAPTURE_AUTHORIZED = FALSE`.

For missing API contracts (per-interface live counters, agent lifecycle,
topology-link evidence, etc.) the UI falls back to honest `Not available`
labels and documents the gap in `docs/frontend/API_INTEGRATION_GAPS.md`.

## Dev / test commands

```bash
npm install
npm run dev            # http://127.0.0.1:4310
npm run typecheck
npm run test
npm run build          # production bundle in dist/
```

## Delivered artifacts

- 13 Vitest/RTL tests (routing, pages, topology) — all passing
- 57 Playwright screenshots at 4 viewports × 2 themes
- `docs/frontend/PROBE_MANAGER_FRONTEND_IMPLEMENTATION.md` — full report
- `docs/frontend/NETWORK_TOPOLOGY_IMPLEMENTATION.md` — topology deep-dive
- `docs/frontend/COMPONENT_INVENTORY.md` — primitive catalog
