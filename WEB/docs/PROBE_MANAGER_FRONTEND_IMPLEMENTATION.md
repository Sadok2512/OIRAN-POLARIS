# OIRAN Probe Manager — frontend implementation report

**App**: `WEB/probe-manager` · `@telecom/probe-manager` v0.1.0 ·
Vite 5 · React 18 · TypeScript 5.7 · @xyflow/react 12

## Scope delivered

### Navigation (sidebar sections)

- **Operations** — Overview, Network Topology, Probes, Interfaces
- **Capture** — Live Captures, Capture Library
- **Platform** — Settings

Routing via `react-router-dom` v6 under `HashRouter`, so the app can be
served behind any reverse-proxy without server rewrites.

### Pages

| Route                   | File                                  | Highlights                                              |
| ----------------------- | ------------------------------------- | ------------------------------------------------------- |
| `/overview`             | `src/pages/Overview.tsx`              | Metric tiles, probe fleet, disk safety, inventory      |
| `/topology`             | `src/pages/NetworkTopology.tsx`       | React Flow canvas, inspector, search, fit, fullscreen  |
| `/probes` + `/probes/:id` | `src/pages/Probes.tsx`              | Table + `ProbeInspector`                                |
| `/interfaces` + `:id`   | `src/pages/Interfaces.tsx`            | Table + `InterfaceInspector`                            |
| `/live-captures`        | `src/pages/LiveCaptures.tsx`          | Per-job cards with every mandated counter + stop CTA   |
| `/capture-library`      | `src/pages/CaptureLibrary.tsx`        | TanStack Table with required columns + filters         |
| `/settings`             | `src/pages/Settings.tsx`              | Auth + operational boundaries                           |

### Backend wiring

Reuses the OIRAN v1 contract described in `OIRAN/OIRAN_LIVE_V1_API_CONTRACT.md`
and `OIRAN/OIRAN_V2_2_API_CONTRACT.md`:

```
GET  /api/v1/probes
GET  /api/v1/probes/:id
GET  /api/v1/probes/:id/interfaces
GET  /api/v1/interfaces
GET  /api/v1/captures?page_size=200
GET  /api/v1/metrics
GET  /api/v1/storage/safety
GET  /api/v1/auth/me
POST /api/v1/captures/validate   (requested, not fired without consent)
POST /api/v1/captures/start      (requested, not fired without consent)
POST /api/v1/captures/:id/stop   (requested, confirmed via ConfirmDialog)
```

Not called from this UI during the review (per acceptance brief): the Start
/ Stop flows build and preview the payload but defer the actual
`POST /captures/start` and `POST /captures/:id/stop` requests until the
deployment execution gate is enabled. See
`API_INTEGRATION_GAPS.md` for the full gap matrix.

### State honesty

- Fields the backend did not report render as `Not available`.
- Backends that explicitly refuse a measurement render through the
  `Unavailable` component (yellow banner, no fabricated zeros).
- Interface-plane mappings are tagged `DISCOVERED` only when they come
  from a backend-reported probe or interface; the 5G SA scaffold nodes
  carry the `INFERRED` tag and the inspector states this explicitly.

### Component inventory (new)

| Component                         | File                                              |
| --------------------------------- | ------------------------------------------------- |
| `AppShell`                        | `src/layout/AppShell.tsx`                         |
| `SidebarNavigation`               | `src/layout/SidebarNavigation.tsx`                |
| `PageHeader`                      | `src/ui/PageHeader.tsx`                           |
| `StatusIndicator`                 | `src/ui/StatusIndicator.tsx`                      |
| `EmptyState`/`ErrorState`         | `src/ui/EmptyErrorLoading.tsx`                    |
| `LoadingSkeleton`/`Unavailable`   | `src/ui/EmptyErrorLoading.tsx`                    |
| `ConfirmDialog`                   | `src/ui/ConfirmDialog.tsx`                        |
| `ProbeInspector`                  | `src/components/ProbeInspector.tsx`               |
| `InterfaceInspector`              | `src/components/InterfaceInspector.tsx`           |
| `TelecomNode`                     | `src/topology/TelecomNode.tsx`                    |
| `TopologyInspector`               | `src/topology/TopologyInspector.tsx`              |
| `buildTopology`                   | `src/topology/buildTopology.ts`                   |

### Capture Library — TanStack Table columns

Capture name · Probe · Interfaces · Protocol · Start time · Duration ·
Packets · Size · Status · Dataset · Actions

Filters: free-text search, probe, interface, status. Actions: View,
Analyzer deep link (disabled when `dataset_id` is null), download metadata
link, failure badge for `FAILED` captures.

## Dev commands

```bash
cd WEB/probe-manager
npm install
npm run dev            # http://127.0.0.1:4310
npm run typecheck      # tsc -b --pretty false
npm run test           # vitest run
npm run build          # production bundle in dist/
```

## Verification

- `npm run typecheck` — exit 0
- `npm run test` — 13/13 passing (4 pages + 2 topology + 5 routing + ad hoc)
- `npm run build` — 499 kB JS, 31 kB CSS, 1 816 modules transformed
- Playwright screenshots: 57 PNGs covering every route × 4 viewports × 2
  themes + one empty-state capture
