# CHANGELOG — WEB (Portal + Probe Manager)

All notable changes to the `WEB/` folder. Dates are UTC.

## [0.1.0] – 2026-10-27

### Added

- Dedicated frontend branch `frontend/premium-portal-probe-manager`.
- `WEB/shared/` — Enterprise Precision tokens, OIRAN v1 types, API client,
  theme persistence helpers.
- `WEB/portal/` — `@telecom/portal` Vite+React+TS app. Three-card landing
  page for Simulator Control (POLARIS), Probe Manager, OIRAN Analyzer.
  Theme switch, health polling, responsive 3/2/1-column grid.
- `WEB/probe-manager/` — `@telecom/probe-manager` Vite+React+TS app with
  seven routes (Overview, Network Topology, Probes, Interfaces, Live
  Captures, Capture Library, Settings).
- Network Topology (React Flow `@xyflow/react` 12.3.6) with custom
  telecom-aware nodes, DISCOVERED / CONFIGURED / INFERRED / UNKNOWN
  evidence tags, inspector drawer, search, Fit View, fullscreen.
- `ProbeInspector`, `InterfaceInspector`, `TopologyInspector` right-side
  drawers.
- `LiveCaptures` monitor with every mandated counter + ConfirmDialog
  Stop control (dispatch deferred per the no-live-capture directive).
- `CaptureLibrary` TanStack Table (sortable, searchable, filtered by
  probe/interface/status) with Analyzer deep-link preserving
  `capture_id` + `dataset_id`.
- `WEB/e2e/` — Playwright 1.57 project with mock OIRAN API and
  65 screenshot specs (every route × 4 viewports × 2 themes +
  1 empty-state capture).
- `WEB/SCREENSHOTS/` — 65 PNGs of the delivered build.
- `WEB/docs/` — 9 reports covering design system, portal, probe manager,
  topology, API gaps, tests, visual review and this changelog.

### Backend changes

None. The brief explicitly set `BACKEND_MODIFICATION_AUTHORIZED = FALSE`.
No file under `OIRAN/apps/api/`, `OIRAN/apps/web/`, `POLARIS_CONTROL/`
was modified.

### Deployment

None. `PRODUCTION_DEPLOYMENT_AUTHORIZED = FALSE`.
No live capture was executed from this UI: `LIVE_CAPTURE_AUTHORIZED = FALSE`.
