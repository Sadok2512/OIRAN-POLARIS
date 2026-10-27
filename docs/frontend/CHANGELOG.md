# CHANGELOG — Frontend (Portal + Probe Manager)

All notable changes to the `apps/portal`, `apps/probe-manager`,
`packages/ui`, `e2e` and `docs/frontend` scopes. Dates are UTC.

## [0.2.0] – 2026-10-27

### Changed

- **Monorepo integration.** Code previously developed on
  `frontend/premium-portal-probe-manager` under `WEB/*` was moved to the
  canonical monorepo layout established by PR #1 (foundation):
  - `WEB/portal/*`         → `apps/portal/*`
  - `WEB/probe-manager/*`  → `apps/probe-manager/*`
  - `WEB/shared/*`         → `packages/ui/src/*`
    (now the `@oiran-polaris/ui` package)
  - `WEB/e2e/*`            → `e2e/*`
  - `WEB/docs/*`           → `docs/frontend/*`
  - `WEB/SCREENSHOTS/*`    → `docs/frontend/SCREENSHOTS/*`
- `tsconfig.json`, `vite.config.ts` and `tailwind.config.js` paths updated
  from `../shared` to `../../packages/ui/src` in both apps.
- `e2e/screenshots.spec.ts` now writes to
  `docs/frontend/SCREENSHOTS/` instead of `WEB/SCREENSHOTS/`.
- Placeholder READMEs in `apps/portal`, `apps/probe-manager`,
  `packages/ui` were rewritten (not overwritten) to preserve the
  foundation guidance and append implementation notes.

### Verified at new paths

- `apps/portal`: tsc PASS · build PASS (195 kB JS gzip 62 kB) ·
  Vitest 4/4
- `apps/probe-manager`: tsc PASS · build PASS (499 kB JS gzip 153 kB) ·
  Vitest 13/13
- `e2e`: Playwright 65/65 passing — 65 PNGs regenerated under
  `docs/frontend/SCREENSHOTS/`

## [0.1.0] – 2026-10-27

### Added

- Dedicated frontend branch `frontend/premium-portal-probe-manager`.
- `packages/ui/src/` — Enterprise Precision tokens, OIRAN v1 types, API client,
  theme persistence helpers.
- `apps/portal/` — `@telecom/portal` Vite+React+TS app. Three-card landing
  page for Simulator Control (POLARIS), Probe Manager, OIRAN Analyzer.
  Theme switch, health polling, responsive 3/2/1-column grid.
- `apps/probe-manager/` — `@telecom/probe-manager` Vite+React+TS app with
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
- `e2e/` — Playwright 1.57 project with mock OIRAN API and
  65 screenshot specs (every route × 4 viewports × 2 themes +
  1 empty-state capture).
- `docs/frontend/SCREENSHOTS/` — 65 PNGs of the delivered build.
- `docs/frontend/` — 9 reports covering design system, portal, probe manager,
  topology, API gaps, tests, visual review and this changelog.

### Backend changes

None. The brief explicitly set `BACKEND_MODIFICATION_AUTHORIZED = FALSE`.
No file under `OIRAN/apps/api/`, `OIRAN/apps/web/`, `POLARIS_CONTROL/`
was modified.

### Deployment

None. `PRODUCTION_DEPLOYMENT_AUTHORIZED = FALSE`.
No live capture was executed from this UI: `LIVE_CAPTURE_AUTHORIZED = FALSE`.
