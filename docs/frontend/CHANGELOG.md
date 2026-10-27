# CHANGELOG — Frontend (Portal + Probe Manager)

All notable changes to the `apps/portal`, `apps/probe-manager`,
`packages/ui`, `e2e` and `docs/frontend` scopes. Dates are UTC.

## [0.3.0] – 2026-10-27 — PR #2 review corrections

### Fixed (P0)

- **Topology evidence.** `apps/probe-manager/src/topology/buildTopology.ts`
  no longer upgrades plane-name heuristics (`N2`/`N3`/`N4`/`SBI`) to
  `CONFIGURED`. All name-based edges are now explicitly `INFERRED` with
  `evidenceSource: "interface name prefix matches a 5G plane; no
  backend-verified mapping was supplied"`. A new `VerifiedInterfaceMapping`
  input lets the backend (future `/topology/links` contract) supply
  genuinely `CONFIGURED` or `DISCOVERED` edges without touching unrelated
  edges. `probe→interface` MONITOR edges stay `DISCOVERED`.
- **Cross-application authentication.** `packages/ui/src/api.ts` now
  requires `options.authScope` to attach `Authorization`. Tokens live in
  per-scope session storage keys (`oiran`, `polaris`, `probe-manager`).
  Cross-origin absolute bases never receive a token. `apps/portal`
  declares a dedicated `apiBase` per application; health probes bypass
  the shared client to guarantee anonymity.
- **Portal health classification.** `apps/portal/src/config/usePortalConfig.ts`
  now distinguishes four states — `ok`, `auth-required`, `degraded`,
  `unknown` — based on both the HTTP status and the body. A 200 reply
  with `{data: {status: "degraded"}}` is reported as degraded, not healthy.

### Fixed (P1)

- **Capture Library pagination.** `useCapturesPage({ page, pageSize })`
  queries `GET /captures?page=N&page_size=M` and consumes `meta.total`
  / `meta.total_pages`. The page footer renders the actual server totals
  (`Page 1 of 10 · Showing 25 / 25`). When the backend omits `meta.total`
  the UI shows a `partial-results-notice` instead of pretending the
  dataset is complete.
- **Capture actions.** View opens an in-page metadata panel without any
  network call. Analyzer deep-link stays disabled unless the capture has
  a `dataset_id`. Download is disabled unless the user is authenticated
  AND the capture has stored bytes; the endpoint is
  `/api/v1/captures/:id/download` (requires backend authorization).
  Stop capture still never dispatches a request from this UI.
- **API contract validation.** New `apps/probe-manager/src/data/apiContract.test.ts`
  exercises null/missing fields on `Probe`, `CaptureInterface`,
  `DiskSafety`; empty captures; 401 error envelopes; network failures;
  cross-origin token isolation; HTTP status classification.

### Verified

- `apps/portal`: `tsc -b` PASS · Vitest 11/11 · `vite build` PASS
- `apps/probe-manager`: `tsc -b` PASS · Vitest 51/51 · `vite build` PASS
- `e2e`: Playwright 65/65 · 65 PNGs regenerated at
  `docs/frontend/SCREENSHOTS/`

### Not changed

- Enterprise Precision design system (tokens, spacing, radii, typography)
- Portal three-card layout + Probe Manager navigation
- React Flow topology scaffold + inspector affordances
- TanStack Table columns + filters
- Light/Dark/responsive layouts
- Any backend file (`BACKEND_CHANGED = FALSE`)
- No live capture dispatched (`LIVE_CAPTURE_EXECUTED = FALSE`)

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
