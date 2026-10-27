# PR body — `feat(frontend): premium portal and probe manager`

> Paste the content below as the body of PR
> `feat/frontend-portal-probe-manager → main` at
> https://github.com/Sadok2512/OIRAN-POLARIS/pull/2
>
> The gh CLI token stored at `~/.config/gh/hosts.yml` is reported as
> `Bad credentials` by `GET /user`. Re-run `gh auth login -h github.com`
> if you want this agent to open PRs directly in the future.

---

## Review corrections (follow-up on PR #2 feedback)

Five issues identified in the PR #2 review were addressed on this
branch. See the full details in `docs/frontend/CHANGELOG.md` entry
`[0.3.0] – 2026-10-27`.

### P0

1. **Topology evidence** —
   `apps/probe-manager/src/topology/buildTopology.ts` no longer promotes
   plane-name heuristics (`N2`/`N3`/`N4`/`SBI`) to `CONFIGURED`. All
   name-derived edges are now `INFERRED` with an explicit
   `evidenceSource`. A new `VerifiedInterfaceMapping` input (see
   `apps/probe-manager/src/topology/types.ts`) is the ONLY way to upgrade
   an edge to `CONFIGURED` or `DISCOVERED`. 11 new tests enforce this.
2. **Authentication isolation + honest health** —
   `packages/ui/src/api.ts` now requires an explicit `authScope`
   (`oiran` / `polaris` / `probe-manager`) and stores tokens under
   per-scope session-storage keys. Cross-origin absolute bases never
   receive a token. The Portal probes each app with its own `apiBase`
   via a dedicated anonymous `fetch` so no OIRAN token can leak to
   POLARIS. Health states are now four — `ok`, `auth-required`,
   `degraded`, `unknown` — derived from HTTP status AND the response
   body (`{data.status}` or `{status}`).

### P1

3. **Capture Library pagination** — `useCapturesPage` requests
   `GET /captures?page=N&page_size=M` and consumes
   `meta.total`/`meta.total_pages`. When the backend omits the total the
   UI shows a `partial-results-notice` instead of silently truncating.
4. **Capture actions** — View opens an in-page metadata panel with no
   network request. Analyzer stays disabled unless `dataset_id` exists
   (test enforces this). Download target is
   `/api/v1/captures/:id/download` and the button stays disabled unless
   `/auth/me.authenticated === true` AND `size_bytes > 0`. Stop still
   dispatches nothing from this UI (`LIVE_CAPTURE_AUTHORIZED = FALSE`).
5. **API contract validation** — new file
   `apps/probe-manager/src/data/apiContract.test.ts` exercises nullable
   fields, empty captures, 401 envelopes, `fetch`-rejection paths, HTTP
   status classification, and cross-scope token isolation.

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
- Any backend file; no live capture executed

---

## Scope

- **Apps**: `apps/portal`, `apps/probe-manager`
- **Package**: `packages/ui` (`@oiran-polaris/ui`)
- **Shared e2e**: `e2e/`
- **Docs + screenshots**: `docs/frontend/`
- **No change** to `OIRAN/`, `POLARIS_CONTROL/`, backend contracts, CI, or infrastructure

## Existing work reused

All source files originated from commit `1535e20` on branch
`frontend/premium-portal-probe-manager` (previously under `WEB/*`). No
file was regenerated. The migration consisted of path relocation, alias
updates in `tsconfig.json`, `vite.config.ts` and `tailwind.config.js`,
and README rewrites that preserve the foundation guidance verbatim.

| Old path                 | New path                          |
| ------------------------ | --------------------------------- |
| `WEB/portal/*`           | `apps/portal/*`                   |
| `WEB/probe-manager/*`    | `apps/probe-manager/*`            |
| `WEB/shared/*`           | `packages/ui/src/*`               |
| `WEB/e2e/*`              | `e2e/*`                           |
| `WEB/docs/*`             | `docs/frontend/*`                 |
| `WEB/SCREENSHOTS/*`      | `docs/frontend/SCREENSHOTS/*`     |

## Components implemented

Shared (`packages/ui`): `tokens`, `theme`, `api`, `types`.

Portal (`apps/portal/src`):

- `AppLauncher`, `PortalHeader`, `PortalFooter`, `StatusDot`
- Config-driven app URL registry (`config/apps.ts`)
- Query-driven health hook (`config/usePortalConfig.ts`)
- `useTheme` hook consuming `@shared/theme`

Probe Manager (`apps/probe-manager/src`):

- `AppShell`, `SidebarNavigation`
- `PageHeader`, `StatusIndicator`, `EmptyState`, `ErrorState`,
  `LoadingSkeleton`, `Unavailable`, `ConfirmDialog`
- `ProbeInspector`, `InterfaceInspector`
- Topology: `TelecomNode`, `TopologyInspector`, `buildTopology`
- 7 route pages: `Overview`, `NetworkTopology`, `Probes`, `Interfaces`,
  `LiveCaptures`, `CaptureLibrary`, `Settings`
- Data layer: `data/queries.ts` + `data/format.ts`

## Screenshots

65 PNGs at 4 viewports (1920×1080, 1440×900, 1280×800, 1024×768) × 2
themes (light, dark) regenerated at the new path:
`docs/frontend/SCREENSHOTS/`. Captured through Playwright 1.57 against a
fixture-only mock OIRAN API (`e2e/mock-api.ts`).

Representative examples:

- `docs/frontend/SCREENSHOTS/portal_light_1440x900.png` — Portal landing
- `docs/frontend/SCREENSHOTS/probe_topology_dark_1440x900.png` — Topology (dark)
- `docs/frontend/SCREENSHOTS/probe_capture_library_light_1440x900.png`
- `docs/frontend/SCREENSHOTS/probe_capture_library_empty_light_1440x900.png`
  (empty-state honesty)

## Tests

All executed at the new monorepo paths before pushing:

| Workspace            | Command            | Result             |
| -------------------- | ------------------ | ------------------ |
| `apps/portal`        | `npm run typecheck`| PASS (exit 0)      |
| `apps/portal`        | `npm run test`     | 4/4 passing        |
| `apps/portal`        | `npm run build`    | PASS (195 kB JS)   |
| `apps/probe-manager` | `npm run typecheck`| PASS (exit 0)      |
| `apps/probe-manager` | `npm run test`     | 13/13 passing      |
| `apps/probe-manager` | `npm run build`    | PASS (499 kB JS)   |
| `e2e`                | `npx playwright test` | 65/65 passing   |

## API integration status

Covered: `/api/v1/{auth/me, health, system/health, probes, interfaces,
captures, metrics, storage/safety}`.

Prepared but not fired during this review (per `LIVE_CAPTURE_AUTHORIZED
= FALSE`): `POST /captures/validate|start|:id/stop`. The UI builds the
payload and gates the request behind a `ConfirmDialog`; no network call
leaves the browser.

Full gap matrix in `docs/frontend/API_INTEGRATION_GAPS.md`:

- `GET /topology/links` — currently inferred from plane names
- `GET /probes/:id/telemetry` — history/trend missing
- `GET /interfaces/:id/metrics` — only aggregate `/metrics` consumed
- `GET /captures/:id/events` — no stream contract
- Agent lifecycle endpoints — Start/Stop Probe Agent not reachable

## Known limitations

- Scaffold topology nodes (`UE → gNB → AMF → SMF → UPF`) carry the
  `INFERRED` evidence tag. Backend-reported probes and interfaces upgrade
  neighbouring edges to `CONFIGURED`/`DISCOVERED`.
- Start/Stop capture controls are UI-only on this branch. They render
  the payload and the ConfirmDialog but never POST.
- The Playwright suite points at a mock API fixture — fixtures never
  reach production builds.
- No history/trend charts drawn when the backend reports a single sample
  (would mislead).

## Backend dependencies

Zero new backend dependencies introduced. Consumes the existing OIRAN v1
contract described in `OIRAN/OIRAN_LIVE_V1_API_CONTRACT.md` and
`OIRAN/OIRAN_V2_2_API_CONTRACT.md`. Backend sources (`OIRAN/`,
`POLARIS_CONTROL/`) are unchanged on this branch.

## Deployment impact / rollback

- Deployment impact: none in this PR. Frontend bundles are built but not
  published anywhere. The brief explicitly set
  `PRODUCTION_DEPLOYMENT_AUTHORIZED = FALSE`.
- Rollback: revert this single commit; the foundation state is preserved
  by PR #1.

## Checklist

- [x] Branched from `main` after fetching
- [x] Isolated branch `feat/frontend-portal-probe-manager`
- [x] No `node_modules`, `dist`, `.tsbuildinfo`, Playwright report or
      test-results staged
- [x] No credentials, captures or raw datasets committed
- [x] Placeholder READMEs rewritten with their original guidance
      preserved verbatim
- [x] Tests and screenshots regenerated at the new paths
- [x] Backend not modified
