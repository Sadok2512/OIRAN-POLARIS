# Portal

**Responsibility (foundation guidance):** launch and link to the independent
applications. The Portal must not duplicate simulator, capture, decoding,
session, correlation, or authentication-domain logic.

This directory was initialized on `feat/frontend-portal-probe-manager`
with the premium Enterprise Precision implementation.

## What this app does

Minimal three-card landing page. Each card renders:

- application icon
- application name + description
- reachability dot (from `/api/v1/health` or `/api/v1/system/health`)
- "Open application" primary action (no iframe, no embed)

Target applications are URL-configurable via build-time env vars:

| Variable                        | Default           |
| ------------------------------- | ----------------- |
| `VITE_APP_SIMULATOR_URL`        | `/polaris/`       |
| `VITE_APP_PROBE_MANAGER_URL`    | `/probe-manager/` |
| `VITE_APP_OIRAN_URL`            | `/oiran/`         |

## Scope boundaries

- No simulator, capture, decode, session, correlation or authentication
  logic — strictly a launcher.
- Shared tokens/types come from `packages/ui` (`@shared/*`).
- No fake telemetry: health reflects actual HTTP responses, including
  `401/403` as "Reachable, authentication required".

## Dev / test commands

```bash
npm install
npm run dev            # http://127.0.0.1:4300
npm run typecheck
npm run test
npm run build          # production bundle in dist/
```

## Delivered artifacts

- 4 Vitest/RTL tests (`src/app/App.test.tsx`) — all passing
- 8 Playwright screenshots (`docs/frontend/SCREENSHOTS/portal_*.png`)
- See `docs/frontend/PORTAL_FRONTEND_IMPLEMENTATION.md` for the full
  implementation report.
