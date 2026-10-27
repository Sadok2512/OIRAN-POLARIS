# WEB — Telecom Platform Portal & OIRAN Probe Manager

Two independent frontend applications that complement the OIRAN and POLARIS
Control backends in this repository. They do not modify any backend file and
do not deploy anywhere.

| Path                   | App                        | Purpose                                                             |
| ---------------------- | -------------------------- | ------------------------------------------------------------------- |
| `WEB/portal`           | Telecom Platform Portal    | Minimal landing with three application cards.                       |
| `WEB/probe-manager`    | OIRAN Probe Manager        | Topology, probes, interfaces, live captures, capture library.      |
| `WEB/shared`           | Shared primitives          | Design tokens, UI primitives, API client, telecom types.            |
| `WEB/docs`             | Documentation              | Implementation reports, API gap analysis, design system reference.  |
| `WEB/SCREENSHOTS`      | Visual evidence            | Playwright/manual screenshots of the delivered build.               |

Both apps follow the **Enterprise Precision** design system (see
`WEB/docs/ENTERPRISE_PRECISION_DESIGN_SYSTEM.md`) and consume the existing
OIRAN v1 API documented in `OIRAN/OIRAN_LIVE_V1_API_CONTRACT.md` and
`OIRAN/OIRAN_V2_2_API_CONTRACT.md`.

## Running locally

```bash
cd WEB/portal          # or WEB/probe-manager
npm install
npm run dev            # http://127.0.0.1:4300 (portal) / 4310 (probe-manager)
npm run build          # production bundle in dist/
npm run typecheck
npm run test
```

Both apps proxy `/api/v1/*` to `http://127.0.0.1:7080` by default (the OIRAN
API dev server). Override with `VITE_API_BASE` in `.env.local`.

No real captures are ever executed from the frontend; Start/Stop controls
build the request body and defer to the backend. If the backend is
unauthenticated or disabled, the UI displays an honest unavailable state
instead of fabricating telemetry.
