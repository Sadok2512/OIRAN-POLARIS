# Portal — frontend implementation report

**App**: `WEB/portal` · `@telecom/portal` v0.1.0 · Vite 5 · React 18 · TypeScript 5.7

## Scope delivered

- Minimal three-card landing page: Simulator Control, Probe Manager, OIRAN Analyzer
- Config-driven URLs (overridable via `VITE_APP_*` build-time env vars)
- Health polling against each app's reported endpoint using
  `@tanstack/react-query` (`/system/health` for POLARIS Control, `/health`
  for OIRAN and Probe Manager)
- Light / dark / system theme switch persisted to `localStorage`
- Responsive 3 / 2 / 1-column grid validated at 1920×1080, 1440×900,
  1280×800, 1024×768 — see `WEB/SCREENSHOTS/portal_*.png`

## Health reporting policy

| Backend response | UI label                               | Visual                      |
| ---------------- | --------------------------------------- | --------------------------- |
| 2xx              | `Reachable · <ms> ms`                   | success dot                 |
| 401 / 403        | `Reachable, authentication required`    | warning dot                 |
| other HTTP       | `HTTP <status> <code>`                  | warning dot                 |
| network error    | `Unreachable: <error>`                  | neutral dot                 |

The portal never claims a service is up when it is not; the raw backend
message is surfaced to the operator.

## File inventory

| File                                                         | Lines | Purpose                              |
| ------------------------------------------------------------ | -----:| ------------------------------------ |
| `src/main.tsx`                                               |    22 | React root + query client            |
| `src/app/App.tsx`                                            |    58 | Layout, grid, error banner           |
| `src/components/AppLauncher.tsx`                             |    68 | Launcher card                        |
| `src/components/PortalHeader.tsx`                            |    65 | Brand + theme switch                 |
| `src/components/PortalFooter.tsx`                            |    12 | Static footer                        |
| `src/components/StatusDot.tsx`                               |    25 | Reachability dot                     |
| `src/config/apps.ts`                                         |    64 | Descriptor registry                  |
| `src/config/usePortalConfig.ts`                              |    60 | Health polling hook                  |
| `src/hooks/useTheme.ts`                                      |    27 | Theme state                          |
| `src/styles/globals.css`                                     |    76 | Tokens + utilities                   |
| `src/test/setup.ts`                                          |    23 | vitest + matchMedia polyfill         |
| `src/app/App.test.tsx`                                       |    57 | 4 Vitest/RTL tests                   |

Shared code consumed via alias: `@shared/tokens`, `@shared/api`,
`@shared/types`, `@shared/theme`.

## Dev commands

```bash
cd WEB/portal
npm install
npm run dev            # http://127.0.0.1:4300
npm run typecheck      # tsc -b --pretty false
npm run test           # vitest run
npm run build          # production bundle in dist/
```

## Verification

- `npm run typecheck` — exit 0
- `npm run test` — 4/4 passing
- `npm run build` — 194 kB JS, 12 kB CSS, 1 634 modules transformed
- Playwright screenshots: 8 PNGs (`portal_<theme>_<viewport>.png`)
