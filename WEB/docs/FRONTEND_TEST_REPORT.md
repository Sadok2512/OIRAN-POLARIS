# Frontend test report

Date: 2026-10-27
Branch: `frontend/premium-portal-probe-manager`

## Static analysis

| Command                               | Result   |
| ------------------------------------- | -------- |
| `WEB/portal` → `npm run typecheck`    | **PASS** |
| `WEB/probe-manager` → `npm run typecheck` | **PASS** |

Both projects run `tsc -b --pretty false` with `strict`, `noUnusedLocals`,
`noUnusedParameters`, `noFallthroughCasesInSwitch`, `isolatedModules`.

## Production builds

| App            | Modules | JS gzip  | CSS gzip | Status |
| -------------- | -------:| --------:| --------:| ------ |
| Portal         |   1 634 |  61.9 kB |   3.3 kB | PASS   |
| Probe Manager  |   1 816 | 153.1 kB |   6.4 kB | PASS   |

(Measured with Vite 5.4.11 default rollup output.)

## Unit / component tests (Vitest + Testing Library + jsdom)

### Portal (`WEB/portal/src/app/App.test.tsx`) — 4 passing

1. renders the three application cards
2. provides an Open Application link per card
3. reports reachable health on 200 response
4. reports degraded health on 401

### Probe Manager — 13 passing

- `src/app/App.test.tsx` (5)
  1. Overview page by default
  2. Capture Library navigation
  3. All seven sidebar entries present
  4. Theme switch exposed
  5. Unknown routes redirect to Overview
- `src/pages/Overview.test.tsx` (2)
  1. Empty states when backend returns zero items
  2. Unavailable state when `/storage/safety` returns no filesystem data
- `src/pages/CaptureLibrary.test.tsx` (4)
  1. All required columns rendered
  2. Text search filters rows
  3. Empty state on empty backend
  4. Analyzer action disabled when `dataset_id` is null
- `src/topology/buildTopology.test.ts` (2)
  1. 5G SA scaffold always emitted
  2. Backend probes marked DISCOVERED and interfaces linked

```
Portal:         Test Files 1 passed · Tests 4 passed · Duration ~2.6 s
Probe Manager:  Test Files 4 passed · Tests 13 passed · Duration ~4.1 s
```

## Browser E2E (Playwright 1.57)

`WEB/e2e/screenshots.spec.ts` renders both apps against the local Vite
preview servers, stubs the OIRAN v1 API with `WEB/e2e/mock-api.ts` (both
`populated` and `empty` scenarios) and takes full-page PNGs at every
mandated viewport × theme pair.

| Scope             | Route × viewport × theme                                        | Specs |
| ----------------- | --------------------------------------------------------------- | ----- |
| Portal            | 4 viewports × 2 themes                                          | 8     |
| Probe Manager     | 7 routes × 4 viewports × 2 themes                               | 56    |
| Empty-state honesty | 1 scenario (Capture Library · light · 1440×900)               | 1     |
| **Total**         |                                                                 | **65 passing** |

Browser: pre-installed Chromium 1248 at
`/home/devmat/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome`.
Config: `WEB/e2e/playwright.config.ts` sets `executablePath` so Playwright
reuses the local binary without downloading another ~300 MB.

Run:

```bash
# Terminal 1
cd WEB/portal && npx vite preview --host 127.0.0.1 --port 4300

# Terminal 2
cd WEB/probe-manager && npx vite preview --host 127.0.0.1 --port 4310

# Terminal 3
cd WEB/e2e
PLAYWRIGHT_BROWSERS_PATH=/home/devmat/.cache/ms-playwright npx playwright test
```

Output images: `WEB/SCREENSHOTS/*.png` (65 files, 5.9 MiB total).

## Responsive validation

| Viewport        | Portal       | Probe Manager                                 |
| --------------- | ------------ | --------------------------------------------- |
| 1920×1080       | 3 columns    | sidebar + content, no overflow                |
| 1440×900        | 3 columns    | sidebar + content, inspector drawers visible  |
| 1280×800        | 3 columns    | sidebar + content                             |
| 1024×768        | 2 columns    | sidebar collapses on narrow pages             |

No horizontal page overflow observed. Table rows wrap long IDs; capture
names ellipsize instead of pushing columns.

## No fabricated live-state tests

- Overview empty-state test: every backend returns `{ data: [], meta: {} }`
  — the UI must not fabricate counters. Verified.
- Overview unavailable test: `storage/safety` responds with
  `filesystem: null` — the UI renders the `Unavailable` component instead
  of a 0 % bar. Verified.
- Capture Library empty test: backend returns 0 captures — UI shows the
  empty state, not a stub row. Verified.
- Capture Library disabled Analyzer: capture has `dataset_id: null` — the
  Analyzer deep-link must be disabled. Verified.
