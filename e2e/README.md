# e2e — Playwright screenshot + browser suite

Shared Playwright 1.57 project that renders both frontend apps against a
mock OIRAN v1 API and captures full-page PNGs at four viewports × two
themes. Output goes to `docs/frontend/SCREENSHOTS/`.

## Why a top-level `e2e/` directory

Both `apps/portal` and `apps/probe-manager` are validated as a pair
(launcher → application flow). Keeping the browser suite outside either
app avoids coupling and keeps the Node dependency weight (`@playwright/test`
+ fixture data) out of individual app bundles.

## Running

```bash
# Terminal 1
cd apps/portal && npx vite preview --host 127.0.0.1 --port 4300

# Terminal 2
cd apps/probe-manager && npx vite preview --host 127.0.0.1 --port 4310

# Terminal 3
cd e2e
npm install
PLAYWRIGHT_BROWSERS_PATH=/home/devmat/.cache/ms-playwright \
  npx playwright test
```

The browser binary is pulled from the pre-installed Chromium 1248 at
`/home/devmat/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome`
via `launchOptions.executablePath` in `playwright.config.ts`. Override
with `PLAYWRIGHT_CHROMIUM_EXECUTABLE`.

## Scope boundaries

- `mock-api.ts` is **fixture-only** and never ships to production.
  Production builds never see this file.
- The suite does not execute any live capture; it only renders the UI
  states that the backend would produce.
