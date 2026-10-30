// 0.6.0 — minimal Playwright setup for simulator-control captures.
// 0.10.0 — Added 1920×1080 viewport projects alongside 1440×900 so the
// honest-UX pass (no overlap, no horizontal scroll in UE Manager, Scenario
// Builder, Create Subscriber dialog) is validated at both reference
// widths. Captures write screenshots regardless of pass/fail now; the
// 0.10.0 report ships `screenshots-1440/` and `screenshots-1920/`.
//
// Scope:
//   * Capture Templates, UE Manager, Provisioning, UE detail pages
//   * Light + dark themes
//   * Backend is MOCKED through `page.route('**/polaris-api/v1/**', …)`
//     so the suite runs without a live POLARIS instance. See
//     docs/screenshots/README.md for the "mocked API" caveat.
//
// Run:
//   npm run dev   # terminal 1 (vite on 127.0.0.1:4330)
//   npx playwright test   # terminal 2

import { defineConfig, devices } from '@playwright/test';

const BASE = process.env.POLARIS_SIM_E2E_BASE_URL ?? 'http://127.0.0.1:4330/simulator/';

export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  workers: 1,
  use: {
    baseURL: BASE,
    viewport: { width: 1440, height: 900 },
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium-1440-light',
      use: {
        ...devices['Desktop Chrome'],
        colorScheme: 'light',
        viewport: { width: 1440, height: 900 },
      },
    },
    {
      name: 'chromium-1440-dark',
      use: {
        ...devices['Desktop Chrome'],
        colorScheme: 'dark',
        viewport: { width: 1440, height: 900 },
      },
    },
    {
      name: 'chromium-1920-light',
      use: {
        ...devices['Desktop Chrome'],
        colorScheme: 'light',
        viewport: { width: 1920, height: 1080 },
      },
    },
    {
      name: 'chromium-1920-dark',
      use: {
        ...devices['Desktop Chrome'],
        colorScheme: 'dark',
        viewport: { width: 1920, height: 1080 },
      },
    },
  ],
  reporter: [['list']],
});
