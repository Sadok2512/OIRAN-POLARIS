// 0.6.0 — minimal Playwright setup for simulator-control captures.
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
    { name: 'chromium-light', use: { ...devices['Desktop Chrome'], colorScheme: 'light' } },
    { name: 'chromium-dark', use: { ...devices['Desktop Chrome'], colorScheme: 'dark' } },
  ],
  reporter: [['list']],
});
