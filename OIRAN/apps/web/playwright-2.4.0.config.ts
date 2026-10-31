// 2.4.0 — Standalone Playwright config for the anti-overlap matrix
// (Sessions page at 1280 / 1440 / 1920 × light / dark) and the
// mockup/impl side-by-side captures. Separate from the historical
// `tests/e2e/*.spec.ts` suite so Codex can run it against the vite
// dev server without touching the certified fixtures.

import { defineConfig, devices } from '@playwright/test';

const runtimeEnv =
  (globalThis as { process?: { env?: Record<string, string | undefined> } }).process
    ?.env;
const BASE = runtimeEnv?.OIRAN_SIM_E2E_BASE_URL ?? 'http://127.0.0.1:4173/';

export default defineConfig({
  testDir: './e2e-2.4.0',
  timeout: 60_000,
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: BASE,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium-1280-light',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1280, height: 800 } },
    },
    {
      name: 'chromium-1280-dark',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1280, height: 800 } },
    },
    {
      name: 'chromium-1440-light',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } },
    },
    {
      name: 'chromium-1440-dark',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } },
    },
    {
      name: 'chromium-1920-light',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1920, height: 1080 } },
    },
    {
      name: 'chromium-1920-dark',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1920, height: 1080 } },
    },
  ],
});
