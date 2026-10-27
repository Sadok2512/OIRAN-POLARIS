import { defineConfig } from '@playwright/test';

const runtimeEnv=(globalThis as {process?:{env?:Record<string,string|undefined>}}).process?.env;

export default defineConfig({
  testDir: '../../tests/e2e',
  // Screenshot suites visit several data-heavy routes in both themes. Keep the
  // assertion semantics strict while allowing bounded rendering on a loaded lab host.
  timeout: 60_000,
  fullyParallel: false,
  workers: 1,
  reporter: [['list'], ['json', { outputFile: '../../tests/e2e/oiran_v2_3_results.json' }]],
  use: {
    baseURL: runtimeEnv?.OIRAN_E2E_BASE_URL??'http://127.0.0.1:49152',
    viewport: { width: 1440, height: 900 },
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
});
