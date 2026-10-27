import { defineConfig, devices } from '@playwright/test';

const CHROMIUM_PATH =
  process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE ??
  '/home/devmat/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome';

export default defineConfig({
  testDir: '.',
  outputDir: 'test-results',
  reporter: [['list']],
  use: {
    headless: true,
    viewport: { width: 1440, height: 900 },
    ignoreHTTPSErrors: true,
    trace: 'off',
    screenshot: 'off',
    video: 'off',
    launchOptions: {
      executablePath: CHROMIUM_PATH,
    },
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
