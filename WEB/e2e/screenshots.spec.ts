import { test, expect, type Page } from '@playwright/test';
import { installMockApi } from './mock-api';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCREENSHOT_DIR = path.join(__dirname, '..', 'SCREENSHOTS');
mkdirSync(SCREENSHOT_DIR, { recursive: true });

const PORTAL_URL = process.env.PORTAL_URL ?? 'http://127.0.0.1:4300';
const PROBE_URL = process.env.PROBE_URL ?? 'http://127.0.0.1:4310';

const VIEWPORTS = [
  { width: 1920, height: 1080, label: '1920x1080' },
  { width: 1440, height: 900, label: '1440x900' },
  { width: 1280, height: 800, label: '1280x800' },
  { width: 1024, height: 768, label: '1024x768' },
];

async function setTheme(page: Page, theme: 'light' | 'dark') {
  await page.evaluate((value) => {
    localStorage.setItem('telecom.theme', value);
    document.documentElement.dataset.theme = value;
  }, theme);
}

async function snap(page: Page, name: string) {
  await page.waitForTimeout(600); // allow network settle
  await page.screenshot({
    path: path.join(SCREENSHOT_DIR, `${name}.png`),
    fullPage: true,
    animations: 'disabled',
  });
}

for (const theme of ['light', 'dark'] as const) {
  for (const viewport of VIEWPORTS) {
    test(`portal · ${theme} · ${viewport.label}`, async ({ page }) => {
      await page.setViewportSize({ width: viewport.width, height: viewport.height });
      await installMockApi(page, 'populated');
      await page.goto(PORTAL_URL);
      await setTheme(page, theme);
      await page.reload();
      await expect(page.getByTestId('app-card-simulator')).toBeVisible();
      await snap(page, `portal_${theme}_${viewport.label}`);
    });
  }
}

const PROBE_ROUTES: Array<{ hash: string; wait: string; name: string }> = [
  { hash: '/overview', wait: '[data-testid="page-header"]', name: 'probe_overview' },
  { hash: '/topology', wait: '[data-testid="topology-canvas"]', name: 'probe_topology' },
  { hash: '/probes', wait: '[data-testid="probe-table"]', name: 'probe_probes' },
  { hash: '/interfaces', wait: '[data-testid="interface-table"]', name: 'probe_interfaces' },
  { hash: '/live-captures', wait: '[data-testid="live-capture-list"]', name: 'probe_live_captures' },
  { hash: '/capture-library', wait: '[data-testid="capture-table"]', name: 'probe_capture_library' },
  { hash: '/settings', wait: '[data-testid="page-header"]', name: 'probe_settings' },
];

for (const theme of ['light', 'dark'] as const) {
  for (const viewport of VIEWPORTS) {
    for (const route of PROBE_ROUTES) {
      test(`probe-manager · ${route.name} · ${theme} · ${viewport.label}`, async ({ page }) => {
        await page.setViewportSize({ width: viewport.width, height: viewport.height });
        await installMockApi(page, 'populated');
        await page.goto(`${PROBE_URL}/#${route.hash}`);
        await setTheme(page, theme);
        await page.goto(`${PROBE_URL}/#${route.hash}`);
        await page.waitForSelector(route.wait, { timeout: 20_000 });
        await snap(page, `${route.name}_${theme}_${viewport.label}`);
      });
    }
  }
}

test('probe-manager · empty state honesty · light · 1440x900', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await installMockApi(page, 'empty');
  await page.goto(`${PROBE_URL}/#/capture-library`);
  await setTheme(page, 'light');
  await page.goto(`${PROBE_URL}/#/capture-library`);
  await page.waitForSelector('[data-testid="empty-state"]', { timeout: 20_000 });
  await snap(page, 'probe_capture_library_empty_light_1440x900');
});
