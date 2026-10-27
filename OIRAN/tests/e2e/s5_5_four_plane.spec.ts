import { expect, test } from '../../apps/web/node_modules/@playwright/test';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

const root = path.resolve(process.cwd(), '../..');
const screenshots = path.join(root, 'S5_5_UI_SCREENSHOTS');

test('S5.5 Probe Manager exposes the fixed four-plane profile', async ({ page }) => {
  await page.goto('/operations/probes');
  await expect(page.getByRole('heading', { name: 'Probe Manager' })).toBeVisible();
  for (const plane of ['NG-C', 'SBI', 'N4', 'NG-U']) {
    await expect(page.getByText(plane, { exact: true }).first()).toBeVisible();
  }
  const response = await page.request.get('/api/v1/interfaces');
  expect(response.status()).toBe(200);
  expect((await response.json()).data.map((item: { interface: string }) => item.interface)).toEqual([
    'N2', 'SBI', 'N4', 'N3',
  ]);
  await expect(page.getByRole('button', { name: 'Start capture' })).toBeDisabled();
});

test('S5.5 visual review covers four-plane investigation in both themes', async ({ page }) => {
  await fs.mkdir(screenshots, { recursive: true });
  const flowResponse = await page.request.get('/api/v1/sessions/5g-UE-A-pdu-1/callflow');
  const flow = await flowResponse.json();
  const selected = flow.data.events[0].event_id as string;
  const views = [
    ['probe-manager', '/operations/probes'],
    ['capture-library', '/operations/probes?search=N2.pcapng'],
    ['session-explorer', '/investigation/sessions/5g-UE-A-pdu-1'],
    ['callflow-viewer', '/investigation/callflow/5g-UE-A-pdu-1'],
    ['message-inspector', `/investigation/callflow/5g-UE-A-pdu-1?event_id=${encodeURIComponent(selected)}`],
  ] as const;
  for (const [width, height] of [[1440, 900], [1920, 1080]] as const) {
    await page.setViewportSize({ width, height });
    for (const theme of ['light', 'dark'] as const) {
      await page.goto('/');
      await page.evaluate((value) => localStorage.setItem('oiran.theme', value), theme);
      for (const [name, route] of views) {
        await page.goto(route);
        await page.waitForLoadState('networkidle');
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
        expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe(theme);
        await page.screenshot({
          path: path.join(screenshots, `${name}-${theme}-${width}x${height}.png`),
          fullPage: false,
        });
      }
    }
  }
});
