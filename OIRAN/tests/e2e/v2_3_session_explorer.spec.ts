import { expect, test, type Page } from '../../apps/web/node_modules/@playwright/test';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

const ROOT = path.resolve(process.cwd(), '../..');
const screenshots = path.join(ROOT, 'OIRAN_V2_3_UI_SCREENSHOTS');
const historical = 'OIRAN_5G_PDU_SESSION_DATA_V1';
const recovered = 'recovered-dataset-live-1792964646320-0003';

async function openExplorer(page: Page, query = '') {
  await page.goto(`/investigation/sessions${query}`);
  await expect(page.getByRole('heading', { name: 'Session Explorer' })).toBeVisible();
}

test('V2.3 dataset inventory is normalized and truthfully session-scoped', async ({ request }) => {
  const response = await request.get('/api/v1/datasets?page_size=100');
  expect(response.status()).toBe(200);
  const body = await response.json();
  expect(body.meta.total).toBeGreaterThanOrEqual(4);
  const certified = body.data.find((item: { dataset_id: string }) => item.dataset_id === historical);
  expect(certified).toMatchObject({ dataset_kind: 'HISTORICAL', packet_count: 78, normalized_event_count: 54, session_count: 1 });
  const recoveredDataset = body.data.find((item: { dataset_id: string }) => item.dataset_id === recovered);
  expect(recoveredDataset).toMatchObject({ dataset_kind: 'RECOVERED', packet_count: 50, normalized_event_count: 20, session_count: 0 });
});

test('V2.3 explicit scopes never fall back to an unrelated historical session', async ({ page }) => {
  await openExplorer(page);
  await page.getByLabel('Dataset filter').selectOption('scope:CAPTURED_LIVE');
  await expect(page).toHaveURL(/dataset_scope=CAPTURED_LIVE/);
  const liveResponse = await page.request.get('/api/v1/sessions?page_size=100&dataset_scope=CAPTURED_LIVE');
  expect(liveResponse.status()).toBe(200);
  const liveBody = await liveResponse.json();
  if (liveBody.meta.total === 0) {
    await expect(page.getByText('No sessions match these filters')).toBeVisible();
  }
  await expect(page.getByText('5g-UE-A-pdu-1')).toHaveCount(0);

  await page.getByLabel('Dataset filter').selectOption(recovered);
  await expect(page).toHaveURL(new RegExp(`dataset_id=${recovered}`));
  await expect(page.getByRole('heading', { name: 'No reconstructed sessions in this dataset.' })).toBeVisible();
  await expect(page.getByText(/will not substitute a historical session/)).toBeVisible();
});

test('V2.3 historical selection and Call Flow retain the exact dataset context', async ({ page }) => {
  await openExplorer(page, `?dataset_id=${historical}`);
  await expect(page.getByText('5g-UE-A-pdu-1').first()).toBeVisible();
  await page.getByRole('button', { name: /Call Flow/ }).first().click();
  await expect(page).toHaveURL(/callflow\/5g-UE-A-pdu-1/);
  await expect(page).toHaveURL(new RegExp(`dataset_id=${historical}`));
  await expect(page.locator('.flow-event')).toHaveCount(26);
});

for (const viewport of [{ width: 1440, height: 900 }, { width: 1920, height: 1080 }]) {
  for (const theme of ['light', 'dark'] as const) {
    test(`V2.3 Session Explorer ${theme} ${viewport.width}x${viewport.height}`, async ({ page }) => {
      await fs.mkdir(screenshots, { recursive: true });
      await page.setViewportSize(viewport);
      await page.goto('/');
      await page.evaluate((value) => localStorage.setItem('oiran.theme', value), theme);
      await openExplorer(page, `?dataset_id=${historical}`);
      await page.waitForLoadState('networkidle');
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
      expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe(theme);
      await page.screenshot({ path: path.join(screenshots, `session-explorer-${theme}-${viewport.width}x${viewport.height}.png`), fullPage: false });

      await page.getByLabel('Dataset filter').selectOption(recovered);
      await expect(page.getByRole('heading', { name: 'No reconstructed sessions in this dataset.' })).toBeVisible();
      await page.screenshot({ path: path.join(screenshots, `zero-session-${theme}-${viewport.width}x${viewport.height}.png`), fullPage: false });
    });
  }
}
