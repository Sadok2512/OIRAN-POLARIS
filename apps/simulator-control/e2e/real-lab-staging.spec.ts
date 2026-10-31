import { expect, test } from '@playwright/test';

const API = '/polaris-api/v1';

test('real-lab staging is read-only and renders honest LTE/5G data', async ({ page, request }, testInfo) => {
  const version = await request.get(`${API}/version`);
  expect(version.ok()).toBeTruthy();
  await expect.poll(async () => (await version.json()).staging_read_only).toBe(true);

  const templatesResponse = await request.get(`${API}/scenario-templates`);
  expect(templatesResponse.ok()).toBeTruthy();
  const templates = await templatesResponse.json();
  expect(templates.total).toBe(13);
  expect(templates.items).toHaveLength(13);
  expect(JSON.stringify(templates)).not.toMatch(/DEMO/i);

  const blocked = await request.post(`${API}/traffic/sessions`, { data: {} });
  expect(blocked.status()).toBe(423);
  expect((await blocked.json()).error).toBe('STAGING_READ_ONLY');

  await page.goto('network/topology');
  await expect(page.getByTestId('topology-view')).toBeVisible();
  await expect(page.getByTestId('topology-node-GNB-01')).toContainText('UERANSIM');
  await expect(page.getByTestId('topology-node-ENB-01')).toContainText('srsRAN');
  await expect(page.locator('body')).not.toContainText(/DEMO/i);

  await page.goto('ues');
  await expect(page.getByTestId('ue-table')).toBeVisible();
  await expect(page.getByTestId('ue-technology-LTE-SRSUE-TEST-01')).toContainText('LTE');
  await expect(page.getByTestId('ue-simulator-LTE-SRSUE-TEST-01')).toContainText('srsUE');
  await expect(page.locator('body')).not.toContainText(/DEMO/i);

  await page.goto('scenarios');
  await page.getByTestId('scenarios-tab-templates').click();
  await expect(page.getByTestId('templates-table')).toBeVisible();
  await expect(page.locator('[data-testid^="template-row-"]')).toHaveCount(13);

  await page.goto('traffic');
  await expect(page.getByTestId('traffic-card')).toBeVisible();
  await expect(page.getByTestId('traffic-directions')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Current traffic' })).toBeVisible();
  await expect(page.locator('body')).not.toContainText(/DEMO/i);

  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
  expect(overflow).toBe(false);

  if (testInfo.project.name === 'chromium-1440-light') {
    await page.screenshot({
      path: '/root/polaris-staging-anr2.y2vSUn/evidence/traffic-real-lab-1440.png',
      fullPage: true,
    });
  }
});
