import { expect, test } from '@playwright/test';

const simulatorUrl = process.env.SIMULATOR_URL ?? 'https://151.242.147.49:8020/simulator/';
const username = process.env.POLARIS_OPERATOR_USERNAME;
const password = process.env.POLARIS_OPERATOR_PASSWORD;
const testImsi = process.env.POLARIS_TEST_SUBSCRIBER_IMSI;
const testK = process.env.POLARIS_TEST_SUBSCRIBER_K;
const testOpc = process.env.POLARIS_TEST_SUBSCRIBER_OPC;
const bulkCsv = process.env.POLARIS_TEST_SUBSCRIBER_CSV;
const simulatorPath = (path: string) => new URL(path, simulatorUrl).toString();

async function login(page: import('@playwright/test').Page) {
  expect(username, 'POLARIS_OPERATOR_USERNAME must be securely injected').toBeTruthy();
  expect(password, 'POLARIS_OPERATOR_PASSWORD must be securely injected').toBeTruthy();
  await page.goto(simulatorPath('settings'), { waitUntil: 'domcontentloaded' });
  await page.getByTestId('operator-login-username').fill(username!);
  await page.getByTestId('operator-login-password').fill(password!);
  await page.getByTestId('operator-login-submit').click();
  await expect(page.getByTestId('operator-account').getByText('operator', { exact: true })).toBeVisible();
}

test('real provisioning, UE detail and template clone/save contracts', async ({ page }) => {
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  await login(page);

  const checks = await page.evaluate(async () => Promise.all(
    ['auth/me', 'gnbs', 'owners', 'plmns', 'dnns', 'scenario-definitions'].map(async (path) => {
      const response = await fetch(`/polaris-api/v1/${path}`);
      const body = await response.json();
      const items = Array.isArray(body) ? body : body.items ?? [];
      return { path, status: response.status, count: Array.isArray(items) ? items.length : 0, body };
    }),
  ));
  for (const result of checks) expect(result.status, result.path).toBe(200);
  expect(checks.find((item) => item.path === 'auth/me')?.body.role).toBe('operator');
  for (const path of ['gnbs', 'owners', 'plmns', 'dnns', 'scenario-definitions']) {
    expect(checks.find((item) => item.path === path)?.count, path).toBeGreaterThan(0);
  }

  await page.goto(simulatorPath('provisioning'), { waitUntil: 'domcontentloaded' });
  const subscriberTable = page.getByTestId('provisioning-subscribers');
  await expect(subscriberTable).toBeVisible();
  await expect(subscriberTable.getByText('PROTECTED').first()).toBeVisible();

  await page.goto(simulatorPath('ues/UE-01'), { waitUntil: 'domcontentloaded' });
  for (const block of ['identity', 'provisioning', 'network', 'registration', 'pdu', 'ims', 'scenario', 'traffic']) {
    await expect(page.getByTestId(`ue-block-${block}`), block).toBeVisible();
  }

  await page.goto(simulatorPath('scenarios'), { waitUntil: 'domcontentloaded' });
  await page.getByTestId('scenarios-tab-templates').click();
  await expect(page.getByTestId('templates-table')).toBeVisible();
  await page.getByTestId('template-clone-tpl-voice-long').click();
  await expect(page.getByTestId('builder-locked-step-banner')).toBeVisible();
  const saveResponse = page.waitForResponse((response) =>
    response.request().method() === 'POST' && response.url().endsWith('/scenario-definitions'));
  await page.getByTestId('builder-save').click();
  expect((await saveResponse).status()).toBe(201);
  await expect(page).toHaveURL(/\/scenarios\/[^/]+\/edit$/);
  expect(pageErrors).toEqual([]);
});

test('operator creates one protected subscriber and imports two CSV rows', async ({ page }) => {
  expect(testImsi, 'POLARIS_TEST_SUBSCRIBER_IMSI must be securely injected').toMatch(/^\d{15}$/);
  expect(testK, 'POLARIS_TEST_SUBSCRIBER_K must be securely injected').toMatch(/^[0-9a-fA-F]{32}$/);
  expect(testOpc, 'POLARIS_TEST_SUBSCRIBER_OPC must be securely injected').toMatch(/^[0-9a-fA-F]{32}$/);
  expect(bulkCsv, 'POLARIS_TEST_SUBSCRIBER_CSV must be securely injected').toBeTruthy();
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  await login(page);

  await page.goto(simulatorPath('provisioning'), { waitUntil: 'domcontentloaded' });
  await page.getByTestId('provisioning-add').click();
  await page.getByTestId('subscriber-imsi').fill(testImsi!);
  await page.getByTestId('subscriber-k').fill(testK!);
  await page.getByTestId('subscriber-opc').fill(testOpc!);
  const createResponse = page.waitForResponse((response) =>
    response.request().method() === 'POST' && response.url().endsWith('/subscribers'));
  await page.getByTestId('add-subscriber-submit').click();
  expect((await createResponse).status()).toBe(201);
  await expect(page.getByTestId('add-subscriber-created')).toContainText('PROTECTED');

  await page.getByLabel('Close').click();
  await page.getByTestId('provisioning-import').click();
  await page.getByTestId('csv-file-field').setInputFiles({
    name: 'subscribers.csv',
    mimeType: 'text/csv',
    buffer: Buffer.from(bulkCsv!),
  });
  await expect(page.getByTestId('csv-ok-under-cap')).toBeVisible();
  const bulkResponse = page.waitForResponse((response) =>
    response.request().method() === 'POST' && response.url().endsWith('/subscribers/bulk'));
  await page.getByTestId('csv-upload-submit').click();
  const response = await bulkResponse;
  expect(response.status()).toBe(200);
  await expect(page.getByTestId('csv-import-report')).toContainText('2 accepted');
  await expect(page.getByTestId('csv-import-report')).toContainText('0 rejected');
  expect(pageErrors).toEqual([]);
});
