import { expect, test } from '@playwright/test';

const simulatorUrl = process.env.SIMULATOR_URL ?? 'https://151.242.147.49:8020/simulator/';
const username = process.env.POLARIS_OPERATOR_USERNAME;
const password = process.env.POLARIS_OPERATOR_PASSWORD;
const simulatorPath = (path: string) => new URL(path, simulatorUrl).toString();

test('real provisioning, UE detail and template clone/save contracts', async ({ page }) => {
  expect(username, 'POLARIS_OPERATOR_USERNAME must be securely injected').toBeTruthy();
  expect(password, 'POLARIS_OPERATOR_PASSWORD must be securely injected').toBeTruthy();
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));

  await page.goto(simulatorPath('settings'), { waitUntil: 'domcontentloaded' });
  await page.getByTestId('operator-login-username').fill(username!);
  await page.getByTestId('operator-login-password').fill(password!);
  await page.getByTestId('operator-login-submit').click();
  await expect(page.getByTestId('operator-account').getByText('operator', { exact: true })).toBeVisible();

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
