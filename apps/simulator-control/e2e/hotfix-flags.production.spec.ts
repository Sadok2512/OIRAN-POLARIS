import { expect, test } from '@playwright/test';

const base = process.env.SIMULATOR_URL ?? 'https://151.242.147.49:8020/simulator/';
const username = process.env.POLARIS_OPERATOR_USERNAME;
const password = process.env.POLARIS_OPERATOR_PASSWORD;

function url(path: string): string {
  return new URL(path, base).toString();
}

async function login(page: import('@playwright/test').Page): Promise<void> {
  expect(username, 'POLARIS_OPERATOR_USERNAME must be securely injected').toBeTruthy();
  expect(password, 'POLARIS_OPERATOR_PASSWORD must be securely injected').toBeTruthy();
  await page.goto(url('settings'), { waitUntil: 'domcontentloaded' });
  await page.getByTestId('operator-login-username').fill(username!);
  await page.getByTestId('operator-login-password').fill(password!);
  await page.getByTestId('operator-login-submit').click();
  await expect(page.getByTestId('operator-account')).toContainText('operator');
}

test('fresh browser exposes the backend UE form and Provisioning', async ({ page }, testInfo) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));

  await login(page);
  await page.goto(url('ues'), { waitUntil: 'networkidle' });
  await expect(page.getByText('POLARIS Simulator Control 0.9.2-hotfix')).toBeVisible();
  await page.getByTestId('ue-add').click();
  await expect(page.getByTestId('ue-provisioning-add-dialog')).toBeVisible();
  await expect(page.getByTestId('ue-add-gnb')).toBeVisible();
  await expect(page.getByTestId('ue-add-owner')).toBeVisible();
  await expect(page.getByTestId('ue-add-imsi')).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('add-ue-profile-backend.png'), fullPage: true });

  await page.getByRole('button', { name: 'Close' }).click();
  await page.goto(url('provisioning'), { waitUntil: 'networkidle' });
  await expect(page.getByTestId('provisioning-subscribers')).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('provisioning-backend.png'), fullPage: true });
  expect(errors).toEqual([]);
});

test('legacy OFF values are migrated once to the enabled v2 schema', async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem(
      'polaris.featureFlags.v1',
      JSON.stringify({
        profileBackend: false,
        polarisProvisioning: false,
        scenarioBackend: false,
        scenarioTemplates: false,
      }),
    );
  });
  await page.goto(url('ues'), { waitUntil: 'domcontentloaded' });
  const flags = await page.evaluate(() =>
    JSON.parse(localStorage.getItem('polaris.featureFlags.v2') ?? 'null'),
  );
  expect(flags).toEqual({
    profileBackend: true,
    polarisProvisioning: true,
    scenarioBackend: true,
    scenarioTemplates: true,
  });
});
