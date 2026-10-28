import { expect, test } from '@playwright/test';

const simulatorUrl = process.env.SIMULATOR_URL ?? 'https://151.242.147.49:8020/simulator/';
const username = process.env.POLARIS_OPERATOR_USERNAME;
const password = process.env.POLARIS_OPERATOR_PASSWORD;

function simulatorPath(path: string): string {
  return new URL(path, simulatorUrl).toString();
}

test('Simulator 0.5.2 authenticates an Operator and renders current BrowserRouter routes', async ({ page }) => {
  expect(username, 'POLARIS_OPERATOR_USERNAME must be securely injected').toBeTruthy();
  expect(password, 'POLARIS_OPERATOR_PASSWORD must be securely injected').toBeTruthy();

  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));

  await page.goto(simulatorPath('settings'), { waitUntil: 'domcontentloaded' });
  await page.getByTestId('operator-login-username').fill(username!);
  await page.getByTestId('operator-login-password').fill(password!);
  await page.getByTestId('operator-login-submit').click();

  const account = page.getByTestId('operator-account');
  await expect(account.getByText(username!, { exact: true })).toBeVisible();
  await expect(account.getByText('operator', { exact: true })).toBeVisible();
  await expect(account.getByText('Can start', { exact: true })).toBeVisible();
  await expect(account.getByText('Yes', { exact: true }).first()).toBeVisible();

  const auth = await page.evaluate(async () => {
    const response = await fetch('/polaris-api/v1/auth/me');
    return { status: response.status, body: await response.json() };
  });
  expect(auth.status).toBe(200);
  expect(auth.body.authenticated).toBe(true);
  expect(auth.body.role).toBe('operator');

  for (const [path, title] of [
    ['network/topology', 'Topology'],
    ['network/gnbs', 'gNodeBs'],
    ['scenarios', 'Scenarios'],
    ['ues', 'UE Profile Manager'],
  ] as const) {
    await page.goto(simulatorPath(path), { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('heading', { name: title, level: 1 })).toBeVisible();
  }

  await page.goto(simulatorPath('scenarios'), { waitUntil: 'domcontentloaded' });
  await page.getByRole('tab', { name: 'Templates (tpl-*)' }).click();
  await expect(page.getByTestId('templates-table')).toBeVisible();
  for (const templateId of [
    'tpl-voice-long',
    'tpl-voice-short',
    'tpl-small-traffic',
    'tpl-high-runner',
  ]) {
    await expect(page.getByTestId(`template-row-${templateId}`)).toBeVisible();
  }

  const downloadPromise = page.waitForEvent('download');
  await page.getByTestId('template-download-tpl-high-runner').click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('tpl-high-runner-v1.json');

  const exported = await page.evaluate(async () => {
    const response = await fetch('/polaris-api/v1/scenario-definitions/tpl-high-runner/export');
    return { status: response.status, body: await response.text() };
  });
  expect(exported.status).toBe(200);

  await page.getByTestId('scenarios-import').click();
  await page.getByTestId('import-file-field').setInputFiles({
    name: download.suggestedFilename(),
    mimeType: 'application/json',
    buffer: Buffer.from(exported.body),
  });
  await expect(page.getByTestId('import-preview')).toBeVisible();
  const collisionResponse = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      response.url().includes('/scenario-definitions/import'),
  );
  await page.getByTestId('import-submit').click();
  expect((await collisionResponse).status()).toBe(409);
  await expect(page.getByTestId('import-collision')).toBeVisible();
  await page.getByTestId('import-rename-field').fill('ui-import-681d42e');
  const renamedResponse = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      response.url().includes('/scenario-definitions/import?rename=ui-import-681d42e'),
  );
  await page.getByTestId('import-rename-submit').click();
  expect((await renamedResponse).status()).toBe(201);
  await expect(page.getByTestId('import-scenario-dialog')).toBeHidden();

  expect(pageErrors).toEqual([]);
});
