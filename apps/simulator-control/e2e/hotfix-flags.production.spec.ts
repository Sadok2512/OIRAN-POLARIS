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

test('fresh browser exposes the 0.9.4 Add UE dialog and Provisioning', async ({ page }, testInfo) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));

  await login(page);
  await page.goto(url('ues'), { waitUntil: 'networkidle' });
  // 0.9.4 — the shell displays the exact package version. The 0.9.2-hotfix
  // regex is gone because that version is superseded by the 0.9.3/0.9.4
  // lineage. `cache-control: no-store` on index.html guarantees a fresh
  // browser always sees the new version string.
  await expect(page.getByText('POLARIS Simulator Control 0.9.4')).toBeVisible();
  await page.getByTestId('ue-add').click();
  const dialog = page.getByTestId('ue-provisioning-add-dialog');
  await expect(dialog).toBeVisible();

  // 0.9.4 defect #29 contract — audit each MANQUANT that landed:
  // 29b: PLMN + DNN dropdowns with lab defaults 001-01 / internet.
  await expect(page.getByTestId('ue-add-plmn')).toHaveValue('001-01');
  await expect(page.getByTestId('ue-add-dnn')).toHaveValue('internet');
  // 29b: GNB-01 preselected when present in /gnbs.
  await expect(page.getByTestId('ue-add-gnb')).toHaveValue('GNB-01');
  // 29c: NO IMSI text input; slot picker + Generate button instead.
  await expect(page.locator('[data-testid="ue-add-imsi"]')).toHaveCount(0);
  await expect(page.getByTestId('ue-add-slot')).toBeVisible();
  await expect(page.getByTestId('ue-add-generate')).toBeVisible();
  // 29d: no UE IP form control.
  await expect(page.getByLabel(/^UE IP/i)).toHaveCount(0);
  // 29e: SST / SD dropdowns pre-filled with 1 / 010203.
  await expect(page.getByTestId('ue-add-sst')).toHaveValue('1');
  await expect(page.getByTestId('ue-add-sd')).toHaveValue('010203');
  // 29f: UE ID prefilled (non-empty, matches UE-NN / UE-NNNNN pattern).
  const ueIdValue = await page.getByTestId('ue-add-ue-id').inputValue();
  expect(ueIdValue).toMatch(/^UE-(?:\d{2}|\d{5})$/);
  // Confidentiality: identity material renders PROTECTED, no digits leak.
  const dialogText = await dialog.innerText();
  expect(dialogText).toContain('PROTECTED');
  expect(dialogText).not.toMatch(/\b\d{14,16}\b/);

  await page.screenshot({ path: testInfo.outputPath('add-ue-profile-0.9.4.png'), fullPage: true });

  await page.getByRole('button', { name: 'Close' }).click();
  await page.goto(url('provisioning'), { waitUntil: 'networkidle' });
  await expect(page.getByTestId('provisioning-subscribers')).toBeVisible();
  const firstSlot = page.locator('[data-testid^="subscriber-row-"]').first();
  await expect(firstSlot).toBeVisible();
  await firstSlot.click();
  await expect(page.getByTestId('subscriber-detail-panel')).toBeVisible();
  await expect(page.getByTestId('subscriber-detail-identity')).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('provisioning-0.9.4.png'), fullPage: true });
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
