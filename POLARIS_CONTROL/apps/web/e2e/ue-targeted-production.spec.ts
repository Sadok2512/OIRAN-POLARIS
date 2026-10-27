import { expect, test } from '@playwright/test';
import { mkdirSync } from 'node:fs';

const password = process.env.POLARIS_OPERATOR_PASSWORD;
const username = process.env.POLARIS_OPERATOR_USERNAME;
const shots = `${process.env.RELEASE_SCREENSHOT_DIR ?? 'screenshots/release_consolidation_v1'}/traffic`;

test('deployed four-UE inventory and targeted traffic remain safe', async ({ page }) => {
  test.setTimeout(120_000);
  expect(username, 'POLARIS_OPERATOR_USERNAME must be securely injected').toBeTruthy();
  expect(password, 'POLARIS_OPERATOR_PASSWORD must be securely injected').toBeTruthy();
  mkdirSync(shots, { recursive: true });

  await page.goto('/#/settings');
  await page.getByLabel('Username').fill(username!);
  await page.getByLabel('Password').fill(password!);
  await page.getByRole('button', { name: 'Sign in securely' }).click();
  await expect(page.getByText(username!, { exact: true }).first()).toBeVisible();
  const observedInventory = await (await page.request.get('/api/v1/ues')).json();
  const observedUe04 = observedInventory.items.find((item: { internal_ue_id?: string }) => item.internal_ue_id === 'UE-04');
  expect(observedUe04).toBeTruthy();

  for (const theme of ['light', 'dark']) {
    for (const size of [{ width: 1440, height: 900 }, { width: 1920, height: 1080 }]) {
      await page.setViewportSize(size);

      await page.goto('/#/ues');
      await page.getByLabel('Theme').selectOption(theme);
      const inventory = page.getByRole('heading', { name: 'Configured UE state' }).locator('xpath=ancestor::section');
      await expect(inventory.locator('tbody tr')).toHaveCount(4);
      const ue04 = inventory.locator('tbody tr').filter({ hasText: 'UE-PSEUDONYM-04' });
      await expect(ue04.getByText(observedUe04.process_state, { exact: true }).first()).toBeVisible();
      await expect(ue04.getByText(observedUe04.registration_state, { exact: true }).first()).toBeVisible();
      await expect(ue04.getByText(observedUe04.pdu_session, { exact: true }).first()).toBeVisible();
      await expect(ue04.getByRole('button', { name: 'Traffic' })).toBeDisabled();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      await page.screenshot({ path: `${shots}/UE_Manager_${theme}_${size.width}x${size.height}.png` });

      await page.goto('/#/traffic');
      await page.getByLabel('Theme').selectOption(theme);
      const selector = page.getByLabel('Target UE');
      await expect(selector.locator('option')).toHaveCount(3, { timeout: 15_000 });
      await expect(selector.locator('option', { hasText: 'UE-PSEUDONYM-01' })).toHaveCount(0);
      await expect(selector.locator('option', { hasText: 'UE-PSEUDONYM-04' })).toHaveCount(0);
      await expect(page.getByText('Shared observed UEs are protected', { exact: false })).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      await page.screenshot({ path: `${shots}/Traffic_Generator_${theme}_${size.width}x${size.height}.png` });

      await page.goto('/#/console');
      await page.getByLabel('Theme').selectOption(theme);
      await expect(page.getByText('4 configured', { exact: true }).first()).toBeVisible({ timeout: 15_000 });
      await expect(page.getByText('3 running', { exact: true }).first()).toBeVisible();
      const capability = await page.evaluate(() => fetch('/api/v1/scenario-capabilities').then(response => response.json()));
      expect([
        'READY_TO_START',
        'WARNING_NON_BLOCKING',
        'WARNING_BLOCKING',
        'BLOCKED',
        'INSUFFICIENT_RESOURCES',
        'OPERATOR_PERMISSION_REQUIRED',
      ]).toContain(capability.execution_status);
      expect(capability.reason).toEqual(expect.any(String));
      const runtime = await page.evaluate(() => fetch('/api/v1/scenarios/status').then(response => response.json()));
      const expectedConsoleState = runtime.active_job?.state
        ?? (capability.execution_status === 'READY_TO_START'
          ? 'VALIDATION_REQUIRED'
          : capability.execution_status);
      await expect(page.getByText(expectedConsoleState.replaceAll('_', ' '), { exact: true }).first()).toBeVisible();
      await page.screenshot({ path: `${shots}/CPU_Safety_${theme}_${size.width}x${size.height}.png` });

      await page.goto('/#/health');
      await page.getByLabel('Theme').selectOption(theme);
      await expect(page.getByText('running', { exact: true }).first()).toBeVisible({ timeout: 15_000 });
      await expect(page.getByText('No automatic cleanup is performed.')).toBeVisible();
      await page.screenshot({ path: `${shots}/Disk_Safety_${theme}_${size.width}x${size.height}.png` });
    }
  }
});
