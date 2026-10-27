import { expect, test } from '@playwright/test';
import { mkdirSync } from 'node:fs';

const password = process.env.POLARIS_OPERATOR_PASSWORD;
const username = process.env.POLARIS_OPERATOR_USERNAME;
const shots = `${process.env.RELEASE_SCREENSHOT_DIR ?? 'screenshots/release_consolidation_v1'}/config`;

test('deployed operator sees configurable counts without starting processes', async ({ page }) => {
  expect(username, 'POLARIS_OPERATOR_USERNAME must be securely injected').toBeTruthy();
  expect(password, 'POLARIS_OPERATOR_PASSWORD must be securely injected').toBeTruthy();
  mkdirSync(shots, { recursive: true });

  await page.goto('/#/settings');
  await page.getByLabel('Username').fill(username!);
  await page.getByLabel('Password').fill(password!);
  await page.getByRole('button', { name: 'Sign in securely' }).click();
  await expect(page.getByText(username!, { exact: true }).first()).toBeVisible();

  for (const theme of ['light', 'dark']) {
    for (const size of [{ width: 1440, height: 900 }, { width: 1920, height: 1080 }]) {
      await page.setViewportSize(size);
      await page.goto('/#/console');
      await page.getByLabel('Theme').selectOption(theme);
      await expect(page.getByLabel('UE count')).toBeEnabled();
      await expect(page.getByLabel('UE count')).toHaveAttribute('max', '10');
      await expect(page.getByLabel('gNB count')).toBeEnabled();
      await expect(page.getByLabel('gNB count')).toHaveAttribute('max', '2');
      await expect(page.getByText('UE-PSEUDONYM-01').first()).toBeVisible();
      await expect(page.getByText('REGISTERED', { exact: true }).first()).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      await page.screenshot({ path: `${shots}/Console_${theme}_${size.width}x${size.height}.png`, fullPage: true });

      await page.goto('/#/ues');
      await expect(page.getByRole('button', { name: 'Add UE' })).toBeEnabled();
      await expect(page.getByText('UE-PSEUDONYM-01').first()).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      await page.screenshot({ path: `${shots}/UE_Manager_${theme}_${size.width}x${size.height}.png`, fullPage: true });
    }
  }
});
