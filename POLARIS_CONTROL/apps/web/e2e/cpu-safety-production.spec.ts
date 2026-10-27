import { expect, test } from '@playwright/test';
import { mkdirSync } from 'node:fs';

const password = process.env.POLARIS_OPERATOR_PASSWORD;
const username = process.env.POLARIS_OPERATOR_USERNAME;
const shots = `${process.env.RELEASE_SCREENSHOT_DIR ?? 'screenshots/release_consolidation_v1'}/cpu`;

test('production CPU evidence is truthful and operational pages remain usable', async ({ page, request }) => {
  expect(username, 'POLARIS_OPERATOR_USERNAME must be securely injected').toBeTruthy();
  expect(password, 'POLARIS_OPERATOR_PASSWORD must be securely injected').toBeTruthy();
  mkdirSync(shots, { recursive: true });

  const healthResponse = await request.get('/api/v1/system/health');
  expect(healthResponse.ok()).toBe(true);
  const health = await healthResponse.json();
  expect(health.cpu.logical_cpus).toBe(10);
  expect(health.cpu_safety.api_cgroup.effective_capacity_cpus).toBeGreaterThan(0);
  expect(health.cpu_safety.api_cgroup.effective_capacity_cpus).toBeLessThanOrEqual(health.cpu.logical_cpus);
  expect(health.cpu_safety.telemetry_fresh).toBe(true);
  expect(health.cpu_safety.valid_samples).toBeGreaterThanOrEqual(3);
  expect(['READY', 'WARNING_NON_BLOCKING', 'WARNING_BLOCKING', 'BLOCKED_HOST_CPU', 'BLOCKED_CGROUP_THROTTLING', 'BLOCKED_CPU_PRESSURE', 'BLOCKED_RESOURCE_BUDGET', 'BLOCKED_STALE_TELEMETRY', 'BLOCKED_UNKNOWN_CAPACITY']).toContain(health.cpu_safety.state);

  await page.goto('/#/settings');
  await page.getByLabel('Username').fill(username!);
  await page.getByLabel('Password').fill(password!);
  await page.getByRole('button', { name: 'Sign in securely' }).click();
  await expect(page.getByText(username!, { exact: true }).first()).toBeVisible();

  for (const theme of ['light', 'dark']) {
    for (const size of [{ width: 1440, height: 900 }, { width: 1920, height: 1080 }]) {
      await page.setViewportSize(size);
      for (const [path, title, file] of [
        ['console', 'Operations Console', 'Dashboard'],
        ['health', 'System Health', 'System_Health'],
        ['ues', 'UE Manager', 'UE_Manager'],
        ['traffic', 'Traffic Generator', 'Traffic_Generator'],
      ]) {
        await page.goto(`/#/${path}`);
        await page.getByLabel('Theme').selectOption(theme);
        await expect(page.getByRole('heading', { name: title, level: 1 })).toBeVisible();
        if (path === 'health') {
          await expect(page.getByText('running', { exact: true }).first()).toBeVisible();
        }
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
        await page.screenshot({ path: `${shots}/${file}_${theme}_${size.width}x${size.height}.png`, fullPage: true });
      }
    }
  }

  await page.goto('/#/health');
  await expect(page.locator('.page-head .badge')).toHaveText(/READY|WARNING|BLOCKED/);
  await expect(page.getByText(`${health.cpu_safety.api_cgroup.effective_capacity_cpus.toFixed(2)} CPUs`, { exact: true })).toBeVisible();
  await expect(page.getByText(/Load average \(informational\)/)).toBeVisible();
});
