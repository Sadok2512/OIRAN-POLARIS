import { expect, test, type Page } from '@playwright/test';

const json = (body: unknown) => ({
  status: 200,
  contentType: 'application/json',
  body: JSON.stringify(body),
});

async function mockPolaris(page: Page) {
  // Registered first because Playwright evaluates routes in reverse order.
  await page.route('**/polaris-api/v1/**', (route) => route.fulfill(json({ items: [] })));
  await page.route('**/polaris-api/v1/auth/me', (route) =>
    route.fulfill(json({ role: 'OPERATOR', can_start: true })),
  );
  await page.route('**/polaris-api/v1/ues', (route) =>
    route.fulfill(json({ items: [], configured_profiles: [], configured_count: 1, active_count: 0 })),
  );
  await page.route('**/polaris-api/v1/ue-profiles**', (route) =>
    route.fulfill(json({ items: [], total: 0, page: 1, page_size: 10, pages: 1, max: 10 })),
  );
  await page.route('**/polaris-api/v1/lte/status', (route) =>
    route.fulfill(json({
      technology: 'LTE 4G', simulator: 'srsRAN', certified: false, live_enabled: true,
      operation_mode: 'CERTIFICATION_RUN', certification_state: 'CERTIFICATION_PENDING',
      certification_run_enabled: true, manual_certification_required: true,
      safety_ready: true, grant_active: false, ownership_verified: true,
      epc: { process_state: 'running', health: 'unknown', observed: true },
      s1_state: 'UNKNOWN',
      enb: { process_state: 'stopped', health: 'unknown', observed: true, controller_owned: true },
      ue: { process_state: 'stopped', health: 'unknown', observed: true, controller_owned: true },
      ue_id: 'LTE-SRSUE-TEST-01', attach_state: 'DETACHED', apn: 'internet', ue_ip: null, active_sessions: 0,
    })),
  );
  await page.route('**/polaris-api/v1/lte/profiles/LTE-SRSUE-TEST-01', (route) =>
    route.fulfill(json({
      profile_id: 'LTE-SRSUE-TEST-01', revision: 1, enabled: true,
      owner: 'POLARIS_CONTROLLER', grant_required: true,
      configuration_sha256: 'a'.repeat(64), compose_model_sha256: 'c'.repeat(64),
      scenario_id: 'lte-e2e-certification-v1', scenario_revision: 1,
      scenario_sha256: 'b'.repeat(64), max_running_ues: 1,
    })),
  );
  await page.route('**/polaris-api/v1/lte/logs**', (route) =>
    route.fulfill(json({ lines: ['S1 setup complete'], redacted: true })),
  );
}

test('LTE certification mode is visible, bounded and does not claim certification', async ({ page }) => {
  await mockPolaris(page);
  await page.goto('./ues');
  await page.getByTestId('technology-lte').click();

  const panel = page.getByTestId('lte-control-panel');
  await expect(panel).toBeVisible();
  await expect(panel).toContainText('LTE 4G — srsRAN');
  await expect(panel).toContainText('CERTIFICATION PENDING');
  await expect(panel).toContainText('never promote themselves');
  await expect(page.getByRole('button', { name: 'Start LTE certification run' })).toBeEnabled();

  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
  expect(overflow).toBe(false);
});
