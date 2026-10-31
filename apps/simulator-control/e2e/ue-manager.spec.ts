// Offline observed-contract test for the RAT-aware UE Manager. Route stubs are
// test-only and are never bundled into the operational application.

import { test, expect, type Page } from '@playwright/test';

async function mockApi(page: Page) {
  await page.route('**/polaris-api/v1/auth/me', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ role: 'OPERATOR', can_start: true }),
    }),
  );

  await page.route('**/polaris-api/v1/ue-profiles**', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        items: [
          {
            ue_id: 'UE-01',
            name: 'UE-01',
            serving_gnb: 'GNB-01',
            plmn: { mcc: '001', mnc: '01' },
            dnn: 'internet',
            snssai: { sst: 1, sd: '010203' },
            pdu_session: { dnn: 'internet', type: 'IPv4' },
            scenario_id: null,
            auto_run_scenario: false,
            subscription_status: 'VERIFIED',
            subscriber_identity: 'PROTECTED',
            authentication_material: 'PROTECTED',
            profile: 'POLARIS',
            revision: 1,
            updated_at_epoch_s: 1_730_200_000,
          },
        ],
        total: 1,
        page: 1,
        page_size: 10,
        pages: 1,
        max: 10,
        secrets_exposed: false,
      }),
    }),
  );

  await page.route('**/polaris-api/v1/ues', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        items: [
          {
            id: 'UE-01',
            internal_ue_id: 'UE-01',
            profile: 'POLARIS',
            profile_state: 'VERIFIED',
            subscription_status: 'VERIFIED',
            serving_node: 'GNB-01',
            technology: '5G SA',
            simulator: 'UERANSIM',
            process_state: 'running',
            registration_state: 'REGISTERED',
            pdu_session: 'ACTIVE',
            ue_ip: '10.46.0.5',
            traffic_state: 'IDLE',
            last_event: null,
            controller_owned: true,
            actions: { start: false, stop: true, pdu_start: false, pdu_stop: true },
          },
        ],
        configured_profiles: [],
        configured_count: 1,
        active_count: 1,
        registered_count: 1,
        source: 'TEST_OBSERVED_CONTRACT',
      }),
    }),
  );

  await page.route('**/polaris-api/v1/nodes', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        items: [{
          id: 'GNB-01', technology: '5G SA', simulator: 'UERANSIM',
          configured: true, controller_owned: false, process_state: 'running',
          n2_state: 'CONNECTED', n3_state: 'SOCKET_OBSERVED',
          actions: { start: false, stop: false, reason: 'SHARED_NODE_PROTECTED' },
        }],
        source: 'TEST_OBSERVED_CONTRACT',
      }),
    }),
  );
}

test.describe('UE Manager', () => {
  test.beforeEach(async ({ page }) => {
    await mockApi(page);
    await page.addInitScript(() => {
      localStorage.setItem(
        'polaris.featureFlags.v1',
        JSON.stringify({
          scenarioBackend: true,
          profileBackend: true,
          scenarioTemplates: true,
          polarisProvisioning: false,
        }),
      );
    });
  });

  test('table shows RAT, simulator and observed runtime fields at fixed width', async ({ page }) => {
    await page.goto('./ues');
    const table = page.getByTestId('ue-table');
    await expect(table).toBeVisible();
    await expect(table).toContainText('Technology');
    await expect(table).toContainText('Simulator');
    await expect(table).toContainText('Serving RAN');
    await expect(table).toContainText('Attach / Registration');
    await expect(table).toContainText('Session · IP');

    const row = page.getByTestId('ue-row-UE-01');
    await expect(row).toBeVisible();
    await expect(row).toContainText('UE-01');
    await expect(row).toContainText('5G SA');
    await expect(row).toContainText('UERANSIM');
    await expect(row).toContainText('REGISTERED');
    await expect(row).toContainText('10.46.0.5');

    await page.screenshot({
      path: 'docs/screenshots/ue-manager-grouped-runtime.png',
      fullPage: true,
    });
  });
});
