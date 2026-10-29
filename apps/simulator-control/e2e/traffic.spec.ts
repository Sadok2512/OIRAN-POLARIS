// Traffic Generator capture (simulator-control 0.9.0 + polaris-control-api
// 0.16.0 traffic_ul / traffic_dl + DL sender state).
//
// Mocked API — no identity in clear anywhere (target_ue_pseudonym is the
// literal "PROTECTED").

import { test, expect, type Page } from '@playwright/test';

async function mockApi(page: Page) {
  await page.route('**/polaris-api/v1/auth/me', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ role: 'OPERATOR', can_start: true }),
    }),
  );

  await page.route('**/polaris-api/v1/capabilities', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        approved_destinations: ['10.46.0.1'],
      }),
    }),
  );

  await page.route('**/polaris-api/v1/traffic/status', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        state: 'COMPLETED',
        packets_requested: 1024,
        packets_sent: 1024,
        packets_received: 1024,
        bytes: 1_048_576,
        accounting_source: 'PROTECTED',
        target_ue_id: 'UE-01',
        target_ue_pseudonym: 'PROTECTED',
        tun_interface: 'uesimtun0',
        last_result: null,
        approved_destinations: ['10.46.0.1'],
        traffic_ul: {
          measured_sender_bytes: 1_048_576,
          measured_ue_bytes: 1_048_576,
        },
        traffic_dl: {
          measured_sender_bytes: 1_048_576,
          measured_ue_bytes: 1_048_576,
        },
        dl_sender_state: 'HEALTHY',
        dl_sender_available: true,
      }),
    }),
  );
}

test.describe('traffic generator', () => {
  test.beforeEach(async ({ page }) => {
    await mockApi(page);
  });

  test('shows UL and DL direction cards with measured bytes and DL sender state', async ({ page }) => {
    await page.goto('/#/traffic');
    await expect(page.getByTestId('traffic-ul-card')).toBeVisible();
    await expect(page.getByTestId('traffic-dl-card')).toBeVisible();
    await expect(page.getByTestId('traffic-ul-sender')).toContainText('1');
    await expect(page.getByTestId('traffic-dl-sender')).toContainText('1');
    await expect(page.getByTestId('traffic-dl-state')).toContainText('HEALTHY');
    await expect(page.getByTestId('traffic-dl-available')).toContainText('yes');

    await page.screenshot({
      path: 'docs/screenshots/traffic-ul-dl.png',
      fullPage: true,
    });
  });
});
