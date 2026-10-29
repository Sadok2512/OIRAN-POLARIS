// Topology capture — UE cards under each gNB (simulator-control 0.9.0).
// Mocked API; identity marker stays PROTECTED.

import { test, expect, type Page } from '@playwright/test';

async function mockApi(page: Page) {
  await page.route('**/polaris-api/v1/auth/me', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ role: 'OPERATOR' }),
    }),
  );

  await page.route('**/polaris-api/v1/lab', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        observed: {
          open5gs: {
            amf: { process_state: 'running', health: 'healthy' },
          },
        },
      }),
    }),
  );

  await page.route('**/polaris-api/v1/nodes', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        items: [
          {
            id: 'GNB-01',
            technology: 'NR',
            simulator: 'POLARIS',
            configured: true,
            controller_owned: true,
            process_state: 'running',
            plmn: '001-01',
            cell_id: '000000010',
            link_ip: '10.0.0.1',
            n2_endpoint: '10.0.0.1:38412',
            n3_endpoint: '10.0.0.1:2152',
            actions: { reason: '' },
          },
        ],
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
            serving_node: 'GNB-01',
            process_state: 'running',
            registration_state: 'REGISTERED',
            pdu_session: 'ACTIVE',
            ue_ip: '10.46.0.5',
            traffic_state: 'IDLE',
            last_event: null,
            controller_owned: true,
            subscriber_identity: 'PROTECTED',
          },
          {
            id: 'UE-02',
            serving_node: 'GNB-01',
            process_state: 'stopped',
            registration_state: 'NOT_OBSERVED',
            pdu_session: 'INACTIVE',
            ue_ip: null,
            traffic_state: 'IDLE',
            last_event: null,
            controller_owned: true,
            subscriber_identity: 'PROTECTED',
          },
        ],
        configured_profiles: [],
        configured_count: 2,
        active_count: 1,
        registered_count: 1,
        source: 'MOCK',
      }),
    }),
  );
}

test.describe('topology', () => {
  test.beforeEach(async ({ page }) => {
    await mockApi(page);
  });

  test('each gNB card shows UE cards with PROTECTED identity marker', async ({ page }) => {
    await page.goto('./network/topology');
    const node = page.getByTestId('topology-node-GNB-01');
    await expect(node).toBeVisible();
    await expect(page.getByTestId('topology-ues-GNB-01')).toBeVisible();
    const ueCard = page.getByTestId('topology-ue-UE-01');
    await expect(ueCard).toBeVisible();
    await expect(ueCard).toContainText('REGISTERED');
    await expect(ueCard).toContainText('ACTIVE');
    await expect(ueCard).toContainText('PROTECTED');

    await page.screenshot({
      path: 'docs/screenshots/topology-ue-cards.png',
      fullPage: true,
    });
  });
});
