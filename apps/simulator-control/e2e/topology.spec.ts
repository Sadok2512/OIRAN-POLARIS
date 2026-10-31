// Offline contract test. Route stubs represent observed API evidence and are
// never bundled into the operational application.

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
            technology: '5G SA',
            simulator: 'UERANSIM',
            configured: true,
            controller_owned: true,
            process_state: 'running',
            plmn: '001-01',
            cell_id: '000000010',
            link_ip: '10.0.0.1',
            n2_endpoint: '10.0.0.1:38412',
            n3_endpoint: '10.0.0.1:2152',
            n2_state: 'CONNECTED',
            n3_state: 'SOCKET_OBSERVED',
            actions: { reason: '' },
          },
          {
            id: 'ENB-01',
            technology: 'LTE 4G',
            simulator: 'srsRAN',
            configured: true,
            controller_owned: true,
            process_state: 'running',
            plmn: 'NOT_AVAILABLE',
            cell_id: 'NOT_OBSERVED',
            link_ip: 'NOT_OBSERVED',
            n2_endpoint: null,
            n3_endpoint: null,
            s1_state: 'CONNECTED',
            s1u_state: 'SESSION_OBSERVED',
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
          {
            id: 'LTE-SRSUE-TEST-01',
            serving_node: 'ENB-01',
            technology: 'LTE 4G',
            simulator: 'srsRAN',
            process_state: 'running',
            registration_state: 'ATTACHED',
            pdu_session: 'ACTIVE',
            ue_ip: '10.45.0.2',
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
        source: 'TEST_OBSERVED_CONTRACT',
      }),
    }),
  );

  await page.route('**/polaris-api/v1/plmns', (route) =>
    route.fulfill(jsonResponse({ items: ['001-01'], source: 'TEST_OBSERVED_CONTRACT' })),
  );
}

function jsonResponse(body: unknown) {
  return { status: 200, contentType: 'application/json', body: JSON.stringify(body) };
}

test.describe('topology', () => {
  test.beforeEach(async ({ page }) => {
    await mockApi(page);
  });

  test('shows observed 5G and LTE chains including UERANSIM, srsENB and srsUE', async ({ page }) => {
    await page.goto('./network/topology');
    const node = page.getByTestId('topology-node-GNB-01');
    await expect(node).toBeVisible();
    await expect(page.getByTestId('topology-ues-GNB-01')).toBeVisible();
    const ueCard = page.getByTestId('topology-ue-UE-01');
    await expect(ueCard).toBeVisible();
    await expect(ueCard).toContainText('REGISTERED');
    await expect(ueCard).toHaveAttribute('data-pdu', 'ACTIVE');
    const enb = page.getByTestId('topology-node-ENB-01');
    await expect(enb).toContainText('srsENB');
    const srsUe = page.getByTestId('topology-ue-LTE-SRSUE-TEST-01');
    await expect(srsUe).toContainText('srsUE');
    await expect(page.getByTestId('topology-chain-5g')).toBeVisible();
    await expect(page.getByTestId('topology-chain-lte')).toBeVisible();

    await page.screenshot({
      path: 'docs/screenshots/topology-ue-cards.png',
      fullPage: true,
    });
  });
});
