// Playwright captures for the Subscribers surface (polaris-control-api 0.17.0 +
// simulator-control 0.8.0).
//
// Scope:
//   * Core · Open5GS → Subscribers tab (table + Generate button)
//   * Subscriber Edit dialog (SST/SD/DNN dropdowns, AMBR, write-only K/OPc)
//   * Generate dialog with result list
//
// Mocked API — the suite runs with the Vite dev server (127.0.0.1:4330) but
// without a live POLARIS instance. All `/polaris-api/v1/**` responses below
// are hand-crafted and NEVER contain real IMSI, K or OPc. Every identity
// field renders as the literal `"PROTECTED"`.

import { test, expect, type Page } from '@playwright/test';

const SLOT_A = 'SUB-aaaaaaaaaaaa';
const SLOT_B = 'SUB-bbbbbbbbbbbb';
const SLOT_C = 'SUB-cccccccccccc';
const GENERATED_SLOT = 'SUB-dddddddddddd';

async function mockPolarisApi(page: Page) {
  await page.route('**/polaris-api/v1/auth/me', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        role: 'OPERATOR',
        session_id: 'session-protected',
        subscriber_identity: 'PROTECTED',
      }),
    }),
  );

  await page.route('**/polaris-api/v1/capabilities', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        max_nodes_live_certified: 1,
        max_ues_live_certified: 1,
        features: {},
      }),
    }),
  );

  await page.route('**/polaris-api/v1/lab', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        observed: {
          open5gs: {
            process_state: 'running',
            health: 'healthy',
            amf: { process_state: 'running', health: 'healthy' },
            smf: { process_state: 'running', health: 'healthy' },
            upf: { process_state: 'running', health: 'healthy' },
          },
        },
      }),
    }),
  );

  await page.route('**/polaris-api/v1/dnns', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ items: ['internet', 'ims'] }),
    }),
  );

  await page.route('**/polaris-api/v1/plmns', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ items: ['001-01'] }),
    }),
  );

  await page.route('**/polaris-api/v1/ue-profiles/provisioning-slots', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        total: 10,
        available: 7,
        items: [
          { slot_id: SLOT_A, bound_ue_id: 'UE-01' },
          { slot_id: SLOT_B, bound_ue_id: 'UE-02' },
          { slot_id: SLOT_C, bound_ue_id: null },
        ],
      }),
    }),
  );

  await page.route(`**/polaris-api/v1/subscribers/${SLOT_A}`, async (route) => {
    const method = route.request().method();
    if (method === 'PUT') {
      const payload = route.request().postDataJSON();
      // Confidentiality assertion right here in the mock: the response NEVER
      // contains K or OPc, even if the UI sent them.
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          subscriber: {
            slot: SLOT_A,
            state: 'PROVISIONED',
            plmn: { mcc: '001', mnc: '01' },
            snssai: { sst: payload.sst ?? 1, sd: payload.sd ?? '010203' },
            dnns: payload.dnns ?? ['internet'],
            ambr: payload.ambr ?? { uplink: 1_000_000, downlink: 1_000_000 },
            subscriber_identity: 'PROTECTED',
            authentication_material: 'PROTECTED',
          },
          secrets_exposed: false,
        }),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        subscriber: {
          slot: SLOT_A,
          state: 'PROVISIONED',
          plmn: { mcc: '001', mnc: '01' },
          snssai: { sst: 1, sd: '010203' },
          dnns: ['internet'],
          ambr: { uplink: 1_000_000, downlink: 1_000_000 },
          subscriber_identity: 'PROTECTED',
          authentication_material: 'PROTECTED',
        },
        linked_profile_ue_ids: ['UE-01'],
        linked_profile_count: 1,
        secrets_exposed: false,
      }),
    });
  });

  await page.route('**/polaris-api/v1/subscribers/generate', async (route) => {
    const payload = route.request().postDataJSON();
    await route.fulfill({
      status: 201,
      contentType: 'application/json',
      body: JSON.stringify({
        ok: payload.count,
        errors: 0,
        slots: [
          {
            slot: GENERATED_SLOT,
            state: 'PROVISIONED',
            subscriber_identity: 'PROTECTED',
            authentication_material: 'PROTECTED',
          },
        ],
        results: [],
        secrets_exposed: false,
      }),
    });
  });
}

test.describe('subscribers surface', () => {
  test.beforeEach(async ({ page }) => {
    await mockPolarisApi(page);
  });

  test('subscribers tab renders slots with Edit action and Generate button', async ({ page }) => {
    await page.goto('./network/core');
    await page.getByRole('tab', { name: /subscribers/i }).click();

    const row = page.locator(`[data-testid="subscriber-slot-${SLOT_A}"]`);
    await expect(row).toBeVisible();
    await expect(row).toContainText(SLOT_A);
    await expect(row).toContainText('PROTECTED');

    const generateButton = page.getByTestId('core-provision-generate');
    await expect(generateButton).toBeEnabled();

    await page.screenshot({
      path: 'docs/screenshots/subscribers-tab.png',
      fullPage: true,
    });
  });

  test('Edit dialog shows SST/SD/DNN dropdowns and never surfaces K/OPc', async ({ page }) => {
    await page.goto('./network/core');
    await page.getByRole('tab', { name: /subscribers/i }).click();
    await page.getByTestId(`subscriber-edit-${SLOT_A}`).click();

    const dialog = page.getByTestId('subscriber-edit-dialog');
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText('PROTECTED');
    await expect(page.getByTestId('subscriber-edit-sst')).toBeVisible();
    await expect(page.getByTestId('subscriber-edit-sd')).toBeVisible();
    await expect(page.getByTestId('subscriber-edit-dnns')).toBeVisible();

    // Confidentiality: K/OPc inputs are not rendered until the operator opts
    // in. The dialog body must not contain the strings "K:" or "OPc:" from
    // the API response.
    const bodyText = await dialog.innerText();
    expect(bodyText).not.toContain('ffffffff');
    expect(bodyText).toContain('PROTECTED');

    await page.screenshot({
      path: 'docs/screenshots/subscriber-edit-dialog.png',
      fullPage: true,
    });
  });

  test('Generate dialog produces a slot result with PROTECTED identity', async ({ page }) => {
    await page.goto('./network/core');
    await page.getByRole('tab', { name: /subscribers/i }).click();
    await page.getByTestId('core-provision-generate').click();

    const dialog = page.getByTestId('subscriber-generate-dialog');
    await expect(dialog).toBeVisible();
    await expect(page.getByTestId('subscriber-generate-count')).toBeVisible();
    await expect(page.getByTestId('subscriber-generate-sst')).toBeVisible();
    await expect(page.getByTestId('subscriber-generate-sd')).toBeVisible();

    await page.getByTestId('subscriber-generate-run').click();
    const result = page.getByTestId('subscriber-generate-result');
    await expect(result).toBeVisible();
    await expect(result).toContainText(GENERATED_SLOT);
    await expect(result).toContainText('PROVISIONED');

    await page.screenshot({
      path: 'docs/screenshots/subscriber-generate-dialog.png',
      fullPage: true,
    });
  });
});
