// 0.9.4 — Playwright captures of the Add UE dialog after defect #29.
//
// Two frames:
//   1. The dialog freshly opened: UE ID prefilled, GNB-01 / 001-01 /
//      internet / SST=1 / SD=010203 preselected, slot picker populated
//      with a SUB-… item, Generate button visible. No required-field
//      error banner (29a).
//   2. The dialog mid-filling: operator picked an owner. All validations
//      green, Create button active.
//
// Mocked API — no live POLARIS. Identity renders PROTECTED throughout.

import { test, expect, type Page } from '@playwright/test';

const EXISTING_SLOT = 'SUB-aaaaaaaaaaaa';

async function mockApi(page: Page) {
  await page.route('**/polaris-api/v1/auth/me', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        authenticated: true,
        username: 'ops',
        role: 'Operator',
        can_start: true,
        can_manage_permissions: false,
      }),
    }),
  );
  await page.route('**/polaris-api/v1/capabilities', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        live_control: false,
        approval_state: 'NOT_REQUESTED',
        max_ues: 10,
        max_nodes: 2,
        registration_modes: [],
        traffic_protocols: [],
        approved_destinations: [],
        profiles: [],
        technologies: [],
        services: [],
      }),
    }),
  );
  await page.route('**/polaris-api/v1/scenarios/status', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ active_job: null, latest_terminal_job: null, active_count: 0, history_count: 0, source: 'MOCK', observed_at_epoch_s: 0 }),
    }),
  );
  await page.route('**/polaris-api/v1/ues', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        items: [],
        configured_profiles: [],
        configured_count: 0,
        active_count: 0,
        registered_count: 0,
        source: 'MOCK',
      }),
    }),
  );
  await page.route('**/polaris-api/v1/ue-profiles**', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        items: [],
        total: 0,
        page: 1,
        page_size: 50,
        pages: 0,
        max: 100,
        secrets_exposed: false,
      }),
    }),
  );
  await page.route('**/polaris-api/v1/gnbs', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        items: [
          { gnb_id: 'GNB-01', link_ip: '10.77.0.20' },
          { gnb_id: 'GNB-02', link_ip: '10.77.0.21' },
        ],
        total: 2,
        source: 'MOCK',
      }),
    }),
  );
  await page.route('**/polaris-api/v1/owners', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        items: [
          { id: 'ops-nancy', name: 'Nancy Operator', role: 'Operator', email: null },
        ],
        total: 1,
      }),
    }),
  );
  await page.route('**/polaris-api/v1/plmns', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ items: ['001-01', '208-93'] }),
    }),
  );
  await page.route('**/polaris-api/v1/dnns', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ items: ['internet', 'ims'] }),
    }),
  );
  await page.route('**/polaris-api/v1/subscribers', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        items: [
          { slot: EXISTING_SLOT, state: 'PROVISIONED' },
        ],
        total: 1,
      }),
    }),
  );
}

test.describe('Add UE dialog (0.9.4 defect #29)', () => {
  test.beforeEach(async ({ page }) => {
    await mockApi(page);
  });

  test('empty dialog preselects lab defaults and shows no required errors', async ({ page }) => {
    await page.goto('ues');
    await page.getByTestId('ue-add').click();

    const dialog = page.getByTestId('ue-provisioning-add-dialog');
    await expect(dialog).toBeVisible();

    // 29a — no required-field errors on open
    await expect(page.getByTestId('ue-add-ue-id-error')).toHaveCount(0);
    await expect(page.getByTestId('ue-add-slot-error')).toHaveCount(0);

    // 29b — GNB-01 / 001-01 / internet preselected
    await expect(page.getByTestId('ue-add-gnb')).toHaveValue('GNB-01');
    await expect(page.getByTestId('ue-add-plmn')).toHaveValue('001-01');
    await expect(page.getByTestId('ue-add-dnn')).toHaveValue('internet');

    // 29c — no IMSI input, slot picker + Generate present
    await expect(page.locator('[data-testid="ue-add-imsi"]')).toHaveCount(0);
    await expect(page.getByTestId('ue-add-slot')).toBeVisible();
    await expect(page.getByTestId('ue-add-generate')).toBeVisible();

    // 29e — SST=1 / SD=010203 preselected
    await expect(page.getByTestId('ue-add-sst')).toHaveValue('1');
    await expect(page.getByTestId('ue-add-sd')).toHaveValue('010203');

    // 29f — UE ID prefilled with the next-free id
    await expect(page.getByTestId('ue-add-ue-id')).toHaveValue('UE-01');

    await page.screenshot({
      path: 'docs/screenshots/ue-add-dialog-empty.png',
      fullPage: true,
    });
  });

  test('filled dialog is ready to Create with slot bound and no identity in clear', async ({ page }) => {
    await page.goto('ues');
    await page.getByTestId('ue-add').click();
    await page.getByTestId('ue-add-owner').selectOption('ops-nancy');
    // The slot is auto-selected from the mocked /subscribers list.
    await expect(page.getByTestId('ue-add-slot')).toHaveValue(EXISTING_SLOT);

    const dialog = page.getByTestId('ue-provisioning-add-dialog');
    const dialogText = await dialog.innerText();
    expect(dialogText).toContain('PROTECTED');
    // No raw identity material in the dialog's rendered text.
    expect(dialogText).not.toMatch(/\b\d{14,16}\b/);

    await page.screenshot({
      path: 'docs/screenshots/ue-add-dialog-filled.png',
      fullPage: true,
    });
  });
});
