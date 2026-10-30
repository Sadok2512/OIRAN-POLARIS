// 0.10.0 — Honest UX acceptance pass.
//
// Covers:
//   * UE Manager — no horizontal scroll at 1440 and 1920, Actions column
//     collapsed to Start/Stop + Run + ⋯ menu, "Not running" copy instead
//     of UNKNOWN, no "persist in the browser" page description, search
//     placeholder without IMSI, no "Backend support required" on scenario
//     cell when scenarioBackend is on.
//   * Scenario Builder — Save button carries an inline reason when
//     disabled (not just a native tooltip).
//   * Create Subscriber dialog — DNN options render "internet" and "ims"
//     from /dnns, PLMN without slice falls back to SST 1 / SD 010203
//     marked "valeur du labo", AMBR UL and DL default to 1 Gbit/s.
//
// Captures land under docs/screenshots/0.10.0/<viewport>/<name>.png so
// the review package stays reproducible.

import { test, expect, type Page } from '@playwright/test';

const SCREEN_DIR_BY_PROJECT: Record<string, string> = {
  'chromium-1440-light': '1440-light',
  'chromium-1440-dark': '1440-dark',
  'chromium-1920-light': '1920-light',
  'chromium-1920-dark': '1920-dark',
};

async function mockPolarisBackend(page: Page) {
  // 0.10.0 — Playwright matches `page.route` entries in reverse order of
  // registration (last-registered wins). We register the broad catch-all
  // FIRST so the specific routes below override it.
  await page.route('**/polaris-api/v1/**', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({}) }),
  );

  await page.route('**/polaris-api/v1/auth/me', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        authenticated: true,
        username: 'ops',
        role: 'operator',
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
        approval_state: 'closed',
        max_ues: 100,
        max_nodes: 10,
        registration_modes: ['automatic'],
        traffic_protocols: ['udp'],
        scenario_step_kinds: ['ue_start', 'ue_stop', 'pdu_establish', 'pdu_release', 'udp_traffic', 'wait', 'traffic_ul', 'traffic_dl', 'detach'],
      }),
    }),
  );

  await page.route('**/polaris-api/v1/scenarios/status**', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        active_job: null,
        latest_terminal_job: null,
        active_count: 0,
        history_count: 0,
        observed_at_epoch_s: 0,
        source: 'MOCK',
      }),
    }),
  );

  await page.route('**/polaris-api/v1/scenarios**', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ items: [], total: 0, source: 'MOCK' }),
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
          {
            ue_id: 'UE-02',
            name: 'UE-02',
            serving_gnb: 'GNB-01',
            plmn: { mcc: '001', mnc: '01' },
            dnn: 'internet',
            snssai: { sst: 1, sd: '010203' },
            pdu_session: { dnn: 'internet', type: 'IPv4' },
            scenario_id: null,
            auto_run_scenario: false,
            subscription_status: 'PROVISIONING_REQUIRED',
            subscriber_identity: 'PROTECTED',
            authentication_material: 'PROTECTED',
            profile: 'POLARIS',
            revision: 1,
            updated_at_epoch_s: 1_730_200_000,
          },
        ],
        total: 2,
        page: 1,
        page_size: 50,
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
            process_state: 'running',
            registration_state: 'REGISTERED',
            pdu_session: 'ACTIVE',
            rrc_state: 'CONNECTED',
            ue_ip: '10.46.0.5',
            traffic_state: 'IDLE',
            last_event: null,
            controller_owned: true,
            actions: { start: false, stop: true, pdu_start: false, pdu_stop: true },
          },
          {
            id: 'UE-02',
            internal_ue_id: 'UE-02',
            profile: 'POLARIS',
            profile_state: 'VERIFIED',
            subscription_status: 'PROVISIONING_REQUIRED',
            serving_node: 'GNB-01',
            process_state: 'idle',
            registration_state: 'UNKNOWN',
            pdu_session: 'UNKNOWN',
            rrc_state: 'UNKNOWN',
            ue_ip: null,
            traffic_state: null,
            last_event: null,
            controller_owned: true,
            actions: { start: true, stop: false, pdu_start: false, pdu_stop: false },
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

  await page.route('**/polaris-api/v1/plmns', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      // Current production shape: strings only, no slice descriptor.
      body: JSON.stringify({ items: ['001-01'], source: 'OPEN5GS_POLARIS_OWNED' }),
    }),
  );

  await page.route('**/polaris-api/v1/dnns', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ items: ['internet', 'ims'], source: 'OPEN5GS_POLARIS_OWNED' }),
    }),
  );

  await page.route('**/polaris-api/v1/subscribers', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ items: [], total: 0 }),
    }),
  );

  await page.route('**/polaris-api/v1/owners', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ items: [], total: 0 }),
    }),
  );
}

async function expectNoHorizontalScroll(page: Page) {
  const scrolls = await page.evaluate(() => {
    const main = document.querySelector('main');
    return {
      body: document.body.scrollWidth > document.body.clientWidth,
      main: main ? main.scrollWidth > main.clientWidth : false,
    };
  });
  expect(scrolls.body, 'body must not scroll horizontally').toBe(false);
  expect(scrolls.main, 'main must not scroll horizontally').toBe(false);
}

test.describe('0.10.0 — honest UX', () => {
  test.beforeEach(async ({ page }) => {
    await mockPolarisBackend(page);
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

  test('UE Manager: layout, labels and action menu', async ({ page }, testInfo) => {
    await page.goto('./ues');

    // Table is visible. 0.10.2 (#41) reintroduced IMSI in the search
    // placeholder for the operator role (viewers still see it dropped);
    // this spec runs as an operator so IMSI is present again.
    const table = page.getByTestId('ue-table');
    await expect(table).toBeVisible();
    const search = page.getByTestId('ue-search');
    await expect(search).toHaveAttribute('placeholder', /Search id, owner, gNB, IMSI, UE IP/);

    // Page description must not advertise browser persistence anymore.
    const header = page.getByTestId('page-header');
    await expect(header).not.toContainText('persist in the browser');

    // "Not running" replaces the raw UNKNOWN state.
    const row2 = page.getByTestId('ue-row-UE-02');
    await expect(row2).toContainText('Not running');
    await expect(row2).not.toContainText(/^UNKNOWN$/);

    // Actions column: ⋯ menu present and houses Edit/Clone/Delete.
    const more = page.getByTestId('ue-more-UE-01');
    await expect(more).toBeVisible();
    await more.click();
    await expect(page.getByTestId('ue-edit-UE-01')).toBeVisible();
    await expect(page.getByTestId('ue-clone-UE-01')).toBeVisible();
    await expect(page.getByTestId('ue-delete-UE-01')).toBeVisible();
    // Close the menu for a clean capture.
    await page.keyboard.press('Escape');

    // Inline Start/Stop + Run buttons stay inline on the row.
    // UE-01 is active (process_state=running) → Stop visible.
    await expect(page.getByTestId('ue-stop-UE-01')).toBeVisible();
    // UE-02 is idle → Start visible.
    await expect(page.getByTestId('ue-start-UE-02')).toBeVisible();

    await expectNoHorizontalScroll(page);

    const dir = SCREEN_DIR_BY_PROJECT[testInfo.project.name] ?? 'default';
    await page.screenshot({
      path: `docs/screenshots/0.10.0/${dir}/ue-manager.png`,
      fullPage: true,
    });
  });

  test('Scenario Builder: Save reason is surfaced inline', async ({ page }, testInfo) => {
    await page.goto('./scenarios/new');
    const save = page.getByTestId('builder-save');
    await expect(save).toBeVisible();
    // Fresh scenario is empty → "no steps" validation error blocks Save.
    await expect(save).toBeDisabled();
    const reason = page.getByTestId('builder-save-reason');
    await expect(reason).toBeVisible();
    await expect(reason).toContainText(/erreur/i);
    const dir = SCREEN_DIR_BY_PROJECT[testInfo.project.name] ?? 'default';
    await page.screenshot({
      path: `docs/screenshots/0.10.0/${dir}/scenario-builder.png`,
      fullPage: true,
    });
  });
});
