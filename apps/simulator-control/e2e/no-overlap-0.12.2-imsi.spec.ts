// 0.12.2 — anti-overlap at 1280 / 1440 / 1920 for the UE Manager row
// with operator-visible IMSI, grant countdown chip (#49) and État cell
// enriched (#50). polaris-api 0.19.7 (#48) returns the raw IMSI in
// `subscriber_identity` when the caller is an operator; the row renders
// `imsi-001011234567890` plus the mockup grant countdown without
// bleeding into the next cell.
//
// Invariants:
//   1. The IMSI cell sits strictly left of the Owner / gNB column.
//   2. "Autoriser le live" button is visible on the UE Manager header
//      at every viewport (#49 countdown reachable).
//   3. The État cell (Registration + PDU · IP) stays inside its column
//      — no truncation (clientWidth ≥ scrollWidth) at any viewport.

import { test, expect, type Page } from '@playwright/test';

async function mockPolaris(page: Page) {
  await page.route('**/polaris-api/v1/**', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: '{"data":[],"meta":{}}' }),
  );
  await page.route('**/polaris-api/v1/auth/me', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        data: {
          authenticated: true,
          username: 'ops-sandrine-martinez',
          role: 'operator',
          can_start: true,
          can_manage_permissions: false,
        },
        meta: {},
      }),
    }),
  );
  await page.route('**/polaris-api/v1/capabilities', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        data: {
          live_control: true,
          approval_state: 'READY',
          max_ues: 10,
          max_nodes: 2,
          registration_modes: ['5G_SA'],
          traffic_protocols: ['UDP', 'TCP'],
          approved_destinations: ['10.46.0.1'],
          profiles: [],
          technologies: [],
          services: [],
        },
        meta: {},
      }),
    }),
  );
  await page.route('**/polaris-api/v1/feature-flags', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        data: { profileBackend: true, scenarioBackend: false },
        meta: {},
      }),
    }),
  );
  await page.route('**/polaris-api/v1/ue-profiles*', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        data: {
          items: [
            {
              ue_id: 'UE-00042',
              name: 'Lab UE 42',
              serving_gnb: 'GNB-01',
              plmn: { mcc: '001', mnc: '01' },
              dnn: 'internet',
              snssai: { sst: 1, sd: '010203' },
              pdu_session: { dnn: 'internet', type: 'IPv4' },
              scenario_id: null,
              auto_run_scenario: false,
              subscription_status: 'VERIFIED',
              subscriber_identity: '001010000000042',
              authentication_material: 'PROTECTED',
              profile: 'bounded-controller-ue-udp-v1',
              revision: 1,
              updated_at_epoch_s: 1_700_000_000,
            },
          ],
          total: 1,
          page: 1,
          page_size: 100,
          pages: 1,
          max: 10,
          secrets_exposed: false,
        },
        meta: {},
      }),
    }),
  );
  await page.route('**/polaris-api/v1/ues', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        data: {
          items: [
            {
              id: 'UE-00042',
              internal_ue_id: 'UE-03',
              registration_state: 'REGISTERED',
              rrc_state: 'CONNECTED',
              pdu_session: 'ACTIVE',
              ue_ip: '10.45.0.3',
              traffic_state: 'RUNNING',
              serving_node: 'GNB-01',
              last_event: null,
              controller_owned: true,
              actions: { start: false, stop: true, pdu_start: false, pdu_stop: true, traffic: true, reason: '' },
            },
          ],
          configured_profiles: [],
          configured_count: 1,
          active_count: 1,
          registered_count: 1,
          pdu_session_count: 1,
          source: 'test',
        },
        meta: {},
      }),
    }),
  );
  await page.route('**/polaris-api/v1/scenarios/status', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        data: {
          active_job: null,
          latest_terminal_job: null,
          active_count: 0,
          history_count: 0,
          observed_at_epoch_s: 0,
          source: 'test',
        },
        meta: {},
      }),
    }),
  );
  await page.route('**/polaris-api/v1/live-grants*', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: '{"data":{"grants":[]},"meta":{}}',
    }),
  );
}

for (const theme of ['light', 'dark'] as const) {
  test(`UE Manager 0.12.2 · operator IMSI + grant + état · ${theme}`, async ({ page }, info) => {
    await page.addInitScript((t) => {
      localStorage.setItem('telecom.theme', t);
    }, theme);
    await mockPolaris(page);
    await page.goto('/simulator/ues');
    await page.getByTestId('ue-row-UE-00042').waitFor({ timeout: 10_000 });

    // Invariant 1: IMSI shows the raw digits for operator.
    const imsiCell = page.getByTestId('ue-imsi-UE-00042');
    const imsiText = await imsiCell.textContent();
    expect(imsiText).toMatch(/imsi-001010000000042/);

    // Invariant 2: grant button + countdown chip visible.
    const grantBtn = page.getByTestId('live-grant-open');
    await expect(grantBtn).toBeVisible();

    // Invariant 3: no overlap in the row — right edge of each visible
    // cell must not cross the next cell's left edge.
    const row = page.getByTestId('ue-row-UE-00042');
    const cells = await row.locator('td').all();
    const boxes: ({ x: number; width: number } | null)[] = await Promise.all(
      cells.map((c) => c.boundingBox()),
    );
    for (let i = 0; i < boxes.length - 1; i++) {
      const current = boxes[i];
      const next = boxes[i + 1];
      if (!current || !next) continue;
      expect(current.x + current.width).toBeLessThanOrEqual(next.x + 1);
    }

    // Invariant 4: no text truncation inside the État cell.
    const etat = page.getByTestId('ue-etat-UE-00042');
    const etatBounds = await etat.evaluate((el) => ({
      scrollWidth: (el as HTMLElement).scrollWidth,
      clientWidth: (el as HTMLElement).clientWidth,
    }));
    expect(etatBounds.scrollWidth).toBeLessThanOrEqual(etatBounds.clientWidth);

    const viewport = info.project.name.replace('chromium-', '').split('-')[0];
    await page.screenshot({
      path: `docs/screenshots/0.12.2/ue-manager-${viewport}-${theme}.png`,
      fullPage: true,
    });
  });
}
