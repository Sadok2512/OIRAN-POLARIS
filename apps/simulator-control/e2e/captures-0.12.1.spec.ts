// 0.12.1 — Side-by-side captures: mockup vs implementation for UE Manager
// at 1440 light + dark. The mockup HTML is served statically from
// `public/polaris-mockup.html` (extracted from origin/docs/ui-mockups @
// 48dea75) so Playwright can navigate both sides without a network round
// trip.
//
// Output:
//   docs/screenshots/0.12.1/ue-manager/
//     mockup.light.png     (full mockup, UE Manager tab)
//     impl.light.png       (live /ues implementation)
//     mockup.dark.png
//     impl.dark.png
//     side-by-side.light.png (composite = mockup + impl, same height)
//     side-by-side.dark.png
//
// The capture spec is NOT part of the no-overlap matrix; it runs only
// when invoked explicitly (`npx playwright test -g 'capture 0.12.1'`).

import { test, expect } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

const OUT_DIR = join('docs', 'screenshots', '0.12.1', 'ue-manager');
mkdirSync(OUT_DIR, { recursive: true });

async function mockPolaris(page: import('@playwright/test').Page) {
  await page.route('**/polaris-api/v1/auth/me', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        data: {
          authenticated: true,
          username: 'operator',
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
  await page.route('**/polaris-api/v1/scenario-capabilities', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        data: { items: [], execution_status: 'READY_TO_START', reason: 'OK', role: 'operator' },
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
          source: 'mock',
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
              id: 'UE-01',
              internal_ue_id: 'UE-01',
              registration_state: 'REGISTERED',
              rrc_state: 'CONNECTED',
              pdu_session: 'ACTIVE',
              ue_ip: '10.45.0.2',
              traffic_state: 'IDLE',
              serving_node: 'GNB-01',
              last_event: null,
              controller_owned: false,
              actions: { start: false, stop: true, pdu_start: false, pdu_stop: true, traffic: false, reason: '' },
            },
            {
              id: 'UE-12',
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
            {
              id: 'UE-13',
              registration_state: 'STOPPED',
              pdu_session: 'INACTIVE',
              ue_ip: null,
              traffic_state: 'IDLE',
              serving_node: null,
              last_event: null,
              controller_owned: true,
              actions: { start: true, stop: false, pdu_start: false, pdu_stop: false, traffic: false, reason: 'PROVISIONING_REQUIRED' },
            },
            {
              id: 'UE-14',
              registration_state: 'STOPPED',
              pdu_session: 'INACTIVE',
              ue_ip: null,
              traffic_state: 'IDLE',
              serving_node: 'GNB-02',
              last_event: null,
              controller_owned: true,
              actions: { start: false, stop: false, pdu_start: false, pdu_stop: false, traffic: false, reason: 'LIVE_005_APPROVAL_REQUIRED' },
            },
          ],
          configured_profiles: [],
          configured_count: 4,
          active_count: 2,
          registered_count: 2,
          pdu_session_count: 2,
          source: 'mock',
        },
        meta: {},
      }),
    }),
  );
  await page.route('**/polaris-api/v1/nodes', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        data: {
          items: [],
          configured_count: 1,
          running_count: 1,
          observed_at_epoch_s: 0,
          source: 'mock',
        },
        meta: {},
      }),
    }),
  );
  await page.route('**/polaris-api/v1/lab', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        data: {
          ue_count: 4,
          desired_ue_count: 4,
          gnb_count: 1,
          max_ues: 10,
          max_gnbs: 2,
          max_ues_live_certified: 10,
          max_gnbs_live_certified: 1,
          missing_subscriber_profiles: 0,
          updated_at_epoch_s: 0,
          updated_by: 'mock',
          observed_controller_running: 2,
          observed_total_running: 2,
          reconciliation: {
            operation_id: null,
            desired_count: 4,
            state: 'IDLE',
            started_at_epoch_s: null,
            completed_at_epoch_s: null,
            started: [],
            stopped: [],
            failures: [],
          },
          execution_started: false,
          observed: {
            open5gs: { process_state: 'running', health: 'healthy', observed: true },
          },
        },
        meta: {},
      }),
    }),
  );
  await page.route('**/polaris-api/v1/live-grants*', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ data: { grants: [] }, meta: {} }),
    }),
  );
  await page.route('**/polaris-api/v1/**', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: '{"data":{},"meta":{}}' }),
  );
}

for (const theme of ['light', 'dark'] as const) {
  test(`capture 0.12.1 ue-manager · mockup+impl · ${theme}`, async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });

    // 1 — Mockup side. Navigate to the hash #ues to open the UE Manager tab.
    await page.goto(`/simulator/polaris-mockup.html#ues`);
    if (theme === 'dark') {
      await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'dark'));
    } else {
      await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'light'));
    }
    // Wait for the mockup's React tree to render.
    await page.getByRole('heading', { name: 'UE Manager' }).waitFor({ timeout: 10_000 });
    const mockupPath = join(OUT_DIR, `mockup.${theme}.png`);
    await page.screenshot({ path: mockupPath, fullPage: true });

    // 2 — Implementation side. Clear theme + reseed via localStorage so the
    // app's own theme switch lands on the matching value.
    await page.goto('/simulator/');
    await page.evaluate((t) => localStorage.setItem('telecom.theme', t), theme);
    await page.goto('/simulator/ues');
    await page.getByRole('heading', { name: 'UE Manager' }).waitFor({ timeout: 10_000 });
    const implPath = join(OUT_DIR, `impl.${theme}.png`);
    await page.screenshot({ path: implPath, fullPage: true });

    // 3 — Composite side-by-side. Both images are loaded as base64 so
    // the composite PNG is self-contained and viewable without the raw
    // files alongside it.
    const [mockupData, implData] = await Promise.all([
      readFile(mockupPath).then((buf) => buf.toString('base64')),
      readFile(implPath).then((buf) => buf.toString('base64')),
    ]);
    await page.setContent(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  body { margin: 0; padding: 24px; background: ${theme === 'dark' ? '#0B1220' : '#F5F7FA'}; font-family: Inter, Arial, sans-serif; color: ${theme === 'dark' ? '#E7F0FF' : '#17283F'}; }
  .row { display: flex; gap: 16px; align-items: flex-start; }
  .col { flex: 1; min-width: 0; }
  h2 { margin: 0 0 8px; font-size: 14px; letter-spacing: 1px; text-transform: uppercase; color: ${theme === 'dark' ? '#9AAAC0' : '#5B6A80'}; }
  img { width: 100%; display: block; border: 1px solid ${theme === 'dark' ? '#2A3A54' : '#DEE5ED'}; border-radius: 8px; }
</style></head><body>
  <div class="row">
    <div class="col"><h2>Mockup</h2><img src="data:image/png;base64,${mockupData}"></div>
    <div class="col"><h2>Implementation (0.12.1)</h2><img src="data:image/png;base64,${implData}"></div>
  </div>
</body></html>`);
    await page.setViewportSize({ width: 2920, height: 1600 });
    const compositePath = join(OUT_DIR, `side-by-side.${theme}.png`);
    await page.screenshot({ path: compositePath, fullPage: true });

    expect(mockupPath).toContain('mockup');
    expect(implPath).toContain('impl');
    expect(compositePath).toContain('side-by-side');
  });
}
