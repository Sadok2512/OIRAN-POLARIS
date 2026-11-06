// 0.13.2 (#9, ANR1 handoff) — Anti-overlap acceptance for the four
// primary operator surfaces (Run, Activity, Traffic Generator, UE
// Manager) at every supported viewport (1280 / 1440 / 1920) × two
// colour schemes.
//
// Contract: polaris-api 0.29.16 (routes GET verified HTTP 200 by ANR1).
// Backend is MOCKED through `page.route('**/polaris-api/v1/**', …)`
// so the suite runs without a live POLARIS instance. Screenshots land
// under `docs/screenshots/0.13.2/<view>-<theme>-<WxH>.png` and are the
// durable evidence operators replay from the report.
//
// Pass gate: for each view/viewport/theme, assert
//   * `document.documentElement.scrollWidth <= clientWidth` (no
//     horizontal overflow at the chosen width);
//   * no visible control extends past the viewport's right edge
//     (the invariant the 0.10.4 + 0.11.0 + 0.12.2 specs already
//     enforced on their respective pages).

import { test, expect, type Page } from '@playwright/test';
import * as path from 'node:path';
import * as fs from 'node:fs/promises';

const SCREENSHOTS_ROOT = path.resolve(
  path.dirname(new URL(import.meta.url).pathname),
  '..',
  'docs',
  'screenshots',
  '0.13.2',
);

const nowEpoch = Math.floor(Date.UTC(2026, 10, 6) / 1000);

async function mockPolarisBackend(page: Page) {
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
        meta: { api_version: '0.29.16' },
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
          max_ues: 32,
          max_nodes: 8,
          registration_modes: ['5G_SA'],
          traffic_protocols: ['UDP', 'TCP'],
          approved_destinations: ['10.46.0.1'],
          profiles: ['bounded-controller-ue-udp-v1'],
          technologies: ['5G_SA'],
          services: ['imsagent', 'open5gs-smf'],
        },
        meta: { api_version: '0.29.16' },
      }),
    }),
  );
  await page.route('**/polaris-api/v1/feature-flags', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ data: { profileBackend: true, scenarioBackend: true }, meta: {} }),
    }),
  );
  await page.route('**/polaris-api/v1/plmns', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ data: { items: [{ mcc: '001', mnc: '01' }] }, meta: {} }),
    }),
  );
  await page.route('**/polaris-api/v1/dnns', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ data: { items: ['internet', 'ims'] }, meta: {} }),
    }),
  );
  await page.route('**/polaris-api/v1/owners', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ data: { items: ['alice', 'bob'] }, meta: {} }),
    }),
  );
  await page.route('**/polaris-api/v1/ue-profiles**', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        data: {
          items: Array.from({ length: 6 }, (_, index) => ({
            ue_id: `UE-${(index + 1).toString().padStart(2, '0')}`,
            name: `Lab UE ${index + 1}`,
            serving_gnb: `GNB-${(index % 2) + 1}`,
            plmn: { mcc: '001', mnc: '01' },
            dnn: 'internet',
            snssai: { sst: 1, sd: '010203' },
            pdu_session: { dnn: 'internet', type: 'IPv4' },
            scenario_id: null,
            auto_run_scenario: false,
            subscription_status: 'VERIFIED',
            // operator role → raw IMSI (0.29.16 role-aware field).
            subscriber_identity: `00101000000${(index + 1).toString().padStart(4, '0')}`,
            authentication_material: 'PROTECTED',
            profile: 'bounded-controller-ue-udp-v1',
            revision: 1,
            updated_at_epoch_s: nowEpoch - index,
          })),
          max: 10_000,
          page: 1,
          page_size: 50,
          pages: 1,
          secrets_exposed: false,
          total: 6,
        },
        meta: { api_version: '0.29.16' },
      }),
    }),
  );
  await page.route('**/polaris-api/v1/scenario-definitions**', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        data: {
          items: [
            {
              id: 'bounded-controller-ue-udp-v1',
              name: 'Bounded controller · UE UDP',
              version: '1.0',
              owner: 'alice',
            },
          ],
        },
        meta: {},
      }),
    }),
  );
  await page.route('**/polaris-api/v1/scenarios/*/steps', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ data: { steps: [] }, meta: {} }),
    }),
  );
  await page.route('**/polaris-api/v1/ues**', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith('/activity')) {
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            ue_id: 'UE-01',
            running: true,
            imsi: 'imsi-001010000000001',
            states: {
              rm_state: 'RM-REGISTERED',
              cm_state: 'CM-CONNECTED',
              rrc_state: 'RRC-CONNECTED',
              mm_5g_state: 'MM-REGISTERED-NORMAL-SERVICE',
            },
            pdu: { psi: 1, dnn: 'internet', state: 'PS-ACTIVE', address: '10.46.0.1' },
            counters: {
              interface: 'uesimtun0',
              rx_bytes: 42_000, rx_packets: 100,
              tx_bytes: 21_000, tx_packets: 50,
              rx_bps: 4_200, tx_bps: 2_100,
            },
            job_step: null,
            events: [],
          },
          meta: { api_version: '0.29.16' },
        }),
      });
    }
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        data: { items: [{ ue_id: 'UE-01', running: true, imsi: 'imsi-001010000000001' }] },
        meta: {},
      }),
    });
  });
  await page.route('**/polaris-api/v1/traffic/**', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        data: {
          sessions: [
            {
              id: 'tg-01',
              ue_id: 'UE-01',
              protocol: 'UDP',
              destination: '10.46.0.1',
              bitrate_bps: 42_000,
              running: true,
            },
          ],
        },
        meta: { api_version: '0.29.16' },
      }),
    }),
  );
  await page.route('**/polaris-api/v1/live/**', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ data: { grants: [] }, meta: {} }),
    }),
  );
  await page.route('**/polaris-api/v1/subscribers**', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ data: { items: [], total: 0 }, meta: {} }),
    }),
  );
  // Catch-all for anything else — empty shape, HTTP 200.
  await page.route('**/polaris-api/v1/**', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ data: {}, meta: { api_version: '0.29.16' } }),
    }),
  );
}

async function assertNoOverlap(page: Page, name: string) {
  const doc = await page.evaluate(() => ({
    scrollWidth: document.documentElement.scrollWidth,
    clientWidth: document.documentElement.clientWidth,
  }));
  expect(
    doc.scrollWidth,
    `${name}: scrollWidth ${doc.scrollWidth} must not exceed clientWidth ${doc.clientWidth}`,
  ).toBeLessThanOrEqual(doc.clientWidth);
  const overflowers = await page.evaluate(() => {
    const vw = document.documentElement.clientWidth;
    const found: { tag: string; right: number; text: string }[] = [];
    document.querySelectorAll<HTMLElement>('*').forEach((el) => {
      if (!el.offsetParent && el !== document.body) return;
      const rect = el.getBoundingClientRect();
      if (rect.right > vw + 0.5 && rect.width > 0) {
        found.push({
          tag: el.tagName,
          right: Math.round(rect.right),
          text: (el.textContent ?? '').trim().slice(0, 48),
        });
      }
    });
    return found.slice(0, 3);
  });
  expect(overflowers, `${name}: elements extend past the viewport right edge`).toEqual([]);
}

async function captureScreenshot(page: Page, name: string, theme: string, width: number, height: number) {
  const dir = path.join(SCREENSHOTS_ROOT, `${width}x${height}-${theme}`);
  await fs.mkdir(dir, { recursive: true });
  await page.screenshot({ path: path.join(dir, `${name}.png`), fullPage: false });
}

const VIEWS: Array<{ name: string; route: string; readyLocator: (page: Page) => Promise<unknown> }> = [
  {
    name: 'ue-manager',
    route: '/ues',
    readyLocator: (page) => page.getByTestId('ue-search').waitFor({ state: 'visible' }),
  },
  {
    name: 'ue-activity',
    route: '/ues/UE-01/activity',
    readyLocator: (page) => page.getByRole('heading', { name: /UE-01|Activity/i }).first().waitFor({ state: 'visible' }),
  },
  {
    name: 'traffic-generator',
    route: '/traffic',
    readyLocator: (page) => page.locator('main').first().waitFor({ state: 'visible' }),
  },
  {
    name: 'run-scenarios',
    route: '/scenarios',
    readyLocator: (page) => page.locator('main').first().waitFor({ state: 'visible' }),
  },
];

for (const { name, route, readyLocator } of VIEWS) {
  test(`0.13.2 anti-overlap · ${name}`, async ({ page }, testInfo) => {
    await mockPolarisBackend(page);
    await page.goto(route);
    await readyLocator(page);
    await page.waitForLoadState('networkidle');
    const project = testInfo.project.name;
    const [, widthRaw, theme] = project.match(/chromium-(\d+)-(light|dark)/) ?? [];
    const width = Number(widthRaw);
    const height = width === 1920 ? 1080 : width === 1440 ? 900 : 800;
    expect(width, 'project name must encode a known viewport width').toBeGreaterThan(0);
    await assertNoOverlap(page, `${name} ${project}`);
    await captureScreenshot(page, name, theme ?? 'light', width, height);
  });
}
