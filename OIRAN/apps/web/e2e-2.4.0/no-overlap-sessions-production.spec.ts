// 2.5.1 — anti-overlap matrix for the Sessions page with REAL
// production-shaped fixtures. The 2.5.0 anti-overlap spec used short
// synthetic rows (UE-ebee45ec, "Registration" procedure) that never
// stressed the 1280-px layout. Codex surfaced an overlap at 1280 on
// the production backend (sessions-production-1280.png); this spec
// locks the fix by feeding the Sessions page the exact shape of rows
// a lab operator sees: long procedure names, multi-interface
// (N2/N3/N4/SBI), long serving-node annotations.
//
// Invariants (every cell on every row at every certified viewport):
//   1. Each cell's right edge <= next cell's left edge (strict, no
//      overlap between neighbours).
//   2. Session ID line is `truncate` + carries `title={session_id}`.
//   3. The side-detail card does NOT sit next to the table at 1280 /
//      1440 (that was the overlap source) — the layout only becomes
//      two-column at `2xl` (>= 1536 px).

import { test, expect, type Page } from '@playwright/test';

const PRODUCTION_SESSIONS = [
  {
    session_id: '5g-session-18fe28a814c4b09442ab3a7d7c82d1f0e9b1c2d3',
    dataset_id: 'derived-e2e-002-live',
    ue_context_id: 'ue-ebee45ec',
    technology: '5G SA',
    ue_pseudonym: 'UE-ebee45ec',
    pdu_session_id: '1',
    serving_node: 'GNB-01 · 10.77.21.20 · 10.77.22.20',
    procedure: 'Registration + PDU session establishment + modification',
    start_timestamp: '2026-10-26T22:44:41.226Z',
    end_timestamp: '2026-10-26T22:44:41.513Z',
    duration_ns: '287432198',
    interfaces: ['N2', 'SBI', 'N4', 'N3'],
    message_count: 18,
    source_event_count: 18,
    background_event_count: 2,
    correlation_status: 'POSSIBLE',
    decode_completeness: { decoded: 11, partial: 4, unresolved_fields: 2 },
    state: 'ACTIVE_WITH_USER_PLANE',
  },
  {
    session_id: '5g-session-07ac91d2e3f05b11bc83e9d8a7f6e5d4c3b2a190',
    dataset_id: 'derived-e2e-002-live',
    ue_context_id: 'ue-4d1a9c02',
    technology: '5G SA',
    ue_pseudonym: 'UE-4d1a9c02-vprobe-oiran',
    pdu_session_id: '1',
    serving_node: 'GNB-01 · 10.77.21.20',
    procedure: 'Registration (authentication failure, retry)',
    start_timestamp: '2026-10-26T22:46:02.118Z',
    end_timestamp: '2026-10-26T22:46:02.259Z',
    duration_ns: '141842000',
    interfaces: ['N2'],
    message_count: 8,
    source_event_count: 8,
    background_event_count: 0,
    correlation_status: 'UNKNOWN',
    decode_completeness: { decoded: 6, partial: 0, unresolved_fields: 1 },
    state: 'INCOMPLETE',
  },
  {
    session_id: '5g-session-c3b0f7718a2d4e609fe8d7c6b5a4938271605f',
    dataset_id: 'derived-e2e-002-live',
    ue_context_id: 'ue-ebee45ec',
    technology: '5G SA',
    ue_pseudonym: 'UE-ebee45ec',
    pdu_session_id: '1',
    serving_node: 'GNB-01 · 10.77.21.20 · 10.77.22.20',
    procedure: 'PDU session release · controlled teardown',
    start_timestamp: '2026-10-26T22:51:13.904Z',
    end_timestamp: '2026-10-26T22:51:13.968Z',
    duration_ns: '64112000',
    interfaces: ['N2', 'SBI', 'N4'],
    message_count: 9,
    source_event_count: 9,
    background_event_count: 0,
    correlation_status: 'STRONG',
    decode_completeness: { decoded: 9, partial: 0, unresolved_fields: 0 },
    state: 'RELEASED',
  },
];

async function mockProductionBackend(page: Page, theme: 'light' | 'dark') {
  await page.addInitScript((t) => {
    localStorage.setItem('oiran.theme', t);
  }, theme);
  await page.route('**/api/v1/**', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: '{"data":[],"meta":{}}' }),
  );
  await page.route('**/api/v1/auth/me', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        data: {
          authenticated: true,
          role: 'operator',
          permissions: [],
          capture_control: false,
          capture_execution_enabled: false,
          reason: 'OK',
        },
        meta: {},
      }),
    }),
  );
  await page.route('**/api/v1/metrics', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: '{"data":{"observed_at_epoch_s":0,"mode":"OPERATIONAL","packet_rate_pps":null,"bitrate_bps":null,"decode_rate_eps":null,"packet_drops":null,"capture_queue_utilization_percent":null,"active_captures":0,"active_sessions":3,"historical_sessions":3,"historical_events":35,"decode_errors":0,"cpu":{"usage_percent":null,"load_one":null,"logical_cpus":8},"memory":{"total_bytes":null,"available_bytes":null,"used_bytes":null},"disk":null,"interfaces":[]},"meta":{}}',
    }),
  );
  await page.route('**/api/v1/datasets*', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: '{"data":[],"meta":{}}' }),
  );
  await page.route('**/api/v1/ues*', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: '{"data":[],"meta":{}}' }),
  );
  await page.route('**/api/v1/sessions*', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        data: PRODUCTION_SESSIONS,
        meta: { page: 1, page_size: 25, total: 3, total_pages: 1 },
      }),
    }),
  );
}

for (const theme of ['light', 'dark'] as const) {
  test(`sessions · no overlap on production rows · ${theme}`, async ({ page }, info) => {
    await mockProductionBackend(page, theme);
    await page.goto('/investigation/sessions');
    await page.getByTestId('sessions-table').waitFor({ timeout: 10_000 });

    for (const session of PRODUCTION_SESSIONS) {
      const row = page.locator(`[data-testid="session-row-${session.session_id}"]`);
      await row.waitFor({ timeout: 5_000 });
      const cells = await row.locator('td').all();
      const boxes = await Promise.all(cells.map((c) => c.boundingBox()));
      for (let i = 0; i < boxes.length - 1; i++) {
        const cur = boxes[i];
        const next = boxes[i + 1];
        if (!cur || !next) continue;
        // No overlap: current cell right edge <= next cell left edge
        // (allow 1 px rounding slack).
        expect(cur.x + cur.width).toBeLessThanOrEqual(next.x + 1);
      }
      const idSpan = page.getByTestId(`session-id-${session.session_id}`);
      await expect(idSpan).toHaveAttribute('title', session.session_id);
      const idClass = (await idSpan.getAttribute('class')) ?? '';
      expect(idClass).toMatch(/truncate/);
    }

    // The side detail card must not sit next to the table at 1280 / 1440;
    // it only becomes a sidebar at `2xl` (>= 1536 px).
    const viewportWidth = Number(info.project.name.replace('chromium-', '').split('-')[0]);
    if (viewportWidth < 1536) {
      const detail = page.getByTestId('sessions-detail');
      if ((await detail.count()) > 0) {
        const tableBox = await page.getByTestId('sessions-table').boundingBox();
        const detailBox = await detail.boundingBox();
        if (tableBox && detailBox) {
          // Detail card starts below the table (y >= table_y + table_height),
          // not next to it (x > table_x + table_width).
          expect(detailBox.y).toBeGreaterThanOrEqual(tableBox.y + tableBox.height - 2);
        }
      }
    }

    await page.screenshot({
      path: `docs/screenshots/2.5.1/sessions-production/sessions-${viewportWidth}-${theme}.png`,
      fullPage: true,
    });
  });
}
