// 2.4.0 — anti-overlap matrix for the Sessions page. Verifies that the
// Session ID (mono hash) stays inside the Procedure cell (max-w-[260px]
// + truncate) at every certified viewport, in both themes. Pre-2.4.0
// the hash spilled into the UE / Tech / Node cells. The spec mocks
// /auth/me, /datasets and /sessions so no live backend is required.

import { test, expect, type Page } from '@playwright/test';

async function mockApi(page: Page, theme: 'light' | 'dark') {
  await page.addInitScript((t) => {
    localStorage.setItem('oiran.theme', t);
  }, theme);
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
      body: JSON.stringify({
        data: {
          observed_at_epoch_s: 0,
          mode: 'OPERATIONAL',
          packet_rate_pps: null,
          bitrate_bps: null,
          decode_rate_eps: null,
          packet_drops: null,
          capture_queue_utilization_percent: null,
          active_captures: 0,
          active_sessions: 2,
          historical_sessions: 2,
          historical_events: 162,
          decode_errors: 0,
          cpu: { usage_percent: null, load_one: null, logical_cpus: 8 },
          memory: { total_bytes: null, available_bytes: null, used_bytes: null },
          disk: null,
          interfaces: [],
        },
        meta: {},
      }),
    }),
  );
  await page.route('**/api/v1/modules', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: '{"data":[],"meta":{}}' }),
  );
  await page.route('**/api/v1/datasets*', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: '{"data":[],"meta":{}}' }),
  );
  await page.route('**/api/v1/sessions*', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        data: [
          {
            session_id: '5g-session-18fe28a814c4b094',
            dataset_id: 'derived-e2e-002-live',
            ue_context_id: 'ue-ebee45ec',
            technology: '5G SA',
            ue_pseudonym: 'UE-ebee45ec',
            pdu_session_id: '1',
            serving_node: 'GNB-01',
            procedure: 'Registration + PDU session',
            start_timestamp: '2026-10-26T22:44:41.226Z',
            end_timestamp: '2026-10-26T22:44:41.513Z',
            duration_ns: '287000000',
            interfaces: ['N2', 'SBI', 'N4', 'N3'],
            message_count: 18,
            source_event_count: 18,
            background_event_count: 0,
            correlation_status: 'POSSIBLE',
            decode_completeness: { decoded: 11, partial: 4, unresolved_fields: 0 },
            state: 'ACTIVE_WITH_USER_PLANE',
          },
          {
            session_id: '5g-session-07ac91d2e3f05b11',
            dataset_id: 'derived-e2e-002-live',
            ue_context_id: 'ue-4d1a9c02',
            technology: '5G SA',
            ue_pseudonym: 'UE-4d1a9c02',
            pdu_session_id: '1',
            serving_node: 'GNB-01',
            procedure: 'Registration',
            start_timestamp: '2026-10-26T22:46:02.118Z',
            end_timestamp: '2026-10-26T22:46:02.259Z',
            duration_ns: '141000000',
            interfaces: ['N2'],
            message_count: 8,
            source_event_count: 8,
            background_event_count: 0,
            correlation_status: 'UNKNOWN',
            decode_completeness: { decoded: 6, partial: 0, unresolved_fields: 0 },
            state: 'INCOMPLETE',
          },
        ],
        meta: { page: 1, page_size: 25, total: 2, total_pages: 1 },
      }),
    }),
  );
}

for (const theme of ['light', 'dark'] as const) {
  test(`sessions · no overlap · ${theme}`, async ({ page }, info) => {
    await mockApi(page, theme);
    await page.goto('/investigation/sessions');
    await page.getByTestId('sessions-table').waitFor({ timeout: 10_000 });

    const procedure = page.locator('[data-testid="session-row-5g-session-18fe28a814c4b094"] td').first();
    const ueCell = page.locator('[data-testid="session-row-5g-session-18fe28a814c4b094"] td').nth(1);
    const sessionId = page.getByTestId('session-id-5g-session-18fe28a814c4b094');

    const [procedureBox, ueBox, sessionIdBox] = await Promise.all([
      procedure.boundingBox(),
      ueCell.boundingBox(),
      sessionId.boundingBox(),
    ]);
    if (!procedureBox || !ueBox || !sessionIdBox) throw new Error('boundingBox returned null');

    // Session ID must stay inside the Procedure cell's right edge.
    expect(sessionIdBox.x + sessionIdBox.width).toBeLessThanOrEqual(procedureBox.x + procedureBox.width + 1);
    // Procedure cell right edge must not cross the UE cell left edge.
    expect(procedureBox.x + procedureBox.width).toBeLessThanOrEqual(ueBox.x + 1);
    // Session ID must truncate (CSS truncate class).
    const sessionIdClass = (await sessionId.getAttribute('class')) ?? '';
    expect(sessionIdClass).toMatch(/truncate/);
    // The hover title keeps the full identifier reachable.
    await expect(sessionId).toHaveAttribute('title', '5g-session-18fe28a814c4b094');

    // Width is encoded in the project name (chromium-WIDTH-theme).
    const viewport = info.project.name.replace('chromium-', '').split('-')[0];
    await page.screenshot({
      path: `docs/screenshots/2.4.0/sessions-no-overlap/sessions-${viewport}-${theme}.png`,
      fullPage: true,
    });
  });
}
