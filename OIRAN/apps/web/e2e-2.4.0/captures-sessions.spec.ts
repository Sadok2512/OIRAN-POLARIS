// 2.4.0 — Side-by-side captures: mockup vs implementation for the
// Sessions page at 1440 light + dark. The mockup HTML is served from
// `public/oiran-mockup.html` so Playwright can navigate both sides
// without a network round-trip.

import { test, expect, type Page } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

const OUT_DIR = join('docs', 'screenshots', '2.4.0', 'sessions');
mkdirSync(OUT_DIR, { recursive: true });

async function mockApi(page: Page, theme: 'light' | 'dark') {
  await page.addInitScript((t) => {
    localStorage.setItem('oiran.theme', t);
  }, theme);
  // Safety-net catch-all first; specific routes override (LIFO).
  await page.route('**/api/v1/**', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: '{"data":[],"meta":{}}' }),
  );
  await page.route('**/api/v1/ues*', (route) =>
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
    route.fulfill({ status: 200, contentType: 'application/json', body: '{"data":{"observed_at_epoch_s":0,"mode":"OPERATIONAL","packet_rate_pps":null,"bitrate_bps":null,"decode_rate_eps":null,"packet_drops":null,"capture_queue_utilization_percent":null,"active_captures":0,"active_sessions":4,"historical_sessions":4,"historical_events":35,"decode_errors":0,"cpu":{"usage_percent":null,"load_one":null,"logical_cpus":8},"memory":{"total_bytes":null,"available_bytes":null,"used_bytes":null},"disk":null,"interfaces":[]},"meta":{}}' }),
  );
  await page.route('**/api/v1/modules', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: '{"data":[],"meta":{}}' }),
  );
  await page.route('**/api/v1/datasets*', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        data: [
          {
            dataset_id: 'derived-e2e-002-live',
            display_name: 'E2E-002 live capture',
            dataset_kind: 'CAPTURED_LIVE',
            source: 'vProbe · oiran-lab-n2/n3/n4',
            technology: '5G SA',
            ingestion_status: 'COMPLETE',
            ingestion_generation: 1,
            session_count: 3,
            ue_context_count: 2,
            event_count: 35,
            background_event_count: 0,
            unmatched_event_count: 0,
            duplicate_observation_count: 0,
            error_count: 0,
            read_only: true,
            captures: [],
            accounting_status: 'BALANCED',
            decoder_versions: { ngap: '0.3.0' },
          },
        ],
        meta: {},
      }),
    }),
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
  await page.route('**/api/v1/sessions/*', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: '{"data":{"summary":{},"procedures":[],"accounting":{},"capture_references":[]},"meta":{}}' }),
  );
}

for (const theme of ['light', 'dark'] as const) {
  test(`capture 2.4.0 sessions · mockup + impl · ${theme}`, async ({ page }, info) => {
    if (info.project.name !== `chromium-1440-${theme}`) test.skip();
    await page.setViewportSize({ width: 1440, height: 900 });

    // Mockup side.
    await page.goto(`/oiran-mockup.html#sessions`);
    await page.evaluate((t) => {
      document.documentElement.setAttribute('data-theme', t);
    }, theme);
    await page.getByRole('heading', { name: 'Sessions' }).waitFor({ timeout: 10_000 });
    const mockupPath = join(OUT_DIR, `mockup.${theme}.png`);
    await page.screenshot({ path: mockupPath, fullPage: true });

    // Implementation side.
    await mockApi(page, theme);
    await page.goto('/investigation/sessions');
    await page.getByTestId('sessions-table').waitFor({ timeout: 10_000 });
    const implPath = join(OUT_DIR, `impl.${theme}.png`);
    await page.screenshot({ path: implPath, fullPage: true });

    // Side-by-side composite.
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
    <div class="col"><h2>Implementation (2.4.0)</h2><img src="data:image/png;base64,${implData}"></div>
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
