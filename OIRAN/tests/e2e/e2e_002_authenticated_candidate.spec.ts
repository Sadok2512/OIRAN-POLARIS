import { expect, test } from '../../apps/web/node_modules/@playwright/test';
import { mkdirSync } from 'node:fs';

const token = process.env.OIRAN_E2E_OPERATOR_TOKEN;
const datasetId = 'derived-e2e-002-live-1793054609378-0001';
const screenshots = process.env.RELEASE_SCREENSHOT_DIR ?? 'screenshots/release_consolidation_v1/e2e_002';

test('authenticated candidate imports and displays reviewed E2E-002 evidence', async ({ page, request }) => {
  test.setTimeout(120_000);
  expect(token, 'OIRAN_E2E_OPERATOR_TOKEN must be securely injected').toBeTruthy();
  mkdirSync(screenshots, { recursive: true });
  const headers = { Authorization: `Bearer ${token}` };
  const imported = await request.post('/api/v1/datasets/import-derived', {
    headers,
    data: { dataset_id: datasetId },
  });
  expect(imported.status()).toBe(200);
  const registration = (await imported.json()).data;
  expect(registration).toMatchObject({
    dataset_id: datasetId,
    event_count: 92,
    session_count: 1,
    correlation_edge_count: 3,
    complete_e2e_certified: false,
    registration: 'VALIDATED_REGISTERED',
  });

  await page.addInitScript(([key, value]) => sessionStorage.setItem(key, value), ['oiran.access_token', token!]);
  const sessionsResponse = await request.get(`/api/v1/sessions?page_size=100&dataset_id=${datasetId}`, { headers });
  expect(sessionsResponse.ok()).toBe(true);
  const sessions = (await sessionsResponse.json()).data;
  expect(sessions).toHaveLength(1);
  const sessionId = sessions[0].session_id as string;
  const flowResponse = await request.get(`/api/v1/sessions/${sessionId}/callflow`, { headers });
  expect(flowResponse.ok()).toBe(true);
  const flow = (await flowResponse.json()).data;
  expect(flow.correlation_edges.map((edge: { evidence_type: string; confidence: string }) => [edge.evidence_type, edge.confidence])).toEqual(expect.arrayContaining([
    ['EXACT_TUNNEL_MATCH', 'EXACT'],
    ['STRONG_CONTEXT_ASSOCIATION', 'STRONG'],
  ]));
  expect(flow.correlation_status.N2_SBI).toBe('STRONG');
  expect(flow.correlation_status.SBI_N4).toBe('STRONG');
  expect(flow.correlation_status.N4_N3).toBe('UNKNOWN');

  await page.goto('/platform/settings');
  await expect(page.getByText('OPERATOR', { exact: true }).first()).toBeVisible();
  for (const theme of ['light', 'dark']) {
    for (const size of [{ width: 1440, height: 900 }, { width: 1920, height: 1080 }]) {
      await page.setViewportSize(size);
      await page.goto(`/investigation/sessions?dataset_id=${datasetId}`);
      await page.getByLabel('Theme').selectOption(theme);
      await expect(page.getByLabel('Dataset filter')).toHaveValue(datasetId);
      await expect(page.getByText(sessionId, { exact: true }).first()).toBeVisible();
      await page.screenshot({ path: `${screenshots}/Session_Explorer_${theme}_${size.width}x${size.height}.png`, fullPage: true });

      const exact = flow.correlation_edges.find((edge: { evidence_type: string }) => edge.evidence_type === 'EXACT_TUNNEL_MATCH');
      await page.goto(`/investigation/callflow/${sessionId}?dataset_id=${datasetId}&scope=all&event_id=${exact.source_event_id}`);
      await page.getByLabel('Theme').selectOption(theme);
      await expect(page.getByRole('heading', { name: 'Call Flow Viewer' })).toBeVisible();
      await expect(page.getByText('N2 ↔ SBI', { exact: true }).locator('xpath=following-sibling::dd[1]').getByText('STRONG', { exact: true })).toBeVisible();
      await expect(page.getByText('SBI ↔ N4', { exact: true }).locator('xpath=following-sibling::dd[1]').getByText('STRONG', { exact: true })).toBeVisible();
      await expect(page.getByText('UNKNOWN', { exact: true }).first()).toBeVisible();
      await page.getByRole('tab', { name: /Correlation Evidence/ }).click();
      await expect(page.getByText(/EXACT_TUNNEL_MATCH/)).toBeVisible();
      await expect(page.getByText('teid=0xb3b5', { exact: true })).toBeVisible();
      await page.getByRole('tab', { name: 'Provenance' }).click();
      await expect(page.getByText('Packet 39', { exact: true })).toBeVisible();
      await expect(page.getByRole('link', { name: 'Open exact packet' }).first()).toBeVisible();
      await page.screenshot({ path: `${screenshots}/Call_Flow_Evidence_${theme}_${size.width}x${size.height}.png`, fullPage: true });
    }
  }
});
