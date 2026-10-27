import { expect, test, type Page } from '../../apps/web/node_modules/@playwright/test';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

const ROOT = path.resolve(process.cwd(), '../..');
const screenshots = path.join(ROOT, 'OIRAN_V2_2_UI_SCREENSHOTS');

async function authenticate(page: Page) {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Operational Overview' })).toBeVisible();
}

async function callflow(page: Page) {
  await authenticate(page);
  await page.goto('/investigation/callflow/5g-UE-A-pdu-1');
  await expect(page.getByRole('heading', { name: 'Call Flow Viewer' })).toBeVisible();
}

test('WEB-001 public read-only application loads', async ({ page }) => {
  await authenticate(page);
  await expect(page.getByText('OIRAN', { exact: true }).first()).toBeVisible();
});

test('WEB-002 navigates between four pages without errors', async ({ page }) => {
  await authenticate(page);
  for (const [label, heading] of [['Session Explorer', 'Session Explorer'], ['Call Flow Viewer', 'Call Flow Viewer'], ['Correlation Studio', 'Correlation Studio'], ['Probe Manager', 'Probe Manager']]) {
    await page.getByRole('link', { name: label }).click();
    await expect(page.getByRole('heading', { name: heading })).toBeVisible();
  }
});

test('WEB-003 Probe Manager shows real capture metadata', async ({ page }) => {
  await authenticate(page);
  await page.goto('/operations/probes');
  await expect(page.getByText('N2.pcapng', { exact: true })).toBeVisible();
  const response = await page.request.get('/api/v1/captures?page_size=100');
  const body = await response.json();
  expect(body.meta.total).toBeGreaterThanOrEqual(3);
  await expect(page.getByText('Registered captures').locator('..').getByText(String(body.meta.total), { exact: true })).toBeVisible();
});

test('WEB-004 capture selection reveals checksum', async ({ page }) => {
  await authenticate(page);
  await page.goto('/operations/probes');
  await page.getByText('N3.pcapng', { exact: true }).click();
  await expect(page.getByText('806a4ae1eb758a1b2c08ae10d7b7f54881c5e571c7f80ed047f564cb222cb35a')).toBeVisible();
});

test('WEB-005 Session Explorer shows actual session', async ({ page }) => {
  await authenticate(page);
  await page.goto('/investigation/sessions');
  await expect(page.getByText('5g-UE-A-pdu-1').first()).toBeVisible();
  await expect(page.getByText('26', { exact: true }).first()).toBeVisible();
});

test('WEB-006 session selection shows certified accounting', async ({ page }) => {
  await authenticate(page);
  await page.goto('/investigation/sessions/5g-UE-A-pdu-1');
  await expect(page.getByText('28', { exact: true }).first()).toBeVisible();
});

test('WEB-007 real Call Flow events render', async ({ page }) => {
  await callflow(page);
  await expect(page.locator('.flow-event')).toHaveCount(26);
});

test('WEB-008 NGAP selection exposes IE and provenance', async ({ page }) => {
  await callflow(page);
  await page.getByLabel(/InitialUEMessage, NGAP/).click();
  await expect(page.getByRole('heading', { name: 'InitialUEMessage' })).toBeVisible();
  await page.getByRole('tab', { name: /Provenance/ }).click();
  await expect(page.getByText(/Packet/).first()).toBeVisible();
});

test('WEB-009 PFCP selection exposes typed data', async ({ page }) => {
  await callflow(page);
  await page.getByLabel(/PFCP Session Establishment Request, PFCP/).click();
  await page.getByRole('tab', { name: /Decoded Fields/ }).click();
  await expect(page.locator('.ie-tree details').first()).toBeVisible();
});

test('WEB-010 GTP-U selection exposes TEID and packet', async ({ page }) => {
  await callflow(page);
  await page.getByLabel('Protocol filter').selectOption('GTP-U');
  await page.getByLabel(/G-PDU, GTP-U/).first().click();
  await page.getByRole('tab', { name: /Evidence/ }).click();
  await expect(page.getByText(/teid=0x/i).first()).toBeVisible();
});

for (const [id, iface, count] of [['WEB-011', 'N2', 12], ['WEB-012', 'N4', 4], ['WEB-013', 'N3', 10]] as const) {
  test(`${id} filters ${iface}`, async ({ page }) => {
    await callflow(page);
    await page.getByLabel('Interface filter').selectOption(iface);
    await expect(page.locator('.flow-event')).toHaveCount(count);
  });
}

test('WEB-014 background events are separate and available', async ({ page }) => {
  await callflow(page);
  await page.getByText('All capture events').click();
  await expect(page.locator('.flow-event')).toHaveCount(54);
  await expect(page.getByText('BACKGROUND').first()).toBeVisible();
});

test('WEB-015 Correlation Studio shows actual links', async ({ page }) => {
  await authenticate(page);
  await page.goto('/investigation/correlation/5g-UE-A-pdu-1');
  await expect(page.locator('tbody tr')).toHaveCount(12);
});

test('WEB-016 N2/N4 link preserves STRONG evidence', async ({ page }) => {
  await authenticate(page);
  await page.goto('/investigation/correlation/5g-UE-A-pdu-1');
  await page.locator('tbody tr').filter({ hasText: 'N2' }).first().click();
  await expect(page.locator('.edge-inspector').getByText('STRONG')).toBeVisible();
});

test('WEB-017 N4/N3 link preserves EXACT evidence', async ({ page }) => {
  await authenticate(page);
  await page.goto('/investigation/correlation/5g-UE-A-pdu-1');
  await page.locator('tbody tr').filter({ hasText: 'N4' }).filter({ hasText: 'N3' }).first().click();
  await expect(page.locator('.edge-inspector').getByText('EXACT')).toBeVisible();
});

for (const [id, format] of [['WEB-018', 'HTML'], ['WEB-019', 'JSON']] as const) {
  test(`${id} protected ${format} export downloads`, async ({ page }) => {
    await callflow(page);
    const download = page.waitForEvent('download');
    await page.getByRole('button', { name: format }).click();
    expect((await download).suggestedFilename()).toContain(`.${format.toLowerCase()}`);
  });
}

test('WEB-020 selected session URL survives reload', async ({ page }) => {
  await authenticate(page);
  await page.goto('/investigation/sessions/5g-UE-A-pdu-1');
  await page.reload();
  await expect(page.getByRole('heading', { name: '5g-UE-A-pdu-1' })).toBeVisible();
});

test('WEB-021 public read-only API is available without a token', async ({ request }) => {
  expect((await request.get('/api/v1/health')).status()).toBe(200);
});

test('WEB-022 invalid session ID returns controlled error', async ({ request }) => {
  const response = await request.get('/api/v1/sessions/not-real');
  expect(response.status()).toBe(404);
  expect((await response.json()).error.code).toBe('SESSION_NOT_FOUND');
});

test('WEB-023 live capture remains safely gated for Viewer', async ({ page }) => {
  await authenticate(page);
  await page.goto('/operations/probes');
  await expect(page.getByRole('button', { name: 'Start capture' })).toBeDisabled();
  await expect(page.getByText(/Operator permission required/)).toBeVisible();
});

test('WEB-024 1440px visual QA and screenshots', async ({ page }) => {
  await fs.mkdir(screenshots, { recursive: true });
  await page.setViewportSize({ width: 1440, height: 900 });
  await authenticate(page);
  const routes = [['overview', '/overview'], ['probe-manager', '/operations/probes'], ['session-explorer', '/investigation/sessions/5g-UE-A-pdu-1'], ['callflow-viewer', '/investigation/callflow/5g-UE-A-pdu-1'], ['correlation-studio', '/investigation/correlation/5g-UE-A-pdu-1'], ['packet-analyzer', '/analysis/packets'], ['live-monitoring', '/reports/monitoring']] as const;
  for (const theme of ['dark', 'light'] as const) {
    await page.evaluate((value) => localStorage.setItem('oiran.theme', value), theme);
    for (const [name, route] of routes) {
      await page.goto(route);
      await page.waitForLoadState('networkidle');
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
      expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe(theme);
      await page.screenshot({ path: path.join(screenshots, `${name}-${theme}-1440x900.png`), fullPage: false });
    }
  }
});

test('WEB-025 1920px visual QA and screenshots', async ({ page }) => {
  await fs.mkdir(screenshots, { recursive: true });
  await page.setViewportSize({ width: 1920, height: 1080 });
  await authenticate(page);
  const routes = [['overview', '/overview'], ['probe-manager', '/operations/probes'], ['session-explorer', '/investigation/sessions/5g-UE-A-pdu-1'], ['callflow-viewer', '/investigation/callflow/5g-UE-A-pdu-1'], ['correlation-studio', '/investigation/correlation/5g-UE-A-pdu-1'], ['packet-analyzer', '/analysis/packets'], ['live-monitoring', '/reports/monitoring']] as const;
  for (const theme of ['dark', 'light'] as const) {
    await page.evaluate((value) => localStorage.setItem('oiran.theme', value), theme);
    for (const [name, route] of routes) {
      await page.goto(route);
      await page.waitForLoadState('networkidle');
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
      expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe(theme);
      await page.screenshot({ path: path.join(screenshots, `${name}-${theme}-1920x1080.png`), fullPage: false });
    }
  }
});

test('S4.1 dataset and UE discovery endpoints are public and paginated', async ({ request }) => {
  const datasets = await request.get('/api/v1/datasets?page=1&page_size=100');
  expect(datasets.status()).toBe(200);
  const datasetBody = await datasets.json();
  expect(datasetBody.meta.total).toBeGreaterThanOrEqual(2);
  expect(datasetBody.data.find((dataset: { dataset_id: string }) => dataset.dataset_id === 'OIRAN_5G_PDU_SESSION_DATA_V1').event_count).toBe(54);
  const recovered = datasetBody.data.find((dataset: { dataset_id: string }) => dataset.dataset_id === 'recovered-dataset-live-1792964646320-0003');
  expect(recovered.event_count).toBe(20);
  expect(recovered.session_ids).toEqual([]);
  const ues = await request.get('/api/v1/ues?page_size=100');
  const ueBody = await ues.json();
  expect(ueBody.meta.total).toBeGreaterThanOrEqual(1);
});

test('S4.1 Session Explorer preserves dataset and interface filters in URL', async ({ page }) => {
  await authenticate(page);
  await page.goto('/investigation/sessions');
  await page.getByLabel('Dataset filter').selectOption('OIRAN_5G_PDU_SESSION_DATA_V1');
  await page.getByLabel('Interface filter').selectOption('N3');
  await expect(page).toHaveURL(/dataset_id=OIRAN_5G_PDU_SESSION_DATA_V1/);
  await expect(page).toHaveURL(/interface=N3/);
  await expect(page.getByText('5g-UE-A-pdu-1').first()).toBeVisible();
});

test('S4.1 Call Flow selector resolves the chosen session', async ({ page }) => {
  await authenticate(page);
  await page.goto('/investigation/callflow');
  await page.getByRole('link', { name: /5g-UE-A-pdu-1/ }).click();
  await expect(page).toHaveURL(/callflow\/5g-UE-A-pdu-1/);
  await expect(page.locator('.flow-event')).toHaveCount(26);
});

test('S4.2 Probe Manager displays measured fail-closed disk safety', async ({ page }) => {
  await authenticate(page);
  await page.goto('/operations/probes');
  await expect(page.getByRole('heading', { name: 'Mandatory disk safety' })).toBeVisible();
  await expect(page.getByText('256.0 MiB')).toBeVisible();
  const response = await page.request.get('/api/v1/storage/safety');
  const body = await response.json();
  await expect(page.getByText('Capture engine').locator('..').getByText(body.data.capture_job.state, { exact: true })).toBeVisible();
  expect(body.data.policy.stop_percent).toBe(85);
  expect(body.data.policy.hard_limit_percent).toBe(90);
  expect(typeof body.data.capture_job.writes_enabled).toBe('boolean');
});

test('V2 overview separates historical evidence from live telemetry', async ({ page }) => {
  await authenticate(page);
  await expect(page.getByText('54 events')).toBeVisible();
  await expect(page.getByText('No live counters are exported by the current vProbe.')).toBeVisible();
  const metrics = await page.request.get('/api/v1/metrics');
  const body = await metrics.json();
  expect(body.data.active_captures).toBe(0);
  expect(body.data.packet_rate_pps).toBeNull();
  expect(body.data.historical_events).toBe(54);
});

test('V2 Packet Analyzer exposes real provenance and restricted raw bytes', async ({ page }) => {
  await authenticate(page);
  await page.goto('/analysis/packets');
  await expect(page.getByRole('heading', { name: 'Packet Analyzer' })).toBeVisible();
  await page.getByRole('row').nth(1).click();
  await expect(page.getByRole('tab', { name: 'Raw Hex' })).toBeVisible();
  await page.getByRole('tab', { name: 'Provenance' }).click();
  await expect(page.getByText(/capture:\/\//).first()).toBeVisible();
  await page.getByRole('tab', { name: 'Raw Hex' }).click();
  await expect(page.getByText('Raw bytes not available')).toBeVisible();
});

test('Live V1 capture lifecycle API enforces Operator authorization', async ({ request }) => {
  const payload={probe_id:'oiran-vprobe-local-01',name:'POLARIS-5G-SA',interfaces:['N2','N3','N4'],duration_seconds:60,max_bytes:268435456,rotation_files:3,profile:'POLARIS_5G_SA',optional_filter:null};
  const validation = await request.post('/api/v1/captures/validate',{data:payload});
  expect(validation.status()).toBe(403);
  expect((await validation.json()).error.code).toBe('OPERATOR_REQUIRED');
  const start = await request.post('/api/v1/captures/start',{data:payload});
  expect(start.status()).toBe(403);
  expect((await start.json()).error.code).toBe('OPERATOR_REQUIRED');
});

test('P0 selected capture and library use the same authoritative state', async ({ page }) => {
  await page.goto('/operations/probes');
  const row=page.locator('tr').filter({hasText:'live-1792964646320-0003'});
  await expect(row.getByText('FAILED',{exact:true})).toBeVisible();
  await row.click();
  const panel=page.getByRole('heading',{name:'Selected capture'}).locator('xpath=ancestor::*[contains(concat(" ",normalize-space(@class)," ")," panel ")][1]');
  await expect(panel.getByText('FAILED',{exact:true})).toBeVisible();
  await expect(panel.getByText('recovered-dataset-live-1792964646320-0003',{exact:true})).toBeVisible();
});

test('V2 Call Flow inspector preserves partial decode and actual JSON', async ({ page }) => {
  await callflow(page);
  await page.getByLabel(/InitialUEMessage, NGAP/).click();
  const partial = page.locator('.flow-event').filter({ hasText: 'PARTIAL' }).first();
  if (await partial.count()) {
    await partial.click();
    await expect(page.getByText('PARTIAL').first()).toBeVisible();
  }
  await page.getByRole('tab', { name: 'JSON' }).click();
  await expect(page.locator('.json-view')).toContainText('event_id');
});

test('V2.2 capture navigation resolves the exact dataset without fallback', async ({ page }) => {
  await authenticate(page);
  await page.goto('/operations/probes');
  const row=page.locator('tr').filter({hasText:'live-1792966547779-0001'});
  await row.getByRole('button',{name:'Open dataset'}).click();
  await expect(page).toHaveURL(/capture_id=live-1792966547779-0001/);
  await expect(page).toHaveURL(/dataset_id=dataset-live-1792966547779-0001/);
  await expect(page.getByText('No reconstructed sessions in this capture.')).toBeVisible();
  await expect(page.getByText('5g-UE-A-pdu-1')).toHaveCount(0);
});

test('V2.2 directional Call Flow synchronizes arrows, rows and provenance', async ({ page }) => {
  await callflow(page);
  const arrow=page.getByLabel(/InitialUEMessage, NGAP/).first();
  await arrow.click();
  await expect(arrow).toHaveClass(/selected/);
  await expect(page.getByRole('heading',{name:'InitialUEMessage'})).toBeVisible();
  await page.getByRole('tab',{name:'Provenance'}).click();
  await expect(page.getByRole('link',{name:'Open exact packet'}).first()).toHaveAttribute('href',/capture_id=/);
});

test('V2.2 mandatory visual evidence covers inspector, zero-session and filtering', async ({ page }) => {
  await fs.mkdir(screenshots,{recursive:true});
  const response=await page.request.get('/api/v1/sessions/5g-UE-A-pdu-1/callflow');
  const body=await response.json();
  const selected=body.data.events.find((event:{message_name:string})=>event.message_name==='InitialUEMessage').event_id;
  for(const [width,height] of [[1440,900],[1920,1080]] as const){
    await page.setViewportSize({width,height});
    for(const theme of ['dark','light'] as const){
      await page.goto('/');
      await page.evaluate(value=>localStorage.setItem('oiran.theme',value),theme);
      const cases=[
        ['selected-message',`/investigation/callflow/5g-UE-A-pdu-1?dataset_id=OIRAN_5G_PDU_SESSION_DATA_V1&event_id=${encodeURIComponent(selected)}`],
        ['zero-session','/investigation/sessions?capture_id=live-1792966547779-0001&dataset_id=dataset-live-1792966547779-0001&probe_id=oiran-vprobe-local-01'],
        ['multi-interface-filter','/investigation/callflow/5g-UE-A-pdu-1?dataset_id=OIRAN_5G_PDU_SESSION_DATA_V1&interface=N4']
      ] as const;
      for(const [name,route] of cases){
        await page.goto(route);
        await page.waitForLoadState('networkidle');
        if(name==='selected-message')await page.getByRole('tab',{name:/Decoded Fields/}).click();
        expect(await page.evaluate(()=>document.documentElement.scrollWidth<=document.documentElement.clientWidth)).toBe(true);
        await page.screenshot({path:path.join(screenshots,`${name}-${theme}-${width}x${height}.png`),fullPage:false});
      }
    }
  }
});
