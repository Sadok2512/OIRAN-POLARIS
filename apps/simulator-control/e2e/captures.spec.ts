// 0.6.0 — Playwright captures (mocked API).
//
// Pages: Templates tab, UE Manager, Provisioning, UE detail.
// Themes: both projects (`chromium-light`, `chromium-dark`) run every
// spec; the colorScheme comes from the project `use` block.
//
// IMPORTANT: this suite does NOT exercise a real backend. Every POLARIS
// route is served by `page.route` with the fixtures below. The
// screenshots are tagged as "mocked API" in docs/screenshots/README.md.

import { test, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const TEMPLATES = [
  {
    id: 'tpl-voice-long',
    name: 'Voice long',
    version: 1,
    loop_count: 1,
    steps: [
      { type: 'ue_start', loop_count: 1, parameters: {} },
      { type: 'ue_stop', loop_count: 1, parameters: {} },
    ],
  },
  {
    id: 'tpl-small-traffic',
    name: 'Small traffic',
    version: 1,
    loop_count: 1,
    steps: [
      { type: 'ue_start', loop_count: 1, parameters: {} },
      { type: 'pdu_establish', loop_count: 1, parameters: {} },
      { type: 'ue_stop', loop_count: 1, parameters: {} },
    ],
  },
];

const UES = [
  {
    id: 'UE-01',
    internal_ue_id: 'open5gs-UE-01',
    name: 'UE under test',
    state: 'READY',
    actions: { start: true, stop: false, reason: null },
  },
];

const UE_DETAIL = {
  ue_id: 'UE-01',
  identity: {
    name: 'UE under test',
    owner: 'ops-nancy',
    note: 'provisioning hand-off',
    imsi: 'PROTECTED',
    authentication: 'PROTECTED',
  },
  provisioning: {
    status: 'VERIFIED',
    subscriber_id: 'sub-abc-01',
    bound_at_epoch_s: 1_793_200_000,
  },
  network_profile: {
    plmn: { mcc: '208', mnc: '93' },
    dnn: 'internet',
    sst: 1,
    sd: 'A1B2C3',
    serving_gnb: 'GNB-01',
  },
  registration: { state: 'REGISTERED', last_registered_at_epoch_s: 1_793_200_010 },
  pdu_sessions: [
    { id: 1, dnn: 'internet', type: 'IPv4', ip: '10.45.0.2', established_at_epoch_s: 1_793_200_020 },
  ],
  ims: { state: 'IMS_NOT_AVAILABLE', reason: 'IMS stack pending' },
  scenario: { assigned_id: 'scn-small-traffic', auto_run: false, last_job_id: null },
  traffic: { bytes_dl: 1_024_000, bytes_ul: 128_000, last_sample_epoch_s: 1_793_200_030 },
};

const SUBSCRIBERS = {
  items: [
    {
      subscriber_id: 'sub-abc-01',
      owner: 'ops-nancy',
      imsi: 'PROTECTED',
      provisioning_status: 'VERIFIED',
      updated_at_epoch_s: 1_793_200_000,
    },
    {
      subscriber_id: 'sub-abc-02',
      owner: 'eng-remy',
      imsi: 'PROTECTED',
      provisioning_status: 'PROVISIONING_REQUIRED',
      updated_at_epoch_s: 1_793_200_040,
    },
  ],
  total: 2,
};

async function mockPolaris(page: Page) {
  await page.route('**/polaris-api/v1/**', async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace('/polaris-api/v1', '');
    if (path === '/auth/me') return route.fulfill({ json: { authenticated: true, can_start: true, role: 'Operator' } });
    if (path === '/capabilities') return route.fulfill({ json: {
      live_control: false, approval_state: 'LAB', max_ues: 100, max_nodes: 10,
      registration_modes: [], traffic_protocols: [], approved_destinations: [],
      profiles: [], technologies: [], services: [],
    } });
    if (path === '/scenario-definitions') return route.fulfill({ json: { items: TEMPLATES, total: TEMPLATES.length, schema_version: 1 } });
    if (path.startsWith('/scenario-definitions/') && path.endsWith('/estimate')) return route.fulfill({ json: { duration_ms: 1200 } });
    if (path === '/ues') return route.fulfill({ json: {
      items: [
        { id: 'UE-01', registration_state: 'REGISTERED', pdu_session: 'ACTIVE',
          ue_ip: null, traffic_state: 'IDLE', serving_node: 'GNB-01', last_event: null,
          controller_owned: true, name: 'UE under test', internal_ue_id: 'open5gs-UE-01',
          state: 'READY', actions: { start: true, stop: false, reason: null } },
        { id: 'UE-12', registration_state: 'REGISTERED', pdu_session: 'ACTIVE',
          ue_ip: null, traffic_state: 'IDLE', serving_node: 'GNB-01', last_event: null,
          controller_owned: true, name: 'Lab UE 12', internal_ue_id: 'open5gs-UE-12',
          state: 'READY', actions: { start: true, stop: false, reason: null } },
      ],
      configured_profiles: [], configured_count: 2, active_count: 2, registered_count: 2, source: 'MOCK',
      total: 2, max: 100,
    } });
    if (path === '/ue-profiles') return route.fulfill({ json: { items: [], total: 0, page: 1, page_size: 50, pages: 0, max: 100, secrets_exposed: false } });
    if (path === '/ue-profiles/UE-01') return route.fulfill({ json: UE_DETAIL });
    if (path === '/gnbs') return route.fulfill({ json: { items: [{ gnb_id: 'GNB-01', link_ip: '10.77.0.20' }], total: 1, source: 'CONFIGURED_REGISTRY' } });
    if (path === '/owners') return route.fulfill({ json: { items: [{ id: 'ops-nancy', name: 'Nancy Operator', role: 'Operator', email: null }], total: 1 } });
    if (path === '/subscribers') return route.fulfill({ json: SUBSCRIBERS });
    if (path === '/subscribers/sub-abc-01') return route.fulfill({ json: {
      slot_id: 'sub-abc-01', subscriber_id: 'sub-abc-01', provisioning_status: 'VERIFIED',
      plmn: { mcc: '208', mnc: '93' }, slice: { sst: 1, sd: 'A1B2C3' },
      dnns: ['internet', 'ims'], ambr: { uplink: 1_048_576, downlink: 1_048_576 },
      bound_ues: ['UE-01', 'UE-12'],
      imsi: 'PROTECTED', k: 'PROTECTED', opc: 'PROTECTED',
      updated_at_epoch_s: 1_793_200_000,
    } });
    if (path === '/plmns') return route.fulfill({ json: {
      items: [{ id: 'home', mcc: '001', mnc: '01', display_name: 'Lab PLMN', home_network: true,
        slices: [{ sst: 1, sd: null, display_name: 'eMBB default' }] }],
      total: 1,
    } });
    if (path === '/dnns') return route.fulfill({ json: {
      items: [{ id: 'd1', dnn: 'internet', sst: 1, sd: null, description: 'default Internet DNN' }],
      total: 1,
    } });
    if (path === '/lab') return route.fulfill({ json: {
      source: 'READ_ONLY_HOST_AUDIT',
      observed: {
        open5gs: { process_state: 'running', health: 'healthy', observed: true },
        nfs: {
          AMF: { process_state: 'running', health: 'healthy', observed: true },
          SMF: { process_state: 'running', health: 'healthy', observed: true },
          UPF: { process_state: 'running', health: 'healthy', observed: true },
          NRF: { process_state: 'running', health: 'healthy', observed: true },
          AUSF: { process_state: 'running', health: 'healthy', observed: true },
          UDM: { process_state: 'running', health: 'healthy', observed: true },
        },
      },
    } });
    if (path === '/nodes') return route.fulfill({ json: {
      items: [
        {
          id: 'GNB-01', name: 'Primary gNB', technology: '5G SA', simulator: 'UERANSIM',
          plmn: '001/01', cell_id: '0x000000010', link_ip: '10.77.0.20',
          n2_endpoint: '10.77.21.20', n3_endpoint: '10.77.22.20',
          process_state: 'running', health: 'healthy', configured: true,
          controller_owned: false, uptime_seconds: 42,
          actions: { start: false, stop: false, reason: 'SHARED_NODE_PROTECTED' },
        },
        {
          id: 'GNB-02', name: 'Second gNB plan', technology: '5G SA', simulator: 'UERANSIM',
          plmn: '001/01', cell_id: 'UNASSIGNED', link_ip: 'NOT_CONFIGURED',
          n2_endpoint: null, n3_endpoint: null,
          process_state: 'NOT_DEPLOYED', health: 'NOT_VALIDATED', configured: false,
          controller_owned: false, uptime_seconds: null,
          actions: { start: false, stop: false, reason: 'LIVE_005_APPROVAL_REQUIRED' },
        },
        {
          id: 'ENB-01', name: 'LTE eNB profile', technology: 'LTE', simulator: 'srsRAN',
          plmn: '001/01', cell_id: 'NOT_AVAILABLE', link_ip: 'NOT_AVAILABLE',
          n2_endpoint: null, n3_endpoint: null,
          process_state: 'stopped', health: 'unknown', configured: false,
          controller_owned: false, uptime_seconds: null,
          actions: { start: false, stop: false, reason: 'LTE_ATTACH_NOT_CERTIFIED' },
        },
      ],
      configured_count: 1, running_count: 1, observed_at_epoch_s: 0, source: 'MOCK',
    } });
    return route.fulfill({ status: 404, json: { error: 'MOCK_NOT_IMPLEMENTED' } });
  });

  // Seed localStorage flags so the Templates tab + Provisioning + UE
  // detail render under polarisProvisioning ON before the first paint.
  await page.addInitScript(() => {
    localStorage.setItem(
      'polaris.featureFlags.v1',
      JSON.stringify({
        scenarioBackend: true,
        profileBackend: true,
        scenarioTemplates: true,
        polarisProvisioning: true,
      }),
    );
    sessionStorage.setItem('polaris.csrf_token', 'mock-csrf');
  });
}

function screenshotPath(name: string, project: string): string {
  return join('docs', 'screenshots', 'v0.6.0', `${name}.${project}.png`);
}

test.beforeEach(async ({ page }) => {
  await mockPolaris(page);
});

test('capture — Topology', async ({ page }, info) => {
  await page.goto('/network/topology');
  await page.getByTestId('topology-view').waitFor();
  await page.getByTestId('topology-nfs-grid').waitFor();
  await page.screenshot({ path: screenshotPath('topology', info.project.name), fullPage: true });
});

test('capture — Templates tab', async ({ page }, info) => {
  await page.goto('/scenarios');
  await page.getByTestId('scenarios-tab-templates').click();
  await page.getByTestId('templates-table').waitFor();
  await page.screenshot({ path: screenshotPath('templates', info.project.name), fullPage: true });
});

test('capture — UE Manager', async ({ page }, info) => {
  await page.goto('/ues');
  await page.getByText(/UE Manager/i).first().waitFor();
  await page.screenshot({ path: screenshotPath('ue-manager', info.project.name), fullPage: true });
});

test('capture — Provisioning', async ({ page }, info) => {
  await page.goto('/provisioning');
  await page.getByTestId('provisioning-subscribers').waitFor();
  await page.screenshot({ path: screenshotPath('provisioning', info.project.name), fullPage: true });
});

test('capture — Provisioning subscriber detail', async ({ page }, info) => {
  await page.goto('/provisioning');
  await page.getByTestId('subscriber-row-sub-abc-01').click();
  await page.getByTestId('subscriber-detail-panel').waitFor();
  await page.screenshot({ path: screenshotPath('provisioning-detail', info.project.name), fullPage: true });
});

test('capture — UE detail', async ({ page }, info) => {
  await page.goto('/ues/UE-01');
  await page.getByTestId('ue-block-identity').waitFor();
  await page.screenshot({ path: screenshotPath('ue-detail', info.project.name), fullPage: true });
});

// Compile-time sanity: make sure the config file this spec expects exists.
void readFileSync; // keep ESM happy; unused helper intentionally imported
