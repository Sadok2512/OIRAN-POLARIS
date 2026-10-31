import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Plugin } from 'vite';

const now = 1_799_000_000;

const processObservation = (state: string, owned = false) => ({
  process_state: state,
  health: state === 'running' ? 'healthy' : 'unknown',
  observed: true,
  controller_owned: owned,
  last_error: null,
});

const ueItems = [
  {
    id: 'UE-201', internal_ue_id: 'UE-00201', profile: 'DEMO mirror of sanitized UE-201 state',
    profile_state: 'VERIFIED', subscription_status: 'PROTECTED', serving_node: 'GNB-DEMO-01',
    process_state: 'STOPPED', registration_state: 'DEREGISTERED', rrc_state: 'UNKNOWN',
    pdu_session: 'INACTIVE', ue_ip: null, traffic_state: 'IDLE', last_event: null,
    controller_owned: true, dnn: 'internet', active_sessions: 0,
    actions: { start: false, stop: false, pdu_start: false, pdu_stop: false, traffic: false, reason: 'DEMO_READ_ONLY' },
  },
  {
    id: 'LTE-SRSUE-TEST-01', profile: 'DEMO LTE 4G', profile_state: 'VERIFIED',
    subscription_status: 'PROTECTED', serving_node: 'ENB-DEMO-01', process_state: 'running',
    registration_state: 'ATTACHED', rrc_state: 'CONNECTED', pdu_session: 'ACTIVE', ue_ip: '10.45.0.10',
    traffic_state: 'COMPLETED', last_event: 'DEMO_UDP_UL_DL_COMPLETE', controller_owned: true,
    technology: 'LTE 4G', simulator: 'srsRAN', attach_state: 'ATTACHED', access_point_name: 'internet',
    active_sessions: 1, actions: { start: false, stop: false, pdu_start: false, pdu_stop: false, traffic: false, reason: 'DEMO_READ_ONLY' },
  },
];

const ueProfiles = [
  {
    authentication_material: 'PROTECTED', auto_run_scenario: false, dnn: 'internet',
    name: 'DEMO UE-01', pdu_session: { dnn: 'internet', type: 'IPv4' },
    plmn: { mcc: '001', mnc: '01' }, profile: 'demo-ue-01.yaml', revision: 1,
    scenario_id: null, serving_gnb: 'GNB-DEMO-01', snssai: { sd: '010203', sst: 1 },
    subscriber_identity: 'PROTECTED', subscription_status: 'VERIFIED', ue_id: 'UE-01',
    updated_at_epoch_s: now,
  },
  {
    authentication_material: 'PROTECTED', auto_run_scenario: false, dnn: 'internet',
    name: 'DEMO UE-201', pdu_session: { dnn: 'internet', type: 'IPv4' },
    plmn: { mcc: '001', mnc: '01' }, profile: 'demo-ue-201.yaml', revision: 1,
    scenario_id: null, serving_gnb: 'GNB-DEMO-01', snssai: { sd: '010203', sst: 1 },
    subscriber_identity: 'PROTECTED', subscription_status: 'VERIFIED', ue_id: 'UE-201',
    updated_at_epoch_s: now,
  },
  {
    authentication_material: 'PROTECTED', auto_run_scenario: false, dnn: 'internet',
    name: 'DEMO LTE 4G UE', pdu_session: { dnn: 'internet', type: 'IPv4' },
    plmn: { mcc: '001', mnc: '01' }, profile: 'demo-lte.yaml', revision: 1,
    scenario_id: null, serving_gnb: 'ENB-DEMO-01', snssai: { sd: null, sst: 1 },
    subscriber_identity: 'PROTECTED', subscription_status: 'VERIFIED', ue_id: 'LTE-SRSUE-TEST-01',
    updated_at_epoch_s: now,
  },
];

const trafficSessions = [
  {
    session_id: 'traffic-demo-lte', state: 'COMPLETED',
    request: { ue_ids: ['LTE-SRSUE-TEST-01'], direction: 'BOTH', protocol: 'UDP', rate_mbps: 1, duration_s: 30 },
    ue_counters: [{ ue_id: 'LTE-SRSUE-TEST-01', packets_ul: 3125, packets_dl: 3125, bytes_ul: 3_750_000, bytes_dl: 3_750_000, rate_ul_bps: 998_400, rate_dl_bps: 996_800, warnings: [] }],
    started_at_epoch_s: now - 120, ended_at_epoch_s: now - 90, warnings: [],
  },
  {
    session_id: 'traffic-demo-5g', state: 'COMPLETED',
    request: { ue_ids: ['UE-201'], direction: 'BOTH', protocol: 'TCP', rate_mbps: 5, duration_s: 30 },
    ue_counters: [{ ue_id: 'UE-201', packets_ul: 0, packets_dl: 0, bytes_ul: 18_750_000, bytes_dl: 18_500_000, rate_ul_bps: 5_000_000, rate_dl_bps: 4_930_000, warnings: [] }],
    started_at_epoch_s: now - 180, ended_at_epoch_s: now - 150, warnings: [],
  },
];

function response(path: string): unknown {
  if (path === '/auth/me') return { authenticated: true, username: 'DEMO', role: 'viewer', can_start: false, can_manage_permissions: false, csrf_token: null };
  if (path === '/capabilities') return {
    live_control: false, approval_state: 'DEMO_READ_ONLY', max_ues: 10, max_nodes: 2,
    registration_modes: ['5G_SA', 'LTE'], traffic_protocols: ['UDP', 'TCP'], approved_destinations: [],
    profiles: [],
    technologies: [
      { id: 'nr', name: '5G SA', simulator: 'UERANSIM', available: true, certified: true, node_label: 'gNB' },
      { id: 'lte', name: 'LTE 4G', simulator: 'srsRAN', available: true, certified: false, node_label: 'eNB', reason: 'DEMO_ONLY' },
    ],
    services: [],
    scenario_step_kinds: ['ue_start', 'pdu_establish', 'traffic_ul', 'traffic_dl', 'lte_attach', 'lte_detach', 'lte_traffic_ul', 'lte_traffic_dl', 'lte_attach_data', 'wait'],
    executable_scenario_step_types: [],
  };
  if (path === '/scenario-capabilities') return { items: [], execution_status: 'DEMO_READ_ONLY', reason: 'DEMO_READ_ONLY', role: 'viewer' };
  if (path === '/lab') return {
    ue_count: 3, desired_ue_count: 3, gnb_count: 2, max_ues: 10, max_gnbs: 2,
    max_ues_live_certified: 0, max_gnbs_live_certified: 0, missing_subscriber_profiles: 0,
    updated_at_epoch_s: now, updated_by: 'DEMO', observed_controller_running: 2, observed_total_running: 2,
    reconciliation: { operation_id: null, desired_count: 2, state: 'IDLE', started_at_epoch_s: null, completed_at_epoch_s: null, started: [], stopped: [], failures: [] },
    execution_started: false, source: 'DEMO_SYNTHETIC',
    observed: {
      open5gs: processObservation('running'),
      nfs: Object.fromEntries(
        ['AMF', 'SMF', 'UPF', 'NRF', 'AUSF', 'UDM', 'UDR', 'PCF', 'NSSF', 'BSF', 'MME', 'SGWC', 'SGWU', 'HSS', 'PCRF']
          .map((nf) => [nf, processObservation('running')]),
      ),
      ueransim_gnb: processObservation('running'), ueransim_ue: processObservation('running', true),
      srsran_enb: processObservation('running', true), srsran_ue: processObservation('running', true),
      lte_attach: 'ATTACHED',
    },
  };
  if (path === '/system/health') return { cpu: { usage_percent: 18, idle_percent: 82, logical_cpus: 8 }, memory: { total_bytes: 16_000_000_000, available_bytes: 9_000_000_000, used_bytes: 7_000_000_000 }, disk: { total_bytes: 400_000_000_000, used_bytes: 280_000_000_000, available_bytes: 120_000_000_000, usage_percent: 70 }, decision: { state: 'DEMO', writes_allowed: false, reason: 'DEMO_READ_ONLY', maximum_budget_bytes: 0 }, load_average: '0.35 0.42 0.40', uptime_seconds: 86_400, observed_at_epoch_s: now };
  if (path === '/ues') return {
    items: ueItems,
    configured_profiles: [
      { id: 'UE-01', profile: 'demo-ue-01.yaml', serving_gnb: 'GNB-DEMO-01', simulator: 'UERANSIM', state: 'CONFIGURED', configured: true, controller_owned: false, subscription_status: 'VERIFIED' },
      { id: 'UE-201', profile: 'demo-ue-201.yaml', serving_gnb: 'GNB-DEMO-01', simulator: 'UERANSIM', state: 'STOPPED', configured: true, controller_owned: true, subscription_status: 'VERIFIED' },
      { id: 'LTE-SRSUE-TEST-01', profile: 'demo-lte.yaml', serving_gnb: 'ENB-DEMO-01', simulator: 'srsRAN', state: 'CONFIGURED', configured: true, controller_owned: true, subscription_status: 'VERIFIED' },
    ],
    configured_count: 3, active_count: 1, registered_count: 1, pdu_session_count: 1,
    source: 'DEMO_SYNTHETIC',
  };
  if (path.startsWith('/ue-profiles/provisioning-slots')) return { items: [], total: 0, secrets_exposed: false };
  if (path.startsWith('/ue-profiles')) return { items: ueProfiles, total: ueProfiles.length, page: 1, page_size: 10, pages: 1, max: 10, secrets_exposed: false };
  if (path === '/nodes' || path === '/gnbs') return {
    items: [
      { id: 'GNB-DEMO-01', name: 'DEMO 5G gNB', technology: '5G SA', simulator: 'UERANSIM', plmn: '001-01', cell_id: '0xDEMO01', link_ip: '10.77.0.20', n2_endpoint: '10.77.21.20', n3_endpoint: '10.77.22.20', process_state: 'running', health: 'healthy', configured: true, controller_owned: false, uptime_seconds: 3600, actions: { start: false, stop: false, reason: 'DEMO_READ_ONLY' } },
      { id: 'ENB-DEMO-01', name: 'DEMO LTE eNB', technology: 'LTE', simulator: 'srsRAN', plmn: '001-01', cell_id: '0xDEMO02', link_ip: '10.77.0.30', n2_endpoint: '10.77.31.30', n3_endpoint: '10.77.32.30', process_state: 'running', health: 'healthy', configured: true, controller_owned: true, uptime_seconds: 1800, actions: { start: false, stop: false, reason: 'DEMO_READ_ONLY' } },
    ], configured_count: 2, running_count: 2, observed_at_epoch_s: now, source: 'DEMO_SYNTHETIC',
  };
  if (path === '/lte/status') return {
    technology: 'LTE 4G', simulator: 'srsRAN', certified: false, live_enabled: false,
    epc: processObservation('running'), s1_state: 'CONNECTED', enb: processObservation('running', true), ue: processObservation('running', true),
    ue_id: 'LTE-SRSUE-TEST-01', attach_state: 'ATTACHED', apn: 'internet', ue_ip: '10.45.0.10', active_sessions: 1,
    session_state: 'ACTIVE', ownership_verified: true, traffic_ready: false, grant_active: false, safety_ready: true, traffic_allowed: false,
  };
  if (path === '/lte/profiles/LTE-SRSUE-TEST-01') return { schema_version: 'polaris.lte-profile.v1', profile_id: 'LTE-SRSUE-TEST-01', revision: 1, owner: 'POLARIS_CONTROLLER', enabled: false, runtime_state: 'DEMO', apn: 'internet', max_running_ues: 1, configuration_sha256: '0'.repeat(64), scenario_id: 'lte-e2e-certification-v1', scenario_revision: 1, scenario_sha256: '0'.repeat(64), grant_required: true, evidence_schema: 'polaris.lte-evidence.v1' };
  if (path.startsWith('/lte/logs')) return { component: 'DEMO', lines: ['[DEMO] synthetic sanitized log — no live simulator'], redacted: true };
  if (path === '/traffic/status') return { state: 'COMPLETED', packets_requested: 6250, packets_sent: 6250, packets_received: 6248, bytes: 7_500_000, accounting_source: 'DEMO_SYNTHETIC', target_ue_id: 'LTE-SRSUE-TEST-01', target_ue_pseudonym: 'PROTECTED', tun_interface: 'tun_demo', last_result: null, approved_destinations: [], traffic_ul: { measured_sender_bytes: 3_750_000, measured_ue_bytes: 3_749_000 }, traffic_dl: { measured_sender_bytes: 3_750_000, measured_ue_bytes: 3_748_000 }, dl_sender_state: 'DEMO_HEALTHY', dl_sender_available: true };
  if (path === '/traffic/sessions') return { items: trafficSessions, total: trafficSessions.length };
  if (/^\/traffic\/sessions\/[^/]+\/samples$/.test(path)) return { session_id: path.split('/')[3], samples_ring_max: 60, items: Array.from({ length: 12 }, (_, index) => ({ epoch_s: now - 12 + index, bytes_ul_cum: index * 125_000, bytes_dl_cum: index * 124_000, rate_ul_bps: 1_000_000, rate_dl_bps: 992_000 })) };
  if (path === '/scenarios/status') return { active_job: null, latest_terminal_job: null, active_count: 0, history_count: 2, observed_at_epoch_s: now, source: 'DEMO_SYNTHETIC' };
  if (path === '/scenarios/history' || path === '/scenarios') return { items: [], total: 0, source: 'DEMO_SYNTHETIC', live_execution: false, note: 'DEMO READ-ONLY' };
  if (path === '/scenario-definitions') return { schema_version: 'polaris.scenario-catalog.v2', items: [], total: 0 };
  if (path === '/live/grant') return { grants: [], lte_grants: [], max_minutes: 5, server_now_epoch_ms: String(now * 1000) };
  if (path === '/subscribers') return { items: [], total: 0, identity_visibility: 'PROTECTED', secrets_exposed: false };
  if (path === '/owners') return { items: ['DEMO'] };
  if (path === '/plmns') return { items: [{ mcc: '001', mnc: '01' }] };
  if (path === '/dnns') return { items: ['internet'] };
  return { items: [], total: 0, source: 'DEMO_SYNTHETIC' };
}

function handler(req: IncomingMessage, res: ServerResponse, next: () => void) {
  const url = new URL(req.url ?? '/', 'http://127.0.0.1');
  if (!url.pathname.startsWith('/polaris-api/v1')) return next();
  res.setHeader('content-type', 'application/json');
  res.setHeader('cache-control', 'no-store');
  if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method ?? 'GET')) {
    res.statusCode = 423;
    res.end(JSON.stringify({ error: 'DEMO_READ_ONLY', demo: true }));
    return;
  }
  const path = url.pathname.slice('/polaris-api/v1'.length) || '/';
  res.statusCode = 200;
  res.end(JSON.stringify(response(path)));
}

export function demoApiPlugin(): Plugin {
  return {
    name: 'polaris-demo-read-only-api',
    configureServer(server) {
      server.middlewares.use(handler);
    },
    configurePreviewServer(server) {
      server.middlewares.use(handler);
    },
  };
}
