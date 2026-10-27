import type { Page, Request, Route } from '@playwright/test';

const BACKEND_DATA = {
  probes: [
    {
      probe_id: 'oiran-vprobe-local-01',
      name: 'OIRAN vProbe · lab',
      host: 'lab-oiran-01.internal',
      probe_type: 'virtual',
      version: '2.3.0',
      health: 'HEALTHY',
      online: true,
      connected_interfaces: ['N2', 'N3', 'N4', 'SBI'],
      capture_state: 'READY',
      last_heartbeat: new Date().toISOString(),
      last_heartbeat_epoch_s: Math.floor(Date.now() / 1000),
      packet_rate_pps: null,
      decode_rate_eps: null,
      packet_drops: null,
      cpu_usage_percent: 14.3,
      memory_usage_bytes: 1_250_000_000,
      disk_usage_percent: 41.6,
      historical_packet_count: 54321,
      telemetry_status: 'MEASURED',
      distributed: false,
      capture_control_available: true,
    },
    {
      probe_id: 'oiran-pprobe-edge-02',
      name: 'OIRAN physical probe · edge',
      host: 'edge-oiran-02.internal',
      probe_type: 'physical',
      version: '2.3.0',
      health: 'DEGRADED',
      online: false,
      connected_interfaces: ['N3'],
      capture_state: 'OFFLINE',
      last_heartbeat: null,
      last_heartbeat_epoch_s: 0,
      packet_rate_pps: null,
      decode_rate_eps: null,
      packet_drops: null,
      cpu_usage_percent: null,
      memory_usage_bytes: null,
      disk_usage_percent: null,
      historical_packet_count: 0,
      telemetry_status: 'STALE',
      distributed: true,
    },
  ],
  interfaces: [
    {
      interface: 'N2',
      protocol: 'NGAP / SCTP',
      capture_point: 'gNB ↔ AMF',
      source: 'config',
      status: 'UP',
      device: 'veth-n2',
      live_capture_available: true,
      packet_count: 42000,
      file_size: 11_250_432,
      capture_start: '2026-10-27T10:04:00Z',
      capture_end: '2026-10-27T10:14:00Z',
    },
    {
      interface: 'N3',
      protocol: 'GTP-U / UDP',
      capture_point: 'gNB ↔ UPF',
      source: 'config',
      status: 'UP',
      device: 'veth-n3',
      live_capture_available: true,
      packet_count: 988000,
      file_size: 418_421_123,
      capture_start: '2026-10-27T10:04:00Z',
      capture_end: '2026-10-27T10:14:00Z',
    },
    {
      interface: 'N4',
      protocol: 'PFCP / UDP',
      capture_point: 'SMF ↔ UPF',
      source: 'config',
      status: 'UP',
      device: 'veth-n4',
      live_capture_available: false,
      reason: 'GATED_BY_DEPLOYMENT_POLICY',
      packet_count: 2100,
      file_size: 530_112,
      capture_start: '2026-10-27T10:04:00Z',
      capture_end: '2026-10-27T10:14:00Z',
    },
    {
      interface: 'SBI',
      protocol: 'HTTP/2',
      capture_point: 'AMF ↔ SMF',
      source: 'config',
      status: 'UP',
      device: 'veth-sbi',
      live_capture_available: true,
      packet_count: 15800,
      file_size: 5_320_112,
      capture_start: '2026-10-27T10:04:00Z',
      capture_end: '2026-10-27T10:14:00Z',
    },
  ],
  captures: [
    {
      capture_id: 'sha256:11aa22bb33cc44dd55ee66ff7788990011223344556677889900aabbccddeeff',
      name: 'POLARIS-5G-SA · bounded · 2026-10-27 10:04',
      interfaces: ['N2', 'N3', 'N4', 'SBI'],
      protocol: 'multiplane',
      checksum_sha256: '11aa22bb',
      packet_count: 1_045_900,
      decoded_messages: 212_312,
      size_bytes: 435_521_668,
      source: 'POLARIS_WEB_BOUNDED',
      status: 'COMPLETED',
      state: 'COMPLETED',
      dataset_id: 'ds-20261027-1004',
      dataset_kind: 'CAPTURED_LIVE',
      dataset_state: 'REGISTERED',
      probe_id: 'oiran-vprobe-local-01',
      technology: '5G SA',
      capture_group_id: 'cg-20261027',
      scenario_id: 'POLARIS-WEB-20261027-1004',
      planes: [
        {
          plane: 'N2',
          interface: 'N2',
          capture_job_id: 'job-n2-01',
          start_timestamp: Math.floor(Date.now() / 1000) - 600,
          end_timestamp: Math.floor(Date.now() / 1000) - 540,
          packet_count: 42000,
          byte_count: 11_250_432,
          storage_bytes: 11_250_432,
          decode_status: 'DECODED',
          dataset_id: 'ds-20261027-1004',
          source_sha256: ['11aa'],
        },
        {
          plane: 'N3',
          interface: 'N3',
          capture_job_id: 'job-n3-01',
          start_timestamp: Math.floor(Date.now() / 1000) - 600,
          end_timestamp: Math.floor(Date.now() / 1000) - 540,
          packet_count: 988000,
          byte_count: 418_421_123,
          storage_bytes: 418_421_123,
          decode_status: 'DECODED',
          dataset_id: 'ds-20261027-1004',
          source_sha256: ['11aa'],
        },
        {
          plane: 'N4',
          interface: 'N4',
          capture_job_id: 'job-n4-01',
          start_timestamp: Math.floor(Date.now() / 1000) - 600,
          end_timestamp: Math.floor(Date.now() / 1000) - 540,
          packet_count: 2100,
          byte_count: 530_112,
          storage_bytes: 530_112,
          decode_status: 'PARTIAL',
          dataset_id: 'ds-20261027-1004',
          source_sha256: ['11aa'],
        },
        {
          plane: 'SBI',
          interface: 'SBI',
          capture_job_id: 'job-sbi-01',
          start_timestamp: Math.floor(Date.now() / 1000) - 600,
          end_timestamp: Math.floor(Date.now() / 1000) - 540,
          packet_count: 15800,
          byte_count: 5_320_112,
          storage_bytes: 5_320_112,
          decode_status: 'DECODED',
          dataset_id: 'ds-20261027-1004',
          source_sha256: ['11aa'],
        },
      ],
    },
    {
      capture_id: 'sha256:aabbccddee00112233445566778899001122334455667788990011aabbccddee',
      name: 'LIVE · bounded · in progress',
      interfaces: ['N3'],
      protocol: 'GTP-U',
      packet_count: null,
      size_bytes: null,
      state: 'CAPTURING',
      dataset_id: null,
      dataset_kind: undefined,
      probe_id: 'oiran-vprobe-local-01',
      technology: '5G SA',
      capture_group_id: 'cg-20261027',
      scenario_id: null,
      planes: [
        {
          plane: 'N3',
          interface: 'N3',
          capture_job_id: 'job-live-01',
          start_timestamp: Math.floor(Date.now() / 1000) - 60,
          end_timestamp: null,
          packet_count: 108_000,
          byte_count: 45_212_112,
          storage_bytes: 45_212_112,
          decode_status: 'DECODING',
          dataset_id: null,
          source_sha256: [],
        },
      ],
      metrics: {
        packets_received: 108_000,
        bytes_received: 45_212_112,
        packets_per_second: 1800,
        bits_per_second: 6_030_000,
        decoded_events: 24_000,
        decode_errors: 0,
        packet_drops: 0,
        storage_bytes: 45_212_112,
      },
    },
    {
      capture_id: 'sha256:ffff0011223344556677889900aabbccddeeff00112233445566778899aabbcc',
      name: 'historical · regression · 2026-10-20',
      interfaces: ['N2', 'SBI'],
      protocol: 'multiplane',
      packet_count: 85_000,
      size_bytes: 32_521_112,
      state: 'COMPLETED',
      dataset_id: 'ds-20261020-regression',
      dataset_kind: 'HISTORICAL',
      probe_id: 'oiran-vprobe-local-01',
      technology: '5G SA',
    },
  ],
  metrics: {
    observed_at_epoch_s: Math.floor(Date.now() / 1000),
    mode: 'HISTORICAL',
    packet_rate_pps: null,
    bitrate_bps: null,
    decode_rate_eps: null,
    packet_drops: null,
    capture_queue_utilization_percent: null,
    active_captures: 1,
    active_sessions: 0,
    historical_sessions: 128,
    historical_events: 1_324_000,
    decode_errors: 42,
    cpu: { usage_percent: 11.2, load_one: 0.42, logical_cpus: 16 },
    memory: {
      total_bytes: 16_000_000_000,
      available_bytes: 8_400_000_000,
      used_bytes: 7_600_000_000,
    },
    disk: {
      usage_percent: 41.6,
      available_bytes: 220_000_000_000,
      available_inodes: 1_200_000,
    },
    interfaces: [
      { interface: 'N2', state: 'UP', packet_rate_pps: null },
      { interface: 'N3', state: 'UP', packet_rate_pps: 1800 },
      { interface: 'N4', state: 'UP', packet_rate_pps: null },
      { interface: 'SBI', state: 'UP', packet_rate_pps: null },
    ],
  },
  storageSafety: {
    filesystem: {
      total_bytes: 500_000_000_000,
      used_bytes: 208_000_000_000,
      available_bytes: 292_000_000_000,
      usage_percent: 41.6,
      total_inodes: 10_000_000,
      available_inodes: 8_400_000,
    },
    decision: {
      state: 'INFORMATION',
      new_capture_allowed: true,
      active_capture_must_finalize: false,
      read_only_analysis_allowed: true,
      reason: 'HEADROOM_SUFFICIENT',
    },
    budget: {
      allowed: true,
      requested_bytes: 268_435_456,
      maximum_allowed_bytes: 1_073_741_824,
      headroom_to_stop_bytes: 50_000_000_000,
      reserved_bytes: 0,
      reason: 'OK',
    },
    rotation: {
      max_file_bytes: 67_108_864,
      max_files: 4,
      maximum_job_bytes: 268_435_456,
      max_job_seconds: 900,
    },
    policy: {
      information_percent: 75,
      warning_percent: 80,
      stop_percent: 85,
      hard_limit_percent: 90,
      polling_interval_ms: 1000,
    },
    capture_job: { state: 'READY', active: false, writes_enabled: true },
    monitoring: {
      poll_interval_ms: 1000,
      event_driven_limit: 'informational',
      failure_mode: 'close_write_path',
    },
  },
  auth: {
    authenticated: false,
    role: 'viewer',
    permissions: [],
    capture_control: false,
    capture_execution_enabled: false,
    reason: 'READ_ONLY_VIEWER',
  },
  systemHealth: {
    cpu: { usage_percent: 11.2, idle_percent: 88.8, logical_cpus: 16 },
    memory: {
      total_bytes: 16_000_000_000,
      available_bytes: 8_400_000_000,
      used_bytes: 7_600_000_000,
    },
    disk: {
      usage_percent: 41.6,
      available_bytes: 220_000_000_000,
      available_inodes: 1_200_000,
    },
    decision: {
      writes_allowed: true,
      reason: 'Headroom sufficient',
      maximum_budget_bytes: 1_073_741_824,
    },
    load_average: '0.42 0.38 0.33',
  },
};

type MockMode = 'populated' | 'empty';

type Meta = Record<string, unknown>;

export async function installMockApi(page: Page, mode: MockMode = 'populated') {
  const payload = (data: unknown, meta: Meta = {}) => ({ data, meta });

  const empty: Record<string, unknown> = {
    probes: [],
    interfaces: [],
    captures: [],
    storageSafety: {
      filesystem: null,
      decision: { state: 'UNKNOWN', new_capture_allowed: false, active_capture_must_finalize: false, read_only_analysis_allowed: true, reason: 'no data' },
      budget: { allowed: false, requested_bytes: 0, maximum_allowed_bytes: 0, headroom_to_stop_bytes: 0, reserved_bytes: 0, reason: 'no data' },
      rotation: { max_file_bytes: 0, max_files: 0, maximum_job_bytes: 0, max_job_seconds: 0 },
      policy: { information_percent: 0, warning_percent: 0, stop_percent: 0, hard_limit_percent: 0, polling_interval_ms: 0 },
      capture_job: { state: 'UNKNOWN', active: false, writes_enabled: false },
      monitoring: { poll_interval_ms: 0, event_driven_limit: 'none', failure_mode: 'none' },
    },
    metrics: {
      observed_at_epoch_s: 0,
      mode: 'UNKNOWN',
      packet_rate_pps: null,
      bitrate_bps: null,
      decode_rate_eps: null,
      packet_drops: null,
      capture_queue_utilization_percent: null,
      active_captures: 0,
      active_sessions: 0,
      historical_sessions: 0,
      historical_events: 0,
      decode_errors: 0,
      cpu: { usage_percent: null, load_one: null, logical_cpus: 0 },
      memory: { total_bytes: null, available_bytes: null, used_bytes: null },
      disk: null,
      interfaces: [],
    },
    auth: BACKEND_DATA.auth,
    systemHealth: BACKEND_DATA.systemHealth,
  };

  const source = mode === 'populated' ? BACKEND_DATA : empty;

  const handler = async (route: Route, request: Request) => {
    const url = new URL(request.url());
    const path = url.pathname.replace(/^.*\/api\/v1/, '').replace(/^.*\/polaris-api\/v1/, '');

    // Capture pagination honors ?page / ?page_size exactly like the backend
    // would — Section 4 of the review.
    if (/^\/captures(\?.*)?$/.test(path)) {
      const captures = source.captures as unknown[];
      const page = Number(url.searchParams.get('page') ?? '1');
      const pageSize = Number(url.searchParams.get('page_size') ?? String(captures.length));
      const start = (page - 1) * pageSize;
      const slice = captures.slice(start, start + pageSize);
      await route.fulfill({
        status: 200,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(
          payload(slice, {
            total: captures.length,
            total_pages: Math.max(1, Math.ceil(captures.length / pageSize)),
            page,
            page_size: pageSize,
          }),
        ),
      });
      return;
    }

    const map: Array<[RegExp, unknown]> = [
      [/^\/probes$/, source.probes],
      [/^\/probes\/[^/]+$/, (source.probes as unknown[])?.[0] ?? null],
      [/^\/probes\/[^/]+\/interfaces$/, source.interfaces],
      [/^\/interfaces$/, source.interfaces],
      [/^\/metrics$/, source.metrics],
      [/^\/storage\/safety$/, source.storageSafety],
      [/^\/auth\/me$/, source.auth],
      [/^\/system\/health$/, { status: 'ok', service: 'POLARIS Control' }],
      [/^\/health$/, { status: 'healthy', backend_api: '2.3.0' }],
      [/^\/version$/, { backend_api: '2.3.0' }],
    ];
    for (const [pattern, data] of map) {
      if (pattern.test(path)) {
        await route.fulfill({
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(payload(data)),
        });
        return;
      }
    }
    await route.fulfill({
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload([])),
    });
  };

  // Route both the OIRAN API base and the per-app POLARIS API base.
  await page.route('**/api/v1/**', handler);
  await page.route('**/polaris-api/v1/**', handler);
}
