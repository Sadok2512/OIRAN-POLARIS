import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  allowedBasesForScope,
  api,
  ApiError,
  applyAuthHeader,
  authenticatedDownload,
  classifyHttpStatus,
  getAccessToken,
  isBaseAuthorizedForScope,
  scopeStorageKey,
  setAccessToken,
} from '@shared/api';
import type {
  Capture,
  CaptureInterface,
  DiskSafety,
  Probe,
} from '@shared/types';

function respond(status: number, body: unknown, extraHeaders: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...extraHeaders },
  });
}

type FetchCall = { url: string; init?: RequestInit };
const calls: FetchCall[] = [];

function stub(responder: (url: string) => Response) {
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    calls.push({ url, init });
    return responder(url);
  }) as unknown as typeof fetch;
}

beforeEach(() => {
  calls.length = 0;
  sessionStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('shared api — authentication scope isolation (PR #2 Section 3)', () => {
  it('does not attach Authorization when no scope is specified', async () => {
    sessionStorage.setItem(scopeStorageKey('oiran'), 'oiran-token');
    stub(() => respond(200, { data: {}, meta: {} }));
    await api('/health');
    const headers = new Headers(calls[0].init?.headers);
    expect(headers.get('authorization')).toBeNull();
  });

  it('attaches the OIRAN token when authScope="oiran" and a token exists', async () => {
    sessionStorage.setItem(scopeStorageKey('oiran'), 'oiran-token');
    stub(() => respond(200, { data: {}, meta: {} }));
    await api('/probes', { authScope: 'oiran' });
    const headers = new Headers(calls[0].init?.headers);
    expect(headers.get('authorization')).toBe('Bearer oiran-token');
  });

  it('does NOT attach a POLARIS token when the request names the OIRAN scope', async () => {
    sessionStorage.setItem(scopeStorageKey('polaris'), 'polaris-token');
    stub(() => respond(200, { data: {}, meta: {} }));
    await api('/probes', { authScope: 'oiran' });
    const headers = new Headers(calls[0].init?.headers);
    expect(headers.get('authorization')).toBeNull();
  });

  it('does NOT attach a token to an absolute cross-origin URL even if scope matches', async () => {
    sessionStorage.setItem(scopeStorageKey('oiran'), 'oiran-token');
    stub(() => respond(200, { data: {}, meta: {} }));
    await api('/anything', {
      authScope: 'oiran',
      base: 'https://other-origin.example.com/api/v1',
    });
    const headers = new Headers(calls[0].init?.headers);
    expect(headers.get('authorization')).toBeNull();
  });

  it('setAccessToken writes to the per-scope session storage key', () => {
    setAccessToken('polaris', 't');
    expect(sessionStorage.getItem(scopeStorageKey('polaris'))).toBe('t');
    expect(getAccessToken('polaris')).toBe('t');
    expect(getAccessToken('oiran')).toBeNull();
  });
});

describe('shared api — scope ↔ base allowlist (PR #2 final review)', () => {
  it('publishes a non-empty allowlist per scope', () => {
    expect(allowedBasesForScope('oiran')).toContain('/api/v1');
    expect(allowedBasesForScope('polaris')).toContain('/polaris-api/v1');
    expect(allowedBasesForScope('probe-manager')).toContain('/api/v1');
  });

  it('isBaseAuthorizedForScope rejects a same-origin base that targets a different service', () => {
    // OIRAN scope must NOT be authorized to reach /polaris-api/v1 even
    // though both are same-origin.
    expect(isBaseAuthorizedForScope('/polaris-api/v1', 'oiran')).toBe(false);
    expect(isBaseAuthorizedForScope('/polaris-api/v1', 'polaris')).toBe(true);
  });

  it('isBaseAuthorizedForScope rejects ambiguous paths that only share a prefix lexically', () => {
    // "/api/v1-admin" starts lexically with "/api/v1" but is a different
    // service — must NOT inherit the oiran token.
    expect(isBaseAuthorizedForScope('/api/v1-admin', 'oiran')).toBe(false);
    expect(isBaseAuthorizedForScope('/api/v1/admin', 'oiran')).toBe(true);
    expect(isBaseAuthorizedForScope('/api/v1', 'oiran')).toBe(true);
  });

  it('applyAuthHeader does NOT attach the oiran token to a same-origin /polaris-api/v1 base', async () => {
    sessionStorage.setItem(scopeStorageKey('oiran'), 'oiran-token');
    stub(() => respond(200, { data: {}, meta: {} }));
    await api('/something', { authScope: 'oiran', base: '/polaris-api/v1' });
    const headers = new Headers(calls[0].init?.headers);
    expect(headers.get('authorization')).toBeNull();
  });

  it('applyAuthHeader does NOT attach the polaris token to the /api/v1 base', async () => {
    sessionStorage.setItem(scopeStorageKey('polaris'), 'polaris-token');
    stub(() => respond(200, { data: {}, meta: {} }));
    await api('/something', { authScope: 'polaris', base: '/api/v1' });
    const headers = new Headers(calls[0].init?.headers);
    expect(headers.get('authorization')).toBeNull();
  });

  it('attaches the token to any sub-path of an allowlisted base', () => {
    const headers = new Headers();
    sessionStorage.setItem(scopeStorageKey('oiran'), 'tok');
    applyAuthHeader(headers, 'oiran', '/api/v1');
    expect(headers.get('authorization')).toBe('Bearer tok');
    const headers2 = new Headers();
    applyAuthHeader(headers2, 'oiran', '/api/v1/captures');
    expect(headers2.get('authorization')).toBe('Bearer tok');
  });
});

describe('shared api — authenticatedDownload (PR #2 final review)', () => {
  const createBlobUrlMock = vi.fn(() => 'blob:mock-url');
  const revokeBlobUrlMock = vi.fn();

  beforeEach(() => {
    createBlobUrlMock.mockClear();
    revokeBlobUrlMock.mockClear();
    (globalThis as unknown as { URL: typeof URL }).URL.createObjectURL = createBlobUrlMock as unknown as typeof URL.createObjectURL;
    (globalThis as unknown as { URL: typeof URL }).URL.revokeObjectURL = revokeBlobUrlMock as unknown as typeof URL.revokeObjectURL;
  });

  it('sends Authorization: Bearer and never puts the token in the URL', async () => {
    sessionStorage.setItem(scopeStorageKey('oiran'), 'secret-token');
    stub(() =>
      new Response(new Uint8Array([1, 2, 3]), {
        status: 200,
        headers: {
          'content-type': 'application/vnd.tcpdump.pcap',
          'content-disposition': 'attachment; filename="capture.pcap"',
        },
      }),
    );
    const dl = await authenticatedDownload(
      '/captures/sha256:aa/download',
      { authScope: 'oiran' },
    );
    expect(calls[0].url).not.toContain('secret-token');
    expect(calls[0].url).not.toMatch(/token=|access_token=|bearer=/i);
    const headers = new Headers(calls[0].init?.headers);
    expect(headers.get('authorization')).toBe('Bearer secret-token');
    expect(dl.objectUrl).toBe('blob:mock-url');
    expect(dl.filename).toBe('capture.pcap');
    dl.revoke();
    expect(revokeBlobUrlMock).toHaveBeenCalledWith('blob:mock-url');
  });

  it('refuses the download when authScope has no token available', async () => {
    stub(() => respond(200, { data: {}, meta: {} }));
    await expect(
      authenticatedDownload('/x', { authScope: 'oiran' }),
    ).rejects.toMatchObject({
      status: 401,
      code: 'MISSING_OR_UNAUTHORIZED_TOKEN',
    });
    expect(calls.length).toBe(0);
  });

  it('refuses the download when authScope cannot reach the base', async () => {
    sessionStorage.setItem(scopeStorageKey('oiran'), 'secret-token');
    stub(() => respond(200, { data: {}, meta: {} }));
    await expect(
      authenticatedDownload('/x', {
        authScope: 'oiran',
        base: '/polaris-api/v1',
      }),
    ).rejects.toMatchObject({
      status: 401,
      code: 'MISSING_OR_UNAUTHORIZED_TOKEN',
    });
    expect(calls.length).toBe(0);
  });

  it('surfaces non-2xx responses as ApiError', async () => {
    sessionStorage.setItem(scopeStorageKey('oiran'), 'secret-token');
    stub(() =>
      respond(403, { error: { code: 'FORBIDDEN', message: 'nope' } }),
    );
    await expect(
      authenticatedDownload('/x', { authScope: 'oiran' }),
    ).rejects.toMatchObject({ status: 403, code: 'FORBIDDEN' });
  });
});

describe('shared api — HTTP status classification (PR #2 Section 3)', () => {
  it.each([
    [200, 'ok'],
    [201, 'ok'],
    [301, 'degraded'],
    [401, 'auth-required'],
    [403, 'auth-required'],
    [404, 'degraded'],
    [500, 'degraded'],
    [503, 'degraded'],
  ] as const)('status %d → %s', (status, expected) => {
    expect(classifyHttpStatus(status)).toBe(expected);
  });
});

describe('shared api — error envelope handling', () => {
  it('throws ApiError with code+message when the body is an OIRAN error envelope', async () => {
    stub(() =>
      respond(401, {
        error: { code: 'UNAUTHENTICATED', message: 'Missing bearer' },
      }),
    );
    await expect(api('/anything')).rejects.toMatchObject({
      status: 401,
      code: 'UNAUTHENTICATED',
      message: 'Missing bearer',
    });
  });

  it('falls back to REQUEST_FAILED when the error body is malformed', async () => {
    stub(() => respond(500, 'not JSON at all'));
    await expect(api('/anything')).rejects.toBeInstanceOf(ApiError);
  });

  it('surfaces network errors (fetch rejection) as a plain Error', async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new TypeError('Failed to fetch');
    }) as unknown as typeof fetch;
    await expect(api('/anything')).rejects.toMatchObject({
      name: 'TypeError',
    });
  });
});

describe('OIRAN v1 contract — null / missing field tolerance', () => {
  it('accepts a Probe envelope that reports no telemetry (nullable fields)', async () => {
    const probe: Probe = {
      probe_id: 'p1',
      name: 'p1',
      host: 'h',
      probe_type: 'virtual',
      version: '',
      health: 'UNKNOWN',
      online: false,
      connected_interfaces: [],
      capture_state: 'OFFLINE',
      packet_rate_pps: null,
      decode_rate_eps: null,
      packet_drops: null,
      cpu_usage_percent: null,
      memory_usage_bytes: null,
      disk_usage_percent: null,
      historical_packet_count: 0,
      telemetry_status: 'STALE',
      distributed: false,
    };
    stub(() => respond(200, { data: [probe], meta: {} }));
    const envelope = await api<Probe[]>('/probes');
    expect(envelope.data[0].packet_rate_pps).toBeNull();
    expect(envelope.data[0].memory_usage_bytes).toBeNull();
  });

  it('accepts a CaptureInterface where live_capture_available is false and reason is populated', async () => {
    const iface: CaptureInterface = {
      interface: 'N4',
      protocol: 'PFCP',
      capture_point: 'SMF↔UPF',
      source: 'config',
      status: 'DOWN',
      live_capture_available: false,
      reason: 'GATED_BY_DEPLOYMENT_POLICY',
      packet_count: null,
      file_size: null,
      capture_start: null,
      capture_end: null,
    };
    stub(() => respond(200, { data: [iface], meta: {} }));
    const envelope = await api<CaptureInterface[]>('/interfaces');
    expect(envelope.data[0].live_capture_available).toBe(false);
    expect(envelope.data[0].reason).toBe('GATED_BY_DEPLOYMENT_POLICY');
  });

  it('accepts an empty captures list without raising', async () => {
    stub(() => respond(200, { data: [], meta: { total: 0, total_pages: 1 } }));
    const envelope = await api<Capture[]>('/captures');
    expect(envelope.data).toEqual([]);
    expect(envelope.meta.total).toBe(0);
  });

  it('accepts a DiskSafety envelope where filesystem is null (no measurement)', async () => {
    const safety: DiskSafety = {
      filesystem: null,
      decision: {
        state: 'UNKNOWN',
        new_capture_allowed: false,
        active_capture_must_finalize: false,
        read_only_analysis_allowed: true,
        reason: 'no data',
      },
      budget: {
        allowed: false,
        requested_bytes: 0,
        maximum_allowed_bytes: 0,
        headroom_to_stop_bytes: 0,
        reserved_bytes: 0,
        reason: 'no data',
      },
      rotation: { max_file_bytes: 0, max_files: 0, maximum_job_bytes: 0, max_job_seconds: 0 },
      policy: {
        information_percent: 0,
        warning_percent: 0,
        stop_percent: 0,
        hard_limit_percent: 0,
        polling_interval_ms: 0,
      },
      capture_job: { state: 'UNKNOWN', active: false, writes_enabled: false },
      monitoring: {
        poll_interval_ms: 0,
        event_driven_limit: 'none',
        failure_mode: 'none',
      },
    };
    stub(() => respond(200, { data: safety, meta: {} }));
    const envelope = await api<DiskSafety>('/storage/safety');
    expect(envelope.data.filesystem).toBeNull();
    expect(envelope.data.decision.new_capture_allowed).toBe(false);
  });
});

describe('OIRAN v1 contract — authentication failure path', () => {
  it('consumers see ApiError.status=401 and never a mutated empty envelope', async () => {
    stub(() =>
      respond(401, {
        error: { code: 'UNAUTHENTICATED', message: 'Missing bearer' },
      }),
    );
    try {
      await api<Capture[]>('/captures', { authScope: 'oiran' });
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError);
      expect((error as ApiError).status).toBe(401);
      expect((error as ApiError).code).toBe('UNAUTHENTICATED');
    }
  });
});
