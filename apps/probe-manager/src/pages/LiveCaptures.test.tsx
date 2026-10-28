import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithProviders } from '@/test/testUtils';
import { LiveCapturesPage } from './LiveCaptures';

function response(data: unknown) {
  return new Response(JSON.stringify({ data, meta: { api_version: '2.3.0' } }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

type FetchResponder = (url: string, method: string) => Response;

function installFetch(responder: FetchResponder) {
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    return responder(url, init?.method ?? 'GET');
  }) as unknown as typeof fetch;
}

describe('Live capture controls — LOT 1 locked contract (0.2.0)', () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.restoreAllMocks();
  });

  it('keeps Validate / Start locked and emits no POST for the public Viewer', async () => {
    const calls: string[] = [];
    globalThis.fetch = vi.fn(async (input, init) => {
      const url = String(input);
      const method = init?.method ?? 'GET';
      if (method !== 'GET') calls.push(`${method} ${url}`);
      if (url.includes('/auth/me')) return response({ authenticated: false, role: 'viewer', permissions: ['platform.read'], capture_control: false, capture_execution_enabled: true, reason: 'PUBLIC_VIEWER' });
      if (url.includes('/interfaces')) return response([{ interface: 'N2', protocol: 'NGAP', capture_point: 'n2', source: 'backend', status: 'AVAILABLE', packet_count: null, file_size: null, capture_start: null, capture_end: null, live_capture_available: true }]);
      if (url.includes('/probes')) return response([{ probe_id: 'probe-a', online: true }]);
      return response([]);
    }) as unknown as typeof fetch;

    render(renderWithProviders(<LiveCapturesPage />));
    expect(await screen.findByTestId('validate-capture')).toBeDisabled();
    expect(screen.getByTestId('start-capture')).toBeDisabled();
    // No mutating request should have left the UI.
    expect(calls).toEqual([]);
  });

  it('keeps the same lock in place even when auth.me returns an Operator role', async () => {
    sessionStorage.setItem('oiran.access_token', 'test-token');
    const calls: string[] = [];
    globalThis.fetch = vi.fn(async (input, init) => {
      const url = String(input);
      const method = init?.method ?? 'GET';
      if (method !== 'GET') calls.push(`${method} ${url}`);
      if (url.includes('/auth/me')) return response({ authenticated: true, role: 'operator', permissions: ['captures.validate', 'captures.start'], capture_control: true, capture_execution_enabled: true, reason: 'AUTHENTICATED_OPERATOR' });
      if (url.includes('/interfaces')) return response([{ interface: 'N2', protocol: 'NGAP / SCTP', capture_point: 'n2', source: 'backend', status: 'AVAILABLE', packet_count: null, file_size: null, capture_start: null, capture_end: null, live_capture_available: true }]);
      if (url.includes('/probes')) return response([{ probe_id: 'probe-a', online: true }]);
      return response([]);
    }) as unknown as typeof fetch;

    const user = userEvent.setup();
    render(renderWithProviders(<LiveCapturesPage />));
    const validate = await screen.findByTestId('validate-capture');
    const start = screen.getByTestId('start-capture');
    expect(validate).toBeDisabled();
    expect(start).toBeDisabled();
    // Click still does nothing; nothing is sent — the mutating path is physically locked.
    await user.click(validate);
    await user.click(start);
    expect(calls.filter((call) => call.includes('/captures'))).toEqual([]);
  });
});

describe('Live capture stats — honest growth / stalled semantics (0.2.1)', () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.restoreAllMocks();
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  function envelope(data: unknown, meta: Record<string, unknown> = {}) {
    return new Response(JSON.stringify({ data, meta }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }

  function stub(captures: unknown[], disk: unknown = null) {
    installFetch((url) => {
      if (url.includes('/auth/me'))
        return response({ authenticated: false, role: 'viewer', capture_control: false, capture_execution_enabled: false });
      if (url.includes('/probes')) return response([]);
      if (url.includes('/interfaces')) return response([]);
      if (url.includes('/storage/safety'))
        return response(disk ?? {
          filesystem: { total_bytes: 1_000, used_bytes: 100, available_bytes: 900, usage_percent: 10, total_inodes: 1, available_inodes: 1 },
          decision: { state: 'OK', new_capture_allowed: true, active_capture_must_finalize: false, read_only_analysis_allowed: true, reason: '' },
        });
      if (url.includes('/captures'))
        return envelope(captures, { total: captures.length, total_pages: 1 });
      return response([]);
    });
  }

  it('shows 0 Stalled and "measuring…" immediately after the first poll (no 10 s window yet)', async () => {
    stub([
      { capture_id: 'cap-1', name: 'cap-1', state: 'CAPTURING', size_bytes: 1_000, probe_id: 'p1' },
    ]);
    render(renderWithProviders(<LiveCapturesPage />));
    await waitFor(() =>
      expect(screen.getByTestId('live-capture-cap-1')).toBeInTheDocument(),
    );
    expect(screen.getByTestId('stat-stalled').textContent).toMatch(/^Stalled0/);
    expect(screen.getByTestId('stat-written-10-s').textContent).toMatch(/measuring/);
    expect(screen.getByTestId('growth-cap-1').textContent).toMatch(/measuring/);
  });

  it('does NOT mark a STARTING capture as stalled (0.2.2 — transition states are not stalled)', async () => {
    stub([
      // STARTING is a legitimate backend transition; growth is still measuring.
      { capture_id: 'cap-starting', name: 'cap-starting', state: 'STARTING', size_bytes: 0, probe_id: 'p1' },
    ]);
    render(renderWithProviders(<LiveCapturesPage />));
    await waitFor(() =>
      expect(screen.getByTestId('live-capture-cap-starting')).toBeInTheDocument(),
    );
    expect(screen.getByTestId('stat-stalled').textContent).toMatch(/^Stalled0/);
    // The row still shows STARTING as its real state (surfaced through StatusIndicator).
    expect(screen.getByTestId('live-capture-cap-starting').textContent).toMatch(/STARTING/);
    // No "stalled" badge is added to the header.
    expect(screen.getByTestId('live-capture-cap-starting').textContent).not.toMatch(/stalled/i);
  });

  it('renders "—" for the Storage cell when the backend reports no size', async () => {
    stub([
      { capture_id: 'cap-x', name: 'cap-x', state: 'CAPTURING', probe_id: 'p1' },
    ]);
    render(renderWithProviders(<LiveCapturesPage />));
    await waitFor(() =>
      expect(screen.getByTestId('live-capture-cap-x')).toBeInTheDocument(),
    );
    const article = screen.getByTestId('live-capture-cap-x');
    const dl = article.querySelector('dl')!;
    const storageDt = within(dl)
      .getAllByText('Storage', { exact: true })[0];
    const storageDd = storageDt.nextElementSibling as HTMLElement;
    expect(storageDd.textContent).toBe('—');
    // Growth stays "—" too, because the backend did not provide any size.
    expect(screen.getByTestId('growth-cap-x').textContent).toBe('—');
    // "—" must never be counted as stalled.
    expect(screen.getByTestId('stat-stalled').textContent).toMatch(/^Stalled0/);
  });

  it('marks a job stalled once we have a 10 s window with 0 B of growth', async () => {
    const captures: Record<string, unknown>[] = [
      { capture_id: 'cap-s', name: 'cap-s', state: 'CAPTURING', size_bytes: 2_000, probe_id: 'p1' },
    ];
    installFetch((url) => {
      if (url.includes('/auth/me'))
        return response({ authenticated: false, role: 'viewer', capture_control: false, capture_execution_enabled: false });
      if (url.includes('/probes')) return response([]);
      if (url.includes('/interfaces')) return response([]);
      if (url.includes('/storage/safety'))
        return response({
          filesystem: { total_bytes: 1_000, used_bytes: 100, available_bytes: 900, usage_percent: 10, total_inodes: 1, available_inodes: 1 },
          decision: { state: 'OK', new_capture_allowed: true, active_capture_must_finalize: false, read_only_analysis_allowed: true, reason: '' },
        });
      if (url.includes('/captures'))
        return envelope(captures, { total: captures.length, total_pages: 1 });
      return response([]);
    });

    render(renderWithProviders(<LiveCapturesPage />));
    await waitFor(() => expect(screen.getByTestId('live-capture-cap-s')).toBeInTheDocument());
    // First poll already arrived with size=2_000. Advance 11 s so the
    // 4 s refetch runs ≥ 2 times and gives us a ≥ 10 s window.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_000);
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_000);
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_000);
    });
    await waitFor(() => {
      expect(screen.getByTestId('stat-stalled').textContent).toMatch(/^Stalled1/);
    });
    expect(screen.getByTestId('growth-cap-s').textContent).toMatch(/^0 B$/);
  });
});
