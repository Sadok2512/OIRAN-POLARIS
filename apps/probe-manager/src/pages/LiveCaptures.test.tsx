import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithProviders } from '@/test/testUtils';
import { LiveCapturesPage } from './LiveCaptures';

function response(data: unknown) {
  return new Response(JSON.stringify({ data, meta: { api_version: '2.3.0' } }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
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
