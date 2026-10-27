import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithProviders } from '@/test/testUtils';
import { LiveCapturesPage } from './LiveCaptures';

function response(data: unknown) {
  return new Response(JSON.stringify({ data, meta: { api_version: '2.3.0' } }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

describe('Live capture controls', () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.restoreAllMocks();
  });

  it('keeps capture actions disabled for the public Viewer', async () => {
    globalThis.fetch = vi.fn(async (input) => {
      const url = String(input);
      if (url.includes('/auth/me')) return response({ authenticated: false, role: 'viewer', permissions: ['platform.read'], capture_control: false, capture_execution_enabled: true, reason: 'PUBLIC_VIEWER' });
      if (url.includes('/interfaces')) return response([{ interface: 'N2', protocol: 'NGAP', capture_point: 'n2', source: 'backend', status: 'AVAILABLE', packet_count: null, file_size: null, capture_start: null, capture_end: null, live_capture_available: true }]);
      if (url.includes('/probes')) return response([{ probe_id: 'probe-a', online: true }]);
      return response([]);
    }) as unknown as typeof fetch;

    render(renderWithProviders(<LiveCapturesPage />));
    expect(await screen.findByRole('button', { name: 'Validate capture' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Start capture' })).toBeDisabled();
  });

  it('validates before sending a mocked start request as Operator', async () => {
    sessionStorage.setItem('oiran.access_token', 'test-token');
    const calls: Array<{ url: string; method: string; authorization: string | null }> = [];
    globalThis.fetch = vi.fn(async (input, init) => {
      const url = String(input);
      const method = init?.method ?? 'GET';
      calls.push({ url, method, authorization: new Headers(init?.headers).get('Authorization') });
      if (url.includes('/auth/me')) return response({ authenticated: true, role: 'operator', permissions: ['captures.validate', 'captures.start'], capture_control: true, capture_execution_enabled: true, reason: 'AUTHENTICATED_OPERATOR' });
      if (url.includes('/interfaces')) return response([{ interface: 'N2', protocol: 'NGAP / SCTP', capture_point: 'n2', source: 'backend', status: 'AVAILABLE', packet_count: null, file_size: null, capture_start: null, capture_end: null, live_capture_available: true }]);
      if (url.includes('/probes')) return response([{ probe_id: 'probe-a', online: true }]);
      if (url.endsWith('/captures/validate')) return response({ authorization: 'operator', validation: { valid: true } });
      if (url.endsWith('/captures/start')) return response({ capture_id: 'capture-test', name: 'test', state: 'STARTING' });
      return response([]);
    }) as unknown as typeof fetch;

    const user = userEvent.setup();
    render(renderWithProviders(<LiveCapturesPage />));
    await user.click(await screen.findByRole('checkbox', { name: /N2/ }));
    await user.click(screen.getByRole('button', { name: 'Start capture' }));

    await waitFor(() => expect(screen.getByText(/Capture request accepted/)).toBeInTheDocument());
    const mutations = calls.filter((call) => call.method === 'POST');
    expect(mutations.map((call) => call.url)).toEqual(['/api/v1/captures/validate', '/api/v1/captures/start']);
    expect(mutations.every((call) => call.authorization === 'Bearer test-token')).toBe(true);
  });
});
