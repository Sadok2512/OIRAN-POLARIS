import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { App } from './App';

type FetchArgs = {
  url: string;
  init?: RequestInit;
};

const callLog: FetchArgs[] = [];

function makeFetchStub(responder: (args: FetchArgs) => Response) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    callLog.push({ url, init });
    return responder({ url, init });
  }) as unknown as typeof fetch;
}

function stubAll(status = 200, body: unknown = { data: { status: 'healthy' }, meta: {} }) {
  globalThis.fetch = makeFetchStub(() =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    }),
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
  callLog.length = 0;
  if (typeof sessionStorage !== 'undefined') sessionStorage.clear();
  stubAll();
});

function renderApp() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <App />
    </QueryClientProvider>,
  );
}

describe('Portal App — layout', () => {
  it('renders the three application cards', async () => {
    renderApp();
    expect(await screen.findByTestId('app-card-simulator')).toBeInTheDocument();
    expect(screen.getByTestId('app-card-probe-manager')).toBeInTheDocument();
    expect(screen.getByTestId('app-card-oiran-analyzer')).toBeInTheDocument();
    expect(screen.getByTestId('app-grid').children).toHaveLength(3);
  });

  it('names the POLARIS card "POLARIS Control" with the Core · RAN · UE · Scenarios tagline (0.2.0)', () => {
    renderApp();
    const card = screen.getByTestId('app-card-simulator');
    expect(card.textContent).toMatch(/POLARIS Control/);
    expect(card.textContent).toMatch(/Core · RAN · UE · Scenarios/);
    // The old "Simulator Control" name is gone.
    expect(card.textContent).not.toMatch(/^Simulator Control$/m);
  });

  it('surfaces scope chips per card (POLARIS: Open5GS, gNB / eNB, Topology, UE Manager, Scenarios)', () => {
    renderApp();
    const polaris = screen.getByTestId('app-scope-simulator').textContent ?? '';
    for (const chip of ['Open5GS', 'gNB / eNB', 'Topology', 'UE Manager', 'Scenarios']) {
      expect(polaris).toContain(chip);
    }
    const probe = screen.getByTestId('app-scope-probe-manager').textContent ?? '';
    for (const chip of ['Probes', 'Interfaces', 'Live captures', 'Library']) {
      expect(probe).toContain(chip);
    }
    const analyzer = screen.getByTestId('app-scope-oiran-analyzer').textContent ?? '';
    for (const chip of ['Sessions', 'Call flow', 'Correlation', 'Packets', 'Datasets']) {
      expect(analyzer).toContain(chip);
    }
  });

  it('shows the exact GET route the health probe uses in a mono line', () => {
    renderApp();
    expect(screen.getByTestId('app-health-route-simulator').textContent).toBe(
      'GET /polaris-api/v1/system/health',
    );
    expect(screen.getByTestId('app-health-route-probe-manager').textContent).toBe(
      'GET /api/v1/health',
    );
    expect(screen.getByTestId('app-health-route-oiran-analyzer').textContent).toBe(
      'GET /api/v1/health',
    );
  });

  it('renders the Responsibilities card below the grid', () => {
    renderApp();
    const resp = screen.getByTestId('responsibilities');
    expect(resp.textContent).toMatch(/POLARIS Control/);
    expect(resp.textContent).toMatch(/Probe Manager/);
    expect(resp.textContent).toMatch(/anonymous/i);
    expect(resp.textContent).toMatch(/no token is ever sent/i);
  });

  it('provides an Open Application link per card', () => {
    renderApp();
    expect(screen.getByTestId('app-open-simulator')).toHaveAttribute(
      'href',
      '/simulator/',
    );
    expect(screen.getByTestId('app-open-probe-manager')).toHaveAttribute(
      'href',
      expect.stringMatching(/probe-manager/),
    );
    expect(screen.getByTestId('app-open-oiran-analyzer')).toHaveAttribute(
      'href',
      '/analyzer/',
    );
  });
});

describe('Portal App — health classification (PR #2 Section 3)', () => {
  it('reports healthy only when the body advertises a positive status', async () => {
    renderApp();
    await waitFor(() =>
      expect(screen.getByTestId('app-health-simulator').textContent).toMatch(
        /healthy/i,
      ),
    );
  });

  it('reports auth-required on 401 (reachable, authentication required)', async () => {
    stubAll(401, { error: { code: 'UNAUTHENTICATED', message: 'auth' } });
    renderApp();
    await waitFor(() =>
      expect(
        screen.getByTestId('app-health-probe-manager').textContent,
      ).toMatch(/authentication required/i),
    );
  });

  it('reports auth-required on 403', async () => {
    stubAll(403, { error: { code: 'FORBIDDEN', message: 'nope' } });
    renderApp();
    await waitFor(() =>
      expect(
        screen.getByTestId('app-health-oiran-analyzer').textContent,
      ).toMatch(/authentication required/i),
    );
  });

  it('reports degraded on 5xx', async () => {
    stubAll(503, { error: { code: 'SERVICE_UNAVAILABLE', message: 'down' } });
    renderApp();
    await waitFor(() =>
      expect(screen.getByTestId('app-health-simulator').textContent).toMatch(
        /HTTP 503/,
      ),
    );
  });

  it('reports degraded when 200 but the body says status is unhealthy', async () => {
    stubAll(200, { data: { status: 'degraded' }, meta: {} });
    renderApp();
    await waitFor(() =>
      expect(
        screen.getByTestId('app-health-probe-manager').textContent,
      ).toMatch(/degraded/i),
    );
  });

  it('reports unknown when the request raises a network error', async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new TypeError('Failed to fetch');
    }) as unknown as typeof fetch;
    renderApp();
    await waitFor(() =>
      expect(screen.getByTestId('app-health-simulator').textContent).toMatch(
        /failed to fetch/i,
      ),
    );
  });
});

describe('Portal App — cross-application token isolation (PR #2 Section 3)', () => {
  it('does not send Authorization even when an OIRAN token is stored', async () => {
    sessionStorage.setItem('oiran.access_token', 'should-stay-local');
    renderApp();
    await waitFor(() => expect(callLog.length).toBeGreaterThanOrEqual(3));
    for (const call of callLog) {
      const headers = new Headers(call.init?.headers);
      expect(
        headers.get('authorization'),
        `authorization leaked to ${call.url}`,
      ).toBeNull();
    }
  });

  it('targets a dedicated API base per application', async () => {
    renderApp();
    await waitFor(() => expect(callLog.length).toBeGreaterThanOrEqual(3));
    const urls = callLog.map((c) => c.url);
    expect(urls.some((u) => u.includes('/polaris-api/v1/system/health'))).toBe(
      true,
    );
    expect(urls.some((u) => u.includes('/api/v1/health'))).toBe(true);
  });

  it('always sends `credentials: omit` to prevent cookie leakage', async () => {
    renderApp();
    await waitFor(() => expect(callLog.length).toBeGreaterThanOrEqual(3));
    for (const call of callLog) {
      expect(call.init?.credentials).toBe('omit');
    }
  });
});
