import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { App } from './App';

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function stubFetch() {
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.includes('/datasets')) return respond(200, { data: [], meta: {} });
    if (url.includes('/ues')) return respond(200, { data: [], meta: {} });
    if (url.includes('/metrics')) return respond(200, { data: null, meta: {} });
    if (url.includes('/version'))
      return respond(200, {
        data: {
          platform_core: '0.0.1',
          backend_api: '2.3.0',
          web_frontend: 'test',
          event_schema: '1',
          callflow_schema: '1',
          session_engine: 'test',
          correlation_engine: 'test',
          decoders: {},
        },
        meta: {},
      });
    if (url.includes('/auth/me'))
      return respond(200, { data: { authenticated: false }, meta: {} });
    return respond(200, { data: [], meta: {} });
  }) as unknown as typeof fetch;
}

function renderApp(path = '/overview') {
  stubFetch();
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('Analyzer routes', () => {
  it('renders the overview by default', async () => {
    renderApp();
    expect(
      await screen.findByRole('heading', { name: /oiran analyzer/i, level: 1 }),
    ).toBeInTheDocument();
  });

  it('exposes every mandated navigation link', () => {
    renderApp();
    for (const label of [
      'Overview',
      'Datasets',
      'Session Explorer',
      'Signaling',
      'User Plane',
      'Correlation Studio',
      'Packet Analyzer',
      'KPI / Performance',
    ]) {
      expect(
        screen.getByRole('link', { name: new RegExp(label, 'i') }),
      ).toBeInTheDocument();
    }
  });

  it('navigates to the Session Explorer', async () => {
    renderApp();
    const user = userEvent.setup();
    await user.click(screen.getByRole('link', { name: /session explorer/i }));
    await waitFor(() =>
      expect(
        screen.getByRole('heading', { name: /session explorer/i, level: 1 }),
      ).toBeInTheDocument(),
    );
  });

  it('redirects unknown routes to Overview', async () => {
    renderApp('/does-not-exist');
    await waitFor(() =>
      expect(
        screen.getByRole('heading', { name: /oiran analyzer/i, level: 1 }),
      ).toBeInTheDocument(),
    );
  });

  it('offers a theme switch', () => {
    renderApp();
    expect(screen.getByTestId('theme-switch')).toBeInTheDocument();
  });
});
