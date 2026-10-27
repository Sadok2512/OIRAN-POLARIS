import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { App } from './App';

beforeEach(() => {
  vi.restoreAllMocks();
  // Deterministic fetch: always 200 OK with a minimal envelope.
  globalThis.fetch = vi.fn(async () =>
    new Response(JSON.stringify({ data: {}, meta: {} }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }),
  ) as unknown as typeof fetch;
});

function renderApp() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <App />
    </QueryClientProvider>,
  );
}

describe('Portal App', () => {
  it('renders the three application cards', async () => {
    renderApp();
    expect(await screen.findByTestId('app-card-simulator')).toBeInTheDocument();
    expect(screen.getByTestId('app-card-probe-manager')).toBeInTheDocument();
    expect(screen.getByTestId('app-card-oiran-analyzer')).toBeInTheDocument();
    expect(screen.getByTestId('app-grid').children).toHaveLength(3);
  });

  it('provides an Open Application link per card', () => {
    renderApp();
    expect(screen.getByTestId('app-open-simulator')).toHaveAttribute(
      'href',
      expect.stringMatching(/polaris/),
    );
    expect(screen.getByTestId('app-open-probe-manager')).toHaveAttribute(
      'href',
      expect.stringMatching(/probe-manager/),
    );
    expect(screen.getByTestId('app-open-oiran-analyzer')).toHaveAttribute(
      'href',
      expect.stringMatching(/oiran/),
    );
  });

  it('reports reachable health on 200 response', async () => {
    renderApp();
    await waitFor(() =>
      expect(screen.getByTestId('app-health-simulator').textContent).toMatch(
        /Reachable/i,
      ),
    );
  });

  it('reports degraded health on 401', async () => {
    globalThis.fetch = vi.fn(async () =>
      new Response(
        JSON.stringify({ error: { code: 'UNAUTHENTICATED', message: 'auth' } }),
        { status: 401, headers: { 'content-type': 'application/json' } },
      ),
    ) as unknown as typeof fetch;

    renderApp();
    await waitFor(() =>
      expect(screen.getByTestId('app-health-probe-manager').textContent).toMatch(
        /Reachable, authentication required/i,
      ),
    );
  });
});
