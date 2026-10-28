import { describe, it, expect, vi } from 'vitest';
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

function renderApp(route = '/overview') {
  globalThis.fetch = vi.fn(async () =>
    respond(200, { data: [], meta: {} }),
  ) as unknown as typeof fetch;
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[route]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('Probe Manager routes', () => {
  it('renders the Overview page by default', async () => {
    renderApp();
    expect(
      await screen.findByRole('heading', { name: /overview/i, level: 1 }),
    ).toBeInTheDocument();
  });

  it('navigates to Capture Library via the sidebar', async () => {
    renderApp();
    const user = userEvent.setup();
    await user.click(screen.getByRole('link', { name: /capture library/i }));
    await waitFor(() =>
      expect(
        screen.getByRole('heading', { name: /capture library/i, level: 1 }),
      ).toBeInTheDocument(),
    );
  });

  it('renders every mandated navigation entry (Topology moved to POLARIS in 0.2.0)', () => {
    renderApp();
    for (const label of [
      'Overview',
      'Probes',
      'Interfaces',
      'Live Captures',
      'Capture Library',
      'Settings',
    ]) {
      expect(
        screen.getByRole('link', { name: new RegExp(label, 'i') }),
      ).toBeInTheDocument();
    }
    // Topology is no longer in the Probe Manager sidebar — it lives in
    // POLARIS Simulator Control. The /topology route still responds with
    // a stub so old bookmarks don't 404 (asserted in a dedicated test).
    expect(screen.queryByRole('link', { name: /network topology/i })).toBeNull();
  });

  it('renders a "Topology moved to POLARIS" stub at /topology instead of a 404', async () => {
    renderApp('/topology');
    await waitFor(() =>
      expect(screen.getByTestId('topology-moved')).toBeInTheDocument(),
    );
  });

  it('exposes a theme switch in the shell', () => {
    renderApp();
    expect(screen.getByTestId('theme-switch')).toBeInTheDocument();
  });

  it('redirects unknown routes to Overview', async () => {
    renderApp('/does-not-exist');
    await waitFor(() =>
      expect(
        screen.getByRole('heading', { name: /overview/i, level: 1 }),
      ).toBeInTheDocument(),
    );
  });
});
