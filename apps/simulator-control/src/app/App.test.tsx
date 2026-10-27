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
    if (url.includes('/auth/me'))
      return respond(200, { data: { authenticated: false, username: null, role: 'viewer', can_start: false, can_manage_permissions: false }, meta: {} });
    if (url.includes('/capabilities'))
      return respond(200, {
        data: {
          live_control: false,
          approval_state: 'READ_ONLY',
          max_ues: 4,
          max_nodes: 2,
          registration_modes: ['5G_SA'],
          traffic_protocols: ['UDP'],
          approved_destinations: ['10.46.0.1'],
          profiles: [],
          technologies: [],
          services: [],
        },
        meta: {},
      });
    if (url.includes('/scenario-capabilities'))
      return respond(200, { data: { items: [], execution_status: 'READY_TO_START', reason: 'OK', role: 'viewer' }, meta: {} });
    if (url.includes('/scenarios/status'))
      return respond(200, { data: { active_job: null, latest_terminal_job: null, active_count: 0, history_count: 0, observed_at_epoch_s: 0, source: 'test' }, meta: {} });
    if (url.includes('/scenarios/history'))
      return respond(200, { data: { items: [], total: 0, source: 'test', live_execution: false }, meta: {} });
    if (url.includes('/traffic/status'))
      return respond(200, { data: { state: 'IDLE', packets_requested: 0, packets_sent: null, packets_received: null, bytes: null, accounting_source: 'none', last_result: null, approved_destinations: [] }, meta: {} });
    if (url.includes('/ues'))
      return respond(200, { data: { items: [], configured_profiles: [], configured_count: 0, active_count: 0, registered_count: 0, source: 'test' }, meta: {} });
    if (url.includes('/nodes'))
      return respond(200, { data: { items: [], configured_count: 0, running_count: 0, observed_at_epoch_s: 0, source: 'test' }, meta: {} });
    if (url.includes('/lab'))
      return respond(200, { data: { ue_count: 0, desired_ue_count: 0, gnb_count: 0, max_ues: 4, max_gnbs: 2, max_ues_live_certified: 4, max_gnbs_live_certified: 2, missing_subscriber_profiles: 0, updated_at_epoch_s: 0, updated_by: '', observed_controller_running: 0, observed_total_running: 0, reconciliation: { operation_id: null, desired_count: 0, state: 'IDLE', started_at_epoch_s: null, completed_at_epoch_s: null, started: [], stopped: [], failures: [] }, execution_started: false }, meta: {} });
    if (url.includes('/system/health'))
      return respond(200, { data: { disk: null, decision: { state: 'OK', writes_allowed: true, reason: '', maximum_budget_bytes: 0 }, memory: { total_bytes: null, available_bytes: null, used_bytes: null }, load_average: '', uptime_seconds: null }, meta: {} });
    return respond(200, { data: [], meta: {} });
  }) as unknown as typeof fetch;
}

function renderApp(path = '/console') {
  stubFetch();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
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
  if (typeof localStorage !== 'undefined') localStorage.clear();
});

describe('Simulator Control routes', () => {
  it('renders the Console by default', async () => {
    renderApp();
    expect(await screen.findByRole('heading', { name: /console/i, level: 1 })).toBeInTheDocument();
  });

  it('exposes every mandated nav link including Network Nodes + Traffic', () => {
    renderApp();
    for (const label of [
      'Console',
      'Network Nodes',
      'UE Manager',
      'Traffic Generator',
      'Scenarios',
      'Execution Monitor',
      'History',
      'Settings',
    ]) {
      expect(screen.getByRole('link', { name: new RegExp(label, 'i') })).toBeInTheDocument();
    }
  });

  it('navigates to Network Nodes', async () => {
    renderApp();
    const user = userEvent.setup();
    await user.click(screen.getByRole('link', { name: /network nodes/i }));
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: /network nodes/i, level: 1 })).toBeInTheDocument(),
    );
  });

  it('navigates to Traffic Generator', async () => {
    renderApp();
    const user = userEvent.setup();
    await user.click(screen.getByRole('link', { name: /traffic generator/i }));
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: /traffic generator/i, level: 1 })).toBeInTheDocument(),
    );
  });

  it('shows an Operator login form in Settings when not authenticated', async () => {
    renderApp();
    const user = userEvent.setup();
    await user.click(screen.getByRole('link', { name: /settings/i }));
    await waitFor(() =>
      expect(screen.getByTestId('operator-login-form')).toBeInTheDocument(),
    );
    expect(screen.getByTestId('operator-login-username')).toBeInTheDocument();
    expect(screen.getByTestId('operator-login-password')).toBeInTheDocument();
    expect(screen.getByTestId('operator-login-submit')).toBeInTheDocument();
  });

  it('surfaces the header identity badge', async () => {
    renderApp();
    expect(await screen.findByTestId('header-identity')).toHaveTextContent(/not signed in/i);
  });

  it('navigates to Scenarios library and opens the builder', async () => {
    renderApp();
    const user = userEvent.setup();
    await user.click(screen.getByRole('link', { name: /scenarios/i }));
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: /scenarios/i, level: 1 })).toBeInTheDocument(),
    );
    await user.click(screen.getByTestId('scenarios-create'));
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: /scenario builder/i, level: 1 })).toBeInTheDocument(),
    );
  });

  it('redirects unknown routes to Console', async () => {
    renderApp('/does-not-exist');
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: /console/i, level: 1 })).toBeInTheDocument(),
    );
  });
});
