import { describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { GnbsPage } from './Gnbs';

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <GnbsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const NODES = [
  {
    id: 'GNB-01',
    name: 'Primary gNB',
    technology: '5G SA',
    simulator: 'UERANSIM',
    plmn: '001/01',
    cell_id: '0x000000010',
    link_ip: '10.77.0.20',
    n2_endpoint: '10.77.21.20',
    n3_endpoint: '10.77.22.20',
    process_state: 'running',
    health: 'healthy',
    configured: true,
    controller_owned: false,
    uptime_seconds: 42,
    actions: { start: false, stop: false, reason: 'SHARED_NODE_PROTECTED' },
  },
  {
    id: 'GNB-02',
    name: 'Second gNB plan',
    technology: '5G SA',
    simulator: 'UERANSIM',
    plmn: '001/01',
    cell_id: 'UNASSIGNED',
    link_ip: 'NOT_CONFIGURED',
    n2_endpoint: null,
    n3_endpoint: null,
    process_state: 'NOT_DEPLOYED',
    health: 'NOT_VALIDATED',
    configured: false,
    controller_owned: false,
    uptime_seconds: null,
    actions: { start: false, stop: false, reason: 'LIVE_005_APPROVAL_REQUIRED' },
  },
  {
    id: 'ENB-01',
    name: 'LTE eNB profile',
    technology: 'LTE',
    simulator: 'srsRAN',
    plmn: '001/01',
    cell_id: 'NOT_AVAILABLE',
    link_ip: 'NOT_AVAILABLE',
    n2_endpoint: null,
    n3_endpoint: null,
    process_state: 'stopped',
    health: 'unknown',
    configured: false,
    controller_owned: false,
    uptime_seconds: null,
    actions: { start: false, stop: false, reason: 'LTE_ATTACH_NOT_CERTIFIED' },
  },
];

function stub() {
  globalThis.fetch = vi.fn(async (input) => {
    const url = String(input);
    if (url.includes('/auth/me')) return respond(200, { authenticated: false, role: 'viewer' });
    if (url.includes('/nodes'))
      return respond(200, { items: NODES, configured_count: 1, running_count: 1, observed_at_epoch_s: 0, source: 'test' });
    if (url.includes('/ues'))
      return respond(200, { items: [], configured_profiles: [], configured_count: 0, active_count: 0, registered_count: 0, source: 'test' });
    return respond(200, {});
  }) as unknown as typeof fetch;
}

describe('gNodeBs page', () => {
  it('renders GNB-01 as the real card with the live Stop button locked', async () => {
    stub();
    renderPage();
    const card = await screen.findByTestId('gnb-card-GNB-01');
    expect(card).toBeInTheDocument();
    const stop = screen.getByTestId('gnb-stop-GNB-01');
    expect(stop).toBeDisabled();
    expect(stop.getAttribute('title')).toMatch(/Stopping GNB-01/);
  });

  it('surfaces LIVE_005_APPROVAL_REQUIRED on GNB-02 and keeps Deploy locked', async () => {
    stub();
    renderPage();
    const card = await screen.findByTestId('gnb-card-GNB-02');
    expect(screen.getByTestId('gnb-reason-GNB-02').textContent).toMatch(/LIVE_005_APPROVAL_REQUIRED/);
    expect(card.textContent).toMatch(/Multi-gNB execution locked until LIVE-005/);
    expect(screen.getByTestId('gnb-deploy-GNB-02')).toBeDisabled();
  });

  it('shows ENB-01 under the "not certified" group with the LTE_ATTACH_NOT_CERTIFIED badge', async () => {
    stub();
    renderPage();
    const card = await screen.findByTestId('gnb-card-ENB-01');
    expect(screen.getByTestId('gnb-reason-ENB-01').textContent).toMatch(/LTE_ATTACH_NOT_CERTIFIED/);
    expect(card.textContent).toMatch(/LTE attach not certified/);
    expect(screen.getByTestId('gnb-start-ENB-01')).toBeDisabled();
  });

  it('keeps the Add gNodeB action locked (no POST route)', async () => {
    stub();
    renderPage();
    await waitFor(() => expect(screen.getByTestId('gnbs-grid')).toBeInTheDocument());
    expect(screen.getByTestId('gnb-add-locked')).toBeDisabled();
  });
});
