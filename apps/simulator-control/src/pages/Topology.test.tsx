import { describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { TopologyPage, isLinkUp } from './Topology';

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
        <TopologyPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('isLinkUp', () => {
  it('is false when the endpoint is null regardless of state', () => {
    expect(isLinkUp('running', null)).toBe(false);
  });
  it('is true only when process_state is "running" and an endpoint exists', () => {
    expect(isLinkUp('running', '10.77.21.20')).toBe(true);
    expect(isLinkUp('stopped', '10.77.21.20')).toBe(false);
    expect(isLinkUp(undefined, '10.77.21.20')).toBe(false);
  });
});

describe('Topology — composes /lab + /nodes + /ues', () => {
  it('shows the core container, each node, and the UEs attached per node', async () => {
    globalThis.fetch = vi.fn(async (input) => {
      const url = String(input);
      if (url.includes('/auth/me')) return respond(200, { authenticated: false, role: 'viewer' });
      if (url.includes('/lab'))
        return respond(200, {
          source: 'READ_ONLY_HOST_AUDIT',
          observed: {
            open5gs: { process_state: 'running', health: 'healthy', observed: true },
          },
        });
      if (url.includes('/nodes'))
        return respond(200, {
          items: [
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
          ],
          configured_count: 1,
          running_count: 1,
          observed_at_epoch_s: 0,
          source: 'READ_ONLY_LAB_STATE',
        });
      if (url.includes('/ues'))
        return respond(200, {
          items: [
            {
              id: 'UE-01',
              registration_state: 'REGISTERED',
              pdu_session: 'ACTIVE',
              ue_ip: null,
              traffic_state: 'IDLE',
              serving_node: 'GNB-01',
              last_event: null,
              controller_owned: true,
            },
          ],
          configured_profiles: [],
          configured_count: 1,
          active_count: 1,
          registered_count: 1,
          source: 'test',
        });
      return respond(200, {});
    }) as unknown as typeof fetch;

    renderPage();
    await waitFor(() => expect(screen.getByTestId('topology-view')).toBeInTheDocument());
    expect(screen.getByTestId('topology-nf-AMF')).toBeInTheDocument();
    expect(screen.getByTestId('topology-node-GNB-01')).toBeInTheDocument();
    const node = screen.getByTestId('topology-node-GNB-01');
    expect(within(node).getByTestId('topology-ues-GNB-01').textContent).toContain('UE-01');
    // controller_owned=false → the "SHARED_NODE_PROTECTED" reason is surfaced on the card.
    expect(node.textContent).toMatch(/SHARED_NODE_PROTECTED/);
  });
});
