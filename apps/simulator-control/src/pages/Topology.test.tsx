import { describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { TopologyPage, linkState } from './Topology';

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

describe('linkState (0.4.1 — three honest states, no "UP")', () => {
  it('returns "unknown" when no endpoint is reported', () => {
    expect(linkState('running', null)).toBe('unknown');
    expect(linkState(undefined, null)).toBe('unknown');
  });
  it('returns "down" when an endpoint exists but the process is not running', () => {
    expect(linkState('stopped', '10.77.21.20')).toBe('down');
    expect(linkState(undefined, '10.77.21.20')).toBe('down');
  });
  it('returns "configured" when the process is running AND an endpoint is reported', () => {
    expect(linkState('running', '10.77.21.20')).toBe('configured');
    expect(linkState('RUNNING', '10.77.21.20')).toBe('configured');
  });
  it('never says "UP" — NG Setup state is not exposed by the backend yet', () => {
    const values: Array<ReturnType<typeof linkState>> = [
      linkState('running', '10.77.21.20'),
      linkState('stopped', '10.77.21.20'),
      linkState('running', null),
    ];
    expect(values).not.toContain('UP' as never);
  });
});

describe('Topology — composes /lab + /nodes + /ues', () => {
  it('surfaces the real AMF container state, never a fake "5G Core HEALTHY" aggregate', async () => {
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
        return respond(200, { items: [], configured_count: 0, running_count: 0, observed_at_epoch_s: 0, source: 'test' });
      if (url.includes('/ues'))
        return respond(200, { items: [], configured_profiles: [], configured_count: 0, active_count: 0, registered_count: 0, source: 'test' });
      return respond(200, {});
    }) as unknown as typeof fetch;
    renderPage();
    await waitFor(() => expect(screen.getByTestId('topology-view')).toBeInTheDocument());
    // The badge text must name the container and its two fields.
    expect(screen.getByTestId('topology-view').textContent).toMatch(/AMF container: running, healthy/);
    // Non-AMF NFs stay "not exposed" at the tooltip level — not fabricated.
    expect(screen.getByTestId('topology-nf-SMF')).toBeInTheDocument();
  });

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
    // 5G NR labels on a 5G node, "configured" because the process is running.
    expect(within(node).getByTestId('link-N2 · NGAP')).toBeInTheDocument();
    expect(within(node).getByTestId('link-N3 · GTP-U')).toBeInTheDocument();
    // controller_owned=false → the "SHARED_NODE_PROTECTED" reason is surfaced on the card.
    expect(node.textContent).toMatch(/SHARED_NODE_PROTECTED/);
  });

  it('swaps NR labels (N2/N3) for LTE labels (S1-MME / S1-U) on an eNB', async () => {
    globalThis.fetch = vi.fn(async (input) => {
      const url = String(input);
      if (url.includes('/auth/me')) return respond(200, { authenticated: false, role: 'viewer' });
      if (url.includes('/lab'))
        return respond(200, {
          source: 'READ_ONLY_HOST_AUDIT',
          observed: { open5gs: { process_state: 'stopped', health: 'unknown', observed: true } },
        });
      if (url.includes('/nodes'))
        return respond(200, {
          items: [
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
          ],
          configured_count: 0,
          running_count: 0,
          observed_at_epoch_s: 0,
          source: 'test',
        });
      if (url.includes('/ues'))
        return respond(200, { items: [], configured_profiles: [], configured_count: 0, active_count: 0, registered_count: 0, source: 'test' });
      return respond(200, {});
    }) as unknown as typeof fetch;
    renderPage();
    await waitFor(() => expect(screen.getByTestId('topology-node-ENB-01')).toBeInTheDocument());
    const node = screen.getByTestId('topology-node-ENB-01');
    expect(within(node).getByTestId('link-S1-MME · S1AP')).toBeInTheDocument();
    expect(within(node).getByTestId('link-S1-U · GTP-U')).toBeInTheDocument();
    // No N2 / N3 labels on an eNB.
    expect(within(node).queryByTestId('link-N2 · NGAP')).toBeNull();
    expect(within(node).queryByTestId('link-N3 · GTP-U')).toBeNull();
  });
});
