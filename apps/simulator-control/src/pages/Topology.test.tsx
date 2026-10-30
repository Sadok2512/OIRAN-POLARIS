// 0.7.0 — Topology tree against the mockup
// (origin/docs/ui-mockups/polaris-control.html → `Topology` view).

import { describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { TopologyPage, linkState, nfPillState } from './Topology';

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

describe('linkState — three honest states, no "UP"', () => {
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
  it('never returns "UP"', () => {
    const values: Array<ReturnType<typeof linkState>> = [
      linkState('running', '10.77.21.20'),
      linkState('stopped', '10.77.21.20'),
      linkState('running', null),
    ];
    expect(values).not.toContain('UP' as never);
  });
});

describe('nfPillState — honest NF pill tone (0.7.0)', () => {
  it('is neutral when neither per-NF map nor open5gs is reported', () => {
    expect(nfPillState('AMF', undefined).tone).toBe('neutral');
    expect(nfPillState('AMF', {}).tone).toBe('neutral');
  });
  it('reflects the aggregated open5gs container for AMF when nfs is absent', () => {
    const observed = {
      open5gs: { process_state: 'running', health: 'healthy', observed: true },
    };
    expect(nfPillState('AMF', observed).tone).toBe('success');
    // Non-AMF NFs stay neutral under the aggregated contract — not fabricated.
    expect(nfPillState('SMF', observed).tone).toBe('neutral');
  });
  it('prefers the per-NF container when the backend publishes nfs', () => {
    const observed = {
      open5gs: { process_state: 'running', health: 'healthy', observed: true },
      nfs: {
        SMF: { process_state: 'running', health: 'healthy', observed: true },
        UPF: { process_state: 'stopped', health: 'unknown', observed: true },
      },
    };
    expect(nfPillState('SMF', observed).tone).toBe('success');
    expect(nfPillState('UPF', observed).tone).toBe('danger');
    expect(nfPillState('PCF', observed).tone).toBe('neutral');
  });
});

describe('Topology view — mockup fidelity (0.7.0)', () => {
  it('renders the full NF grid with per-pill tones from /lab.observed.nfs when available', async () => {
    globalThis.fetch = vi.fn(async (input) => {
      const url = String(input);
      if (url.includes('/auth/me')) return respond(200, { authenticated: false, role: 'viewer' });
      if (url.includes('/lab'))
        return respond(200, {
          source: 'READ_ONLY_HOST_AUDIT',
          observed: {
            open5gs: { process_state: 'running', health: 'healthy', observed: true },
            nfs: {
              AMF: { process_state: 'running', health: 'healthy', observed: true },
              SMF: { process_state: 'running', health: 'healthy', observed: true },
              UPF: { process_state: 'running', health: 'healthy', observed: true },
              NRF: { process_state: 'running', health: 'healthy', observed: true },
              AUSF: { process_state: 'running', health: 'healthy', observed: true },
              UDM: { process_state: 'running', health: 'healthy', observed: true },
            },
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
    for (const nf of ['AMF', 'SMF', 'UPF', 'NRF', 'AUSF', 'UDM']) {
      expect(screen.getByTestId(`topology-nf-${nf}`)).toHaveAttribute('data-tone', 'success');
    }
    // Pills not in the published map stay neutral (gray dot).
    expect(screen.getByTestId('topology-nf-PCF')).toHaveAttribute('data-tone', 'neutral');
    // Core status label advertises the aggregated count.
    expect(document.body.textContent).toMatch(/6\/6 running \+ healthy/);
  });

  it('falls back to the aggregated open5gs container when /lab omits nfs', async () => {
    globalThis.fetch = vi.fn(async (input) => {
      const url = String(input);
      if (url.includes('/auth/me')) return respond(200, { authenticated: false, role: 'viewer' });
      if (url.includes('/lab'))
        return respond(200, {
          source: 'READ_ONLY_HOST_AUDIT',
          observed: { open5gs: { process_state: 'running', health: 'healthy', observed: true } },
        });
      if (url.includes('/nodes'))
        return respond(200, { items: [], configured_count: 0, running_count: 0, observed_at_epoch_s: 0, source: 'test' });
      if (url.includes('/ues'))
        return respond(200, { items: [], configured_profiles: [], configured_count: 0, active_count: 0, registered_count: 0, source: 'test' });
      return respond(200, {});
    }) as unknown as typeof fetch;
    renderPage();
    await waitFor(() => expect(screen.getByTestId('topology-view')).toBeInTheDocument());
    expect(screen.getByTestId('topology-nf-AMF')).toHaveAttribute('data-tone', 'success');
    expect(screen.getByTestId('topology-nf-SMF')).toHaveAttribute('data-tone', 'neutral');
    // Core status label names the AMF container (not a fake aggregate).
    expect(document.body.textContent).toMatch(/AMF container: running, healthy/);
  });

  it('colours N2/N3 connectors green when the gNB is running + endpoints known', async () => {
    globalThis.fetch = vi.fn(async (input) => {
      const url = String(input);
      if (url.includes('/auth/me')) return respond(200, { authenticated: false, role: 'viewer' });
      if (url.includes('/lab'))
        return respond(200, {
          source: 'READ_ONLY_HOST_AUDIT',
          observed: { open5gs: { process_state: 'running', health: 'healthy', observed: true } },
        });
      if (url.includes('/nodes'))
        return respond(200, {
          items: [
            {
              id: 'GNB-01', name: 'Primary gNB', technology: '5G SA', simulator: 'UERANSIM',
              plmn: '001/01', cell_id: '0x000000010', link_ip: '10.77.0.20',
              n2_endpoint: '10.77.21.20', n3_endpoint: '10.77.22.20',
              process_state: 'running', health: 'healthy', configured: true,
              controller_owned: false, uptime_seconds: 42,
              actions: { start: false, stop: false, reason: 'SHARED_NODE_PROTECTED' },
            },
          ],
          configured_count: 1, running_count: 1, observed_at_epoch_s: 0, source: 'test',
        });
      if (url.includes('/ues'))
        return respond(200, {
          items: [
            { id: 'UE-01', registration_state: 'REGISTERED', pdu_session: 'ACTIVE',
              ue_ip: null, traffic_state: 'IDLE', serving_node: 'GNB-01', last_event: null,
              controller_owned: true },
          ],
          configured_profiles: [], configured_count: 1, active_count: 1, registered_count: 1, source: 'test',
        });
      return respond(200, {});
    }) as unknown as typeof fetch;
    renderPage();
    await waitFor(() => expect(screen.getByTestId('topology-node-GNB-01')).toBeInTheDocument());
    const node = screen.getByTestId('topology-node-GNB-01');
    expect(within(node).getByTestId('topology-link-N2 · NGAP')).toHaveAttribute('data-state', 'configured');
    expect(within(node).getByTestId('topology-link-N3 · GTP-U')).toHaveAttribute('data-state', 'configured');
    // UE grid lists the attached UE.
    expect(within(node).getByTestId('topology-ues-GNB-01').textContent).toContain('UE-01');
    // The gNB card is NOT dashed when configured = true.
    expect(within(node).getByTestId('topology-node-card-GNB-01')).toHaveAttribute('data-dashed', 'false');
    // Shared-node reason surfaces inline.
    expect(node.textContent).toMatch(/SHARED_NODE_PROTECTED/);
  });

  it('renders enriched UE mini-cards under each gNB (reg state + PDU + IP) from /ues (0.7.1)', async () => {
    globalThis.fetch = vi.fn(async (input) => {
      const url = String(input);
      if (url.includes('/auth/me')) return respond(200, { authenticated: false, role: 'viewer' });
      if (url.includes('/lab'))
        return respond(200, {
          source: 'READ_ONLY_HOST_AUDIT',
          observed: { open5gs: { process_state: 'running', health: 'healthy', observed: true } },
        });
      if (url.includes('/nodes'))
        return respond(200, {
          items: [
            {
              id: 'GNB-01', name: 'Primary gNB', technology: '5G SA', simulator: 'UERANSIM',
              plmn: '001/01', cell_id: '0x10', link_ip: '10.77.0.20',
              n2_endpoint: '10.77.21.20', n3_endpoint: '10.77.22.20',
              process_state: 'running', health: 'healthy', configured: true,
              controller_owned: true, uptime_seconds: 42,
              actions: { start: false, stop: false, reason: null },
            },
          ],
          configured_count: 1, running_count: 1, observed_at_epoch_s: 0, source: 'test',
        });
      if (url.includes('/ues'))
        return respond(200, {
          items: [
            {
              id: 'UE-01', registration_state: 'REGISTERED', pdu_session: 'ACTIVE',
              ue_ip: '10.45.0.2', traffic_state: 'IDLE', serving_node: 'GNB-01',
              last_event: null, controller_owned: true,
            },
            {
              id: 'UE-13', registration_state: 'STOPPED', pdu_session: 'INACTIVE',
              ue_ip: null, traffic_state: 'IDLE', serving_node: 'GNB-01',
              last_event: null, controller_owned: true,
            },
          ],
          configured_profiles: [], configured_count: 2, active_count: 2, registered_count: 1, source: 'test',
        });
      return respond(200, {});
    }) as unknown as typeof fetch;
    renderPage();
    await waitFor(() => expect(screen.getByTestId('topology-ue-UE-01')).toBeInTheDocument());

    const ue01 = screen.getByTestId('topology-ue-UE-01');
    expect(ue01).toHaveAttribute('data-registration', 'REGISTERED');
    expect(ue01).toHaveAttribute('data-pdu', 'ACTIVE');
    expect(within(ue01).getByTestId('topology-ue-UE-01-reg')).toHaveTextContent('REGISTERED');
    // Active PDU → the "PDU" pill is rendered.
    expect(within(ue01).getByTestId('topology-ue-UE-01-pdu')).toBeInTheDocument();
    // IP comes from /ues (not fabricated).
    expect(within(ue01).getByTestId('topology-ue-UE-01-ip')).toHaveTextContent('10.45.0.2');

    const ue13 = screen.getByTestId('topology-ue-UE-13');
    expect(ue13).toHaveAttribute('data-registration', 'STOPPED');
    // No IP reported → em dash.
    expect(within(ue13).getByTestId('topology-ue-UE-13-ip')).toHaveTextContent('—');
    // Inactive PDU → no PDU badge.
    expect(within(ue13).queryByTestId('topology-ue-UE-13-pdu')).toBeNull();
  });

  it('draws GNB-02 dashed and ENB-01 with LTE labels; both connectors stay gray when no endpoint is reported', async () => {
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
              id: 'GNB-02', name: 'Second gNB plan', technology: '5G SA', simulator: 'UERANSIM',
              plmn: '001/01', cell_id: 'UNASSIGNED', link_ip: 'NOT_CONFIGURED',
              n2_endpoint: null, n3_endpoint: null,
              process_state: 'NOT_DEPLOYED', health: 'NOT_VALIDATED', configured: false,
              controller_owned: false, uptime_seconds: null,
              actions: { start: false, stop: false, reason: 'LIVE_005_APPROVAL_REQUIRED' },
            },
            {
              id: 'ENB-01', name: 'LTE eNB profile', technology: 'LTE', simulator: 'srsRAN',
              plmn: '001/01', cell_id: 'NOT_AVAILABLE', link_ip: 'NOT_AVAILABLE',
              n2_endpoint: null, n3_endpoint: null,
              process_state: 'stopped', health: 'unknown', configured: false,
              controller_owned: false, uptime_seconds: null,
              actions: { start: false, stop: false, reason: 'LTE_ATTACH_NOT_CERTIFIED' },
            },
          ],
          configured_count: 0, running_count: 0, observed_at_epoch_s: 0, source: 'test',
        });
      if (url.includes('/ues'))
        return respond(200, { items: [], configured_profiles: [], configured_count: 0, active_count: 0, registered_count: 0, source: 'test' });
      return respond(200, {});
    }) as unknown as typeof fetch;
    renderPage();
    await waitFor(() => expect(screen.getByTestId('topology-node-GNB-02')).toBeInTheDocument());
    const gnb2 = screen.getByTestId('topology-node-GNB-02');
    expect(within(gnb2).getByTestId('topology-node-card-GNB-02')).toHaveAttribute('data-dashed', 'true');
    expect(within(gnb2).getByTestId('topology-link-N2 · NGAP')).toHaveAttribute('data-state', 'unknown');

    const enb = screen.getByTestId('topology-node-ENB-01');
    expect(within(enb).getByTestId('topology-link-S1-MME · S1AP')).toBeInTheDocument();
    expect(within(enb).getByTestId('topology-link-S1-U · GTP-U')).toBeInTheDocument();
    // No N2 / N3 labels on an eNB.
    expect(within(enb).queryByTestId('topology-link-N2 · NGAP')).toBeNull();
    expect(within(enb).queryByTestId('topology-link-N3 · GTP-U')).toBeNull();
  });
});
