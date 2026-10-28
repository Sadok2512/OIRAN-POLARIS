import { describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { CoreOpen5gsPage } from './CoreOpen5gs';

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
        <CoreOpen5gsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function stub({ withSlots = true } = {}) {
  globalThis.fetch = vi.fn(async (input) => {
    const url = String(input);
    if (url.includes('/auth/me')) return respond(200, { authenticated: false, role: 'viewer' });
    if (url.includes('/capabilities'))
      return respond(200, {
        live_control: false,
        approval_state: 'READ_ONLY',
        max_ues: 4,
        max_nodes: 2,
        max_nodes_live_certified: 1,
        max_ues_live_certified: 4,
        registration_modes: ['5G_SA'],
        traffic_protocols: ['UDP'],
        approved_destinations: ['10.46.0.1'],
        profiles: [],
        technologies: [],
        services: [],
      });
    if (url.includes('/lab'))
      return respond(200, {
        source: 'READ_ONLY_HOST_AUDIT',
        observed: { open5gs: { process_state: 'running', health: 'healthy', observed: true } },
      });
    if (url.includes('/ue-profiles/provisioning-slots') && withSlots)
      return respond(200, {
        items: [
          { slot_id: 'UE-01', bound_ue_id: 'UE-01' },
          { slot_id: 'UE-02', bound_ue_id: null },
        ],
        total: 2,
        available: 1,
        secrets_exposed: false,
      });
    return respond(200, {});
  }) as unknown as typeof fetch;
}

describe('Core · Open5GS', () => {
  it('surfaces AMF HEALTHY on the functions tab and locks every Restart button', async () => {
    stub();
    renderPage();
    await waitFor(() => {
      expect(screen.getByTestId('core-nf-AMF').textContent).toMatch(/HEALTHY/);
    });
    expect(screen.getByTestId('core-restart-AMF')).toBeDisabled();
    expect(screen.getByTestId('core-restart-SMF')).toBeDisabled();
  });

  it('config tab reads /capabilities values and keeps the Edit button locked', async () => {
    stub();
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByTestId('core-tab-config'));
    await waitFor(() => expect(screen.getByTestId('core-config')).toBeInTheDocument());
    const panel = screen.getByTestId('core-config').textContent ?? '';
    expect(panel).toMatch(/10\.46\.0\.1/);
    expect(screen.getByTestId('core-config-edit')).toBeDisabled();
  });

  it('subscribers tab shows PROTECTED identity, never an IMSI/K/OPc, and locks Provision', async () => {
    stub();
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByTestId('core-tab-subscribers'));
    await waitFor(() => expect(screen.getByTestId('core-subscribers')).toBeInTheDocument());
    const slotRow = screen.getByTestId('subscriber-slot-UE-01');
    expect(slotRow.textContent).toMatch(/PROTECTED/);
    expect(slotRow.textContent).not.toMatch(/\d{14,16}/); // no IMSI leaking
    expect(screen.getByTestId('core-provision-locked')).toBeDisabled();
  });

  it('handles empty /ue-profiles/provisioning-slots honestly', async () => {
    stub({ withSlots: false });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByTestId('core-tab-subscribers'));
    await waitFor(() => expect(screen.getByTestId('core-subscribers')).toBeInTheDocument());
    expect(screen.getByTestId('core-subscribers').textContent).toMatch(/not available/i);
  });
});
