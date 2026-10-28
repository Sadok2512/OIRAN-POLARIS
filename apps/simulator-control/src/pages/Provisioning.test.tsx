// 0.7.1 — Provisioning subscriber detail panel. Row click opens
// GET /subscribers/:slot and renders the richer fields; Edit button
// stays locked until PUT /subscribers/:slot ships.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';
import { ProvisioningPage } from './Provisioning';
import { _resetFlags, setFlag } from '@/data/featureFlags';

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function renderPage(node: ReactNode = <ProvisioningPage />) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const DETAIL = {
  slot_id: 'slot-01',
  subscriber_id: 'sub-abc-01',
  provisioning_status: 'VERIFIED',
  plmn: { mcc: '208', mnc: '93' },
  slice: { sst: 1, sd: 'A1B2C3' },
  dnns: ['internet', 'ims'],
  ambr: { uplink: 1_048_576, downlink: 1_048_576 },
  bound_ues: ['UE-01', 'UE-12'],
  imsi: 'PROTECTED',
  k: 'PROTECTED',
  opc: 'PROTECTED',
  updated_at_epoch_s: 1_793_200_000,
};

beforeEach(() => {
  if (typeof localStorage !== 'undefined') localStorage.clear();
  _resetFlags();
  setFlag('polarisProvisioning', true);
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.endsWith('/subscribers')) {
      return respond(200, {
        items: [
          {
            subscriber_id: 'slot-01',
            owner: 'ops-nancy',
            imsi: 'PROTECTED',
            provisioning_status: 'VERIFIED',
            updated_at_epoch_s: 1,
          },
        ],
        total: 1,
      });
    }
    if (url.includes('/subscribers/slot-01')) return respond(200, DETAIL);
    return respond(404, { error: 'not stubbed' });
  }) as unknown as typeof fetch;
});

afterEach(() => {
  vi.restoreAllMocks();
  _resetFlags();
});

describe('ProvisioningPage — subscriber detail panel (0.7.1)', () => {
  it('opens the detail panel on row click and renders slot/slice/DNN/AMBR/bound UEs', async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByTestId('provisioning-subscribers');
    await user.click(screen.getByTestId('subscriber-row-slot-01'));
    await screen.findByTestId('subscriber-detail-panel');

    const panel = screen.getByTestId('subscriber-detail-panel');
    expect(panel).toHaveTextContent('slot-01');
    expect(panel).toHaveTextContent('208/93');
    expect(panel).toHaveTextContent('SST 1');
    expect(panel).toHaveTextContent('SD A1B2C3');
    expect(panel).toHaveTextContent('internet, ims');
    expect(panel).toHaveTextContent('1,048,576 kbps');
    expect(panel).toHaveTextContent('UE-01');
    expect(panel).toHaveTextContent('UE-12');
    // Secret fields render as PROTECTED, never raw.
    expect(screen.getByTestId('subscriber-detail-identity')).toHaveTextContent('PROTECTED');
  });

  it('shows the Edit button but keeps it locked "Backend pending: PUT /subscribers/:slot"', async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByTestId('provisioning-subscribers');
    await user.click(screen.getByTestId('subscriber-row-slot-01'));
    const edit = await screen.findByTestId('subscriber-detail-edit');
    expect(edit).toBeDisabled();
    expect(edit).toHaveAttribute('title', 'Backend pending: PUT /subscribers/:slot');
  });

  it('closes the panel via the X button', async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByTestId('provisioning-subscribers');
    await user.click(screen.getByTestId('subscriber-row-slot-01'));
    await screen.findByTestId('subscriber-detail-panel');
    await user.click(screen.getByTestId('subscriber-detail-close'));
    await waitFor(() => expect(screen.queryByTestId('subscriber-detail-panel')).toBeNull());
  });
});
