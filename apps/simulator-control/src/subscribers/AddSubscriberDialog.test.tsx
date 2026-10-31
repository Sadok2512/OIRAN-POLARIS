// 0.7.1 — AddSubscriberDialog with slice/DNN dropdowns from /plmns, /dnns.
//
// Contract (polaris-control-api 0.15.1):
//   POST /subscribers { imsi, k, opc, sst, sd, dnns[], ambr: { uplink, downlink } }
//   409 SUBSCRIBER_NOT_POLARIS_OWNED, 422 SUBSCRIBER_NOT_PROVISIONED surfaced verbatim.
//
// The dialog scrubs IMSI/K/OPc from state right after submit, and
// accepts raw IMSI digits — normalised to the `imsi-<digits>` form
// before the POST.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { AddSubscriberDialog } from './AddSubscriberDialog';
import { _resetFlags, setFlag } from '@/data/featureFlags';

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

interface Call {
  method: string;
  url: string;
  body: unknown;
  contentType: string | null;
}

const calls: Call[] = [];

function stubFetch(handler: (call: Call) => Response) {
  calls.length = 0;
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    const headers = new Headers(init?.headers);
    const call = { method, url, body, contentType: headers.get('content-type') };
    calls.push(call);
    return handler(call);
  }) as unknown as typeof fetch;
}

const PLMNS = {
  items: [
    {
      id: 'home',
      mcc: '001',
      mnc: '01',
      display_name: 'Lab PLMN',
      home_network: true,
      slices: [
        { sst: 1, sd: null, display_name: 'eMBB default' },
        { sst: 1, sd: 'A1B2C3', display_name: 'eMBB custom' },
      ],
    },
  ],
  total: 1,
};

const DNNS = {
  items: [
    { id: 'd1', dnn: 'internet', sst: 1, sd: null, description: 'default Internet DNN' },
    { id: 'd2', dnn: 'ims', sst: 1, sd: null, description: 'IMS DNN' },
  ],
  total: 2,
};

function renderDialog() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const wrapper = (children: ReactNode) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
  return render(wrapper(<AddSubscriberDialog open onClose={() => undefined} />));
}

async function fillValid(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByTestId('subscriber-imsi'), '001010000000201');
  await user.type(screen.getByTestId('subscriber-k'), '0a1b2c3d4e5f60718293a4b5c6d7e8f9');
  await user.type(screen.getByTestId('subscriber-opc'), 'ffeeddccbbaa99887766554433221100');
  await waitFor(() => expect(screen.getByTestId('subscriber-slice')).not.toBeDisabled());
  await user.selectOptions(screen.getByTestId('subscriber-slice'), '1/A1B2C3');
  await user.selectOptions(screen.getByTestId('subscriber-dnn'), 'internet');
}

beforeEach(() => {
  if (typeof localStorage !== 'undefined') localStorage.clear();
  if (typeof sessionStorage !== 'undefined') sessionStorage.clear();
  _resetFlags();
  setFlag('polarisProvisioning', true);
});

afterEach(() => {
  vi.restoreAllMocks();
  _resetFlags();
});

describe('AddSubscriberDialog (0.7.1)', () => {
  it('POSTs /subscribers with normalised IMSI and slice/DNN picked from /plmns + /dnns', async () => {
    stubFetch((call) => {
      if (call.method === 'GET' && call.url.endsWith('/plmns')) return respond(200, PLMNS);
      if (call.method === 'GET' && call.url.endsWith('/dnns')) return respond(200, DNNS);
      if (call.method === 'POST' && call.url.endsWith('/subscribers')) {
        return respond(201, {
          slot_id: 'slot-01',
          subscriber_id: 'sub-abc-01',
          imsi: 'PROTECTED',
          k: 'PROTECTED',
          opc: 'PROTECTED',
          sst: 1,
          sd: 'A1B2C3',
          dnns: ['internet'],
          ambr: { uplink: 1_048_576, downlink: 1_048_576 },
          created_at_epoch_s: 1,
        });
      }
      return respond(404, { error: 'not stubbed' });
    });
    const user = userEvent.setup();
    renderDialog();
    await fillValid(user);
    await user.click(screen.getByTestId('add-subscriber-submit'));

    await screen.findByTestId('add-subscriber-created');
    const post = calls.find((c) => c.method === 'POST' && c.url.endsWith('/subscribers'));
    expect(post?.body).toEqual({
      imsi: 'imsi-001010000000201',
      k: '0a1b2c3d4e5f60718293a4b5c6d7e8f9',
      opc: 'ffeeddccbbaa99887766554433221100',
      sst: 1,
      sd: 'A1B2C3',
      dnns: ['internet'],
      // 0.10.0 — default AMBR raised to 1 Gbit/s on both directions.
      ambr: { uplink: 1_000_000, downlink: 1_000_000 },
    });
    // Scrubbed from state.
    expect(screen.getByTestId('subscriber-imsi')).toHaveValue('');
    expect(screen.getByTestId('subscriber-k')).toHaveValue('');
    expect(screen.getByTestId('subscriber-opc')).toHaveValue('');
  });

  it('shows "Backend pending" when /plmns returns no slice and /dnns is empty', async () => {
    stubFetch((call) => {
      if (call.method === 'GET' && call.url.endsWith('/plmns'))
        return respond(200, { items: [], total: 0 });
      if (call.method === 'GET' && call.url.endsWith('/dnns'))
        return respond(200, { items: [], total: 0 });
      return respond(404, { error: 'not stubbed' });
    });
    renderDialog();
    const slice = await screen.findByTestId('subscriber-slice');
    const dnn = screen.getByTestId('subscriber-dnn');
    // 0.10.0 — /plmns without slice no longer disables slice selection; a
    // lab-default S-NSSAI 1/010203 fallback is proposed instead, tagged
    // explicitly "valeur du labo". /dnns truly empty still surfaces the
    // "Backend pending" copy.
    await screen.findByTestId('subscriber-slice-fallback');
    expect(slice.textContent).toMatch(/valeur du labo/i);
    await waitFor(() => expect(dnn).toBeDisabled());
    expect(dnn.textContent).toMatch(/Backend pending/i);
  });

  it('surfaces 409 SUBSCRIBER_NOT_POLARIS_OWNED verbatim', async () => {
    stubFetch((call) => {
      if (call.method === 'GET' && call.url.endsWith('/plmns')) return respond(200, PLMNS);
      if (call.method === 'GET' && call.url.endsWith('/dnns')) return respond(200, DNNS);
      return respond(409, { error: 'SUBSCRIBER_NOT_POLARIS_OWNED' });
    });
    const user = userEvent.setup();
    renderDialog();
    await fillValid(user);
    await user.click(screen.getByTestId('add-subscriber-submit'));
    const err = await screen.findByTestId('add-subscriber-error');
    expect(err).toHaveTextContent('HTTP 409');
    expect(err).toHaveTextContent('SUBSCRIBER_NOT_POLARIS_OWNED');
  });
});
