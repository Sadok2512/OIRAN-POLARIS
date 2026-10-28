// 0.6.1 — Real Add subscriber dialog hitting POST /subscribers.
//
// Contract (polaris-control-api 0.15.1 / fc6d8ed):
//   body: { imsi, k, opc, sst, sd, dnns[], ambr: { uplink, downlink } }
//   409 SUBSCRIBER_NOT_POLARIS_OWNED and 422 SUBSCRIBER_NOT_PROVISIONED
//   are two codes the UI must surface verbatim.
//
// The dialog also guarantees that secret material is scrubbed from React
// state right after submit — we assert this by reading the inputs back.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AddSubscriberDialog } from './AddSubscriberDialog';

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

beforeEach(() => {
  if (typeof localStorage !== 'undefined') localStorage.clear();
  if (typeof sessionStorage !== 'undefined') sessionStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function fillValid(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByTestId('subscriber-imsi'), 'imsi-208930000000001');
  await user.type(
    screen.getByTestId('subscriber-k'),
    '0a1b2c3d4e5f60718293a4b5c6d7e8f9',
  );
  await user.type(
    screen.getByTestId('subscriber-opc'),
    'ffeeddccbbaa99887766554433221100',
  );
  // sst/sd already seeded; set dnns + ambr explicitly for the assert.
  const dnns = screen.getByTestId('subscriber-dnns') as HTMLInputElement;
  await user.clear(dnns);
  await user.type(dnns, 'internet,ims');
}

describe('AddSubscriberDialog', () => {
  it('POSTs /subscribers with the exact 0.15.1 body shape', async () => {
    stubFetch((call) =>
      call.method === 'POST' && call.url.endsWith('/subscribers')
        ? respond(201, {
            slot_id: 'slot-01',
            subscriber_id: 'sub-abc-01',
            imsi: 'PROTECTED',
            k: 'PROTECTED',
            opc: 'PROTECTED',
            sst: 1,
            sd: null,
            dnns: ['internet', 'ims'],
            ambr: { uplink: 1_048_576, downlink: 1_048_576 },
            created_at_epoch_s: 1_793_200_000,
          })
        : respond(404, { error: 'not stubbed' }),
    );
    const user = userEvent.setup();
    render(<AddSubscriberDialog open onClose={() => undefined} />);
    await fillValid(user);
    await user.click(screen.getByTestId('add-subscriber-submit'));

    await screen.findByTestId('add-subscriber-created');
    const post = calls.find((c) => c.method === 'POST' && c.url.endsWith('/subscribers'));
    expect(post).toBeDefined();
    expect(post?.contentType).toBe('application/json');
    expect(post?.body).toEqual({
      imsi: 'imsi-208930000000001',
      k: '0a1b2c3d4e5f60718293a4b5c6d7e8f9',
      opc: 'ffeeddccbbaa99887766554433221100',
      sst: 1,
      sd: null,
      dnns: ['internet', 'ims'],
      ambr: { uplink: 1_048_576, downlink: 1_048_576 },
    });
    // Scrubbed from state: the three secret inputs are empty after submit.
    expect(screen.getByTestId('subscriber-imsi')).toHaveValue('');
    expect(screen.getByTestId('subscriber-k')).toHaveValue('');
    expect(screen.getByTestId('subscriber-opc')).toHaveValue('');
    // Response surfaces slot id and the PROTECTED banner.
    expect(screen.getByTestId('add-subscriber-created')).toHaveTextContent('slot-01');
    expect(screen.getByTestId('add-subscriber-created')).toHaveTextContent('PROTECTED');
  });

  it('surfaces 409 SUBSCRIBER_NOT_POLARIS_OWNED verbatim', async () => {
    stubFetch(() => respond(409, { error: 'SUBSCRIBER_NOT_POLARIS_OWNED' }));
    const user = userEvent.setup();
    render(<AddSubscriberDialog open onClose={() => undefined} />);
    await fillValid(user);
    await user.click(screen.getByTestId('add-subscriber-submit'));

    const err = await screen.findByTestId('add-subscriber-error');
    expect(err).toHaveTextContent('HTTP 409');
    expect(err).toHaveTextContent('SUBSCRIBER_NOT_POLARIS_OWNED');
  });

  it('surfaces 422 SUBSCRIBER_NOT_PROVISIONED verbatim', async () => {
    stubFetch(() => respond(422, { error: 'SUBSCRIBER_NOT_PROVISIONED' }));
    const user = userEvent.setup();
    render(<AddSubscriberDialog open onClose={() => undefined} />);
    await fillValid(user);
    await user.click(screen.getByTestId('add-subscriber-submit'));

    const err = await screen.findByTestId('add-subscriber-error');
    expect(err).toHaveTextContent('HTTP 422');
    expect(err).toHaveTextContent('SUBSCRIBER_NOT_PROVISIONED');
  });

  it('refuses to submit when IMSI/K/OPc are not valid', async () => {
    stubFetch(() => respond(500, { error: 'should not be called' }));
    const user = userEvent.setup();
    render(<AddSubscriberDialog open onClose={() => undefined} />);
    // Type garbage into IMSI/K/OPc.
    await user.type(screen.getByTestId('subscriber-imsi'), 'not-an-imsi');
    await user.type(screen.getByTestId('subscriber-k'), 'short');
    await user.type(screen.getByTestId('subscriber-opc'), 'short');
    await user.click(screen.getByTestId('add-subscriber-submit'));
    // Error hints are shown and no POST hit.
    await waitFor(() => expect(screen.getByTestId('subscriber-imsi-error')).toBeInTheDocument());
    expect(calls.find((c) => c.method === 'POST')).toBeUndefined();
  });
});
