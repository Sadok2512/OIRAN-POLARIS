// 0.6.0 — UE detail page renders the eight structured blocks from the
// backend-returned object. When the flag is OFF or the backend 404s,
// honest placeholders are shown instead of fabricated values.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import type { ReactNode } from 'react';
import { UeDetailPage } from './UeDetail';
import { _resetFlags, setFlag } from '@/data/featureFlags';

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const DETAIL = {
  ue_id: 'UE-01',
  identity: {
    name: 'UE under test',
    owner: 'ops-nancy',
    note: 'provisioning hand-off',
    imsi: 'PROTECTED',
    authentication: 'PROTECTED',
  },
  provisioning: {
    status: 'VERIFIED',
    subscriber_id: 'sub-abc-01',
    bound_at_epoch_s: 1_793_200_000,
  },
  network_profile: {
    plmn: { mcc: '208', mnc: '93' },
    dnn: 'internet',
    sst: 1,
    sd: 'A1B2C3',
    serving_gnb: 'GNB-01',
  },
  registration: { state: 'REGISTERED', last_registered_at_epoch_s: 1_793_200_010 },
  pdu_sessions: [
    { id: 1, dnn: 'internet', type: 'IPv4', ip: '10.45.0.2', established_at_epoch_s: 1_793_200_020 },
  ],
  ims: { state: 'IMS_NOT_AVAILABLE', reason: 'IMS stack pending' },
  scenario: { assigned_id: 'scn-small-traffic', auto_run: false, last_job_id: null },
  traffic: { bytes_dl: 1_024_000, bytes_ul: 128_000, last_sample_epoch_s: 1_793_200_030 },
};

function renderPage(initial: string = '/ues/UE-01', node: ReactNode = <UeDetailPage />) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[initial]}>
        <Routes>
          <Route path="/ues/:ueId" element={node} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  if (typeof localStorage !== 'undefined') localStorage.clear();
  _resetFlags();
  setFlag('polarisProvisioning', true);
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.includes('/ue-profiles/UE-01')) {
      return respond(200, DETAIL);
    }
    return respond(404, { error: 'not stubbed' });
  }) as unknown as typeof fetch;
});

afterEach(() => {
  vi.restoreAllMocks();
  _resetFlags();
});

describe('UeDetailPage', () => {
  it('renders the eight blocks from the backend body', async () => {
    renderPage();
    await screen.findByTestId('ue-block-identity');
    const blocks = [
      'ue-block-identity',
      'ue-block-provisioning',
      'ue-block-network',
      'ue-block-registration',
      'ue-block-pdu',
      'ue-block-ims',
      'ue-block-scenario',
      'ue-block-traffic',
    ];
    for (const testid of blocks) expect(screen.getByTestId(testid)).toBeInTheDocument();
    // IMSI and authentication material surface as PROTECTED, never raw.
    expect(screen.getByTestId('ue-block-identity')).toHaveTextContent('PROTECTED');
    // PDU rows map 1:1.
    expect(screen.getByTestId('ue-pdu-row-1')).toHaveTextContent('internet');
  });

  it('surfaces "Backend pending" placeholder when the flag is OFF', () => {
    setFlag('polarisProvisioning', false);
    renderPage();
    expect(screen.getByText(/polarisProvisioning is OFF/i)).toBeInTheDocument();
  });

  it('surfaces the backend code verbatim on 404', async () => {
    globalThis.fetch = vi.fn(async () =>
      respond(404, { error: 'UE_NOT_FOUND' }),
    ) as unknown as typeof fetch;
    renderPage();
    await waitFor(() => expect(screen.getByText(/UE_NOT_FOUND/)).toBeInTheDocument());
  });
});
