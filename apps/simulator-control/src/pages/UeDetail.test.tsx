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

  it('renders the current FLAT /ue-profiles body without crashing (prod regression 2026-11-14)', async () => {
    // Exact shape served in production by polaris-control 0.35.1 for UE-201
    // (blank page before 0.35.2: `identity` was undefined).
    const FLAT = {
      authentication_material: 'PROTECTED',
      auto_run_scenario: false,
      dnn: 'internet',
      ims: { configured: true, state: 'NOT_OBSERVED' },
      last_job: { bytes_dl: null, bytes_ul: null, job_id: null },
      name: 'UE-201',
      pdu_session: { dnn: 'internet', type: 'IPv4' },
      pdu_sessions: [],
      plmn: { mcc: '001', mnc: '01' },
      profile: 'ue-00201.yaml',
      revision: 15,
      scenario_id: 'simple-voice-register',
      serving_gnb: 'GNB-01',
      snssai: { sd: '010203', sst: 1 },
      subscriber: {
        authentication_material: 'PROTECTED',
        dnns: ['internet', 'ims'],
        msisdn: null,
        plmn: { mcc: '001', mnc: '01' },
        slot: 'SUB-aa285255e257',
        snssai: { sd: '010203', sst: 1 },
        state: 'PROVISIONED',
        subscriber_identity: '001010000000201',
      },
      subscriber_identity: '001010000000201',
      subscriber_identity_exposed: true,
      subscription_status: 'VERIFIED',
      ue_id: 'UE-201',
      updated_at_epoch_s: 1794655154,
    };
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/ue-profiles/UE-201')) return respond(200, FLAT);
      return respond(404, { error: 'not stubbed' });
    }) as unknown as typeof fetch;
    renderPage('/ues/UE-201');
    await screen.findByTestId('ue-block-provisioning');
    expect(screen.getByTestId('ue-block-provisioning')).toHaveTextContent('VERIFIED');
    expect(screen.getByTestId('ue-block-provisioning')).toHaveTextContent('SUB-aa285255e257');
    expect(screen.getByTestId('ue-block-network')).toHaveTextContent('001/01');
    expect(screen.getByTestId('ue-block-network')).toHaveTextContent('010203');
    expect(screen.getByTestId('ue-block-network')).toHaveTextContent('internet, ims');
    expect(screen.getByTestId('ue-block-scenario')).toHaveTextContent('simple-voice-register');
    expect(screen.getByTestId('ue-block-ims')).toHaveTextContent('NOT_OBSERVED');
    expect(screen.getByTestId('ue-block-traffic')).toHaveTextContent('aucun run mesuré');
    expect(screen.getByTestId('ue-block-identity')).toHaveTextContent('non provisionné');
    expect(screen.getByTestId('ue-detail-live-link')).toHaveAttribute('href', '/ues/UE-201/activity');
  });

  it('normalizeUeDetail never throws on an empty or hostile body', async () => {
    const { normalizeUeDetail } = await import('./UeDetail');
    for (const body of [null, undefined, 42, 'x', [], {}, { identity: null, subscriber: 7 }]) {
      const out = normalizeUeDetail(body, 'UE-X');
      expect(out.ue_id).toBe('UE-X');
      expect(out.pdu_sessions).toEqual([]);
      expect(out.traffic.bytes_dl).toBeNull();
    }
  });

  it('surfaces the backend code verbatim on 404', async () => {
    globalThis.fetch = vi.fn(async () =>
      respond(404, { error: 'UE_NOT_FOUND' }),
    ) as unknown as typeof fetch;
    renderPage();
    await waitFor(() => expect(screen.getByText(/UE_NOT_FOUND/)).toBeInTheDocument());
  });
});
