// 0.12.2 — Operator vs viewer IMSI reveal.
//
// polaris-api 0.19.7 (#48) made `WireUeProfile.subscriber_identity`
// role-aware: the raw IMSI digits when the caller is an operator /
// administrator, the literal `"PROTECTED"` otherwise. The simulator-control
// front picks the field up via `recordFromWire` and feeds it to
// `formatImsiForRole`, which decides between the digits and the solid mask.
//
// This test locks the matrix:
// - operator session + API-returned IMSI → digits visible in the UE
//   Manager row, prefixed with `imsi-`.
// - viewer session + API-returned "PROTECTED" → solid mask only, no digit
//   span in the DOM.

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { UeManagerPage } from './UeManager';
import { recordFromWire } from '@/ue/profileSource';
import type { WireUeProfile } from '@/data/profileApi';

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const PROFILE_WIRE: WireUeProfile = {
  ue_id: 'UE-12',
  name: 'Lab UE 12',
  serving_gnb: 'GNB-01',
  plmn: { mcc: '001', mnc: '01' },
  dnn: 'internet',
  snssai: { sst: 1, sd: '010203' },
  pdu_session: { dnn: 'internet', type: 'IPv4' },
  scenario_id: null,
  auto_run_scenario: false,
  subscription_status: 'VERIFIED',
  subscriber_identity: '001011234567890',
  authentication_material: 'PROTECTED',
  profile: 'bounded-controller-ue-udp-v1',
  revision: 1,
  updated_at_epoch_s: 1_700_000_000,
};

function stubFetch(role: 'operator' | 'viewer', imsi: string) {
  globalThis.fetch = vi.fn(async (input) => {
    const url = String(input);
    if (url.includes('/auth/me'))
      return respond(200, {
        data: {
          authenticated: true,
          username: role === 'operator' ? 'op' : 'viewer',
          role,
          can_start: role === 'operator',
          can_manage_permissions: false,
        },
        meta: {},
      });
    if (url.includes('/capabilities'))
      return respond(200, {
        data: {
          live_control: true,
          approval_state: 'READY',
          max_ues: 10,
          max_nodes: 2,
          registration_modes: ['5G_SA'],
          traffic_protocols: ['UDP'],
          approved_destinations: ['10.46.0.1'],
          profiles: [],
          technologies: [],
          services: [],
        },
        meta: {},
      });
    if (url.includes('/ue-profiles')) {
      return respond(200, {
        data: {
          items: [{ ...PROFILE_WIRE, subscriber_identity: imsi }],
          total: 1,
          page: 1,
          page_size: 100,
          pages: 1,
          max: 10,
          secrets_exposed: false,
        },
        meta: {},
      });
    }
    if (url.includes('/scenarios/status'))
      return respond(200, {
        data: {
          active_job: null,
          latest_terminal_job: null,
          active_count: 0,
          history_count: 0,
          observed_at_epoch_s: 0,
          source: 'test',
        },
        meta: {},
      });
    if (url.includes('/ues'))
      return respond(200, {
        data: {
          items: [],
          configured_profiles: [],
          configured_count: 1,
          active_count: 0,
          registered_count: 0,
          source: 'test',
        },
        meta: {},
      });
    if (url.includes('/feature-flags'))
      return respond(200, { data: { profileBackend: true }, meta: {} });
    return respond(200, { data: [], meta: {} });
  }) as unknown as typeof fetch;
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/ues']}>
        <UeManagerPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
  if (typeof localStorage !== 'undefined') {
    localStorage.clear();
    // 0.12.2 — turn the backend profile source on so recordFromWire runs
    // in the test; otherwise the local store is empty and the IMSI never
    // reaches the row.
    localStorage.setItem(
      'polaris.featureFlags.v1',
      JSON.stringify({ profileBackend: true, scenarioBackend: false }),
    );
  }
});

describe('recordFromWire — operator IMSI reveal', () => {
  it('carries the raw IMSI when the backend ships it (operator / admin)', () => {
    const r = recordFromWire({ ...PROFILE_WIRE, subscriber_identity: '001011234567890' });
    expect(r.imsi).toBe('001011234567890');
  });

  it('leaves imsi undefined when the backend returns the viewer sentinel', () => {
    const r = recordFromWire({ ...PROFILE_WIRE, subscriber_identity: 'PROTECTED' });
    expect(r.imsi).toBeUndefined();
  });

  it('leaves imsi undefined when the backend omits subscriber_identity', () => {
    const r = recordFromWire({ ...PROFILE_WIRE, subscriber_identity: '' });
    expect(r.imsi).toBeUndefined();
  });
});

describe('UE Manager — operator sees the API IMSI', () => {
  it('renders the digits (imsi-<15 chars>) for a signed-in operator', async () => {
    stubFetch('operator', '001011234567890');
    renderPage();
    await waitFor(() => expect(screen.getByTestId('ue-imsi-UE-12')).toBeInTheDocument());
    const cell = screen.getByTestId('ue-imsi-UE-12');
    expect(cell.textContent).toMatch(/imsi-001011234567890/);
  });
});

describe('UE Manager — viewer stays on the mask', () => {
  it('never shows a raw digit span when the role is viewer', async () => {
    stubFetch('viewer', 'PROTECTED');
    renderPage();
    await waitFor(() => expect(screen.getByTestId('ue-imsi-UE-12')).toBeInTheDocument());
    const cell = screen.getByTestId('ue-imsi-UE-12');
    expect(cell.textContent).not.toMatch(/\d{14,16}/);
    // The mask contains the Unicode "black circle" bullet repeated.
    expect(cell.textContent).toMatch(/•/);
  });
});
