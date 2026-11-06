// 0.13.2 (#9, ANR1 handoff) — Explicit confidentiality matrix for the
// UE Manager rows, sealed against the polaris-api 0.29.16 contract.
//
// Rule 1 — Viewer session + `subscriber_identity: 'PROTECTED'` →
//          the DOM renders the solid mask and NEVER an IMSI digit
//          span. `formatImsiForRole(_, false)` returns the mask.
// Rule 2 — Operator session + raw IMSI digits →
//          the DOM renders `imsi-<15 digits>` exactly as the server
//          shipped them (no synthesis).
// Rule 3 — Neither role ever sees K / OPc in the rendered DOM. The
//          dialogue handles them as write-only fields; the 0.29.16
//          API never ships them back, and `recordFromWire` ignores
//          `authentication_material` other than the `PROTECTED`
//          sentinel. This test grep's the full rendered HTML for
//          the typical 32-hex K/OPc patterns — any match is a leak.

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { UeManagerPage } from './UeManager';
import type { WireUeProfile } from '@/data/profileApi';

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const PROFILE_OPERATOR: WireUeProfile = {
  ue_id: 'UE-01',
  name: 'Lab UE 01',
  serving_gnb: 'GNB-01',
  plmn: { mcc: '001', mnc: '01' },
  dnn: 'internet',
  snssai: { sst: 1, sd: '010203' },
  pdu_session: { dnn: 'internet', type: 'IPv4' },
  scenario_id: null,
  auto_run_scenario: false,
  subscription_status: 'VERIFIED',
  subscriber_identity: '001010000000001',
  authentication_material: 'PROTECTED',
  profile: 'bounded-controller-ue-udp-v1',
  revision: 1,
  updated_at_epoch_s: 1_730_000_000,
};

const PROFILE_VIEWER: WireUeProfile = {
  ...PROFILE_OPERATOR,
  subscriber_identity: 'PROTECTED',
};

function stubFetch(role: 'operator' | 'viewer') {
  globalThis.fetch = vi.fn(async (input) => {
    const url = String(input);
    if (url.includes('/auth/me'))
      return respond(200, {
        data: {
          authenticated: true,
          username: role === 'operator' ? 'ops' : 'viewer',
          role,
          can_start: role === 'operator',
          can_manage_permissions: false,
        },
        meta: { api_version: '0.29.16' },
      });
    if (url.includes('/capabilities'))
      return respond(200, {
        data: {
          live_control: true,
          approval_state: 'READY',
          max_ues: 32,
          max_nodes: 2,
          registration_modes: ['5G_SA'],
          traffic_protocols: ['UDP'],
          approved_destinations: ['10.46.0.1'],
          profiles: [],
          technologies: [],
          services: [],
        },
        meta: { api_version: '0.29.16' },
      });
    if (url.includes('/ue-profiles')) {
      const profile = role === 'operator' ? PROFILE_OPERATOR : PROFILE_VIEWER;
      return respond(200, {
        data: {
          items: [profile],
          max: 10_000,
          page: 1,
          page_size: 50,
          pages: 1,
          secrets_exposed: false,
          total: 1,
        },
        meta: { api_version: '0.29.16' },
      });
    }
    if (url.includes('/feature-flags'))
      return respond(200, { data: { profileBackend: true, scenarioBackend: false }, meta: {} });
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
    localStorage.setItem(
      'polaris.featureFlags.v1',
      JSON.stringify({ profileBackend: true, scenarioBackend: false }),
    );
  }
});

describe('UE Manager — 0.13.2 confidentiality matrix', () => {
  it('operator sees subscriber_identity digits exactly as 0.29.16 ships them', async () => {
    stubFetch('operator');
    renderPage();
    await waitFor(() => expect(screen.getByTestId('ue-imsi-UE-01')).toBeInTheDocument());
    const cell = screen.getByTestId('ue-imsi-UE-01');
    expect(cell.textContent).toMatch(/imsi-001010000000001/);
    // The `PROTECTED` sentinel must NOT bleed into the DOM for an
    // operator session.
    expect(cell.textContent).not.toMatch(/PROTECTED/);
  });

  it('viewer only sees the solid mask when 0.29.16 returns PROTECTED', async () => {
    stubFetch('viewer');
    renderPage();
    await waitFor(() => expect(screen.getByTestId('ue-imsi-UE-01')).toBeInTheDocument());
    const cell = screen.getByTestId('ue-imsi-UE-01');
    // No 14-16 digit sequence — any such span is a leak.
    expect(cell.textContent).not.toMatch(/\d{14,16}/);
    // The mask contains the Unicode "black circle" bullet repeated.
    expect(cell.textContent).toMatch(/•/);
    // The sentinel string must not appear verbatim either.
    expect(cell.textContent).not.toMatch(/PROTECTED/);
  });

  it('neither role renders a K or OPc 32-hex value anywhere in the DOM', async () => {
    for (const role of ['operator', 'viewer'] as const) {
      stubFetch(role);
      const { unmount } = renderPage();
      await waitFor(() => expect(screen.getByTestId('ue-imsi-UE-01')).toBeInTheDocument());
      const html = document.body.innerHTML;
      // A 32-hex token is the canonical K/OPc shape; any match is a
      // confidentiality regression. Mocked URLs and asset chunk hashes
      // are shorter, so a hit here is genuinely a secret.
      const matches = html.match(/\b[0-9a-fA-F]{32}\b/g) ?? [];
      expect(
        matches,
        `${role} session — no 32-hex K/OPc value may appear in the DOM; found ${matches.length}`,
      ).toEqual([]);
      unmount();
    }
  });
});
