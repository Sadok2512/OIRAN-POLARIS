import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { UeManagerPage } from './UeManager';
import { _resetFlags, setFlag } from '@/data/featureFlags';
import { _resetProfiles } from '@/ue/profileStore';

// Raw POLARIS bodies (no {data, meta} envelope), copied from
// POLARIS_CONTROL/docs/api/ue-profiles.contract.md measured examples.
const ue11 = {
  authentication_material: 'PROTECTED',
  auto_run_scenario: false,
  dnn: 'internet',
  name: 'Contract UE 11',
  pdu_session: { dnn: 'internet', type: 'IPv4' },
  plmn: { mcc: '001', mnc: '01' },
  profile: 'ue-11.yaml',
  revision: 1,
  scenario_id: null,
  serving_gnb: 'GNB-01',
  snssai: { sd: '010203', sst: 1 },
  subscriber_identity: 'PROTECTED',
  subscription_status: 'PROVISIONING_REQUIRED',
  ue_id: 'UE-11',
  updated_at_epoch_s: 1793186621,
};

interface Call {
  method: string;
  url: string;
  body: unknown;
}
const calls: Call[] = [];

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

beforeEach(() => {
  localStorage.clear();
  _resetProfiles();
  _resetFlags();
  setFlag('profileBackend', true);
  calls.length = 0;
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    calls.push({ method, url, body });
    if (url.includes('/auth/me')) {
      return respond(200, {
        authenticated: true,
        username: 'ops',
        role: 'operator',
        can_start: true,
        can_manage_permissions: false,
        csrf_token: null,
      });
    }
    if (url.includes('/ue-profiles/provisioning-slots')) {
      return respond(200, {
        available: 1,
        items: [
          { bound_ue_id: null, slot_id: 'UE-01' },
          { bound_ue_id: 'UE-11', slot_id: 'UE-02' },
        ],
        secrets_exposed: false,
        total: 2,
      });
    }
    if (url.includes('/gnbs')) {
      return respond(200, { items: [{ gnb_id: 'GNB-01', link_ip: '10.77.0.20' }], source: 'LAB_DEFAULT', total: 1 });
    }
    if (method === 'POST' && url.endsWith('/ue-profiles')) {
      return respond(201, { ...ue11, ue_id: body.ue_id, name: body.name });
    }
    if (url.includes('/ue-profiles?')) {
      return respond(200, { items: [ue11], max: 10000, page: 1, page_size: 500, pages: 1, secrets_exposed: false, total: 1 });
    }
    if (url.includes('/scenarios/status')) {
      return respond(200, { active_count: 0, active_job: null, history_count: 0, latest_terminal_job: null, observed_at_epoch_s: 0, source: 'test' });
    }
    if (url.includes('/ues')) {
      return respond(200, { active_count: 0, configured_count: 0, configured_profiles: [], items: [], registered_count: 0, source: 'test' });
    }
    return respond(404, { error: 'NOT_STUBBED' });
  }) as unknown as typeof fetch;
});

afterEach(() => {
  vi.restoreAllMocks();
  _resetFlags();
});

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <UeManagerPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('UE Manager — POLARIS profile registry (profileBackend flag)', () => {
  it('lists profiles from the raw /ue-profiles body and shows the provisioning status', async () => {
    renderPage();
    expect(await screen.findByTestId('ue-row-UE-11')).toBeInTheDocument();
    expect(screen.getByTestId('ue-subscription-UE-11')).toHaveTextContent('Not provisioned in Open5GS');
    expect(screen.getByTestId('ue-import')).toBeDisabled();
  });

  it('creates a profile bound to a provisioned slot without sending or storing any secret', async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByTestId('ue-row-UE-11');
    await user.click(screen.getByTestId('ue-add'));
    expect(await screen.findByTestId('ue-profile-backend-form')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByTestId('backend-profile-slot')).toHaveValue('UE-01'));

    await user.type(screen.getByTestId('backend-profile-ue-id'), 'UE-12');
    await user.type(screen.getByTestId('backend-profile-name'), 'Lab UE 12');
    await user.click(screen.getByTestId('backend-profile-submit'));

    await waitFor(() =>
      expect(calls.some((call) => call.method === 'POST' && call.url.endsWith('/ue-profiles'))).toBe(true),
    );
    const post = calls.find((call) => call.method === 'POST' && call.url.endsWith('/ue-profiles'));
    expect(post?.body).toEqual({
      ue_id: 'UE-12',
      name: 'Lab UE 12',
      supi: null,
      authentication_key: null,
      opc: null,
      provisioning_slot: 'UE-01',
      plmn_mcc: '001',
      plmn_mnc: '01',
      dnn: 'internet',
      sst: 1,
      sd: '010203',
      serving_gnb: 'GNB-01',
      scenario_id: null,
      auto_run_scenario: false,
    });
    // Nothing about subscribers may land in browser storage in backend mode.
    const stored = Object.keys(localStorage).map((key) => localStorage.getItem(key) ?? '').join('\n');
    expect(stored).not.toMatch(/imsi|UE-12/i);
  });
});
