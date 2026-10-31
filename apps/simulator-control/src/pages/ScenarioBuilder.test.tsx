// 0.5.1 — Honest Scenario Builder tests.
//
// What this covers:
//   * Palette: counts of clickable (supported) vs locked step chips in
//     backend mode. Reason is surfaced on the locked chip's `title`.
//   * LoopEditor: Infinite / Random / Custom are disabled when backendOnly.
//   * Save: blocked and shows a banner when the current draft holds a
//     non-certified step (e.g. ims_register) in backend mode.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, type InitialEntry } from 'react-router-dom';
import type { ReactNode } from 'react';
import { ScenarioBuilderPage } from './ScenarioBuilder';
import { _resetFlags, setFlag } from '@/data/featureFlags';
import { STEP_METADATA, type ScenarioStepKind } from '@/scenarios/model';

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function renderPage(children: ReactNode = <ScenarioBuilderPage />, initialEntries: InitialEntry[] = ['/scenarios/new']) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={initialEntries}>{children}</MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  if (typeof localStorage !== 'undefined') localStorage.clear();
  if (typeof sessionStorage !== 'undefined') sessionStorage.clear();
  _resetFlags();
  // 0.5.1 default is ON; be explicit for clarity.
  setFlag('scenarioBackend', true);
  // The library hook fetches /scenario-definitions on mount and the
  // ScenarioBuilder fetches /capabilities; stub both. By default
  // capabilities omits `scenario_step_kinds`, so only the pre-0.5.2
  // whitelist stays clickable.
  stubFetch({ advertisedKinds: undefined });
});

function stubFetch({ advertisedKinds }: { advertisedKinds?: string[] }) {
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.endsWith('/scenario-definitions')) {
      return respond(200, { items: [], total: 0, schema_version: 1 });
    }
    if (url.endsWith('/capabilities')) {
      return respond(200, {
        live_control: false,
        approval_state: 'LAB',
        max_ues: 100,
        max_nodes: 10,
        registration_modes: [],
        traffic_protocols: [],
        approved_destinations: [],
        profiles: [],
        technologies: [],
        services: [],
        ...(advertisedKinds ? { scenario_step_kinds: advertisedKinds } : {}),
      });
    }
    if (url.endsWith('/auth/me')) {
      return respond(200, { authenticated: true, username: 'operator-test', role: 'operator', can_start: true, can_manage_permissions: false });
    }
    if (url.endsWith('/lte/status')) {
      return respond(200, { certified: false, grant_active: false });
    }
    return respond(404, { error: 'not stubbed' });
  }) as unknown as typeof fetch;
}

afterEach(() => {
  vi.restoreAllMocks();
  _resetFlags();
});

describe('ScenarioBuilder — honest palette (0.5.1 + 0.5.2)', () => {
  it('exposes exactly 6 backend-certified step chips when /capabilities omits scenario_step_kinds', async () => {
    renderPage();
    await screen.findByTestId('step-palette');
    // Wait for /capabilities to resolve so the Builder has had a chance to
    // promote any advertised kinds. Here capabilities omits the field, so the
    // palette must only expose the pre-0.5.2 whitelist of six.
    await waitFor(() => {
      expect(screen.getByTestId('add-step-UE_START')).toBeInTheDocument();
    });

    const CERTIFIED_WHEN_UNANNOUNCED: ScenarioStepKind[] = [
      'UE_START',
      'PDU_ESTABLISH',
      'UDP_TRAFFIC',
      'IDLE',
      'PDU_RELEASE',
      'UE_STOP',
    ];
    expect(CERTIFIED_WHEN_UNANNOUNCED).toHaveLength(6);
    for (const kind of CERTIFIED_WHEN_UNANNOUNCED) {
      expect(screen.getByTestId(`add-step-${kind}`)).toBeEnabled();
    }

    // The 0.5.2-pending kinds show up as LOCKED with the exact "Backend
    // pending: feat/polaris-traffic-templates" reason — because
    // /capabilities did not advertise them.
    for (const kind of ['TRAFFIC_UL', 'DETACH', 'REPEAT'] as const) {
      const chip = screen.getByTestId(`locked-step-${kind}`);
      expect(chip).toHaveAttribute('aria-disabled', 'true');
      expect(chip).toHaveAttribute('title', 'Backend pending: feat/polaris-traffic-templates.');
    }
    // STEP_METADATA bookkeeping is still consistent.
    const metaCertifiedCount = (Object.keys(STEP_METADATA) as ScenarioStepKind[]).filter(
      (k) => STEP_METADATA[k].backendCertified,
    ).length;
    expect(metaCertifiedCount).toBe(6);
  });

  it('promotes TRAFFIC_UL / DETACH / REPEAT to clickable when /capabilities advertises them (0.5.2)', async () => {
    stubFetch({ advertisedKinds: ['traffic_ul', 'detach', 'repeat'] });
    renderPage();
    // Wait for the capabilities-driven promotion to show up.
    await waitFor(() => {
      expect(screen.getByTestId('add-step-TRAFFIC_UL')).toBeInTheDocument();
    });
    expect(screen.getByTestId('add-step-TRAFFIC_UL')).toBeEnabled();
    expect(screen.getByTestId('add-step-DETACH')).toBeEnabled();
    expect(screen.getByTestId('add-step-REPEAT')).toBeEnabled();
    // The remaining locked kinds stay locked (TRAFFIC_DL, IMS_REGISTER, …).
    expect(screen.getByTestId('locked-step-TRAFFIC_DL')).toHaveAttribute('aria-disabled', 'true');
    expect(screen.getByTestId('locked-step-IMS_REGISTER')).toHaveAttribute('aria-disabled', 'true');
  });

  it('locks Infinite, Random and Custom loop presets when scenarioBackend is ON', async () => {
    renderPage();
    await screen.findByTestId('loop-editor');
    const infinite = screen.getByTestId('loop-preset-infinite');
    const random = screen.getByTestId('loop-preset-random');
    const custom = screen.getByTestId('loop-preset-custom');
    expect(infinite).toBeDisabled();
    expect(random).toBeDisabled();
    expect(custom).toBeDisabled();
    // Once + ×50 + ×100 stay clickable.
    expect(screen.getByTestId('loop-preset-once')).toBeEnabled();
    expect(screen.getByTestId('loop-preset-×50')).toBeEnabled();
    expect(screen.getByTestId('loop-preset-×100')).toBeEnabled();
  });

  it('allows saving a representable draft but keeps Run blocked for a non-executable step', async () => {
    const user = userEvent.setup();
    renderPage();

    // Seed a certified step first so the draft passes "at least one step" validation.
    const supported = await screen.findByTestId('add-step-UE_START');
    await user.click(supported);

    // Save button should be enabled now.
    const save = screen.getByTestId('builder-save');
    await waitFor(() => expect(save).toBeEnabled());

    // Inject a non-certified step by changing the newly-added UE_START's
    // kind select to IMS_REGISTER. The kind select appears via StepEditor.
    const kindSelect = (await screen.findByLabelText(/Step 1 kind/i)) as HTMLSelectElement;
    await user.selectOptions(kindSelect, 'IMS_REGISTER');

    // Banner appears, Save stays available for the definition copy, while Run is blocked.
    await screen.findByTestId('builder-locked-step-banner');
    expect(save).toBeEnabled();
    expect(screen.getByTestId('builder-run')).toBeDisabled();
    expect(screen.getByTestId('builder-run')).toHaveAttribute('title', expect.stringMatching(/backend execution support/i));
  });

  it('loads, edits and saves a new LTE system-template copy while Run remains certification-gated', async () => {
    const calls: Array<{ method: string; body: string }> = [];
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = (init?.method ?? 'GET').toUpperCase();
      if (url.endsWith('/scenario-definitions') && method === 'GET') return respond(200, { items: [], total: 0, schema_version: 1 });
      if (url.endsWith('/scenario-definitions/tpl-lte-attach/clone') && method === 'POST') {
        calls.push({ method, body: String(init?.body ?? '') });
        const body = JSON.parse(String(init?.body)) as { target_id: string };
        return respond(201, { id: body.target_id, name: 'LTE Attach copy', loop_count: 1, steps: [{ type: 'lte_attach', loop_count: 1, parameters: {} }], version: 1 });
      }
      if (url.includes('/scenario-definitions/') && method === 'PUT') {
        calls.push({ method, body: String(init?.body ?? '') });
        const body = JSON.parse(String(init?.body)) as { id: string; name: string; loop_count: number; steps: unknown[] };
        return respond(200, { ...body, version: 2, created_at_epoch_s: 1, updated_at_epoch_s: 2 });
      }
      if (url.endsWith('/capabilities')) return respond(200, {
        live_control: true, approval_state: 'OPERATOR_AUTHORIZATION_REQUIRED', max_ues: 1, max_nodes: 2,
        registration_modes: [], traffic_protocols: [], approved_destinations: [], profiles: [], technologies: [], services: [],
        scenario_step_kinds: [],
      });
      if (url.endsWith('/auth/me')) return respond(200, { authenticated: true, username: 'operator-test', role: 'operator', can_start: true, can_manage_permissions: false });
      if (url.endsWith('/lte/status')) return respond(200, { certified: false, grant_active: false });
      return respond(404, { error: 'not stubbed' });
    }) as typeof fetch;

    const now = Date.now();
    renderPage(<ScenarioBuilderPage />, [{
      pathname: '/scenarios/new',
      state: {
        seedFromTemplate: {
          id: 'tpl-lte-attach', name: 'LTE Attach copy', description: 'draft',
          version: 1, createdAt: now, updatedAt: now, technology: 'LTE', loop: { kind: 'ONCE' },
          steps: [{ id: 'step-lte', kind: 'LTE_ATTACH', params: {} }],
        },
        systemTemplate: { id: 'tpl-lte-attach', name: 'LTE Attach', action: 'customize', support: 'CERTIFICATION_REQUIRED' },
      },
    }]);

    expect(await screen.findByTestId('builder-template-source')).toHaveTextContent('immutable source');
    const name = screen.getByTestId('scenario-name');
    await userEvent.setup().clear(name);
    await userEvent.setup().type(name, 'My LTE connectivity copy');
    expect(screen.getByTestId('builder-run')).toBeDisabled();
    expect(screen.getByTestId('builder-run')).toHaveAttribute('title', 'Backend execution support is missing for at least one step.');
    expect(screen.getByTestId('builder-save')).toBeEnabled();
    await userEvent.setup().click(screen.getByTestId('builder-save'));
    await waitFor(() => expect(calls).toHaveLength(2));
    expect(calls[0].method).toBe('POST');
    const cloneBody = JSON.parse(calls[0].body) as { target_id: string };
    expect(cloneBody.target_id).not.toMatch(/^tpl-/);
    expect(calls[1].method).toBe('PUT');
    const body = JSON.parse(calls[1].body) as { id: string; name: string; steps: Array<{ type: string }> };
    expect(body.id).not.toBe('tpl-lte-attach');
    expect(body.name).toBe('My LTE connectivity copy');
    expect(body.steps[0].type).toBe('lte_attach');
  });

  it('offline-draft mode (flag OFF) hides the locked-step banner and clears the Save guard', async () => {
    setFlag('scenarioBackend', false);
    const user = userEvent.setup();
    renderPage();
    // Supported chips are still rendered; non-certified ones remain in the
    // locked group, but Save no longer blocks on them.
    const supported = await screen.findByTestId('add-step-UE_START');
    await user.click(supported);
    const kindSelect = (await screen.findByLabelText(/Step 1 kind/i)) as HTMLSelectElement;
    await user.selectOptions(kindSelect, 'IMS_REGISTER');
    expect(screen.queryByTestId('builder-locked-step-banner')).toBeNull();
    expect(screen.getByTestId('builder-save')).toBeEnabled();
    expect(screen.getByTestId('builder-offline-draft-badge')).toBeInTheDocument();
  });
});
