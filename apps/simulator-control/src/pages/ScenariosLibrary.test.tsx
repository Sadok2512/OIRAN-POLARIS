import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { ScenariosLibraryPage } from './ScenariosLibrary';
import { _resetFlags, setFlag } from '@/data/featureFlags';

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

function LocationProbe() {
  const location = useLocation();
  return <div data-testid="probe-location" data-pathname={location.pathname} data-state={JSON.stringify(location.state ?? null)} />;
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/scenarios']}>
        <Routes>
          <Route path="/scenarios" element={<ScenariosLibraryPage />} />
          <Route path="/scenarios/new" element={<LocationProbe />} />
          <Route path="/scenarios/:scenarioId/edit" element={<LocationProbe />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  localStorage.clear();
  _resetFlags();
  setFlag('scenarioTemplates', true);
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.endsWith('/scenario-templates')) return respond(500, { error: 'offline fallback test' });
    if (url.endsWith('/scenario-definitions')) return respond(200, { items: [], total: 0, schema_version: 1 });
    if (url.endsWith('/capabilities')) return respond(200, {
      live_control: true, approval_state: 'OPERATOR_AUTHORIZATION_REQUIRED', max_ues: 10, max_nodes: 2,
      registration_modes: ['STAGGERED'], traffic_protocols: ['UDP'], approved_destinations: [],
      profiles: [], technologies: [], services: [],
      scenario_step_kinds: ['ue_start', 'ue_stop', 'pdu_establish', 'pdu_release', 'udp_traffic', 'wait'],
    });
    if (url.endsWith('/lte/status')) return respond(200, { certified: false, grant_active: false });
    return respond(404, { error: 'not stubbed' });
  }) as typeof fetch;
});

afterEach(() => {
  vi.restoreAllMocks();
  _resetFlags();
});

describe('ScenariosLibrary — default LTE/5G system templates', () => {
  it('shows the thirteen immutable ANR1 templates and all category filters', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByTestId('scenarios-tab-templates'));
    expect(await screen.findAllByTestId(/^template-card-/)).toHaveLength(13);
    for (const category of ['Connectivity', 'Session', 'Data UL/DL', 'Full Session']) {
      expect(screen.getAllByText(category).length).toBeGreaterThan(0);
    }
    expect(screen.getByRole('option', { name: 'Multi-UE' })).toBeVisible();
    expect(screen.getAllByLabelText('Immutable system template')).toHaveLength(13);
    expect(screen.queryByRole('button', { name: /^Edit / })).toBeNull();
    expect(screen.queryByRole('button', { name: /^Delete / })).toBeNull();
  });

  it('filters independently by RAT and category', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByTestId('scenarios-tab-templates'));
    await user.selectOptions(screen.getByLabelText('Template RAT filter'), 'LTE');
    expect(screen.getAllByTestId(/^template-card-/)).toHaveLength(6);
    expect(screen.queryByText('5G SA Registration')).toBeNull();
    await user.selectOptions(screen.getByLabelText('Template category filter'), 'Data UL/DL');
    expect(screen.getAllByTestId(/^template-card-/)).toHaveLength(3);
    expect(screen.getByText('LTE Attach + Data')).toBeVisible();
  });

  it('Use Template loads an editable copy with steps and source metadata', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByTestId('scenarios-tab-templates'));
    await user.click(screen.getByTestId('template-use-tpl-lte-full-session'));
    const probe = await screen.findByTestId('probe-location');
    expect(probe).toHaveAttribute('data-pathname', '/scenarios/new');
    const state = JSON.parse(probe.getAttribute('data-state') ?? 'null') as {
      seedFromTemplate: { id: string; name: string; technology: string; steps: unknown[] };
      systemTemplate: { id: string; action: string; support: string };
    };
    expect(state.seedFromTemplate.id).toBe('tpl-lte-full-session');
    expect(state.seedFromTemplate.name).toContain('copy');
    expect(state.seedFromTemplate.technology).toBe('LTE');
    expect(state.seedFromTemplate.steps).toHaveLength(5);
    expect(state.systemTemplate).toMatchObject({ action: 'use', support: 'BACKEND_REQUIRED' });
  });

  it('Customize uses a fresh draft and exposes honest support badges', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByTestId('scenarios-tab-templates'));
    expect(await screen.findAllByTestId('support-CERTIFICATION_REQUIRED')).toHaveLength(2);
    const card = screen.getByTestId('template-card-tpl-5g-full-session');
    expect(within(card).getByTestId('support-BACKEND_REQUIRED')).toBeVisible();
    await user.click(screen.getByTestId('template-customize-tpl-5g-full-session'));
    const state = JSON.parse((await screen.findByTestId('probe-location')).getAttribute('data-state') ?? 'null') as { systemTemplate: { action: string } };
    expect(state.systemTemplate.action).toBe('customize');
  });
});
