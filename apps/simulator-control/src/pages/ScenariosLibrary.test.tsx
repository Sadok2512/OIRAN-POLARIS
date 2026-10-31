import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { ScenariosLibraryPage } from './ScenariosLibrary';
import { _resetFlags, setFlag } from '@/data/featureFlags';
import { DEFAULT_SCENARIO_TEMPLATES } from '@/scenarios/defaultTemplates';

const templateCatalog = {
  schema_version: 'polaris.scenario-template-catalog.v1',
  total: DEFAULT_SCENARIO_TEMPLATES.length,
  multi_ue_templates: false,
  defaults: {
    ue_count: 1, execution: 'SEQUENTIAL', transport: 'UDP', rate_bps: 1_000_000,
    duration_seconds: 60, tcp_authorized: false, multi_ue: false,
  },
  items: DEFAULT_SCENARIO_TEMPLATES.map((item) => ({
    template_id: item.id,
    version: '1.0.0',
    rat: item.rat,
    simulator: item.simulator,
    description: item.description,
    steps: item.definition.steps,
    parameters: {
      ue_count: 1, execution: 'SEQUENTIAL', transport: 'UDP',
      rate_bps: (item.throughputKbps ?? 0) * 1_000,
      duration_seconds: item.durationSeconds, tcp_authorized: false, multi_ue: false,
    },
    required_capabilities: item.prerequisites,
    backend_support: item.support,
    certification_required: item.support === 'CERTIFICATION_REQUIRED',
    read_only: true,
  })),
};

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
    if (url.endsWith('/scenario-templates')) return respond(200, templateCatalog);
    if (url.includes('/estimate')) return respond(200, { duration_ms: 60_000 });
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
  it('shows the thirteen immutable ANR1 templates from the backend', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByTestId('scenarios-tab-templates'));
    expect(await screen.findAllByTestId(/^template-row-/)).toHaveLength(13);
    expect(screen.getByTestId('template-row-tpl-lte-attach')).toBeVisible();
    expect(screen.getByTestId('template-row-tpl-5g-registration')).toBeVisible();
  });

  it('renders all six LTE and seven 5G descriptors without a browser fallback', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByTestId('scenarios-tab-templates'));
    const rows = await screen.findAllByTestId(/^template-row-/);
    expect(rows.filter((row) => row.dataset.testid?.includes('tpl-lte-'))).toHaveLength(6);
    expect(rows.filter((row) => row.dataset.testid?.includes('tpl-5g-'))).toHaveLength(7);
  });

  it('Clone loads an editable copy while preserving the immutable template', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByTestId('scenarios-tab-templates'));
    await user.click(await screen.findByTestId('template-clone-tpl-lte-full-session'));
    const probe = await screen.findByTestId('probe-location');
    expect(probe).toHaveAttribute('data-pathname', '/scenarios/new');
    const state = JSON.parse(probe.getAttribute('data-state') ?? 'null') as {
      seedFromTemplate: { id: string; name: string; technology: string; steps: unknown[] };
    };
    expect(state.seedFromTemplate.id).toBe('tpl-lte-full-session');
    expect(state.seedFromTemplate.name).toBe('Lte Full Session');
    expect(state.seedFromTemplate.technology).toBe('LTE');
    expect(state.seedFromTemplate.steps).toHaveLength(5);
  });

  it('does not expose edit or delete controls for backend templates', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByTestId('scenarios-tab-templates'));
    expect(await screen.findAllByTestId(/^template-row-/)).toHaveLength(13);
    expect(screen.queryByRole('button', { name: /^Edit / })).toBeNull();
    expect(screen.queryByRole('button', { name: /^Delete / })).toBeNull();
  });
});
