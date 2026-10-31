// 0.6.0 — Templates tab Clone navigates to the Builder with a seeded
// draft. Save then creates a brand-new definition; tpl-* stay read-only
// on the server.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Routes, Route, useLocation } from 'react-router-dom';
import type { ReactNode } from 'react';
import { ScenariosLibraryPage } from './ScenariosLibrary';
import { _resetFlags, setFlag } from '@/data/featureFlags';

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const TEMPLATE = {
  id: 'tpl-voice-long',
  name: 'Voice long',
  version: 1,
  loop_count: 1,
  steps: [
    { type: 'ue_start', loop_count: 1, parameters: {} },
    { type: 'ue_stop', loop_count: 1, parameters: {} },
  ],
};

function LocationProbe() {
  const location = useLocation();
  return (
    <div
      data-testid="probe-location"
      data-pathname={location.pathname}
      data-state={JSON.stringify(location.state ?? null)}
    />
  );
}

function renderPage(children: ReactNode = <ScenariosLibraryPage />) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/scenarios']}>
        <Routes>
          <Route path="/scenarios" element={children} />
          <Route path="/scenarios/new" element={<LocationProbe />} />
          <Route path="/scenarios/:scenarioId/edit" element={<LocationProbe />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  if (typeof localStorage !== 'undefined') localStorage.clear();
  _resetFlags();
  setFlag('scenarioTemplates', true);
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.endsWith('/scenario-definitions')) {
      return respond(200, { items: [TEMPLATE], total: 1, schema_version: 1 });
    }
    if (url.includes('/scenario-definitions/') && url.endsWith('/estimate')) {
      return respond(200, { duration_ms: 1_000 });
    }
    return respond(404, { error: 'not stubbed' });
  }) as unknown as typeof fetch;
});

afterEach(() => {
  vi.restoreAllMocks();
  _resetFlags();
});

describe('ScenariosLibrary — Templates tab (0.6.0)', () => {
  it('Clone navigates to /scenarios/new with a Scenario seed in location state', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByTestId('scenarios-tab-templates'));
    const cloneBtn = await screen.findByTestId(`template-clone-${TEMPLATE.id}`);
    await user.click(cloneBtn);

    const probe = await screen.findByTestId('probe-location');
    expect(probe).toHaveAttribute('data-pathname', '/scenarios/new');
    const state = JSON.parse(probe.getAttribute('data-state') ?? 'null') as {
      seedFromTemplate?: { id: string; name: string; steps: unknown[] };
    } | null;
    expect(state?.seedFromTemplate).toBeDefined();
    expect(state?.seedFromTemplate?.name).toBe(TEMPLATE.name);
    // Builder consumer will reset the id so Save creates a NEW definition.
    expect(state?.seedFromTemplate?.steps).toHaveLength(TEMPLATE.steps.length);
    // Template id itself is preserved in the seed; Builder clears it on mount.
    expect(state?.seedFromTemplate?.id).toBe(TEMPLATE.id);
  });

  it('no POST hits /clone — the backend clone endpoint is NOT called', async () => {
    const calls: string[] = [];
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = (init?.method ?? 'GET').toUpperCase();
      calls.push(`${method} ${url}`);
      if (method === 'GET' && url.endsWith('/scenario-definitions')) {
        return respond(200, { items: [TEMPLATE], total: 1, schema_version: 1 });
      }
      if (url.includes('/estimate')) return respond(200, { duration_ms: 1_000 });
      return respond(404, { error: 'not stubbed' });
    }) as unknown as typeof fetch;

    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByTestId('scenarios-tab-templates'));
    await user.click(await screen.findByTestId(`template-clone-${TEMPLATE.id}`));

    await waitFor(() => expect(screen.getByTestId('probe-location')).toBeInTheDocument());
    expect(calls.find((c) => c.includes('/clone'))).toBeUndefined();
  });
});
