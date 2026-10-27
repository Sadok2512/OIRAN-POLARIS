import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { CallFlowViewer } from '../pages/CallFlowViewer';
import { api } from '../services/api';

vi.mock('../services/api', () => ({ api: vi.fn(), downloadExport: vi.fn() }));

const session = (id: string, ue: string, pdu: string) => ({
  session_id: id, dataset_id: 'synthetic-fixture', ue_context_id: `ctx-${ue}`,
  technology: '5G SA', ue_pseudonym: ue, pdu_session_id: pdu, procedure: 'PDU Session',
  start_timestamp: '1.000Z', end_timestamp: '2.000Z', duration_ns: '1000000000',
  interfaces: ['N2'], message_count: 1, source_event_count: 1, background_event_count: 0,
  correlation_status: 'UNKNOWN', decode_completeness: { decoded: 1, partial: 0, unresolved_fields: 0 }, state: 'INCOMPLETE',
});

const flow = (id: string) => ({
  callflow_id: `cf-${id}`, session_id: id, technology: '5G SA', start_timestamp: '1.000Z', end_timestamp: '2.000Z',
  participants: [], interfaces: ['N2'], procedures: [], events: [], correlation_edges: [],
  correlation_status: { N2_N4: 'UNKNOWN', N4_N3: 'UNKNOWN', E2E: 'UNKNOWN' }, decoder_versions: {},
  schema_version: '1.0.0', capture_references: [],
  accounting: { source_events: 1, session_events: 1, background_events: 0, unmatched_events: 0, duplicate_events: 0, extra_events: 0 },
  unresolved_fields: 0,
});

describe('multi-session navigation fixture', () => {
  beforeEach(() => {
    vi.mocked(api).mockImplementation(async (path: string) => {
      if (path.startsWith('/sessions?')) return { data: [session('s1', 'UE-1', '1'), session('s2', 'UE-1', '2')], meta: {} } as never;
      if (path === '/sessions/s2') return { data: { summary: session('s2', 'UE-1', '2') }, meta: {} } as never;
      if (path === '/sessions/s2/callflow') return { data: flow('s2'), meta: {} } as never;
      throw new Error(`unexpected path ${path}`);
    });
  });

  it('selects an independent Call Flow instead of reusing the first session', async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={['/investigation/callflow']}>
          <Routes>
            <Route path="/investigation/callflow" element={<CallFlowViewer />} />
            <Route path="/investigation/callflow/:sessionId" element={<CallFlowViewer />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(await screen.findByRole('link', { name: /s1/ })).toBeVisible();
    await userEvent.click(screen.getByRole('link', { name: /s2/ }));
    expect(await screen.findByText('s2', { selector: '.page-intro .mono' })).toBeVisible();
    expect(vi.mocked(api)).toHaveBeenCalledWith('/sessions/s2/callflow');
  });
});
