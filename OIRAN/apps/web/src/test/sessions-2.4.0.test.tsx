// 2.4.0 — Sessions page smoke tests: mockup column contract (7 content
// cols, no explicit Session ID column) and Session ID overlap fix
// (procedure cell wraps the mono hash in a max-w + truncate + title).

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SessionExplorer } from '../pages/SessionExplorer';

function respond(body: unknown, meta: Record<string, unknown> = {}) {
  return new Response(JSON.stringify({ data: body, meta }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

function stub() {
  globalThis.fetch = vi.fn(async (input) => {
    const url = String(input);
    if (url.includes('/datasets')) return respond([]);
    if (url.includes('/ues?')) return respond([]);
    if (url.includes('/sessions'))
      return respond(
        [
          {
            session_id: '5g-session-18fe28a814c4b094',
            dataset_id: 'derived-e2e-002-live',
            ue_context_id: 'ue-ebee45ec',
            technology: '5G SA',
            ue_pseudonym: 'UE-ebee45ec',
            pdu_session_id: '1',
            serving_node: 'GNB-01',
            procedure: 'Registration + PDU session',
            start_timestamp: '2026-10-26T22:44:41.226Z',
            end_timestamp: '2026-10-26T22:44:41.513Z',
            duration_ns: '287000000',
            interfaces: ['N2', 'SBI', 'N4', 'N3'],
            message_count: 18,
            source_event_count: 18,
            background_event_count: 0,
            correlation_status: 'POSSIBLE',
            decode_completeness: { decoded: 11, partial: 4, unresolved_fields: 0 },
            state: 'ACTIVE_WITH_USER_PLANE',
          },
        ],
        { page: 1, page_size: 25, total: 1, total_pages: 1 },
      );
    return respond([]);
  }) as unknown as typeof fetch;
}

function renderExplorer() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/investigation/sessions']}>
        <Routes>
          <Route path="/investigation/sessions" element={<SessionExplorer />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('Sessions · 2.4.0 mockup contract', () => {
  beforeEach(stub);

  it('renders the 7 mockup columns and no explicit Session ID header', async () => {
    renderExplorer();
    await waitFor(() => expect(screen.getByTestId('sessions-table')).toBeInTheDocument());
    const headers = screen.getAllByRole('columnheader').map((h) => h.textContent?.trim() ?? '');
    expect(headers).toEqual([
      'Procedure',
      'UE',
      'Start (UTC)',
      'Duration',
      'Interfaces',
      'Msgs',
      'Correlation',
    ]);
  });

  it('fixes the Session ID overlap: hash lives in the Procedure cell, truncated with title', async () => {
    renderExplorer();
    const id = await screen.findByTestId('session-id-5g-session-18fe28a814c4b094');
    expect(id.className).toMatch(/truncate/);
    expect(id).toHaveAttribute('title', '5g-session-18fe28a814c4b094');
    const cell = id.closest('td') as HTMLTableCellElement;
    expect(cell.className).toMatch(/max-w-\[260px\]/);
  });
});
