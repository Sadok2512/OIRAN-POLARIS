import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, expect, it, vi } from 'vitest';
import { AppShell } from '../layouts/AppShell';
import { api } from '../services/api';

vi.mock('../services/api', () => ({ api: vi.fn() }));

beforeEach(() => {
  localStorage.clear();
  vi.mocked(api).mockImplementation(async (path?: string) => {
    if (path === '/modules') return { data: [], meta: {} } as never;
    if (path === '/metrics') return { data: {
      observed_at_epoch_s: 1, mode: 'HISTORICAL_DATASET_ANALYSIS', packet_rate_pps: null,
      bitrate_bps: null, decode_rate_eps: null, packet_drops: null,
      capture_queue_utilization_percent: null, active_captures: 0, active_sessions: 0,
      historical_sessions: 1, historical_events: 54, decode_errors: 0,
      cpu: { usage_percent: null, load_one: 1, logical_cpus: 1 },
      memory: { total_bytes: 1, available_bytes: 1, used_bytes: 0 }, disk: null,
      interfaces: [{ interface: 'N2', state: 'REFERENCE_ONLY', packet_rate_pps: null }],
    }, meta: {} } as never;
    if (path === '/auth/me') return { data: { role: 'viewer' }, meta: {} } as never;
    if (path === '/probes') return { data: [{ probe_id: 'probe-1', online: false }], meta: {} } as never;
    if (path === '/datasets?page_size=100') return { data: [{ technology: '5G SA' }], meta: {} } as never;
    throw new Error(`unexpected path ${path}`);
  });
});

it('renders observed backend state and never claims a pending probe is connected', async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/overview']}>
        <Routes>
          <Route element={<AppShell />}><Route path="/overview" element={<div>page</div>} /></Route>
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await waitFor(() => expect(screen.getByTestId('probe-connection')).toHaveTextContent('vProbe not connected'));
  expect(screen.getByTestId('probe-connection')).not.toHaveTextContent('vProbe connected');
  expect(screen.getByTestId('observed-technologies')).toHaveTextContent('Observed: 5G SA');
  expect(screen.getByText('N2 REFERENCE_ONLY')).toBeVisible();
});
