import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, expect, it, vi } from 'vitest';
import { AppShell } from '../layouts/AppShell';
import { api } from '../services/api';

const BASE_METRICS = {
  observed_at_epoch_s: 1,
  mode: 'HISTORICAL_DATASET_ANALYSIS',
  packet_rate_pps: null,
  bitrate_bps: null,
  decode_rate_eps: null,
  packet_drops: null,
  capture_queue_utilization_percent: null,
  active_captures: 0,
  active_sessions: 0,
  historical_sessions: 1,
  historical_events: 54,
  decode_errors: 0,
  cpu: { usage_percent: null, load_one: 1, logical_cpus: 1 },
  memory: { total_bytes: 1, available_bytes: 1, used_bytes: 0 },
  disk: null,
  interfaces: [{ interface: 'N2', state: 'REFERENCE_ONLY', packet_rate_pps: null }],
};

function renderShell() {
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
}

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

// 2.9.3-fu1 (#9 devmat): revient sur 2.9.2-fu2 — ne masque plus UNKNOWN.
// Affiche chaque technologie avec son compte de datasets (UNKNOWN inclus)
// pour que l'utilisateur voie combien de datasets restent non classifiés.
// Les technologies réelles passent en premier, UNKNOWN en fin.
it('shows every observed technology with its dataset count (UNKNOWN last)', async () => {
  vi.mocked(api).mockImplementation(async (path?: string) => {
    if (path === '/modules') return { data: [], meta: {} } as never;
    if (path === '/metrics') return { data: BASE_METRICS, meta: {} } as never;
    if (path === '/auth/me') return { data: { role: 'viewer' }, meta: {} } as never;
    if (path === '/probes')
      return {
        data: [{
          probe_id: 'probe-1',
          online: false,
          health: 'DEGRADED',
          telemetry_status: 'IDLE',
        }],
        meta: {},
      } as never;
    if (path === '/datasets?page_size=100')
      return {
        data: [
          { technology: '5G SA' },
          { technology: 'UNKNOWN' },
        ],
        meta: {},
      } as never;
    throw new Error(`unexpected path ${path}`);
  });
  renderShell();
  // Single 5G SA dataset + single UNKNOWN dataset — format devmat.
  await waitFor(() =>
    expect(screen.getByTestId('observed-technologies')).toHaveTextContent(
      'Observed: 5G SA · 1 dataset UNKNOWN',
    ),
  );
  await waitFor(() =>
    expect(screen.getByTestId('probe-connection')).toHaveTextContent(
      'vProbe not connected · DEGRADED · IDLE',
    ),
  );
});

// 2.9.3-fu1 : compte plural + plusieurs technologies.
it('pluralises UNKNOWN count and aggregates per-technology counts', async () => {
  vi.mocked(api).mockImplementation(async (path?: string) => {
    if (path === '/modules') return { data: [], meta: {} } as never;
    if (path === '/metrics') return { data: BASE_METRICS, meta: {} } as never;
    if (path === '/auth/me') return { data: { role: 'viewer' }, meta: {} } as never;
    if (path === '/probes')
      return { data: [{ probe_id: 'probe-1', online: false }], meta: {} } as never;
    if (path === '/datasets?page_size=100')
      return {
        data: [
          { technology: '5G SA' },
          { technology: '5G SA' },
          { technology: 'LTE' },
          { technology: 'UNKNOWN' },
          { technology: 'UNKNOWN' },
          { technology: 'UNKNOWN' },
        ],
        meta: {},
      } as never;
    throw new Error(`unexpected path ${path}`);
  });
  renderShell();
  await waitFor(() =>
    expect(screen.getByTestId('observed-technologies')).toHaveTextContent(
      'Observed: 5G SA (2) · LTE · 3 datasets UNKNOWN',
    ),
  );
});
