import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ProbeManager } from '../pages/ProbeManager';
import { api } from '../services/api';

vi.mock('../services/api', () => ({ api: vi.fn() }));

const failedCapture = {
  capture_id: 'live-regression-0002',
  name: 'POLARIS-5G-SA',
  interfaces: ['N2', 'SBI', 'N4', 'N3'],
  state: 'FAILED',
  dataset_id: null,
  session_ids: [],
  error: 'open /captures/live-regression-0002/dataset/oiran_events.jsonl: No such file or directory',
  metrics: {
    packets_received: 48,
    bytes_received: 3872,
    packets_per_second: 0,
    bits_per_second: 0,
    decoded_events: 0,
    decode_errors: 0,
    packet_drops: 0,
    storage_bytes: 4712,
  },
};

describe('Probe Manager failed capture evidence', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api).mockImplementation(async (path: string) => {
      if (path === '/probes') {
        return { data: [{ probe_id: 'oiran-vprobe-local-01', name: 'Local vProbe', host: 'localhost', version: '2.1.0-dev', health: 'ONLINE', online: true, connected_interfaces: ['N2', 'SBI', 'N4', 'N3'], capture_state: 'IDLE', telemetry_status: 'IDLE' }], meta: {} } as never;
      }
      if (path === '/interfaces') {
        return { data: ['N2', 'SBI', 'N4', 'N3'].map((name) => ({ interface: name, protocol: name, capture_point: `${name} bridge`, status: 'AVAILABLE', device: `br-${name.toLowerCase()}`, live_capture_available: true, reason: null })), meta: {} } as never;
      }
      if (path.startsWith('/captures?')) return { data: [failedCapture], meta: {} } as never;
      if (path === '/datasets?page_size=100') return { data: [], meta: {} } as never;
      if (path === '/storage/safety') {
        return { data: { filesystem: { usage_percent: 45, available_bytes: 200_000_000_000 }, decision: { state: 'NORMAL', new_capture_allowed: true }, budget: { reserved_bytes: 33_554_432 }, rotation: { maximum_job_bytes: 2_147_483_648, max_files: 8, max_file_bytes: 268_435_456 }, capture_job: { state: 'FAILED' } }, meta: {} } as never;
      }
      if (path === '/auth/me') return { data: { role: 'operator', capture_control: true, capture_execution_enabled: true }, meta: {} } as never;
      if (path === '/captures/validate') return { data: { validation: { valid: true, blockers: [] } }, meta: {} } as never;
      throw new Error(`unexpected path ${path}`);
    });
  });

  it('shows the exact failure and preserved PCAP evidence without opening a session', async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <ProbeManager />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    await userEvent.click(await screen.findByRole('button', { name: 'View error' }));

    expect(screen.getByText('Exact failure')).toBeVisible();
    expect(screen.getByText(/No such file or directory/)).toBeVisible();
    expect(screen.getByText(/PCAP packets preserved/)).toBeVisible();
    expect(screen.getByText('NOT REGISTERED')).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Open sessions' })).not.toBeInTheDocument();
  });

  it('applies Select All and sends the canonical four-plane validation request', async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <ProbeManager />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    await userEvent.click(await screen.findByRole('button', { name: 'Select all planes' }));
    await userEvent.click(screen.getByRole('button', { name: 'Apply configuration' }));
    await userEvent.click(screen.getByRole('button', { name: 'Validate capture' }));

    const validationCall = vi.mocked(api).mock.calls.find(([path]) => path === '/captures/validate');
    expect(validationCall).toBeDefined();
    const payload = JSON.parse(String(validationCall?.[1]?.body));
    expect(payload.interfaces).toEqual(['N2', 'SBI', 'N4', 'N3']);
    expect(await screen.findByText('READY — all current safety checks pass')).toBeVisible();
  });
});
