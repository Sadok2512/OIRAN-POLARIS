// 0.11.0 (#37) — Activity page tests.
//
// The page is SSE-backed in production; vitest runs under jsdom which
// has `EventSource` stubbed to a no-op (open then idle). We cover:
//   * running:false path renders the "UE non démarré" banner;
//   * running:true path renders the four state chips, PDU block, voice
//     "IMS not available" line, and the timeline;
//   * identity row shows the raw IMSI (no masking at this level — the
//     backend already enforced the role-aware projection).

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import {
  UeActivityPage,
  formatBps,
  formatBytes,
  type UeActivityPayload,
} from './UeActivity';

function respond(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function stubEventSource() {
  class StubEventSource {
    static OPEN = 1 as const;
    static CLOSED = 2 as const;
    readyState = 0;
    onopen: (() => void) | null = null;
    onmessage: ((event: MessageEvent) => void) | null = null;
    onerror: (() => void) | null = null;
    constructor(public url: string) {}
    close() {
      this.readyState = StubEventSource.CLOSED;
    }
  }
  (globalThis as unknown as { EventSource: typeof StubEventSource }).EventSource =
    StubEventSource;
}

function renderAt(id: string) {
  return render(
    <MemoryRouter initialEntries={[`/ues/${id}/activity`]}>
      <Routes>
        <Route path="/ues/:ueId/activity" element={<UeActivityPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

const RUNNING_PAYLOAD: UeActivityPayload = {
  ue_id: 'UE-07',
  running: true,
  imsi: 'imsi-001010000000007',
  states: {
    rm_state: 'RM-REGISTERED',
    cm_state: 'CM-CONNECTED',
    rrc_state: 'RRC-CONNECTED',
    mm_5g_state: 'MM-REGISTERED-NORMAL-SERVICE',
  },
  pdu: {
    psi: 1,
    dnn: 'internet',
    state: 'PS-ACTIVE',
    address: '10.46.0.7',
  },
  counters: {
    interface: 'uesimtun0',
    rx_bytes: 12_345_678,
    rx_packets: 1_024,
    tx_bytes: 2_345_678,
    tx_packets: 512,
    rx_bps: 42_000,
    tx_bps: 8_000,
  },
  job_step: {
    job_id: 'scn-abc-1',
    definition_id: 'bounded-controller-ue-udp-v1',
    state: 'RUNNING',
    current_step: { index: 2, type: 'udp_traffic', state: 'RUNNING' },
  },
  events: [
    { epoch_s: 1_730_200_000, kind: 'live_start', outcome: 'OK', detail: {} },
    { epoch_s: 1_730_200_010, kind: 'registration', outcome: 'OK', detail: {} },
  ],
  voice: { available: false, reason: 'IMS_NOT_AVAILABLE' },
};

const STOPPED_PAYLOAD: UeActivityPayload = {
  ue_id: 'UE-99',
  running: false,
  reason: 'UE_NOT_RUNNING',
  events: [],
  voice: { available: false, reason: 'IMS_NOT_AVAILABLE' },
};

beforeEach(() => {
  stubEventSource();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('UeActivityPage (0.11.0)', () => {
  it('renders the "UE non démarré" banner when running:false', async () => {
    globalThis.fetch = vi.fn(async () => respond(STOPPED_PAYLOAD)) as unknown as typeof fetch;
    renderAt('UE-99');
    const banner = await screen.findByTestId('activity-not-running');
    expect(banner).toHaveTextContent(/non démarré/i);
    expect(banner).toHaveTextContent(/UE_NOT_RUNNING/);
    // Live indicator is wired regardless of running state.
    expect(screen.getByTestId('activity-live')).toBeInTheDocument();
  });

  it('renders the four state chips, PDU, voice and timeline on running:true', async () => {
    globalThis.fetch = vi.fn(async () => respond(RUNNING_PAYLOAD)) as unknown as typeof fetch;
    renderAt('UE-07');
    await waitFor(() => expect(screen.queryByTestId('activity-loading')).toBeNull());
    expect(screen.getByTestId('chip-rm')).toHaveTextContent('RM-REGISTERED');
    expect(screen.getByTestId('chip-cm')).toHaveTextContent('CM-CONNECTED');
    expect(screen.getByTestId('chip-rrc')).toHaveTextContent('RRC-CONNECTED');
    expect(screen.getByTestId('chip-5gmm')).toHaveTextContent('MM-REGISTERED-NORMAL-SERVICE');
    expect(screen.getByTestId('activity-pdu-dnn')).toHaveTextContent('internet');
    expect(screen.getByTestId('activity-pdu-ip')).toHaveTextContent('10.46.0.7');
    expect(screen.getByTestId('activity-voice')).toHaveTextContent(/IMS not available/i);
    expect(screen.getByTestId('activity-voice')).toHaveTextContent('IMS_NOT_AVAILABLE');
    expect(screen.getByTestId('activity-imsi')).toHaveTextContent('imsi-001010000000007');
    expect(screen.getByTestId('activity-job-step')).toHaveTextContent('udp_traffic');
    expect(screen.getByTestId('timeline-list').children.length).toBe(2);
  });
});

describe('format helpers', () => {
  it('formats byte totals in SI units', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(500)).toBe('500 B');
    expect(formatBytes(12_345)).toBe('12.3 KB');
    expect(formatBytes(12_345_678)).toBe('12.3 MB');
    expect(formatBytes(12_345_678_900)).toBe('12.3 GB');
    expect(formatBytes(null)).toBe('—');
  });

  it('formats bps in SI bits/s units', () => {
    expect(formatBps(0)).toBe('0 b/s');
    expect(formatBps(125)).toBe('1.0 kb/s');
    expect(formatBps(125_000)).toBe('1.0 Mb/s');
    expect(formatBps(125_000_000)).toBe('1.0 Gb/s');
    expect(formatBps(null)).toBe('—');
  });
});
