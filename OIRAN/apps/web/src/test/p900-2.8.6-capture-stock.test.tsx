// p900 2.8.6 (ordre #9 7008184610) — Tests des moniteurs ajoutés par ce
// lot : `capture_owned_bytes_percent` (stock sans clamp) et le lot
// quarantaine (`quarantined_segments` + `quarantined_segment_paths`).
//
// 4 scénarios couverts : `null`, `0`, valeur > 100 %, liste vide.

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Metrics } from '../types/api';
import { LiveMonitoring, QuarantineList, showPercentNoCap, showCount, truncatePath } from '../pages/ReportsPages';
import { api } from '../services/api';

vi.mock('../services/api', () => ({ api: vi.fn() }));

function baseMetrics(overrides: Partial<Metrics> = {}): Metrics {
  return {
    observed_at_epoch_s: 1,
    mode: 'HISTORICAL_DATASET_ANALYSIS',
    packet_rate_pps: null,
    bitrate_bps: null,
    decode_rate_eps: null,
    packet_drops: null,
    capture_queue_utilization_percent: null,
    active_captures: 0,
    active_sessions: 0,
    historical_sessions: 0,
    historical_events: 0,
    decode_errors: 0,
    cpu: { usage_percent: null, load_one: 1, logical_cpus: 1 },
    memory: { total_bytes: 1, available_bytes: 1, used_bytes: 0 },
    disk: null,
    interfaces: [],
    ...overrides,
  } as Metrics;
}

function renderLive(metrics: Metrics) {
  vi.mocked(api).mockImplementation(async (path?: string) => {
    if (path === '/metrics') return { data: metrics, meta: {} } as never;
    throw new Error(`unexpected path ${path}`);
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <LiveMonitoring />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.resetAllMocks();
});

describe('showPercentNoCap formatter (p900 2.8.6)', () => {
  it('returns « — » for null', () => {
    expect(showPercentNoCap(null)).toBe('—');
  });
  it('returns « — » for undefined', () => {
    expect(showPercentNoCap(undefined)).toBe('—');
  });
  it('returns « 0.0 % » for 0 (not « — »)', () => {
    expect(showPercentNoCap(0)).toBe('0.0 %');
  });
  it('returns the raw percentage above 100 (SANS clamp)', () => {
    expect(showPercentNoCap(562.4)).toBe('562.4 %');
  });
});

describe('showCount formatter (p900 2.8.6)', () => {
  it('returns « — » for null (not « 0 »)', () => {
    expect(showCount(null)).toBe('—');
  });
  it('returns « 0 » for 0 (a known state, not absence)', () => {
    expect(showCount(0)).toBe('0');
  });
  it('returns localized number for large values', () => {
    expect(showCount(12345)).toBe((12345).toLocaleString());
  });
});

describe('truncatePath helper (p900 2.8.6)', () => {
  it('returns basename when path contains slashes', () => {
    expect(truncatePath('/a/b/c/final-1.pcapng')).toBe('final-1.pcapng');
  });
  it('truncates long basenames with ellipsis', () => {
    const long = 'a'.repeat(60) + '.pcapng';
    const out = truncatePath(long, 40);
    expect(out.endsWith('…')).toBe(true);
    expect(out.length).toBe(40);
  });
});

describe('LiveMonitoring p900 2.8.6 scenarios', () => {
  it('scenario null — 2.21.67 (champs absents) : capture_owned_bytes_percent et quarantined_segments affichent « — »', async () => {
    renderLive(baseMetrics({ capture_owned_bytes_percent: null, quarantined_segments: null }));
    await waitFor(() => expect(screen.getByText('Stock capture')).toBeDefined());
    const stockMonitor = screen.getByText('Stock capture').closest('article');
    expect(stockMonitor?.querySelector('strong')?.textContent).toBe('—');
    const quarantMonitor = screen.getByText('Segments quarantinés').closest('article');
    expect(quarantMonitor?.querySelector('strong')?.textContent).toBe('—');
  });

  it('scenario 0 — capture_owned_bytes_percent=0 affiche « 0.0 % », quarantined_segments=0 affiche « 0 »', async () => {
    renderLive(baseMetrics({ capture_owned_bytes_percent: 0, quarantined_segments: 0 }));
    await waitFor(() => expect(screen.getByText('Stock capture')).toBeDefined());
    const stockMonitor = screen.getByText('Stock capture').closest('article');
    expect(stockMonitor?.querySelector('strong')?.textContent).toBe('0.0 %');
    const quarantMonitor = screen.getByText('Segments quarantinés').closest('article');
    expect(quarantMonitor?.querySelector('strong')?.textContent).toBe('0');
  });

  it('scenario > 100 — ANR2 prod 562 % : stock affiche la vérité (sans clamp)', async () => {
    renderLive(baseMetrics({ capture_owned_bytes_percent: 561.9 }));
    await waitFor(() => expect(screen.getByText('Stock capture')).toBeDefined());
    const stockMonitor = screen.getByText('Stock capture').closest('article');
    expect(stockMonitor?.querySelector('strong')?.textContent).toBe('561.9 %');
  });

  it('scenario liste vide — quarantined_segment_paths=[] : pas de QuarantineList rendue', async () => {
    renderLive(baseMetrics({ quarantined_segments: 0, quarantined_segment_paths: [] }));
    await waitFor(() => expect(screen.getByText('Segments quarantinés')).toBeDefined());
    // Pas de panneau « Afficher (N) »
    expect(screen.queryByTestId('quarantine-toggle')).toBeNull();
  });

  it('scenario liste non vide — expose le toggle, liste repliée par défaut, paths tronqués visibles au clic', async () => {
    renderLive(baseMetrics({
      quarantined_segments: 2,
      quarantined_segment_paths: [
        '/var/lib/oiran/continuous-lab-import/pcap/N2.pcap-cafebabe.pcapng',
        '/var/lib/oiran/continuous-lab-import/pcap/S6a.pcap-deadbeef.pcapng',
      ],
    }));
    await waitFor(() => expect(screen.getByTestId('quarantine-toggle')).toBeDefined());
    // Repliée par défaut — pas de liste visible
    expect(screen.queryByTestId('quarantine-list')).toBeNull();
    const toggle = screen.getByTestId('quarantine-toggle');
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    expect(toggle.textContent).toContain('(2)');
    fireEvent.click(toggle);
    await waitFor(() => expect(screen.getByTestId('quarantine-list')).toBeDefined());
    expect(screen.getByText('N2.pcap-cafebabe.pcapng')).toBeDefined();
    expect(screen.getByText('S6a.pcap-deadbeef.pcapng')).toBeDefined();
  });
});

describe('QuarantineList component (p900 2.8.6)', () => {
  it('ne liste aucun IMSI/MSISDN — les chemins quarantaine portent uniquement nom d\'interface + hash', () => {
    const paths = [
      '/x/N2.pcap-cafebabe.pcapng',
      '/x/S6a.pcap-deadbeef.pcapng',
    ];
    render(<QuarantineList paths={paths} />);
    // Preuve négative : aucun pattern IMSI (15 chiffres) ni MSISDN (10-15 chiffres) dans le DOM.
    const text = document.body.textContent || '';
    expect(/\b\d{15}\b/.test(text)).toBe(false);
    expect(/\bimsi\b|\bmsisdn\b/i.test(text)).toBe(false);
  });
});
