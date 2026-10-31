// 0.13.1 — Lock the Traffic Generator sparkline rendering contract.
// Covers:
//   * Empty samples → "awaiting first tick…" placeholder (no SVG).
//   * One-sample case → dot per direction (polyline needs ≥ 2 pts).
//   * UL-only samples → UL polyline present, DL polyline absent (no
//     misleading zero line).
//   * aria-label summarises UL / DL latest rate for screen readers.

import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { TrafficSparkline } from './TrafficSparkline';
import type { TrafficSample } from '../data/trafficSessionsApi';

function sample(overrides: Partial<TrafficSample> = {}): TrafficSample {
  return {
    epoch_s: 1_792_872_281,
    bytes_ul_cum: 0,
    bytes_dl_cum: 0,
    rate_ul_bps: null,
    rate_dl_bps: null,
    ...overrides,
  };
}

describe('TrafficSparkline', () => {
  it('renders a placeholder when there are zero samples', () => {
    render(<TrafficSparkline samples={[]} />);
    expect(screen.getByTestId('traffic-sparkline-empty')).toHaveTextContent(
      'awaiting first tick…',
    );
    expect(screen.queryByTestId('traffic-sparkline')).toBeNull();
  });

  it('draws a dot per direction when only one sample exists', () => {
    render(
      <TrafficSparkline
        samples={[sample({ rate_ul_bps: 5_000_000, rate_dl_bps: 3_000_000 })]}
      />,
    );
    expect(screen.getByTestId('traffic-sparkline-ul-dot')).toBeInTheDocument();
    expect(screen.getByTestId('traffic-sparkline-dl-dot')).toBeInTheDocument();
    expect(screen.queryByTestId('traffic-sparkline-ul')).toBeNull();
    expect(screen.queryByTestId('traffic-sparkline-dl')).toBeNull();
  });

  it('draws only the UL polyline on an UL-only session', () => {
    const samples = Array.from({ length: 5 }, (_, i) =>
      sample({ epoch_s: 1_792_872_281 + i, rate_ul_bps: 2_000_000 + i * 100_000 }),
    );
    render(<TrafficSparkline samples={samples} />);
    expect(screen.getByTestId('traffic-sparkline-ul')).toBeInTheDocument();
    expect(screen.queryByTestId('traffic-sparkline-dl')).toBeNull();
  });

  it('exposes current UL / DL rate via aria-label for screen readers', () => {
    const samples = [
      sample({ rate_ul_bps: 1_000_000, rate_dl_bps: 500_000 }),
      sample({ rate_ul_bps: 2_000_000, rate_dl_bps: 1_000_000 }),
    ];
    render(<TrafficSparkline samples={samples} label="Session foo" />);
    const svg = screen.getByTestId('traffic-sparkline');
    expect(svg.getAttribute('aria-label')).toBe(
      'Session foo · UL 2.0 Mbit/s · DL 1.0 Mbit/s',
    );
  });

  it('leaves both polylines out when no direction has data', () => {
    const samples = [sample(), sample(), sample()];
    render(<TrafficSparkline samples={samples} />);
    expect(screen.queryByTestId('traffic-sparkline-ul')).toBeNull();
    expect(screen.queryByTestId('traffic-sparkline-dl')).toBeNull();
    expect(screen.queryByTestId('traffic-sparkline-ul-dot')).toBeNull();
    expect(screen.queryByTestId('traffic-sparkline-dl-dot')).toBeNull();
    // The SVG root is still rendered so the empty-chart placeholder
    // does not re-appear when the server is slow to produce rate data.
    expect(screen.getByTestId('traffic-sparkline')).toBeInTheDocument();
  });
});
