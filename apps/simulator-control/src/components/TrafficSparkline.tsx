// 0.13.1 — Live chart for the Traffic Generator (#47).
//
// Hand-rolled SVG polyline — no new npm dep. The server-side ring is
// bounded at `TRAFFIC_SAMPLES_RING_MAX = 60`, so this is always drawing
// at most 60 points. We render two overlaid traces (UL + DL) scaled
// against the shared max rate so the operator can read relative
// progression at a glance; absolute values are shown in the summary row
// right below.
//
// Design rules locked in tests:
//   - When there are 0 samples, show an "awaiting first tick…" placeholder
//     (not an empty SVG — a visibly empty chart looks like a bug).
//   - A single-point sample draws a dot (polyline needs ≥ 2 points to render).
//   - The polyline for a direction is omitted when every rate is null
//     (e.g. UL direction → DL rates are all null; we don't draw a flat
//     zero line that would mislead the operator).
//   - The chart is accessible: role="img" + aria-label summarising
//     current UL / DL rate.

import type { TrafficSample } from '../data/trafficSessionsApi';

export interface TrafficSparklineProps {
  samples: TrafficSample[];
  width?: number;
  height?: number;
  /** Visual label used both in the aria-label and as a title. */
  label?: string;
}

const DEFAULT_WIDTH = 220;
const DEFAULT_HEIGHT = 48;
const PAD = 4;

function formatRateShort(bps: number | null): string {
  if (bps == null) return '—';
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} Mbit/s`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(1)} kbit/s`;
  return `${bps} bit/s`;
}

export function TrafficSparkline({
  samples,
  width = DEFAULT_WIDTH,
  height = DEFAULT_HEIGHT,
  label = 'Traffic rate',
}: TrafficSparklineProps) {
  if (samples.length === 0) {
    return (
      <div
        className="text-xs2 text-mute italic"
        data-testid="traffic-sparkline-empty"
        style={{ width, height }}
      >
        awaiting first tick…
      </div>
    );
  }
  const innerW = width - PAD * 2;
  const innerH = height - PAD * 2;

  const ulValues = samples.map((s) => s.rate_ul_bps);
  const dlValues = samples.map((s) => s.rate_dl_bps);
  const hasUl = ulValues.some((v) => v != null && v > 0);
  const hasDl = dlValues.some((v) => v != null && v > 0);
  const maxRate = Math.max(
    1,
    ...ulValues.map((v) => v ?? 0),
    ...dlValues.map((v) => v ?? 0),
  );
  const lastUl = ulValues[ulValues.length - 1] ?? null;
  const lastDl = dlValues[dlValues.length - 1] ?? null;

  function pointsFor(values: Array<number | null>): string {
    const n = values.length;
    const stride = n === 1 ? innerW : innerW / (n - 1);
    return values
      .map((v, i) => {
        const safe = v ?? 0;
        const x = PAD + i * stride;
        const y = PAD + innerH - (safe / maxRate) * innerH;
        return `${x.toFixed(2)},${y.toFixed(2)}`;
      })
      .join(' ');
  }

  // One-point samples cannot form a polyline — draw a dot per direction instead.
  const singlePoint = samples.length === 1;

  const ariaLabel = `${label} · UL ${formatRateShort(lastUl)} · DL ${formatRateShort(lastDl)}`;

  return (
    <svg
      role="img"
      aria-label={ariaLabel}
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      className="block"
      data-testid="traffic-sparkline"
    >
      <title>{ariaLabel}</title>
      <rect
        x={0.5}
        y={0.5}
        width={width - 1}
        height={height - 1}
        rx={4}
        fill="none"
        stroke="currentColor"
        strokeOpacity={0.08}
      />
      {hasUl ? (
        singlePoint ? (
          <circle
            cx={PAD + innerW / 2}
            cy={PAD + innerH - ((ulValues[0] ?? 0) / maxRate) * innerH}
            r={2}
            fill="var(--c-ok, #22c55e)"
            data-testid="traffic-sparkline-ul-dot"
          />
        ) : (
          <polyline
            points={pointsFor(ulValues)}
            fill="none"
            stroke="var(--c-ok, #22c55e)"
            strokeWidth={1.4}
            data-testid="traffic-sparkline-ul"
          />
        )
      ) : null}
      {hasDl ? (
        singlePoint ? (
          <circle
            cx={PAD + innerW / 2}
            cy={PAD + innerH - ((dlValues[0] ?? 0) / maxRate) * innerH}
            r={2}
            fill="var(--c-brand, #6366f1)"
            data-testid="traffic-sparkline-dl-dot"
          />
        ) : (
          <polyline
            points={pointsFor(dlValues)}
            fill="none"
            stroke="var(--c-brand, #6366f1)"
            strokeWidth={1.4}
            data-testid="traffic-sparkline-dl"
          />
        )
      ) : null}
    </svg>
  );
}
