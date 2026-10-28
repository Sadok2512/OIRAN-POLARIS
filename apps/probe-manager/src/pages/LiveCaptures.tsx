import { useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, Lock } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import { StatusIndicator } from '@/ui/StatusIndicator';
import {
  EmptyState,
  ErrorState,
  LoadingSkeleton,
} from '@/ui/EmptyErrorLoading';
import { bits, bytes, count, durationSeconds, percent, pps } from '@/data/format';
import {
  useAuth,
  useCaptures,
  useDiskSafety,
  useInterfaces,
  useProbes,
} from '@/data/queries';
import type { Capture } from '@shared/types';

const ACTIVE_STATES = ['READY', 'STARTING', 'CAPTURING', 'STOPPING'];
const STALL_STATES = ['STOPPING', 'STARTING'];
// Reason strings surfaced in the UI (never fabricated — these are the
// backend gaps declared in docs/ui-mockups/README.md).
const START_LOCKED_REASON = 'Live start is disabled in this build (no mutating route exercised).';
const STOP_LOCKED_REASON = 'Blocked until lossless resume is proven on OIRAN.';
const DISK_WARN_THRESHOLD = 90;
// A growth value is only honest once we have two real samples spanning the
// window below. Shorter → "measuring…". We also keep samples a little past
// the window so the oldest point stays usable while the newest arrives.
const GROWTH_WINDOW_MS = 10_000;
const SAMPLE_RETENTION_MS = GROWTH_WINDOW_MS + 5_000;

interface GrowthSample {
  timestamp: number;
  /** `null` when the backend did not report any size on that sample. */
  size: number | null;
}

/**
 * Return the capture size reported by the backend, or `null` when the
 * backend omitted both `size_bytes` and `metrics.storage_bytes`. A missing
 * size must never be surfaced as `0 B` — the UI has to say "unknown".
 */
export function readSize(capture: Capture): number | null {
  const value = capture.size_bytes ?? capture.metrics?.storage_bytes;
  return typeof value === 'number' ? value : null;
}

export interface GrowthReading {
  /** `null` when the window is not full yet OR size is unknown. */
  bytes: number | null;
  /** Span (ms) between oldest and newest non-null sample. */
  windowMs: number;
  /** `true` when the backend reports a size for this capture. */
  sizeKnown: boolean;
}

/**
 * Reduce a per-capture sample history to a growth reading. Pure function
 * so tests can lock the semantics without rendering.
 */
export function computeGrowth(samples: GrowthSample[]): GrowthReading {
  const nonNull = samples.filter((s): s is GrowthSample & { size: number } => s.size !== null);
  if (nonNull.length === 0) {
    return { bytes: null, windowMs: 0, sizeKnown: false };
  }
  if (nonNull.length === 1) {
    return { bytes: null, windowMs: 0, sizeKnown: true };
  }
  const first = nonNull[0];
  const last = nonNull[nonNull.length - 1];
  const windowMs = last.timestamp - first.timestamp;
  if (windowMs < GROWTH_WINDOW_MS) {
    return { bytes: null, windowMs, sizeKnown: true };
  }
  return { bytes: last.size - first.size, windowMs, sizeKnown: true };
}

/**
 * A capture is "stalled" when either the backend state is a transition
 * state (STARTING / STOPPING) OR we have a complete 10 s window with 0 B
 * of growth. "Not yet measured" is NEVER stalled.
 */
export function isStalled(state: string | null | undefined, growth: GrowthReading): boolean {
  if (STALL_STATES.includes(state ?? '')) return true;
  if (!growth.sizeKnown) return false;
  if (growth.bytes === null) return false;
  return growth.bytes === 0 && growth.windowMs >= GROWTH_WINDOW_MS;
}

export function LiveCapturesPage() {
  const captures = useCaptures();
  const auth = useAuth();
  const probes = useProbes();
  const interfaces = useInterfaces();
  const disk = useDiskSafety();

  const control = auth.data?.capture_control === true;
  const execution = auth.data?.capture_execution_enabled === true;
  const availableInterfaces = interfaces.data?.filter(
    (item) => item.live_capture_available && item.status === 'AVAILABLE',
  ) ?? [];
  const probeId = probes.data?.find((probe) => probe.online)?.probe_id ?? '';

  const [selectedInterfaces, setSelectedInterfaces] = useState<string[]>([]);
  const [duration, setDuration] = useState(60);

  // Growth tracking is keyed on TanStack Query's `dataUpdatedAt`: each new
  // fetch means a fresh backend reading, so we take exactly one sample per
  // observation. The ref keeps the sliding window; a bump tick triggers a
  // re-read for the memoized derivations. Nothing is persisted across page
  // reloads.
  const historyRef = useRef<Map<string, GrowthSample[]>>(new Map());
  const [growthTick, setGrowthTick] = useState(0);

  const live = useMemo(
    () =>
      captures.data?.items?.filter((item) =>
        ACTIVE_STATES.includes(item.state ?? ''),
      ) ?? [],
    [captures.data],
  );

  useEffect(() => {
    // Only sample when the backend actually gave us a fresh update.
    if (!captures.dataUpdatedAt) return;
    const now = Date.now();
    const history = historyRef.current;
    const liveIds = new Set(live.map((capture) => capture.capture_id));
    for (const capture of live) {
      const key = capture.capture_id;
      const samples = history.get(key) ?? [];
      samples.push({ timestamp: now, size: readSize(capture) });
      // Keep a little more than the growth window so the oldest sample
      // stays within reach when the newest arrives.
      const cutoff = now - SAMPLE_RETENTION_MS;
      while (samples.length > 1 && samples[0].timestamp < cutoff) samples.shift();
      history.set(key, samples);
    }
    for (const key of Array.from(history.keys())) {
      if (!liveIds.has(key)) history.delete(key);
    }
    setGrowthTick((tick) => tick + 1);
    // live is captured through the dependency on captures.dataUpdatedAt.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [captures.dataUpdatedAt]);

  const growthByCapture = useMemo(() => {
    const map = new Map<string, GrowthReading>();
    for (const [key, samples] of historyRef.current) {
      map.set(key, computeGrowth(samples));
    }
    return map;
    // growthTick is the deterministic trigger that re-reads the ref.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [growthTick]);

  const measurableGrowths = Array.from(growthByCapture.values()).filter(
    (reading): reading is GrowthReading & { bytes: number } => reading.bytes !== null,
  );
  const totalGrowthKnown = measurableGrowths.length > 0;
  const totalGrowthBytes = measurableGrowths.reduce((sum, reading) => sum + reading.bytes, 0);
  const measuringCount = live.filter(
    (capture) => (growthByCapture.get(capture.capture_id)?.bytes ?? null) === null,
  ).length;

  const stalledCount = live.filter((capture) => {
    const growth = growthByCapture.get(capture.capture_id) ?? {
      bytes: null,
      windowMs: 0,
      sizeKnown: readSize(capture) !== null,
    };
    return isStalled(capture.state, growth);
  }).length;

  const diskPercent = disk.data?.filesystem?.usage_percent ?? null;
  const diskAlert = diskPercent != null && diskPercent >= DISK_WARN_THRESHOLD;

  return (
    <>
      <PageHeader
        eyebrow="Capture"
        title="Live Captures"
        description="Monitor every live capture job reported by the backend. Counters that the backend did not report are rendered as 'Not available'. All mutating actions are locked in this build."
        actions={
          <div className="flex items-center gap-2">
            <StatusIndicator
              state={execution ? 'EXECUTION_ENABLED' : 'EXECUTION_GATED'}
              tone={execution ? 'success' : 'warning'}
              label={execution ? 'Backend execution enabled' : 'Execution gated'}
            />
            <StatusIndicator
              state={control ? 'CONTROL_READY' : 'CONTROL_READONLY'}
              tone={control ? 'success' : 'warning'}
              label={control ? 'Operator role active' : 'Read-only role'}
            />
          </div>
        }
      />

      <section
        className="grid gap-3 grid-cols-2 md:grid-cols-4 mb-4"
        data-testid="live-capture-stats"
      >
        <StatCard
          label="Written · 10 s"
          value={totalGrowthKnown ? bytes(totalGrowthBytes) : 'measuring…'}
          detail={
            live.length === 0
              ? 'No active capture'
              : measuringCount > 0
                ? `${live.length} active · ${measuringCount} measuring`
                : `${live.length} active capture${live.length === 1 ? '' : 's'}`
          }
        />
        <StatCard
          label="Capturing"
          value={count(live.length)}
          detail="Jobs reporting an active state"
        />
        <StatCard
          label="Stalled"
          value={count(stalledCount)}
          detail={
            stalledCount === 0
              ? 'No stalled job (needs ≥ 10 s window)'
              : 'Active jobs with 0 B growth over ≥ 10 s'
          }
          tone={stalledCount > 0 ? 'warning' : undefined}
        />
        <DiskCard
          percent={diskPercent}
          availableBytes={disk.data?.filesystem?.available_bytes ?? null}
          totalBytes={disk.data?.filesystem?.total_bytes ?? null}
          threshold={DISK_WARN_THRESHOLD}
          alert={diskAlert}
        />
      </section>

      <section className="ep-card mb-4 p-5" aria-label="Capture controls">
        <div className="grid gap-4 md:grid-cols-[1fr_auto]">
          <div>
            <h2 className="text-ep-lg font-semibold">Bounded capture</h2>
            <p className="text-ep-sm text-text-secondary">
              Validation never starts acquisition. In this build the mutating routes
              (<code className="mono">POST /captures/validate</code>,
              <code className="mono">/captures/start</code>,
              <code className="mono">/captures/:id/stop</code>) are not exercised; the buttons stay locked.
            </p>
            <div className="mt-3 flex flex-wrap gap-2">
              {availableInterfaces.map((item) => (
                <label className="ep-button ep-button-sm" key={item.interface}>
                  <input
                    type="checkbox"
                    checked={selectedInterfaces.includes(item.interface)}
                    onChange={(event) =>
                      setSelectedInterfaces((current) =>
                        event.target.checked
                          ? [...current, item.interface]
                          : current.filter((value) => value !== item.interface),
                      )
                    }
                  />
                  {item.interface} · {item.protocol}
                </label>
              ))}
              {availableInterfaces.length === 0 && (
                <span className="text-ep-xs text-text-secondary">
                  No AVAILABLE interface reported by the backend.
                </span>
              )}
            </div>
          </div>
          <label className="text-ep-sm">
            Duration (seconds)
            <input
              className="ep-input ml-2 w-24"
              type="number"
              min={1}
              max={120}
              value={duration}
              onChange={(event) => setDuration(Number(event.target.value))}
            />
          </label>
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <button
            type="button"
            className="ep-button"
            disabled
            aria-disabled="true"
            title={START_LOCKED_REASON}
            data-testid="validate-capture"
          >
            <Lock width={13} height={13} /> Validate capture (locked)
          </button>
          <button
            type="button"
            className="ep-button ep-button-primary"
            disabled
            aria-disabled="true"
            title={START_LOCKED_REASON}
            data-testid="start-capture"
          >
            <Lock width={13} height={13} /> Start capture (locked)
          </button>
          <span className="text-ep-xs text-text-secondary">
            Target probe · <span className="mono">{probeId || 'no online probe'}</span>
            {probeId && ' · '}
            {probeId && (
              <span>
                selected interfaces · <span className="mono">{selectedInterfaces.join(', ') || '—'}</span>
              </span>
            )}
          </span>
        </div>
      </section>

      {captures.isLoading && <LoadingSkeleton label="Loading capture jobs" />}
      {captures.error && !captures.isLoading && (
        <ErrorState
          title="Could not load captures"
          detail={(captures.error as Error).message}
          onRetry={() => void captures.refetch()}
        />
      )}

      {!captures.isLoading && !captures.error && live.length === 0 && (
        <EmptyState
          title="No live captures"
          description="Start a bounded capture from the backend to see its live counters here. The frontend never fabricates a running state."
        />
      )}

      <div className="grid gap-4" data-testid="live-capture-list">
        {live.map((capture) => {
          const metrics = capture.metrics;
          const size = readSize(capture);
          const growth = growthByCapture.get(capture.capture_id) ?? {
            bytes: null,
            windowMs: 0,
            sizeKnown: size !== null,
          };
          const stalled = isStalled(capture.state, growth);
          const growthLabel = formatGrowthLabel(growth);
          return (
            <article
              key={capture.capture_id}
              className="ep-card p-5 flex flex-col gap-3"
              data-testid={`live-capture-${capture.capture_id}`}
            >
              <header className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-ep-xs uppercase tracking-wider text-text-secondary">
                    Job
                  </p>
                  <h2 className="text-ep-lg font-semibold">{capture.name}</h2>
                  <p className="mono text-ep-xs text-text-secondary break-all">
                    {capture.capture_id}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <StatusIndicator state={capture.state ?? 'UNKNOWN'} />
                  {stalled && (
                    <span className="ep-badge border-warning/40 text-warning">
                      <AlertTriangle width={11} height={11} /> stalled ≥ 10 s
                    </span>
                  )}
                </div>
              </header>

              <dl className="grid grid-cols-2 md:grid-cols-4 gap-x-5 gap-y-1 text-ep-sm">
                <dt className="text-text-secondary">Probe</dt>
                <dd>{capture.probe_id ?? '—'}</dd>
                <dt className="text-text-secondary">Interfaces</dt>
                <dd className="truncate">
                  {capture.interface ??
                    capture.interfaces?.join(' + ') ??
                    '—'}
                </dd>
                <dt className="text-text-secondary">Started</dt>
                <dd>
                  {capture.planes?.[0]?.start_timestamp
                    ? new Date(
                        capture.planes[0].start_timestamp * 1000,
                      ).toLocaleTimeString()
                    : '—'}
                </dd>
                <dt className="text-text-secondary">Duration</dt>
                <dd className="num">
                  {capture.planes?.[0]?.start_timestamp
                    ? durationSeconds(
                        capture.planes[0].start_timestamp,
                        capture.planes[0].end_timestamp,
                      )
                    : '—'}
                </dd>
                <dt className="text-text-secondary">Packets</dt>
                <dd className="num">{count(metrics?.packets_received)}</dd>
                <dt className="text-text-secondary">Bytes</dt>
                <dd className="num">{bytes(metrics?.bytes_received)}</dd>
                <dt className="text-text-secondary">Rate</dt>
                <dd className="num">{pps(metrics?.packets_per_second)}</dd>
                <dt className="text-text-secondary">Bitrate</dt>
                <dd className="num">{bits(metrics?.bits_per_second)}</dd>
                <dt className="text-text-secondary">{growthLabel.header}</dt>
                <dd className="num" data-testid={`growth-${capture.capture_id}`}>
                  {growthLabel.value}
                </dd>
                <dt className="text-text-secondary">Drops</dt>
                <dd className="num">{count(metrics?.packet_drops)}</dd>
                <dt className="text-text-secondary">Storage</dt>
                <dd className="num">{size == null ? '—' : bytes(size)}</dd>
                <dt className="text-text-secondary">Decode errors</dt>
                <dd className="num">{count(metrics?.decode_errors)}</dd>
              </dl>

              {!!capture.planes?.length && (
                <ul className="grid grid-cols-2 md:grid-cols-4 gap-2 text-ep-xs">
                  {capture.planes.map((plane) => (
                    <li
                      key={plane.plane}
                      className="rounded-md border border-border p-2"
                    >
                      <div className="flex items-center justify-between">
                        <b>{plane.plane}</b>
                        <StatusIndicator state={plane.decode_status} compact />
                      </div>
                      <p className="text-text-secondary">
                        {count(plane.packet_count)} pkt · {bytes(plane.byte_count)}
                      </p>
                    </li>
                  ))}
                </ul>
              )}

              <footer className="pt-2 border-t border-border flex items-center justify-between gap-2">
                <span className="text-ep-xs text-text-secondary flex items-center gap-2">
                  <Lock width={11} height={11} /> {STOP_LOCKED_REASON}
                </span>
                <button
                  type="button"
                  className="ep-button ep-button-sm ep-button-danger"
                  disabled
                  aria-disabled="true"
                  title={STOP_LOCKED_REASON}
                  data-testid={`stop-capture-${capture.capture_id}`}
                >
                  <Lock width={13} height={13} /> Stop (locked)
                </button>
              </footer>
            </article>
          );
        })}
      </div>
    </>
  );
}

function formatGrowthLabel(growth: GrowthReading): { header: string; value: string } {
  if (!growth.sizeKnown) {
    return { header: 'Growth · 10 s', value: '—' };
  }
  if (growth.bytes === null) {
    const seconds = growth.windowMs / 1000;
    const detail = seconds > 0 ? ` (${seconds.toFixed(1)} s)` : '';
    return { header: 'Growth · 10 s', value: `measuring…${detail}` };
  }
  const seconds = Math.max(10, growth.windowMs / 1000);
  return { header: `Growth · ${seconds.toFixed(1)} s`, value: bytes(growth.bytes) };
}

function StatCard({
  label,
  value,
  detail,
  tone,
}: {
  label: string;
  value: string;
  detail?: string;
  tone?: 'warning';
}) {
  return (
    <div
      className={`ep-card p-3 flex flex-col gap-0.5 ${
        tone === 'warning' ? 'border-warning/40' : ''
      }`}
      data-testid={`stat-${label.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`}
    >
      <span className="text-ep-xs uppercase tracking-wider text-text-secondary">
        {label}
      </span>
      <span className="text-ep-h2 font-semibold num">{value}</span>
      {detail && <span className="text-ep-xs text-text-secondary">{detail}</span>}
    </div>
  );
}

function DiskCard({
  percent: pct,
  availableBytes,
  totalBytes,
  threshold,
  alert,
}: {
  percent: number | null;
  availableBytes: number | null;
  totalBytes: number | null;
  threshold: number;
  alert: boolean;
}) {
  const safePercent = pct == null ? 0 : Math.min(100, Math.max(0, pct));
  return (
    <div
      className={`ep-card p-3 flex flex-col gap-0.5 ${alert ? 'border-error/40' : ''}`}
      data-testid="stat-disk"
    >
      <span className="text-ep-xs uppercase tracking-wider text-text-secondary">
        Disk usage
      </span>
      <span className={`text-ep-h2 font-semibold num ${alert ? 'text-error' : ''}`}>
        {percent(pct ?? null)}
      </span>
      <div
        className="relative h-2 rounded-full bg-canvas border border-border overflow-hidden"
        role="progressbar"
        aria-valuenow={pct ?? undefined}
        aria-valuemin={0}
        aria-valuemax={100}
        data-testid="disk-bar"
      >
        <div
          className={`h-full ${alert ? 'bg-error' : 'bg-primary'}`}
          style={{ width: `${safePercent}%` }}
        />
        <div
          className="absolute top-0 bottom-0 w-px bg-warning"
          style={{ left: `${threshold}%` }}
          aria-label={`Threshold ${threshold}%`}
          title={`Threshold ${threshold}%`}
        />
      </div>
      <span className="text-ep-xs text-text-secondary">
        {bytes(availableBytes)} free of {bytes(totalBytes)} · stop line {threshold}%
      </span>
    </div>
  );
}
