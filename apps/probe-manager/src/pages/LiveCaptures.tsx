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

interface GrowthSample {
  timestamp: number;
  size: number;
}

function readSize(capture: Capture): number {
  return capture.size_bytes ?? capture.metrics?.storage_bytes ?? 0;
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

  // Growth tracking: keep a 10 s sliding window of (timestamp, size) per
  // capture. useCaptures polls every 4 s so we normally get 2–3 samples,
  // enough to display a 10 s growth number. Values are not stored across
  // page reloads — strictly in-memory.
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
    const history = historyRef.current;
    const now = Date.now();
    const liveIds = new Set(live.map((capture) => capture.capture_id));
    for (const capture of live) {
      const key = capture.capture_id;
      const samples = history.get(key) ?? [];
      samples.push({ timestamp: now, size: readSize(capture) });
      // Keep only the last 10 s.
      const cutoff = now - 10_000;
      while (samples.length > 1 && samples[0].timestamp < cutoff) samples.shift();
      history.set(key, samples);
    }
    // Drop histories for captures that are no longer live.
    for (const key of Array.from(history.keys())) {
      if (!liveIds.has(key)) history.delete(key);
    }
    setGrowthTick((tick) => tick + 1);
  }, [live]);

  const growthByCapture = useMemo(() => {
    const map = new Map<string, number>();
    const history = historyRef.current;
    for (const [key, samples] of history) {
      if (samples.length < 2) {
        map.set(key, 0);
        continue;
      }
      map.set(key, samples[samples.length - 1].size - samples[0].size);
    }
    return map;
    // growthTick is the deterministic trigger that re-reads the ref.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [growthTick]);

  const totalGrowth10s = Array.from(growthByCapture.values()).reduce(
    (sum, value) => sum + value,
    0,
  );
  const stalledCount = live.filter((capture) => {
    const growth = growthByCapture.get(capture.capture_id) ?? 0;
    return STALL_STATES.includes(capture.state ?? '') || (ACTIVE_STATES.includes(capture.state ?? '') && growth === 0);
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
          label="Written · 10s"
          value={bytes(totalGrowth10s)}
          detail={`${live.length} active capture${live.length === 1 ? '' : 's'}`}
        />
        <StatCard
          label="Capturing"
          value={count(live.length)}
          detail="Jobs reporting an active state"
        />
        <StatCard
          label="Stalled"
          value={count(stalledCount)}
          detail="Active jobs with 0 B growth in 10 s"
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
          const growth = growthByCapture.get(capture.capture_id) ?? 0;
          const stalled =
            STALL_STATES.includes(capture.state ?? '') ||
            (ACTIVE_STATES.includes(capture.state ?? '') && growth === 0);
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
                      <AlertTriangle width={11} height={11} /> stalled 10 s
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
                <dt className="text-text-secondary">Growth · 10 s</dt>
                <dd className="num" data-testid={`growth-${capture.capture_id}`}>
                  {bytes(growth)}
                </dd>
                <dt className="text-text-secondary">Drops</dt>
                <dd className="num">{count(metrics?.packet_drops)}</dd>
                <dt className="text-text-secondary">Storage</dt>
                <dd className="num">{bytes(metrics?.storage_bytes)}</dd>
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
