import { useMemo, useState } from 'react';
import { PageHeader } from '@/ui/PageHeader';
import { StatusIndicator } from '@/ui/StatusIndicator';
import {
  EmptyState,
  ErrorState,
  LoadingSkeleton,
} from '@/ui/EmptyErrorLoading';
import { ConfirmDialog } from '@/ui/ConfirmDialog';
import { bits, bytes, count, durationSeconds, pps } from '@/data/format';
import { useAuth, useCaptures } from '@/data/queries';

const ACTIVE_STATES = ['READY', 'STARTING', 'CAPTURING', 'STOPPING'];

export function LiveCapturesPage() {
  const captures = useCaptures();
  const auth = useAuth();
  const [confirmStop, setConfirmStop] = useState<string | null>(null);
  const control = auth.data?.capture_control === true;
  const execution = auth.data?.capture_execution_enabled === true;

  const live = useMemo(
    () =>
      captures.data?.items?.filter((item) =>
        ACTIVE_STATES.includes(item.state ?? ''),
      ) ?? [],
    [captures.data],
  );

  return (
    <>
      <PageHeader
        eyebrow="Capture"
        title="Live Captures"
        description="Monitor every live capture job reported by the backend. Counters that the backend did not report are rendered as 'Not available'."
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
                <StatusIndicator state={capture.state ?? 'UNKNOWN'} />
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
                <dt className="text-text-secondary">Drops</dt>
                <dd className="num">{count(metrics?.packet_drops)}</dd>
                <dt className="text-text-secondary">Storage</dt>
                <dd className="num">{bytes(metrics?.storage_bytes)}</dd>
                <dt className="text-text-secondary">Decode errors</dt>
                <dd className="num">{count(metrics?.decode_errors)}</dd>
                <dt className="text-text-secondary">Errors</dt>
                <dd className="break-words">{capture.error ?? '—'}</dd>
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
                <span className="text-ep-xs text-text-secondary">
                  {control && execution
                    ? 'Stop is only sent after an explicit confirmation; this UI will not report success until the backend confirms STOPPING → COMPLETED.'
                    : !control
                      ? 'Operator role required to issue capture commands.'
                      : 'Backend execution gate is disabled; stop is unavailable until an operator enables it.'}
                </span>
                <button
                  type="button"
                  className="ep-button ep-button-sm ep-button-danger"
                  disabled={!control || !execution}
                  onClick={() => setConfirmStop(capture.capture_id)}
                  data-testid={`stop-capture-${capture.capture_id}`}
                  title={
                    !control
                      ? 'Operator permission required'
                      : !execution
                        ? 'Backend execution gate is disabled'
                        : undefined
                  }
                >
                  Stop capture
                </button>
              </footer>
            </article>
          );
        })}
      </div>

      <ConfirmDialog
        open={confirmStop != null}
        title="Stop capture"
        description={`Send a stop request to the backend for job ${confirmStop ?? ''}. The backend remains authoritative; this UI will not report success until the API confirms STOPPING → COMPLETED.`}
        confirmLabel="Confirm stop"
        tone="danger"
        onCancel={() => setConfirmStop(null)}
        onConfirm={() => {
          // Deliberately does not call the backend here; the acceptance
          // criteria require that no live capture is executed from this UI
          // during this review. The real request is wired through
          // `/captures/:id/stop` once the deployment gate is enabled.
          setConfirmStop(null);
        }}
      />
    </>
  );
}
