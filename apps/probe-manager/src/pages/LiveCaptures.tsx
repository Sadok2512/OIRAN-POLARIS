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
import {
  useAuth,
  useCaptures,
  useInterfaces,
  useProbes,
  useStartCapture,
  useStopCapture,
  useValidateCapture,
} from '@/data/queries';
import type { CaptureRequest } from '@shared/types';

const ACTIVE_STATES = ['READY', 'STARTING', 'CAPTURING', 'STOPPING'];

export function LiveCapturesPage() {
  const captures = useCaptures();
  const auth = useAuth();
  const probes = useProbes();
  const interfaces = useInterfaces();
  const validateCapture = useValidateCapture();
  const startCapture = useStartCapture();
  const stopCapture = useStopCapture();
  const [confirmStop, setConfirmStop] = useState<string | null>(null);
  const [selectedInterfaces, setSelectedInterfaces] = useState<string[]>([]);
  const [duration, setDuration] = useState(60);
  const [feedback, setFeedback] = useState('');
  const control = auth.data?.capture_control === true;
  const execution = auth.data?.capture_execution_enabled === true;
  const availableInterfaces = interfaces.data?.filter(
    (item) => item.live_capture_available && item.status === 'AVAILABLE',
  ) ?? [];
  const probeId = probes.data?.find((probe) => probe.online)?.probe_id ?? '';

  const request = (): CaptureRequest => ({
    probe_id: probeId,
    name: `Portal-${Date.now()}`,
    interfaces: selectedInterfaces,
    duration_seconds: duration,
    max_bytes: 256 * 1024 * 1024,
    rotation_files: 1,
    profile: 'POLARIS_5G_SA',
    optional_filter: null,
  });

  async function validateOnly() {
    setFeedback('');
    try {
      const result = await validateCapture.mutateAsync(request());
      setFeedback(result.validation.valid === false
        ? `Validation rejected: ${result.validation.blockers.join(', ')}`
        : 'Validation passed. No capture was started.');
    } catch (error) {
      setFeedback((error as Error).message);
    }
  }

  async function start() {
    setFeedback('');
    try {
      const validation = await validateCapture.mutateAsync(request());
      if (validation.validation.valid === false) {
        setFeedback(`Validation rejected: ${validation.validation.blockers.join(', ')}`);
        return;
      }
      const job = await startCapture.mutateAsync(request());
      setFeedback(`Capture request accepted: ${job.capture_id}`);
    } catch (error) {
      setFeedback((error as Error).message);
    }
  }

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

      <section className="ep-card mb-4 p-5" aria-label="Capture controls">
        <div className="grid gap-4 md:grid-cols-[1fr_auto]">
          <div>
            <h2 className="text-ep-lg font-semibold">Bounded capture</h2>
            <p className="text-ep-sm text-text-secondary">
              Select verified backend interfaces. Validation never starts acquisition.
            </p>
            <div className="mt-3 flex flex-wrap gap-2">
              {availableInterfaces.map((item) => (
                <label className="ep-button ep-button-sm" key={item.interface}>
                  <input
                    type="checkbox"
                    checked={selectedInterfaces.includes(item.interface)}
                    onChange={(event) => setSelectedInterfaces((current) =>
                      event.target.checked
                        ? [...current, item.interface]
                        : current.filter((value) => value !== item.interface))}
                  />
                  {item.interface} · {item.protocol}
                </label>
              ))}
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
            disabled={!control || !execution || !probeId || selectedInterfaces.length === 0 || validateCapture.isPending}
            onClick={() => void validateOnly()}
          >
            Validate capture
          </button>
          <button
            type="button"
            className="ep-button ep-button-primary"
            disabled={!control || !execution || !probeId || selectedInterfaces.length === 0 || startCapture.isPending}
            onClick={() => void start()}
          >
            Start capture
          </button>
          <span className="text-ep-xs text-text-secondary">
            {!control ? 'Operator authentication required.' : feedback}
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
          const captureId = confirmStop;
          setConfirmStop(null);
          if (!captureId) return;
          void stopCapture.mutateAsync(captureId)
            .then(() => setFeedback(`Stop request accepted: ${captureId}`))
            .catch((error: Error) => setFeedback(error.message));
        }}
      />
    </>
  );
}
