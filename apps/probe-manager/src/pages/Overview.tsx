import { HardDrive, Radio, Activity, Database } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import {
  EmptyState,
  ErrorState,
  LoadingSkeleton,
  Unavailable,
} from '@/ui/EmptyErrorLoading';
import { StatusIndicator, toneFor } from '@/ui/StatusIndicator';
import {
  useAuth,
  useCaptures,
  useDiskSafety,
  useInterfaces,
  useMetrics,
  useProbes,
} from '@/data/queries';
import { bytes, count, pps, percent } from '@/data/format';

function MetricTile({
  label,
  value,
  sub,
  state,
}: {
  label: string;
  value: string;
  sub?: string;
  state?: string;
}) {
  return (
    <div className="ep-card p-4 flex flex-col gap-1" data-testid="metric-tile">
      <div className="flex items-center justify-between">
        <span className="text-ep-xs uppercase tracking-wider text-text-secondary">
          {label}
        </span>
        {state && <StatusIndicator state={state} compact />}
      </div>
      <strong className="text-ep-xl font-semibold text-text-primary num">{value}</strong>
      {sub && <span className="text-ep-xs text-text-secondary">{sub}</span>}
    </div>
  );
}

export function OverviewPage() {
  const probes = useProbes();
  const interfaces = useInterfaces();
  const captures = useCaptures();
  const metrics = useMetrics();
  const safety = useDiskSafety();
  const auth = useAuth();

  const anyLoading =
    probes.isLoading ||
    interfaces.isLoading ||
    captures.isLoading ||
    metrics.isLoading ||
    safety.isLoading;
  const anyError =
    probes.error || interfaces.error || captures.error || metrics.error;

  const online = probes.data?.filter((p) => p.online).length ?? 0;
  const activeCapture = captures.data?.items?.find((item) =>
    ['CAPTURING', 'STARTING', 'STOPPING', 'PROCESSING'].includes(
      item.state ?? '',
    ),
  );

  return (
    <>
      <PageHeader
        eyebrow="Operations"
        title="Overview"
        description="Real backend state. Every tile labelled 'Not available' means the OIRAN backend has not reported that value."
        actions={
          auth.data?.authenticated ? (
            <StatusIndicator
              state="AUTHENTICATED"
              label={`Role ${auth.data.role}`}
              tone="success"
            />
          ) : (
            <StatusIndicator state="UNAUTHENTICATED" tone="warning" />
          )
        }
      />

      {anyLoading && <LoadingSkeleton label="Loading operational telemetry" />}

      {anyError && !anyLoading && (
        <ErrorState
          title="Backend unreachable"
          detail="Overview counters require the OIRAN API. Running without a backend only renders empty states."
          onRetry={() => {
            void probes.refetch();
            void interfaces.refetch();
            void captures.refetch();
            void metrics.refetch();
            void safety.refetch();
          }}
        />
      )}

      {!anyLoading && !anyError && (
        <div className="grid gap-4 grid-cols-2 md:grid-cols-4">
          <MetricTile
            label="Registered probes"
            value={count(probes.data?.length)}
            sub={`${online} online`}
            state={online > 0 ? 'ONLINE' : 'OFFLINE'}
          />
          <MetricTile
            label="Interfaces discovered"
            value={count(interfaces.data?.length)}
            sub={
              interfaces.data?.filter((i) => i.live_capture_available).length
                ? `${interfaces.data.filter((i) => i.live_capture_available).length} live-capable`
                : 'None currently live-capable'
            }
          />
          <MetricTile
            label="Captures recorded"
            value={count(captures.data?.items?.length)}
            sub={activeCapture ? 'Capture in progress' : 'No active capture'}
            state={activeCapture ? 'CAPTURING' : 'READY'}
          />
          <MetricTile
            label="Packet rate (host)"
            value={pps(metrics.data?.packet_rate_pps)}
            sub={
              metrics.data?.mode
                ? `Mode: ${metrics.data.mode}`
                : 'Mode unknown'
            }
            state={toneFor(metrics.data?.mode)}
          />
        </div>
      )}

      <section className="mt-6 grid gap-4 md:grid-cols-2">
        <article className="ep-card p-5 flex flex-col gap-3">
          <header className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <HardDrive width={16} height={16} className="text-text-secondary" />
              <h2 className="text-ep-md font-semibold">Storage safety</h2>
            </div>
            {safety.data?.decision?.state && (
              <StatusIndicator state={safety.data.decision.state} />
            )}
          </header>
          {safety.isLoading ? (
            <LoadingSkeleton label="Reading disk safety" />
          ) : !safety.data?.filesystem ? (
            <Unavailable reason="Backend did not return filesystem metrics." />
          ) : (
            <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-ep-sm">
              <dt className="text-text-secondary">Usage</dt>
              <dd className="num text-right">
                {percent(safety.data.filesystem.usage_percent)}
              </dd>
              <dt className="text-text-secondary">Available</dt>
              <dd className="num text-right">
                {bytes(safety.data.filesystem.available_bytes)}
              </dd>
              <dt className="text-text-secondary">New capture allowed</dt>
              <dd className="text-right">
                {safety.data.decision.new_capture_allowed ? 'Yes' : 'No'}
              </dd>
              <dt className="text-text-secondary">Capture engine</dt>
              <dd className="text-right">
                <StatusIndicator state={safety.data.capture_job.state} compact />
              </dd>
            </dl>
          )}
        </article>

        <article className="ep-card p-5 flex flex-col gap-3">
          <header className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Radio width={16} height={16} className="text-text-secondary" />
              <h2 className="text-ep-md font-semibold">Probe fleet</h2>
            </div>
          </header>
          {probes.isLoading ? (
            <LoadingSkeleton label="Loading probes" />
          ) : !probes.data?.length ? (
            <EmptyState
              title="No probes registered"
              description="The backend has not returned any probe. Register at least one vProbe to populate this view."
            />
          ) : (
            <ul className="flex flex-col gap-2 text-ep-sm">
              {probes.data.slice(0, 5).map((probe) => (
                <li
                  key={probe.probe_id}
                  className="flex items-center justify-between gap-2 py-1"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <Activity
                      width={14}
                      height={14}
                      className="text-text-secondary shrink-0"
                    />
                    <span className="truncate">{probe.name}</span>
                    <span className="text-text-secondary mono text-ep-xs truncate">
                      {probe.host}
                    </span>
                  </div>
                  <StatusIndicator
                    state={probe.online ? 'ONLINE' : 'OFFLINE'}
                    compact
                  />
                </li>
              ))}
            </ul>
          )}
        </article>
      </section>

      <section className="mt-6">
        <article className="ep-card p-5 flex flex-col gap-3">
          <header className="flex items-center gap-2">
            <Database width={16} height={16} className="text-text-secondary" />
            <h2 className="text-ep-md font-semibold">Capture inventory</h2>
          </header>
          {captures.isLoading ? (
            <LoadingSkeleton label="Loading capture inventory" />
          ) : !captures.data?.items?.length ? (
            <EmptyState
              title="No captures reported"
              description="The library will populate once the backend registers at least one capture."
            />
          ) : (
            <dl className="grid grid-cols-2 md:grid-cols-4 gap-x-6 gap-y-1 text-ep-sm">
              <dt className="text-text-secondary">Total records</dt>
              <dd className="num text-right">{count(captures.data.items.length)}</dd>
              <dt className="text-text-secondary">Active</dt>
              <dd className="num text-right">
                {activeCapture ? '1' : '0'}
              </dd>
              <dt className="text-text-secondary">Historical</dt>
              <dd className="num text-right">
                {count(
                  captures.data.items.filter(
                    (item) => item.dataset_kind === 'HISTORICAL',
                  ).length,
                )}
              </dd>
              <dt className="text-text-secondary">Captured live</dt>
              <dd className="num text-right">
                {count(
                  captures.data.items.filter(
                    (item) => item.dataset_kind === 'CAPTURED_LIVE',
                  ).length,
                )}
              </dd>
            </dl>
          )}
        </article>
      </section>
    </>
  );
}
