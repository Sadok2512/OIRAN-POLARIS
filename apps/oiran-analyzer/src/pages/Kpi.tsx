import { PageHeader } from '@/ui/PageHeader';
import { EmptyState, LoadingSkeleton, Unavailable } from '@/ui/EmptyErrorLoading';
import { StatusIndicator } from '@/ui/StatusIndicator';
import { useMetrics, useVersion } from '@/data/queries';
import { bits, bytes, count, pps, percent } from '@/data/format';

export function KpiPage() {
  const metrics = useMetrics();
  const version = useVersion();

  return (
    <>
      <PageHeader
        eyebrow="Analysis"
        title="KPI / Performance"
        description="Decoder throughput, backend resource usage, decode error accounting. Every counter is backend-reported; absent counters render as 'Not available'."
        actions={
          <StatusIndicator state={metrics.data?.mode ?? 'UNKNOWN'} />
        }
      />
      {metrics.isLoading && !metrics.data ? (
        <LoadingSkeleton label="Loading metrics" />
      ) : metrics.error ? (
        <EmptyState title="Metrics unavailable" description={(metrics.error as Error).message} />
      ) : (
        <>
          <div className="grid gap-4 grid-cols-2 md:grid-cols-4">
            <KpiTile label="Packet rate (host)" value={pps(metrics.data?.packet_rate_pps)} />
            <KpiTile label="Decode rate" value={count(metrics.data?.decode_rate_eps) + ' eps'} />
            <KpiTile label="Bitrate" value={bits(metrics.data?.bitrate_bps)} />
            <KpiTile label="Capture queue" value={percent(metrics.data?.capture_queue_utilization_percent)} />
            <KpiTile label="Active captures" value={count(metrics.data?.active_captures)} />
            <KpiTile label="Active sessions" value={count(metrics.data?.active_sessions)} />
            <KpiTile label="Historical sessions" value={count(metrics.data?.historical_sessions)} />
            <KpiTile label="Historical events" value={count(metrics.data?.historical_events)} />
            <KpiTile label="Decode errors" value={count(metrics.data?.decode_errors)} />
            <KpiTile label="Packet drops" value={count(metrics.data?.packet_drops)} />
            <KpiTile label="CPU usage" value={percent(metrics.data?.cpu.usage_percent)} />
            <KpiTile label="RAM available" value={bytes(metrics.data?.memory.available_bytes)} />
          </div>

          <section className="mt-6 ep-card p-5">
            <h2 className="text-ep-md font-semibold mb-2">Per-interface rates</h2>
            {metrics.data?.interfaces?.length ? (
              <table className="ep-table text-ep-sm">
                <thead>
                  <tr>
                    <th>Interface</th>
                    <th>State</th>
                    <th className="text-right">Packet rate</th>
                  </tr>
                </thead>
                <tbody>
                  {metrics.data.interfaces.map((iface) => (
                    <tr key={iface.interface}>
                      <td className="mono">{iface.interface}</td>
                      <td>
                        <StatusIndicator state={iface.state} compact />
                      </td>
                      <td className="num text-right">{pps(iface.packet_rate_pps)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <Unavailable reason="Backend did not report per-interface rates." />
            )}
          </section>

          <section className="mt-6 ep-card p-5">
            <h2 className="text-ep-md font-semibold mb-2">Backend versions</h2>
            {version.data ? (
              <dl className="grid grid-cols-2 md:grid-cols-3 gap-x-6 gap-y-1 text-ep-sm">
                <dt className="text-text-secondary">Platform core</dt>
                <dd>{version.data.platform_core}</dd>
                <dt className="text-text-secondary">Backend API</dt>
                <dd>{version.data.backend_api}</dd>
                <dt className="text-text-secondary">Event schema</dt>
                <dd>{version.data.event_schema}</dd>
                <dt className="text-text-secondary">Call-flow schema</dt>
                <dd>{version.data.callflow_schema}</dd>
                <dt className="text-text-secondary">Session engine</dt>
                <dd>{version.data.session_engine}</dd>
                <dt className="text-text-secondary">Correlation engine</dt>
                <dd>{version.data.correlation_engine}</dd>
              </dl>
            ) : (
              <Unavailable reason="Backend did not return a version envelope." />
            )}
          </section>
        </>
      )}
    </>
  );
}

function KpiTile({ label, value }: { label: string; value: string }) {
  return (
    <article className="ep-card p-4" data-testid="kpi-tile">
      <p className="text-ep-xs uppercase tracking-wider text-text-secondary">{label}</p>
      <strong className="text-ep-xl num text-text-primary mt-1 block">{value}</strong>
    </article>
  );
}
