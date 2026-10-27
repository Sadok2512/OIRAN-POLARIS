import { Info } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import { StatusIndicator } from '@/ui/StatusIndicator';
import { EmptyState, LoadingSkeleton } from '@/ui/EmptyErrorLoading';
import { useCapabilities, useTraffic } from '@/data/queries';
import { count, isoToLocal } from '@/data/format';

export function TrafficPage() {
  const traffic = useTraffic();
  const capabilities = useCapabilities();

  return (
    <>
      <PageHeader
        eyebrow="Operations"
        title="Traffic Generator"
        description="Observe the backend-reported bounded traffic state. User-driven bounded UDP runs through Scenarios → Run Scenario; this page is strictly observability — no action is dispatched from here."
      />

      {traffic.isLoading && !traffic.data && <LoadingSkeleton label="Loading traffic" />}

      {traffic.data && (
        <section className="ep-card p-5 mb-4" data-testid="traffic-card">
          <header className="flex items-center justify-between mb-3">
            <h2 className="text-ep-md font-semibold">Current traffic</h2>
            <StatusIndicator state={traffic.data.state} />
          </header>
          <dl className="grid grid-cols-2 md:grid-cols-4 gap-x-6 gap-y-1 text-ep-sm">
            <dt className="text-text-secondary">Packets requested</dt>
            <dd className="num">{count(traffic.data.packets_requested)}</dd>
            <dt className="text-text-secondary">Packets sent</dt>
            <dd className="num">{count(traffic.data.packets_sent)}</dd>
            <dt className="text-text-secondary">Packets received</dt>
            <dd className="num">{count(traffic.data.packets_received)}</dd>
            <dt className="text-text-secondary">Bytes</dt>
            <dd className="num">{count(traffic.data.bytes)}</dd>
            <dt className="text-text-secondary">Current rate</dt>
            <dd className="num">
              {traffic.data.current_rate_pps != null ? `${traffic.data.current_rate_pps} pps` : '—'}
            </dd>
            <dt className="text-text-secondary">TUN interface</dt>
            <dd className="mono text-ep-xs">{traffic.data.tun_interface ?? '—'}</dd>
            <dt className="text-text-secondary">Target UE</dt>
            <dd>{traffic.data.target_ue_id ?? '—'}</dd>
            <dt className="text-text-secondary">Accounting source</dt>
            <dd>{traffic.data.accounting_source}</dd>
          </dl>
          {traffic.data.last_result && (
            <p className="mt-3 text-ep-xs text-text-secondary">
              Last recorded controller-owned job: {traffic.data.last_result.scenario_id} ·{' '}
              {isoToLocal(traffic.data.last_result.started_at)} · result{' '}
              {traffic.data.last_result.terminal_result ?? '—'}
            </p>
          )}
        </section>
      )}

      <section className="ep-card p-5 mb-4" data-testid="traffic-destinations">
        <h3 className="text-ep-md font-semibold mb-2">Approved destinations</h3>
        {!capabilities.data?.approved_destinations?.length ? (
          <EmptyState
            title="No approved destination reported"
            description="POLARIS /capabilities did not advertise any approved destination."
          />
        ) : (
          <ul className="flex flex-wrap gap-1 text-ep-xs">
            {capabilities.data.approved_destinations.map((destination) => (
              <li key={destination}>
                <span className="ep-badge mono">{destination}</span>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="ep-card p-4 flex items-start gap-2 text-ep-xs text-text-secondary border-primary/30">
        <Info width={13} height={13} className="text-primary mt-0.5 shrink-0" />
        <span>
          To start bounded UDP traffic, open <a className="text-primary" href="/simulator/scenarios">Scenarios</a>,
          build (or pick) a scenario with a single <code className="mono">UDP_TRAFFIC</code> step, assign it to a UE in
          <a className="text-primary" href="/simulator/ues"> UE Manager</a>, then press
          <strong> Run Scenario</strong>. Backend endpoint:{' '}
          <code className="mono">POST /polaris-api/v1/scenarios/start</code>.
        </span>
      </section>
    </>
  );
}
