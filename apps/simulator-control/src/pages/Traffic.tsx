import { Info, ArrowDown, ArrowUp } from 'lucide-react';
import { PageHeader } from '@/components/mockup';
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
        description="Bounded UDP uplink + iperf3 downlink. Uplink is measured on the UE sender; downlink is measured on the health-gated DN sender (polaris-dn-sender) and on the UE receiver — the backend compares both counts. This page is observability only; executions start from Scenarios → Run Scenario."
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

      {traffic.data ? (
        <section
          className="grid gap-4 md:grid-cols-2 mb-4"
          data-testid="traffic-directions"
        >
          <article className="ep-card p-4 flex flex-col gap-2" data-testid="traffic-ul-card">
            <header className="flex items-center justify-between">
              <h3 className="text-ep-md font-semibold flex items-center gap-2">
                <ArrowUp width={14} height={14} /> Uplink · traffic_ul
              </h3>
              <StatusIndicator
                state={traffic.data.traffic_ul ? 'MEASURED' : 'IDLE'}
                tone={traffic.data.traffic_ul ? 'success' : 'neutral'}
                compact
              />
            </header>
            <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-ep-sm">
              <dt className="text-text-secondary">UE sender bytes</dt>
              <dd className="num" data-testid="traffic-ul-sender">
                {count(traffic.data.traffic_ul?.measured_sender_bytes ?? null)}
              </dd>
              <dt className="text-text-secondary">DN receiver bytes</dt>
              <dd className="num" data-testid="traffic-ul-ue">
                {count(traffic.data.traffic_ul?.measured_ue_bytes ?? null)}
              </dd>
            </dl>
          </article>

          <article className="ep-card p-4 flex flex-col gap-2" data-testid="traffic-dl-card">
            <header className="flex items-center justify-between">
              <h3 className="text-ep-md font-semibold flex items-center gap-2">
                <ArrowDown width={14} height={14} /> Downlink · traffic_dl
              </h3>
              <StatusIndicator
                state={traffic.data.dl_sender_state ?? (traffic.data.dl_sender_available ? 'HEALTHY' : 'DL_SENDER_NOT_AVAILABLE')}
                tone={traffic.data.dl_sender_available ? 'success' : 'warning'}
                compact
              />
            </header>
            <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-ep-sm">
              <dt className="text-text-secondary">DN sender bytes</dt>
              <dd className="num" data-testid="traffic-dl-sender">
                {count(traffic.data.traffic_dl?.measured_sender_bytes ?? null)}
              </dd>
              <dt className="text-text-secondary">UE receiver bytes</dt>
              <dd className="num" data-testid="traffic-dl-ue">
                {count(traffic.data.traffic_dl?.measured_ue_bytes ?? null)}
              </dd>
              <dt className="text-text-secondary">Sender state</dt>
              <dd data-testid="traffic-dl-state">
                {traffic.data.dl_sender_state ?? '—'}
              </dd>
              <dt className="text-text-secondary">Executable now</dt>
              <dd data-testid="traffic-dl-available">
                {traffic.data.dl_sender_available == null
                  ? '—'
                  : traffic.data.dl_sender_available
                  ? 'yes'
                  : 'no — DL_SENDER_NOT_AVAILABLE'}
              </dd>
            </dl>
          </article>
        </section>
      ) : null}

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
