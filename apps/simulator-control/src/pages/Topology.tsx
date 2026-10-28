import { useMemo } from 'react';
import { AlertTriangle, Antenna, Cpu, Smartphone } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import { StatusIndicator } from '@/ui/StatusIndicator';
import { EmptyState, ErrorState, LoadingSkeleton } from '@/ui/EmptyErrorLoading';
import { useLabObserved, useNodes, useUes, type WireLabObserved } from '@/data/queries';

// 3GPP core NFs we observe through container_status in POLARIS /lab.
// The backend reports `open5gs` as a single aggregate container (the
// current lab deploys AMF+SMF+UPF+NRF in one compose unit); other NFs
// stay listed as "not exposed" until POLARIS surfaces them individually.
const CORE_NF_ROWS = [
  { key: 'AMF', detail: 'Access and mobility' },
  { key: 'SMF', detail: 'Session management' },
  { key: 'UPF', detail: 'User plane' },
  { key: 'NRF', detail: 'NF repository' },
  { key: 'AUSF', detail: 'Authentication' },
  { key: 'UDM', detail: 'Subscriber data' },
] as const;

export function TopologyPage() {
  const lab = useLabObserved();
  const nodes = useNodes();
  const ues = useUes();

  const observed = lab.data?.observed;
  const openCore = containerTone(observed?.open5gs);

  const uesByNode = useMemo(() => {
    const map = new Map<string, string[]>();
    for (const ue of ues.data?.items ?? []) {
      const key = ue.serving_node ?? 'UNASSIGNED';
      const list = map.get(key) ?? [];
      list.push(ue.id);
      map.set(key, list);
    }
    return map;
  }, [ues.data?.items]);

  const loading = lab.isLoading || nodes.isLoading || ues.isLoading;
  const errored = lab.error || nodes.error || ues.error;

  return (
    <>
      <PageHeader
        eyebrow="Network"
        title="Topology"
        description="Core, radio and UEs as POLARIS reports them. Links are shown as 'up' only when backend state proves it; nothing is simulated client-side."
        actions={
          <StatusIndicator
            state={openCore.state}
            tone={openCore.tone}
            label={openCore.label}
          />
        }
      />

      {loading && (
        <LoadingSkeleton label="Loading /lab + /nodes + /ues" />
      )}
      {errored && !loading && (
        <ErrorState
          title="Could not compose topology"
          detail={(errored as Error).message}
          onRetry={() => {
            void lab.refetch();
            void nodes.refetch();
            void ues.refetch();
          }}
        />
      )}

      {!loading && !errored && (
        <section className="flex flex-col gap-4" data-testid="topology-view">
          <article className="ep-card p-4">
            <header className="flex items-center justify-between gap-2 mb-3">
              <div className="flex items-center gap-2">
                <Cpu className="text-primary" width={18} height={18} />
                <h2 className="text-ep-md font-semibold">5G Core · Open5GS</h2>
              </div>
              <StatusIndicator state={openCore.state} tone={openCore.tone} compact />
            </header>
            <div className="grid grid-cols-2 md:grid-cols-6 gap-2 text-ep-sm">
              {CORE_NF_ROWS.map((row) => (
                <div
                  key={row.key}
                  className="border border-border rounded-md px-2 py-1.5 flex items-center justify-between gap-1"
                  data-testid={`topology-nf-${row.key}`}
                >
                  <div className="min-w-0">
                    <p className="mono font-medium truncate">{row.key}</p>
                    <p className="text-ep-xs text-text-secondary truncate">{row.detail}</p>
                  </div>
                  <span
                    className={`h-2 w-2 rounded-full shrink-0 ${
                      row.key === 'AMF' && openCore.tone === 'success'
                        ? 'bg-success'
                        : 'bg-text-secondary/40'
                    }`}
                    title={
                      row.key === 'AMF'
                        ? openCore.label
                        : 'not exposed by /lab (observed only on container "open5gs")'
                    }
                  />
                </div>
              ))}
            </div>
            <p className="text-ep-xs text-text-secondary mt-2 flex items-start gap-1">
              <AlertTriangle width={11} height={11} className="mt-0.5 shrink-0" />
              POLARIS /lab reports a single aggregated container{' '}
              <code className="mono mx-1">open5gs</code>. Per-NF health is not exposed yet.
            </p>
          </article>

          {nodes.data && nodes.data.items.length === 0 && (
            <EmptyState
              title="No node reported"
              description="/nodes returned an empty inventory."
            />
          )}

          <div className="grid gap-4 md:grid-cols-2">
            {(nodes.data?.items ?? []).map((node) => {
              const attachedUes = uesByNode.get(node.id) ?? [];
              return (
                <article
                  key={node.id}
                  className={`ep-card p-4 flex flex-col gap-3 ${
                    node.configured ? '' : 'border-dashed'
                  }`}
                  data-testid={`topology-node-${node.id}`}
                >
                  <header className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Antenna className="text-primary" width={18} height={18} />
                      <div>
                        <h3 className="text-ep-md font-semibold mono">{node.id}</h3>
                        <p className="text-ep-xs text-text-secondary">
                          {node.technology} · {node.simulator}
                        </p>
                      </div>
                    </div>
                    <StatusIndicator state={node.process_state ?? 'UNKNOWN'} compact />
                  </header>

                  <LinkRail
                    n2Up={isLinkUp(node.process_state, node.n2_endpoint)}
                    n3Up={isLinkUp(node.process_state, node.n3_endpoint)}
                    n2Endpoint={node.n2_endpoint}
                    n3Endpoint={node.n3_endpoint}
                  />

                  <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-ep-xs">
                    <dt className="text-text-secondary">PLMN</dt>
                    <dd className="mono">{node.plmn}</dd>
                    <dt className="text-text-secondary">Cell ID</dt>
                    <dd className="mono">{node.cell_id}</dd>
                    <dt className="text-text-secondary">Link IP</dt>
                    <dd className="mono">{node.link_ip}</dd>
                    <dt className="text-text-secondary">N2 / N3 endpoint</dt>
                    <dd className="mono">
                      {node.n2_endpoint ?? '—'} / {node.n3_endpoint ?? '—'}
                    </dd>
                  </dl>

                  <section>
                    <p className="text-ep-xs uppercase tracking-wider text-text-secondary mb-1">
                      UEs attached · {attachedUes.length}
                    </p>
                    {attachedUes.length === 0 ? (
                      <p className="text-ep-xs text-text-secondary">
                        No UE reports <span className="mono">serving_node = {node.id}</span>.
                      </p>
                    ) : (
                      <ul className="flex flex-wrap gap-1.5" data-testid={`topology-ues-${node.id}`}>
                        {attachedUes.map((ueId) => (
                          <li key={ueId}>
                            <span className="ep-badge inline-flex items-center gap-1 mono">
                              <Smartphone width={11} height={11} />
                              {ueId}
                            </span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </section>

                  {!node.controller_owned && (
                    <p className="text-ep-xs text-warning flex items-start gap-1">
                      <AlertTriangle width={11} height={11} className="mt-0.5 shrink-0" />
                      {node.actions.reason || 'Not controller-owned'}
                    </p>
                  )}
                </article>
              );
            })}
          </div>

          <p className="text-ep-xs text-text-secondary">
            Each UE searches only for its serving gNB (<span className="mono">gnbSearchList</span>). UERANSIM has no
            handover, so a UE stays on its gNB. "NGAP: unknown" means POLARIS has not yet reported an NG Setup result.
          </p>
        </section>
      )}
    </>
  );
}

export function isLinkUp(processState: string | null | undefined, endpoint: string | null): boolean {
  if (!endpoint) return false;
  return (processState ?? '').toUpperCase() === 'RUNNING';
}

function LinkRail({
  n2Up,
  n3Up,
  n2Endpoint,
  n3Endpoint,
}: {
  n2Up: boolean;
  n3Up: boolean;
  n2Endpoint: string | null;
  n3Endpoint: string | null;
}) {
  return (
    <div className="flex gap-3 text-ep-xs" data-testid="link-rail">
      <LinkLabel
        label="N2 · NGAP"
        state={n2Endpoint ? (n2Up ? 'UP' : 'DOWN') : 'unknown'}
      />
      <LinkLabel
        label="N3 · GTP-U"
        state={n3Endpoint ? (n3Up ? 'UP' : 'DOWN') : 'unknown'}
      />
    </div>
  );
}

function LinkLabel({ label, state }: { label: string; state: 'UP' | 'DOWN' | 'unknown' }) {
  const tone = state === 'UP' ? 'success' : state === 'DOWN' ? 'danger' : 'neutral';
  return (
    <span className="flex items-center gap-1">
      <StatusIndicator state={state} tone={tone === 'neutral' ? 'neutral' : tone} compact />
      <span className="mono text-text-secondary">{label}</span>
    </span>
  );
}

function containerTone(container: WireLabObserved['open5gs']): {
  state: string;
  tone: 'success' | 'warning' | 'danger' | 'neutral';
  label: string;
} {
  if (!container) {
    return {
      state: 'UNKNOWN',
      tone: 'neutral',
      label: 'open5gs container not reported by /lab',
    };
  }
  if (container.process_state === 'running' && container.health === 'healthy') {
    return { state: 'HEALTHY', tone: 'success', label: 'open5gs: running, healthy' };
  }
  if (container.process_state === 'running') {
    return {
      state: 'DEGRADED',
      tone: 'warning',
      label: `open5gs: running, health=${container.health}`,
    };
  }
  return {
    state: (container.process_state || 'UNKNOWN').toUpperCase(),
    tone: 'danger',
    label: `open5gs process_state=${container.process_state}`,
  };
}
