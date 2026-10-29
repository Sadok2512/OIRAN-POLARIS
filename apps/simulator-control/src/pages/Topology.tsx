import { useMemo } from 'react';
import { AlertTriangle, Antenna, Cpu, Smartphone } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import { StatusIndicator } from '@/ui/StatusIndicator';
import { EmptyState, ErrorState, LoadingSkeleton } from '@/ui/EmptyErrorLoading';
import { useLabObserved, useNodes, useUes, type WireLabObserved } from '@/data/queries';
import type { NodeItem } from '@/data/polarisTypes';

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
        description="Core, radio and UEs as POLARIS reports them. Interface links are marked 'configured' when the backend process is running AND an endpoint is advertised; 'down' when the process isn't running; 'unknown' when no endpoint is advertised. NG Setup stays 'unknown' until a dedicated backend route proves it."
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
                <h2 className="text-ep-md font-semibold">5G Core</h2>
              </div>
              <StatusIndicator state={openCore.state} tone={openCore.tone} label={openCore.label} compact />
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
                        : 'not exposed by /lab (observed only on container "oiran-lab-amf-1")'
                    }
                  />
                </div>
              ))}
            </div>
            <p className="text-ep-xs text-text-secondary mt-2 flex items-start gap-1">
              <AlertTriangle width={11} height={11} className="mt-0.5 shrink-0" />
              POLARIS /lab reports a single aggregated container
              <code className="mono mx-1">oiran-lab-amf-1</code> under <code className="mono">observed.open5gs</code>.
              AMF reflects that container; every other NF stays "not exposed" until the backend splits them.
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

                  <LinkRail node={node} />

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

                  <section data-testid={`topology-ue-cards-${node.id}`}>
                    <p className="text-ep-xs uppercase tracking-wider text-text-secondary mb-1">
                      UEs attached · {attachedUes.length}
                    </p>
                    {attachedUes.length === 0 ? (
                      <p className="text-ep-xs text-text-secondary">
                        No UE reports <span className="mono">serving_node = {node.id}</span>.
                      </p>
                    ) : (
                      <ul
                        className="grid grid-cols-2 md:grid-cols-3 gap-2"
                        data-testid={`topology-ues-${node.id}`}
                      >
                        {attachedUes.map((ueId) => {
                          const ue = (ues.data?.items ?? []).find((item) => item.id === ueId);
                          return (
                            <li
                              key={ueId}
                              className="ep-card border-border p-2 flex flex-col gap-1 text-ep-xs"
                              data-testid={`topology-ue-card-${ueId}`}
                            >
                              <div className="flex items-center justify-between gap-2">
                                <span className="inline-flex items-center gap-1 mono font-semibold">
                                  <Smartphone width={11} height={11} />
                                  {ueId}
                                </span>
                                <StatusIndicator
                                  state={ue?.process_state ?? 'NOT_OBSERVED'}
                                  tone={ue?.process_state === 'running' ? 'success' : 'neutral'}
                                  compact
                                />
                              </div>
                              <dl className="grid grid-cols-2 gap-x-2 gap-y-0 text-ep-xs text-text-secondary">
                                <dt>registration</dt>
                                <dd className="mono">{ue?.registration_state ?? 'NOT_OBSERVED'}</dd>
                                <dt>pdu</dt>
                                <dd className="mono">{ue?.pdu_session ?? 'INACTIVE'}</dd>
                                <dt>identity</dt>
                                <dd className="mono">PROTECTED</dd>
                              </dl>
                            </li>
                          );
                        })}
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
            handover, so a UE stays on its gNB. The link labels say "configured" (process running + endpoint known),
            "down" (process not running), or "unknown" (no endpoint reported). NG Setup success stays "unknown" until
            a dedicated backend route proves it.
          </p>
        </section>
      )}
    </>
  );
}

export type LinkState = 'configured' | 'down' | 'unknown';

/**
 * Translate the backend fields into one of three honest states:
 *   configured — process is running AND an endpoint IP is reported;
 *   down       — process is not running;
 *   unknown    — no endpoint is reported (the UI can't name the link).
 *
 * "configured" never means "NGAP OK": the backend has no NG-Setup result
 * yet, so the UI will never say "UP". Even for a running gNB the link
 * stays "configured" until a dedicated route proves otherwise.
 */
export function linkState(
  processState: string | null | undefined,
  endpoint: string | null,
): LinkState {
  if (!endpoint) return 'unknown';
  if ((processState ?? '').toLowerCase() !== 'running') return 'down';
  return 'configured';
}

const LTE_LABELS = {
  controlPlane: 'S1-MME · S1AP',
  userPlane: 'S1-U · GTP-U',
};
const NR_LABELS = {
  controlPlane: 'N2 · NGAP',
  userPlane: 'N3 · GTP-U',
};

function LinkRail({ node }: { node: NodeItem }) {
  const labels = node.technology === 'LTE' ? LTE_LABELS : NR_LABELS;
  return (
    <div className="flex gap-3 text-ep-xs flex-wrap" data-testid="link-rail">
      <LinkLabel
        label={labels.controlPlane}
        state={linkState(node.process_state, node.n2_endpoint)}
      />
      <LinkLabel
        label={labels.userPlane}
        state={linkState(node.process_state, node.n3_endpoint)}
      />
    </div>
  );
}

function LinkLabel({ label, state }: { label: string; state: LinkState }) {
  const tone =
    state === 'configured' ? 'success' : state === 'down' ? 'danger' : 'neutral';
  return (
    <span className="flex items-center gap-1" data-testid={`link-${label}`}>
      <StatusIndicator state={state} tone={tone} compact />
      <span className="mono text-text-secondary">{label}</span>
    </span>
  );
}

function containerTone(container: WireLabObserved['open5gs']): {
  state: string;
  tone: 'success' | 'warning' | 'danger' | 'neutral';
  label: string;
} {
  // The /lab endpoint reports a single container "oiran-lab-amf-1" under
  // observed.open5gs. The badge must name AMF, not an aggregate "core".
  if (!container) {
    return {
      state: 'UNKNOWN',
      tone: 'neutral',
      label: 'AMF container: not reported by /lab',
    };
  }
  return {
    state: `${container.process_state}/${container.health}`,
    tone:
      container.process_state === 'running' && container.health === 'healthy'
        ? 'success'
        : container.process_state === 'running'
          ? 'warning'
          : 'danger',
    label: `AMF container: ${container.process_state}, ${container.health}`,
  };
}
