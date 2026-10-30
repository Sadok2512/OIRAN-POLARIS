// 0.7.0 — Topology page redrawn to match the mockup
// (origin/docs/ui-mockups/polaris-control.html → `Topology` view).
//
// Shape:
//   ┌─ 5G Core · openX ──────────────────────────────┐
//   │   grid of ALL NF pills with their state dot    │
//   └────────────────────────────────────────────────┘
//            │ N2 · NGAP           │ N3 · GTP-U
//        ┌───┴────┐            ┌───┴────┐
//        │ GNB-01 │            │ GNB-02 │   (dashed if !configured)
//        └───┬────┘            └───┬────┘
//            │                     │
//        ┌───┴───┐             ┌───┴───┐
//        │ UE-01 │             │ UE-14 │
//        │ UE-12 │             └───────┘
//        └───────┘
//
// Line colour mapping — single source of truth is `linkState`:
//     configured → success (green)
//     down       → danger  (red)
//     unknown    → neutral (gray)
// The UI NEVER says "UP". `linkState` returns `configured` as soon as the
// process is running AND an endpoint is reported, but that is still not
// the same as "NGAP OK".

import { useMemo } from 'react';
import {
  AlertTriangle,
  Antenna,
  Cpu,
  Smartphone,
} from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import { StatusIndicator } from '@/ui/StatusIndicator';
import { EmptyState, ErrorState, LoadingSkeleton } from '@/ui/EmptyErrorLoading';
import {
  useLabObserved,
  useNodes,
  useUes,
  type WireContainerStatus,
  type WireLabObserved,
} from '@/data/queries';
import type { NodeItem, UeState } from '@/data/polarisTypes';

/**
 * Fallback NF catalogue. The mockup renders a grid of ten; we expose
 * the six accepted by the backend contract today plus the four most
 * common extras so operators recognise the shape even before the
 * backend publishes `observed.nfs`. Each entry carries a `role` string
 * that renders as the sub-caption inside the pill.
 */
const CORE_NF_CATALOGUE: { nf: string; role: string }[] = [
  { nf: 'AMF', role: 'Access & mobility' },
  { nf: 'SMF', role: 'Session management' },
  { nf: 'UPF', role: 'User plane' },
  { nf: 'NRF', role: 'NF repository' },
  { nf: 'AUSF', role: 'Authentication' },
  { nf: 'UDM', role: 'Subscriber data' },
  { nf: 'UDR', role: 'Subscriber repository' },
  { nf: 'PCF', role: 'Policy control' },
  { nf: 'NSSF', role: 'Network slicing' },
  { nf: 'BSF', role: 'Binding support' },
];

export type LinkState = 'configured' | 'down' | 'unknown';

export function linkState(
  processState: string | null | undefined,
  endpoint: string | null,
): LinkState {
  if (!endpoint) return 'unknown';
  if ((processState ?? '').toLowerCase() !== 'running') return 'down';
  return 'configured';
}

type NfPillState = { tone: 'success' | 'warning' | 'danger' | 'neutral'; title: string };

/** Resolve the dot colour + hover text for one NF pill. */
export function nfPillState(
  nfKey: string,
  observed: WireLabObserved | undefined,
): NfPillState {
  const explicit = observed?.nfs?.[nfKey];
  const aggregate = observed?.open5gs;
  // Prefer the explicit per-NF container when the backend ships it.
  const container: WireContainerStatus | undefined =
    explicit ?? (nfKey === 'AMF' ? aggregate : undefined);
  if (!container) {
    return {
      tone: 'neutral',
      title:
        `${nfKey}: not exposed by /lab.observed.nfs ` +
        '(backend publishes a per-NF map when open5gs is deployed as separate containers).',
    };
  }
  if (container.process_state === 'running' && container.health === 'healthy') {
    return { tone: 'success', title: `${nfKey}: running, healthy` };
  }
  if (container.process_state === 'running') {
    return { tone: 'warning', title: `${nfKey}: running, ${container.health}` };
  }
  return { tone: 'danger', title: `${nfKey}: ${container.process_state}, ${container.health}` };
}

export function TopologyPage() {
  const lab = useLabObserved();
  const nodes = useNodes();
  const ues = useUes();

  const observed = lab.data?.observed;
  const openCoreTone = topologyCoreTone(observed);

  const uesByNode = useMemo(() => {
    const map = new Map<string, UeState[]>();
    for (const ue of ues.data?.items ?? []) {
      const key = ue.serving_node ?? 'UNASSIGNED';
      const list = map.get(key) ?? [];
      list.push(ue);
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
        description="Core, radio and UEs as POLARIS reports them. Link colours: green = configured (process running + endpoint reported), gray = unknown (no endpoint reported), red = down (process not running). The UI never says 'UP' without proof."
        actions={
          <StatusIndicator
            state={openCoreTone.state}
            tone={openCoreTone.tone}
            label={openCoreTone.label}
          />
        }
      />

      {loading && <LoadingSkeleton label="Loading /lab + /nodes + /ues" />}
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
          <div className="ep-card p-4 overflow-x-auto">
            <div className="min-w-[720px] flex flex-col items-center gap-0">
              <CoreBlock observed={observed} />
              <GnbTree
                nodes={nodes.data?.items ?? []}
                uesByNode={uesByNode}
              />
            </div>
          </div>

          {nodes.data && nodes.data.items.length === 0 && (
            <EmptyState
              title="No node reported"
              description="/nodes returned an empty inventory."
            />
          )}

          <p className="text-ep-xs text-text-secondary">
            Each UE searches only for its serving gNB (<span className="mono">gnbSearchList</span>). UERANSIM has no
            handover. GNB-02 renders dashed because the backend reports it as not configured; ENB-01 uses the LTE
            interface labels (<span className="mono">S1-MME · S1AP</span>, <span className="mono">S1-U · GTP-U</span>)
            instead of N2/N3.
          </p>
        </section>
      )}
    </>
  );
}

function CoreBlock({ observed }: { observed: WireLabObserved | undefined }) {
  return (
    <article className="w-full max-w-3xl rounded-2xl border border-border bg-canvas/40 p-4" data-testid="topology-core-block">
      <header className="flex items-center justify-between gap-2 mb-3">
        <div className="flex items-center gap-2 min-w-0">
          <Cpu className="text-primary" width={18} height={18} />
          <div className="min-w-0">
            <p className="font-semibold">5G Core · Open5GS</p>
            <p className="mono text-ep-xs text-text-secondary truncate">
              PLMN 001/01 · DNN internet · observed from /lab
            </p>
          </div>
        </div>
      </header>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-2" data-testid="topology-nfs-grid">
        {CORE_NF_CATALOGUE.map((entry) => {
          const pill = nfPillState(entry.nf, observed);
          return (
            <div
              key={entry.nf}
              className="flex items-center gap-1.5 rounded-md border border-border bg-canvas px-2 py-1.5 min-w-0"
              title={pill.title}
              data-testid={`topology-nf-${entry.nf}`}
              data-tone={pill.tone}
            >
              <span className={`h-2 w-2 rounded-full shrink-0 ${toneDotClass(pill.tone)}`} />
              <div className="min-w-0">
                <p className="mono text-ep-sm font-medium truncate">{entry.nf}</p>
                <p className="text-[10px] text-text-secondary truncate">{entry.role}</p>
              </div>
            </div>
          );
        })}
      </div>
      <p className="text-ep-xs text-text-secondary mt-2 flex items-start gap-1">
        <AlertTriangle width={11} height={11} className="mt-0.5 shrink-0" />
        NFs without a per-container report in <code className="mono mx-1">/lab.observed.nfs</code> stay gray.
        AMF reflects <code className="mono mx-1">observed.open5gs</code> while the backend publishes a single
        aggregated container.
      </p>
    </article>
  );
}

function GnbTree({
  nodes,
  uesByNode,
}: {
  nodes: NodeItem[];
  uesByNode: Map<string, UeState[]>;
}) {
  if (nodes.length === 0) {
    return (
      <div className="mt-4 text-ep-xs text-text-secondary">
        No gNB reported by <code className="mono">/nodes</code>.
      </div>
    );
  }
  return (
    <div
      className={`mt-2 grid gap-x-6 gap-y-4 w-full max-w-3xl ${
        nodes.length === 1 ? 'grid-cols-1' : 'grid-cols-2'
      }`}
      data-testid="topology-gnb-tree"
    >
      {nodes.map((node) => (
        <GnbColumn
          key={node.id}
          node={node}
          attachedUes={uesByNode.get(node.id) ?? []}
        />
      ))}
    </div>
  );
}

function GnbColumn({ node, attachedUes }: { node: NodeItem; attachedUes: UeState[] }) {
  const isLte = node.technology === 'LTE';
  const controlLabel = isLte ? 'S1-MME · S1AP' : 'N2 · NGAP';
  const userLabel = isLte ? 'S1-U · GTP-U' : 'N3 · GTP-U';
  const controlState = linkState(node.process_state, node.n2_endpoint);
  const userState = linkState(node.process_state, node.n3_endpoint);
  return (
    <div className="flex flex-col items-center" data-testid={`topology-node-${node.id}`}>
      <div className="flex gap-6 items-stretch">
        <Connector label={controlLabel} state={controlState} />
        <Connector label={userLabel} state={userState} />
      </div>
      <article
        className={`w-full rounded-xl border bg-canvas p-3 flex flex-col gap-2 ${
          node.configured ? 'border-border' : 'border-dashed border-border'
        }`}
        data-testid={`topology-node-card-${node.id}`}
        data-dashed={node.configured ? 'false' : 'true'}
      >
        <header className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <Antenna className="text-primary" width={16} height={16} />
            <div className="min-w-0">
              <p className="mono font-semibold truncate">{node.id}</p>
              <p className="text-ep-xs text-text-secondary truncate">
                {node.technology} · {node.simulator}
              </p>
            </div>
          </div>
          <StatusIndicator state={node.process_state ?? 'UNKNOWN'} compact />
        </header>
        <dl className="grid grid-cols-2 gap-x-3 gap-y-0.5 text-ep-xs">
          <dt className="text-text-secondary">PLMN</dt>
          <dd className="mono">{node.plmn}</dd>
          <dt className="text-text-secondary">Cell</dt>
          <dd className="mono">{node.cell_id}</dd>
          <dt className="text-text-secondary">Link IP</dt>
          <dd className="mono truncate">{node.link_ip}</dd>
        </dl>
        {!node.controller_owned && (
          <p className="text-ep-xs text-warning flex items-start gap-1">
            <AlertTriangle width={11} height={11} className="mt-0.5 shrink-0" />
            {node.actions.reason || 'Not controller-owned'}
          </p>
        )}
      </article>

      <VerticalSegment state={attachedUes.length > 0 ? 'configured' : 'unknown'} />

      <div className="w-full grid grid-cols-1 sm:grid-cols-2 gap-2" data-testid={`topology-ues-${node.id}`}>
        {attachedUes.length === 0 ? (
          <p className="col-span-2 text-ep-xs text-center text-text-secondary border border-dashed border-border rounded-md py-2">
            No UE attached
          </p>
        ) : (
          attachedUes.map((ue) => <UeMiniCard key={ue.id} ue={ue} />)
        )}
      </div>
    </div>
  );
}

/**
 * 0.7.1 — Compact UE card rendered under each gNB. Fields come straight
 * from `/ues` (`UeState`): id, registration_state, pdu_session, ue_ip.
 * No field is fabricated when `/ues` doesn't report it — the UI shows
 * an em-dash instead.
 */
function UeMiniCard({ ue }: { ue: UeState }) {
  const regTone = regTonePill(ue.registration_state);
  const pduActive = (ue.pdu_session ?? '').toUpperCase() === 'ACTIVE';
  return (
    <div
      className="rounded-lg border border-border bg-canvas p-2 flex flex-col gap-1"
      data-testid={`topology-ue-${ue.id}`}
      data-registration={ue.registration_state}
      data-pdu={ue.pdu_session}
    >
      <div className="flex items-center gap-1.5">
        <Smartphone width={13} height={13} className="text-primary shrink-0" />
        <span className="mono text-ep-sm font-medium truncate">{ue.id}</span>
      </div>
      <div className="flex flex-wrap gap-1 text-[10px]">
        <span className={`ep-badge ${regTone}`} data-testid={`topology-ue-${ue.id}-reg`}>
          {ue.registration_state || 'UNKNOWN'}
        </span>
        {pduActive && (
          <span className="ep-badge bg-success/15 text-success" data-testid={`topology-ue-${ue.id}-pdu`}>
            PDU
          </span>
        )}
      </div>
      <p className="mono text-[10px] text-text-secondary truncate" data-testid={`topology-ue-${ue.id}-ip`}>
        {ue.ue_ip ?? '—'}
      </p>
    </div>
  );
}

function regTonePill(state: string | null | undefined): string {
  const s = (state ?? '').toUpperCase();
  if (s === 'REGISTERED') return 'bg-success/15 text-success';
  if (s === 'STOPPED' || s === 'DEREGISTERED' || s === 'FAILED') return 'bg-error/15 text-error';
  return 'bg-canvas text-text-secondary border border-border';
}

/**
 * Vertical trace line + label used between the Core block and each gNB
 * card. The connector carries the link state via the colour of the two
 * vertical segments and the text badge in the middle.
 */
function Connector({ label, state }: { label: string; state: LinkState }) {
  const barClass = toneBarClass(state);
  const badgeClass = toneBadgeClass(state);
  return (
    <div
      className="flex flex-col items-center py-0.5"
      aria-label={`${label} ${state}`}
      data-testid={`topology-link-${label}`}
      data-state={state}
    >
      <div className={`w-0.5 h-5 ${barClass}`} />
      <span className={`mono text-[10px] px-1.5 py-0.5 rounded ${badgeClass}`}>{label}</span>
      <div className={`w-0.5 h-5 ${barClass}`} />
    </div>
  );
}

function VerticalSegment({ state }: { state: LinkState }) {
  return <div className={`w-0.5 h-5 ${toneBarClass(state)}`} />;
}

function toneBarClass(state: LinkState): string {
  if (state === 'configured') return 'bg-success';
  if (state === 'down') return 'bg-error';
  return 'bg-border';
}

function toneBadgeClass(state: LinkState): string {
  if (state === 'configured') return 'bg-success/15 text-success';
  if (state === 'down') return 'bg-error/15 text-error';
  return 'bg-canvas text-text-secondary border border-border';
}

function toneDotClass(tone: 'success' | 'warning' | 'danger' | 'neutral'): string {
  if (tone === 'success') return 'bg-success';
  if (tone === 'warning') return 'bg-warning';
  if (tone === 'danger') return 'bg-error';
  return 'bg-text-secondary/40';
}

function topologyCoreTone(observed: WireLabObserved | undefined): {
  state: string;
  tone: 'success' | 'warning' | 'danger' | 'neutral';
  label: string;
} {
  const map = observed?.nfs;
  if (map && Object.keys(map).length > 0) {
    const total = Object.keys(map).length;
    const up = Object.values(map).filter(
      (c) => c.process_state === 'running' && c.health === 'healthy',
    ).length;
    const tone = up === total ? 'success' : up > 0 ? 'warning' : 'danger';
    return {
      state: `${up}/${total}`,
      tone,
      label: `Core NFs: ${up}/${total} running + healthy (from /lab.observed.nfs)`,
    };
  }
  const open = observed?.open5gs;
  if (!open) {
    return {
      state: 'UNKNOWN',
      tone: 'neutral',
      label: 'AMF container: not reported by /lab',
    };
  }
  const tone =
    open.process_state === 'running' && open.health === 'healthy'
      ? 'success'
      : open.process_state === 'running'
        ? 'warning'
        : 'danger';
  return {
    state: `${open.process_state}/${open.health}`,
    tone,
    label: `AMF container: ${open.process_state}, ${open.health}`,
  };
}
