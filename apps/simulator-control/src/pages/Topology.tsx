// 0.12.0 — Topology redrawn against docs/ui-mockups/polaris-control.html.
// Preserves the "three honest link states" model from 0.7.0 but swaps the
// surface into the mockup primitives (Card / Pill / PageHeader) and drops
// the PROTECTED footer on UE mini-cards (mockup never renders identity).
//
// Shape:
//   ┌─ 5G Core · Open5GS 2.8.0 ──────────────────────────┐
//   │   grid of all NF pills with their state dot        │
//   └────────────────────────────────────────────────────┘
//            │ N2 · NGAP           │ N3 · GTP-U
//        ┌───┴────┐            ┌───┴────┐
//        │ GNB-01 │ live        │ GNB-02 │ dashed
//        └───┬────┘            └───┬────┘
//            │                     │
//        ┌───┴───┐             ┌───┴───┐
//        │ UE-01 │             │ UE-14 │
//        │ UE-12 │
//        └───────┘
//
// Line colour mapping — single source of truth is `linkState`:
//     configured → ok    (green)
//     down       → bad   (red)
//     unknown    → mute  (gray)

import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, Antenna, Smartphone } from 'lucide-react';
import { Card, PageHeader, Pill, regTone } from '@/components/mockup';
import { EmptyState, ErrorState, LoadingSkeleton } from '@/ui/EmptyErrorLoading';
import {
  useLabObserved,
  useNodes,
  useUes,
  type WireContainerStatus,
  type WireLabObserved,
} from '@/data/queries';
import type { NodeItem, UeState } from '@/data/polarisTypes';

const CORE_VERSION = 'Open5GS 2.8.0';

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

type NfPillTone = 'success' | 'warning' | 'danger' | 'neutral';
type NfPillState = { tone: NfPillTone; title: string };

export function nfPillState(
  nfKey: string,
  observed: WireLabObserved | undefined,
): NfPillState {
  const explicit = observed?.nfs?.[nfKey];
  const aggregate = observed?.open5gs;
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
  const coreTone = topologyCoreTone(observed);

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

  // Aggregate N2/N3 state across all configured 5G gNBs.
  const nodeList = nodes.data?.items ?? [];
  const anyLinkUp = nodeList.some(
    (n) =>
      linkState(n.process_state, n.n2_endpoint) === 'configured' ||
      linkState(n.process_state, n.n3_endpoint) === 'configured',
  );

  return (
    <>
      <PageHeader
        eyebrow="Network"
        title="Topology"
        desc="Core, radio and UEs as they are wired now. Links show the live state of each interface."
        actions={
          <div className="flex flex-wrap gap-2">
            <Pill tone={anyLinkUp ? 'ok' : 'mute'} dot={anyLinkUp ? 'live' : undefined}>
              {anyLinkUp ? 'N2 / N3 up' : 'N2 / N3 unknown'}
            </Pill>
            <Pill tone="mute">No mobility (UERANSIM)</Pill>
          </div>
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
        <>
          <Card className="p-5 overflow-x-auto">
            <div className="min-w-[680px] flex flex-col items-center gap-0" data-testid="topology-view">
              <CoreBlock observed={observed} coreLabel={coreTone.label} />
              <GnbTree nodes={nodeList} uesByNode={uesByNode} />
            </div>
          </Card>

          {nodes.data && nodes.data.items.length === 0 && (
            <EmptyState title="No node reported" description="/nodes returned an empty inventory." />
          )}

          <p className="text-ep-sm text-mute">
            Each UE searches only for its serving gNB (<span className="mono">gnbSearchList</span>). UERANSIM
            has no handover, so a UE stays on its gNB.
          </p>
        </>
      )}
    </>
  );
}

function CoreBlock({
  observed,
  coreLabel,
}: {
  observed: WireLabObserved | undefined;
  coreLabel: string;
}) {
  return (
    <article className="w-full max-w-3xl rounded-2xl border border-line bg-canvas p-4" data-testid="topology-core-block">
      <header className="flex items-center justify-between gap-2 mb-3">
        <p className="font-semibold">5G Core · {CORE_VERSION}</p>
        <span className="mono text-ep-sm text-mute truncate">
          PLMN 001/01 · S-NSSAI 1/010203 · DNN internet
        </span>
      </header>
      <p className="text-ep-xs text-mute mb-2" data-testid="topology-core-status">
        {coreLabel}
      </p>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-2" data-testid="topology-nfs-grid">
        {CORE_NF_CATALOGUE.map((entry) => {
          const pill = nfPillState(entry.nf, observed);
          return (
            <div
              key={entry.nf}
              className="flex items-center gap-1.5 rounded-md border border-line bg-surface px-2 py-1.5 min-w-0"
              title={pill.title}
              data-testid={`topology-nf-${entry.nf}`}
              data-tone={pill.tone}
            >
              <span className={`h-2 w-2 rounded-full shrink-0 ${toneDotClass(pill.tone)}`} />
              <div className="min-w-0">
                <p className="mono text-ep-sm font-medium truncate">{entry.nf}</p>
                <p className="text-[10px] text-mute truncate">{entry.role}</p>
              </div>
            </div>
          );
        })}
      </div>
      <p className="text-ep-xs text-mute mt-2 flex items-start gap-1">
        <AlertTriangle width={11} height={11} className="mt-0.5 shrink-0" />
        NFs without a per-container report in <code className="mono mx-1">/lab.observed.nfs</code> stay gray.
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
      <div className="mt-4 text-ep-sm text-mute">
        No gNB reported by <code className="mono">/nodes</code>.
      </div>
    );
  }
  return (
    <div
      className={`mt-2 grid gap-x-16 gap-y-4 w-full max-w-3xl ${
        nodes.length === 1 ? 'grid-cols-1' : 'grid-cols-2'
      }`}
      data-testid="topology-gnb-tree"
    >
      {nodes.map((node) => (
        <GnbColumn key={node.id} node={node} attachedUes={uesByNode.get(node.id) ?? []} />
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
  const running = (node.process_state ?? '').toLowerCase() === 'running';
  const stateLabel = running ? 'ACTIVE' : node.configured ? node.process_state : 'PLANNED';

  return (
    <div className="flex flex-col items-center" data-testid={`topology-node-${node.id}`}>
      <div className="flex gap-6 items-stretch">
        <Connector label={controlLabel} state={controlState} />
        <Connector label={userLabel} state={userState} />
      </div>
      <article
        className={`w-full rounded-xl border bg-surface p-3 flex flex-col gap-2 shadow-e1 ${
          node.configured ? 'border-line' : 'border-dashed border-line'
        }`}
        data-testid={`topology-node-card-${node.id}`}
        data-dashed={node.configured ? 'false' : 'true'}
      >
        <header className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <span className={`grid place-items-center h-8 w-8 rounded-lg ${running ? 'bg-ok-soft text-ok' : 'bg-brand-soft text-brand'}`}>
              <Antenna width={16} height={16} aria-hidden />
            </span>
            <div className="min-w-0">
              <p className="mono font-semibold truncate">{node.id}</p>
              <p className="mono text-ep-xs text-mute truncate">
                link {node.link_ip} · {isLte ? 'eUTRAN' : 'NR'}
              </p>
            </div>
          </div>
        </header>
        <div className="flex flex-wrap gap-1.5">
          <Pill tone={regTone(stateLabel)} dot={running ? 'live' : undefined}>
            {stateLabel}
          </Pill>
          {!node.controller_owned && node.actions.reason && (
            <Pill tone="mute">{node.actions.reason}</Pill>
          )}
        </div>
      </article>

      <VerticalSegment state={attachedUes.length > 0 ? 'configured' : 'unknown'} />

      <div className="w-full grid grid-cols-1 sm:grid-cols-2 gap-2" data-testid={`topology-ues-${node.id}`}>
        {attachedUes.length === 0 ? (
          <p className="col-span-2 text-ep-sm text-center text-mute border border-dashed border-line rounded-md py-2">
            No UE attached
          </p>
        ) : (
          attachedUes.map((ue) => <UeMiniCard key={ue.id} ue={ue} />)
        )}
      </div>
    </div>
  );
}

function UeMiniCard({ ue }: { ue: UeState }) {
  const pduActive = (ue.pdu_session ?? '').toUpperCase() === 'ACTIVE';
  const regState = (ue.registration_state ?? 'UNKNOWN').toUpperCase();
  return (
    <Link
      to={`/ues/${encodeURIComponent(ue.id)}/activity`}
      className="rounded-lg border border-line bg-surface p-2 flex flex-col gap-1 hover:border-brand focus:outline-none focus:ring-2 focus:ring-brand/40"
      data-testid={`topology-ue-${ue.id}`}
      data-registration={ue.registration_state}
      data-pdu={ue.pdu_session}
    >
      <div className="flex items-center gap-1.5">
        <Smartphone width={14} height={14} className="text-mute shrink-0" />
        <span className="mono text-ep-sm font-medium truncate">{ue.id}</span>
      </div>
      <div className="flex flex-wrap gap-1">
        <Pill tone={regTone(regState)}>
          <span data-testid={`topology-ue-${ue.id}-reg`}>{regState}</span>
        </Pill>
        {pduActive && (
          <Pill tone="ok">
            <span data-testid={`topology-ue-${ue.id}-pdu`}>PDU</span>
          </Pill>
        )}
      </div>
      <p className="mono text-[10px] text-mute truncate" data-testid={`topology-ue-${ue.id}-ip`}>
        {ue.ue_ip ?? '—'}
      </p>
    </Link>
  );
}

function Connector({ label, state }: { label: string; state: LinkState }) {
  const barClass = toneBarClass(state);
  const badgeClass = toneBadgeClass(state);
  return (
    <div
      className="flex flex-col items-center py-1"
      aria-label={`${label} ${state}`}
      data-testid={`topology-link-${label}`}
      data-state={state}
    >
      <div className={`w-0.5 h-6 ${barClass}`} />
      <span className={`mono text-ep-xs px-1.5 rounded ${badgeClass}`}>{label}</span>
      <div className={`w-0.5 h-6 ${barClass}`} />
    </div>
  );
}

function VerticalSegment({ state }: { state: LinkState }) {
  return <div className={`w-0.5 h-6 ${toneBarClass(state)}`} />;
}

function toneBarClass(state: LinkState): string {
  if (state === 'configured') return 'bg-ok';
  if (state === 'down') return 'bg-bad';
  return 'bg-line';
}

function toneBadgeClass(state: LinkState): string {
  if (state === 'configured') return 'text-ok bg-ok-soft';
  if (state === 'down') return 'text-bad bg-bad-soft';
  return 'text-mute bg-track';
}

function toneDotClass(tone: NfPillTone): string {
  if (tone === 'success') return 'bg-ok';
  if (tone === 'warning') return 'bg-warn';
  if (tone === 'danger') return 'bg-bad';
  return 'bg-mute';
}

function topologyCoreTone(observed: WireLabObserved | undefined): { label: string } {
  const map = observed?.nfs;
  if (map && Object.keys(map).length > 0) {
    const total = Object.keys(map).length;
    const up = Object.values(map).filter(
      (c) => c.process_state === 'running' && c.health === 'healthy',
    ).length;
    return {
      label: `Core NFs: ${up}/${total} running + healthy (from /lab.observed.nfs)`,
    };
  }
  const open = observed?.open5gs;
  if (!open) return { label: 'AMF container: not reported by /lab' };
  return { label: `AMF container: ${open.process_state}, ${open.health}` };
}
