import { Antenna, Plus } from 'lucide-react';
import { Card, Locked, PageHeader, Pill, regTone } from '@/components/mockup';
import { EmptyState, ErrorState, LoadingSkeleton } from '@/ui/EmptyErrorLoading';
import { useNodes, useUes } from '@/data/queries';
import type { NodeItem } from '@/data/polarisTypes';
import { LteControlPanel } from '@/components/LteControlPanel';

const KNOWN_LOCK_REASONS: Record<string, string> = {
  LIVE_005_APPROVAL_REQUIRED: 'Multi-gNB execution locked until LIVE-005 approval.',
  LTE_ATTACH_NOT_CERTIFIED: 'LTE attach not certified on this lab (eNB stays read-only).',
  SHARED_NODE_PROTECTED: 'Shared node — protected against operator start/stop.',
};

export function GnbsPage() {
  const nodes = useNodes();
  const ues = useUes();

  const gnbs = (nodes.data?.items ?? []).filter((node) => node.technology.includes('5G'));
  const enbs = (nodes.data?.items ?? []).filter((node) => node.technology === 'LTE');

  return (
    <>
      <PageHeader
        eyebrow="Network"
        title="gNodeBs"
        desc="UERANSIM gNodeBs connected to the core. A UE profile names its serving gNB; the controller writes it into the UE's gnbSearchList."
        actions={
          <Locked reason="gNB creation ships in V1.1" data-testid="gnb-add-locked">
            <Plus width={13} height={13} /> Add gNodeB
          </Locked>
        }
      />

      {nodes.isLoading && <LoadingSkeleton label="Loading /nodes" />}
      {nodes.error && (
        <ErrorState
          title="Could not load /nodes"
          detail={(nodes.error as Error).message}
          onRetry={() => void nodes.refetch()}
        />
      )}

      {nodes.data && gnbs.length === 0 && enbs.length === 0 && (
        <EmptyState title="No gNodeB" description="POLARIS /nodes did not return any 5G node." />
      )}

      {gnbs.length > 0 && (
        <section className="grid gap-5 lg:grid-cols-2" data-testid="gnbs-grid">
          {gnbs.map((node) => (
            <GnbCard
              key={node.id}
              node={node}
              attachedUes={countAttached(ues.data?.items, node.id)}
            />
          ))}
        </section>
      )}

      {enbs.length > 0 && (
        <section className="flex flex-col gap-3" data-testid="enbs-grid">
          <h2 className="text-ep-md font-semibold">LTE profile (not certified)</h2>
          <LteControlPanel compact />
          <div className="grid gap-5 lg:grid-cols-2">
            {enbs.map((node) => (
              <GnbCard
                key={node.id}
                node={node}
                attachedUes={countAttached(ues.data?.items, node.id)}
                legacy
              />
            ))}
          </div>
        </section>
      )}
    </>
  );
}

function GnbCard({
  node,
  attachedUes,
  legacy,
}: {
  node: NodeItem;
  attachedUes: string[];
  legacy?: boolean;
}) {
  const isActive = node.process_state === 'running';
  const isPlanned = node.process_state === 'NOT_DEPLOYED' || !node.configured;
  const reason = node.actions.reason || '';
  const friendlyReason = KNOWN_LOCK_REASONS[reason] ?? reason;
  const stateLabel = isActive ? 'ACTIVE' : isPlanned ? 'PLANNED' : (node.process_state ?? 'UNKNOWN').toUpperCase();
  const ngSetup = isActive && node.n2_endpoint ? 'SUCCESS' : '—';

  return (
    <Card
      className={`p-5 flex flex-col gap-4 ${isPlanned ? 'border-dashed' : ''}`}
      data-testid={`gnb-card-${node.id}`}
    >
      <header className="flex flex-wrap items-start justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="grid place-items-center h-9 w-9 rounded-lg bg-brand-soft text-brand">
            <Antenna width={18} height={18} aria-hidden />
          </span>
          <div className="min-w-0">
            <h2 className="mono text-ep-xl font-semibold">{node.id}</h2>
            <p className="text-ep-sm text-mute truncate">
              {node.simulator} · {node.technology}
            </p>
          </div>
        </div>
        <div className="flex flex-wrap gap-1.5">
          <Pill tone={regTone(stateLabel)} dot={isActive ? 'live' : undefined}>
            {stateLabel}
          </Pill>
          {node.controller_owned ? (
            <Pill tone="ok">Live certified</Pill>
          ) : (
            <Pill tone="mute">Not certified</Pill>
          )}
        </div>
      </header>

      <dl className="grid grid-cols-2 sm:grid-cols-3 gap-x-4 gap-y-3 text-ep-md">
        <div>
          <dt className="text-ep-xs uppercase tracking-wider text-mute">PLMN · TAC</dt>
          <dd className="mono">{node.plmn} · 200</dd>
        </div>
        <div>
          <dt className="text-ep-xs uppercase tracking-wider text-mute">Link IP</dt>
          <dd className="mono">{node.link_ip}</dd>
        </div>
        <div>
          <dt className="text-ep-xs uppercase tracking-wider text-mute">NGAP IP</dt>
          <dd className="mono">{node.n2_endpoint ?? '—'}</dd>
        </div>
        <div>
          <dt className="text-ep-xs uppercase tracking-wider text-mute">GTP-U IP</dt>
          <dd className="mono">{node.n3_endpoint ?? '—'}</dd>
        </div>
        <div>
          <dt className="text-ep-xs uppercase tracking-wider text-mute">NG Setup</dt>
          <dd>
            {ngSetup === 'SUCCESS' ? <Pill tone="ok">SUCCESS</Pill> : <span className="mono">—</span>}
          </dd>
        </div>
        <div>
          <dt className="text-ep-xs uppercase tracking-wider text-mute">UEs attached</dt>
          <dd className="mono">{attachedUes.length === 0 ? '—' : attachedUes.join(', ')}</dd>
        </div>
      </dl>

      {reason && (
        <p className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-ep-xs font-semibold tracking-wide bg-warn-soft text-warn self-start" data-testid={`gnb-reason-${node.id}`}>
          {reason}
        </p>
      )}
      {reason && friendlyReason !== reason && (
        <p className="text-ep-sm text-mute">{friendlyReason}</p>
      )}

      <footer className="flex items-center justify-end gap-2 border-t border-line pt-3">
        {isActive ? (
          <Locked
            reason="Stopping GNB-01 detaches every UE on it; ships with confirmation in V1.1"
            data-testid={`gnb-stop-${node.id}`}
          >
            Stop gNB
          </Locked>
        ) : legacy ? (
          <Locked
            reason="LTE attach is not certified on this lab."
            data-testid={`gnb-start-${node.id}`}
          >
            Start eNB
          </Locked>
        ) : (
          <div className="flex flex-wrap items-center gap-2">
            <Locked
              reason={friendlyReason || 'Backend does not expose a start action for this node.'}
              data-testid={`gnb-deploy-${node.id}`}
            >
              Deploy and start
            </Locked>
            <span className="text-ep-sm text-mute">Reserved addresses from the gNB audit; recheck before deploy.</span>
          </div>
        )}
      </footer>
    </Card>
  );
}

function countAttached(
  items: NonNullable<ReturnType<typeof useUes>['data']>['items'] | undefined,
  nodeId: string,
): string[] {
  return (items ?? []).filter((ue) => ue.serving_node === nodeId).map((ue) => ue.id);
}
