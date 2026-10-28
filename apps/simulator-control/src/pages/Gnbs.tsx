import { Lock, Plus } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import { StatusIndicator } from '@/ui/StatusIndicator';
import { EmptyState, ErrorState, LoadingSkeleton } from '@/ui/EmptyErrorLoading';
import { useNodes, useUes } from '@/data/queries';
import type { NodeItem } from '@/data/polarisTypes';

// Reasons mirror POLARIS /nodes `actions.reason` payload. The UI never
// invents a reason — it reads whatever the backend reports and badges
// it visibly next to the locked action button.
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
        description="UERANSIM gNodeBs (and the LTE eNB plan). The UI only exposes POLARIS /nodes and /gnbs — no live start/stop is attempted, and reasons shown next to Add/Start/Stop come straight from the backend action payload."
        actions={
          <button
            type="button"
            className="ep-button ep-button-sm"
            disabled
            aria-disabled="true"
            title="gNB creation ships in V1.1 — the UI never fabricates a success."
            data-testid="gnb-add-locked"
          >
            <Lock width={13} height={13} /> <Plus width={13} height={13} /> Add gNodeB
          </button>
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

      {nodes.data && gnbs.length === 0 && (
        <EmptyState title="No gNodeB" description="POLARIS /nodes did not return any 5G node." />
      )}

      {gnbs.length > 0 && (
        <section className="grid gap-4 lg:grid-cols-2 mb-4" data-testid="gnbs-grid">
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
          <div className="grid gap-4 lg:grid-cols-2">
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
  const certifiedBadgeTone = node.technology.includes('5G')
    ? node.controller_owned
      ? 'success'
      : 'warning'
    : 'warning';

  return (
    <article
      className={`ep-card p-4 flex flex-col gap-3 ${isPlanned ? 'border-dashed' : ''}`}
      data-testid={`gnb-card-${node.id}`}
    >
      <header className="flex items-start justify-between gap-3">
        <div>
          <h3 className="mono text-ep-lg font-semibold">{node.id}</h3>
          <p className="text-ep-xs text-text-secondary">
            {node.technology} · {node.simulator} · {node.name}
          </p>
        </div>
        <div className="flex flex-col items-end gap-1">
          <StatusIndicator state={node.process_state ?? 'UNKNOWN'} compact />
          <StatusIndicator
            state={node.controller_owned ? 'controller-owned' : reason || 'shared'}
            tone={certifiedBadgeTone}
            compact
          />
        </div>
      </header>

      <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-ep-sm">
        <dt className="text-text-secondary">PLMN</dt>
        <dd className="mono">{node.plmn}</dd>
        <dt className="text-text-secondary">Cell ID</dt>
        <dd className="mono">{node.cell_id}</dd>
        <dt className="text-text-secondary">Link IP</dt>
        <dd className="mono">{node.link_ip}</dd>
        <dt className="text-text-secondary">N2 endpoint</dt>
        <dd className="mono">{node.n2_endpoint ?? '—'}</dd>
        <dt className="text-text-secondary">N3 endpoint</dt>
        <dd className="mono">{node.n3_endpoint ?? '—'}</dd>
        <dt className="text-text-secondary">UEs attached</dt>
        <dd className="mono">
          {attachedUes.length === 0 ? '—' : attachedUes.join(', ')}
        </dd>
      </dl>

      {reason && (
        <p
          className="ep-badge border-warning/40 text-warning self-start"
          data-testid={`gnb-reason-${node.id}`}
        >
          {reason}
        </p>
      )}
      {reason && friendlyReason !== reason && (
        <p className="text-ep-xs text-text-secondary">{friendlyReason}</p>
      )}

      <footer className="flex items-center justify-end gap-2 border-t border-border pt-3">
        {isActive ? (
          <button
            type="button"
            className="ep-button ep-button-sm"
            disabled
            aria-disabled="true"
            title="Stopping GNB-01 detaches every UE on it; ships with explicit confirmation in V1.1."
            data-testid={`gnb-stop-${node.id}`}
          >
            <Lock width={13} height={13} /> Stop gNB
          </button>
        ) : legacy ? (
          <button
            type="button"
            className="ep-button ep-button-sm"
            disabled
            aria-disabled="true"
            title="LTE attach is not certified on this lab."
            data-testid={`gnb-start-${node.id}`}
          >
            <Lock width={13} height={13} /> Start eNB
          </button>
        ) : (
          <button
            type="button"
            className="ep-button ep-button-sm"
            disabled
            aria-disabled="true"
            title={friendlyReason || 'Backend does not expose a start action for this node.'}
            data-testid={`gnb-deploy-${node.id}`}
          >
            <Lock width={13} height={13} /> Deploy and start
          </button>
        )}
      </footer>
    </article>
  );
}

function countAttached(items: NonNullable<ReturnType<typeof useUes>['data']>['items'] | undefined, nodeId: string): string[] {
  return (items ?? []).filter((ue) => ue.serving_node === nodeId).map((ue) => ue.id);
}
