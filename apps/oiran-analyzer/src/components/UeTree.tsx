import { useMemo, useState } from 'react';
import {
  ChevronDown,
  ChevronRight,
  Smartphone,
  Workflow,
  Share2,
  Network,
  FileSearch,
} from 'lucide-react';
import clsx from 'clsx';
import { EvidenceBadge } from '@/ui/EvidenceBadge';
import type {
  HierarchyPduSession,
  HierarchyUe,
} from '@/analyzer/hierarchy';

type Selection = { kind: 'session'; sessionId: string } | null;

export function UeTree({
  hierarchy,
  unknownPdus,
  selection,
  onSelect,
  search,
}: {
  hierarchy: HierarchyUe[];
  unknownPdus: HierarchyPduSession[];
  selection: Selection;
  onSelect: (selection: Selection) => void;
  search: string;
}) {
  const [open, setOpen] = useState<Record<string, boolean>>({});

  const filtered = useMemo(() => {
    if (!search) return hierarchy;
    const needle = search.toLowerCase();
    return hierarchy.filter((ue) => {
      if (ue.context.ue_pseudonym.toLowerCase().includes(needle)) return true;
      if (ue.context.ue_context_id.toLowerCase().includes(needle)) return true;
      return ue.pduSessions.some((pdu) =>
        [
          pdu.session.session_id,
          pdu.pduSessionId,
          pdu.session.procedure,
          ...pdu.pfcpSeids,
          ...pdu.gtpuTeids,
        ]
          .join(' ')
          .toLowerCase()
          .includes(needle),
      );
    });
  }, [hierarchy, search]);

  const toggle = (id: string) =>
    setOpen((prev) => ({ ...prev, [id]: !(prev[id] ?? true) }));
  const isOpen = (id: string) => open[id] ?? true;

  return (
    <div className="flex flex-col gap-1 text-ep-sm" data-testid="ue-tree">
      {filtered.map((ue) => (
        <div key={ue.ueContextId} className="flex flex-col">
          <button
            type="button"
            className="flex items-center gap-1.5 py-1 px-1 rounded hover:bg-canvas text-left"
            onClick={() => toggle(ue.ueContextId)}
            aria-expanded={isOpen(ue.ueContextId)}
            data-testid={`ue-row-${ue.ueContextId}`}
          >
            {isOpen(ue.ueContextId) ? (
              <ChevronDown width={12} height={12} />
            ) : (
              <ChevronRight width={12} height={12} />
            )}
            <Smartphone width={14} height={14} className="text-primary" />
            <span className="font-medium truncate">
              {ue.context.ue_pseudonym || ue.context.ue_context_id}
            </span>
            <span className="text-ep-xs text-text-secondary ml-auto">
              {ue.pduSessions.length} PDU
            </span>
          </button>
          {isOpen(ue.ueContextId) && (
            <div className="flex flex-col ml-5 border-l border-border pl-2 gap-1 my-1">
              <div
                className="flex items-center gap-1.5 text-ep-xs text-text-secondary py-1"
                title="Mobility and NAS events live under the UE context; counts come from the backend-reported message_count on each PDU session."
              >
                <Workflow width={12} height={12} />
                Registration / Mobility / NAS
              </div>
              {ue.pduSessions.map((pdu) => (
                <PduNode
                  key={pdu.session.session_id}
                  pdu={pdu}
                  selected={selection?.sessionId === pdu.session.session_id}
                  onSelect={onSelect}
                />
              ))}
            </div>
          )}
        </div>
      ))}

      {unknownPdus.length > 0 && (
        <div className="mt-3 border-t border-border pt-3">
          <p className="text-ep-xs uppercase tracking-wider text-text-secondary mb-1">
            Unknown UE context
          </p>
          <p className="text-ep-xs text-text-secondary mb-2">
            Sessions whose backend-reported <code className="mono">ue_context_id</code>
            {' '}does not resolve to a known UE context are kept in their own
            bucket. They are never merged into another UE.
          </p>
          <div className="flex flex-col gap-1">
            {unknownPdus.map((pdu) => (
              <PduNode
                key={pdu.session.session_id}
                pdu={pdu}
                selected={selection?.sessionId === pdu.session.session_id}
                onSelect={onSelect}
              />
            ))}
          </div>
        </div>
      )}

      {filtered.length === 0 && unknownPdus.length === 0 && (
        <p className="text-ep-xs text-text-secondary">
          No UE context matches the current search / dataset selection.
        </p>
      )}
    </div>
  );
}

function PduNode({
  pdu,
  selected,
  onSelect,
}: {
  pdu: HierarchyPduSession;
  selected: boolean;
  onSelect: (s: Selection) => void;
}) {
  return (
    <button
      type="button"
      className={clsx(
        'flex items-start gap-1.5 py-1 px-1 rounded text-left hover:bg-canvas',
        selected && 'bg-canvas',
      )}
      onClick={() =>
        onSelect({ kind: 'session', sessionId: pdu.session.session_id })
      }
      data-selected={selected}
      data-testid={`pdu-row-${pdu.session.session_id}`}
    >
      <Share2 width={12} height={12} className="mt-0.5 text-text-secondary shrink-0" />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <span className="font-medium">PDU {pdu.pduSessionId}</span>
          <EvidenceBadge confidence={pdu.correlation} compact />
        </div>
        <div className="text-ep-xs text-text-secondary flex items-center gap-2 mt-0.5 flex-wrap">
          <span className="inline-flex items-center gap-1">
            <Network width={10} height={10} />
            {pdu.interfaces.join(' + ') || '—'}
          </span>
          {pdu.pfcpSeids.length > 0 && (
            <span>
              PFCP: <span className="mono">{pdu.pfcpSeids.length}</span>
            </span>
          )}
          {pdu.gtpuTeids.length > 0 && (
            <span>
              GTP-U: <span className="mono">{pdu.gtpuTeids.length}</span>
            </span>
          )}
          {pdu.flows.length > 0 && (
            <span className="inline-flex items-center gap-1">
              <FileSearch width={10} height={10} />
              {pdu.flows.length} flows
            </span>
          )}
        </div>
      </div>
    </button>
  );
}
