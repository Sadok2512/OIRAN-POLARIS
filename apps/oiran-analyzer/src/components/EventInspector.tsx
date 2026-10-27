import { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import type { CallFlowEvent, InformationElement } from '@shared/types';
import { EvidenceBadge } from '@/ui/EvidenceBadge';
import { isoToLocal } from '@/data/format';

export function EventInspector({
  event,
  onClose,
}: {
  event: CallFlowEvent | null;
  onClose: () => void;
}) {
  if (!event) {
    return (
      <aside
        className="ep-card p-5 text-ep-sm text-text-secondary"
        data-testid="event-inspector-empty"
      >
        <p>
          Select a signaling message in the Call Flow or a packet event in
          the Session Explorer to inspect its decoded content.
        </p>
      </aside>
    );
  }
  return (
    <aside
      className="ep-card p-4 flex flex-col gap-3"
      aria-label="Event inspector"
      data-testid="event-inspector"
    >
      <header className="flex items-start justify-between gap-2">
        <div>
          <p className="text-ep-xs uppercase tracking-wider text-text-secondary">
            Decoded message
          </p>
          <h3 className="text-ep-lg font-semibold">{event.message_name}</h3>
          <p className="text-ep-xs text-text-secondary mono">
            {event.interface} · {event.protocol}
          </p>
        </div>
        <button
          type="button"
          className="ep-button ep-button-sm"
          onClick={onClose}
          aria-label="Close inspector"
        >
          Close
        </button>
      </header>

      <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-ep-sm">
        <dt className="text-text-secondary">Timestamp</dt>
        <dd>{isoToLocal(event.timestamp)}</dd>
        <dt className="text-text-secondary">Direction</dt>
        <dd>{event.direction}</dd>
        <dt className="text-text-secondary">Source</dt>
        <dd className="mono text-ep-xs">{event.source_participant}</dd>
        <dt className="text-text-secondary">Destination</dt>
        <dd className="mono text-ep-xs">{event.destination_participant}</dd>
        <dt className="text-text-secondary">Procedure</dt>
        <dd>{event.procedure_group}</dd>
        <dt className="text-text-secondary">Semantic</dt>
        <dd>{event.semantic_status}</dd>
        <dt className="text-text-secondary">Decode status</dt>
        <dd>{event.decoding_status}</dd>
        <dt className="text-text-secondary">Decoder</dt>
        <dd>
          {event.decoder_name} <span className="text-ep-xs text-text-secondary">v{event.decoder_version}</span>
        </dd>
      </dl>

      <section>
        <h4 className="text-ep-sm font-semibold mb-1">
          Information Element tree
        </h4>
        {event.decoded_ie_tree.length ? (
          <div className="border border-border rounded-md max-h-80 overflow-y-auto">
            <IeTree nodes={event.decoded_ie_tree} />
          </div>
        ) : (
          <p className="text-ep-xs text-text-secondary">
            Backend did not return a decoded IE tree for this event.
          </p>
        )}
      </section>

      <section>
        <h4 className="text-ep-sm font-semibold mb-1">Packet provenance</h4>
        {event.packet_references.length ? (
          <ul className="text-ep-xs mono flex flex-col gap-0.5">
            {event.packet_references.slice(0, 8).map((ref, index) => (
              <li
                key={`${ref.source_file}-${ref.packet_number}-${index}`}
                className="truncate"
                title={`${ref.source_file} · packet #${ref.packet_number} · offset ${ref.byte_offset}`}
              >
                {ref.source_file.split('/').slice(-1)[0]} · pkt #{ref.packet_number} ·
                {' '}off {ref.byte_offset} · len {ref.captured_length}/{ref.original_length}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-ep-xs text-text-secondary">
            No packet reference reported for this event.
          </p>
        )}
      </section>

      <section>
        <h4 className="text-ep-sm font-semibold mb-1">Capture reference</h4>
        <p className="mono text-ep-xs text-text-secondary break-all">
          Capture: {event.capture_id || '—'}
        </p>
        <p className="mono text-ep-xs text-text-secondary break-all">
          Raw payload ref: {event.raw_payload_reference || '—'}
        </p>
      </section>

      <section>
        <h4 className="text-ep-sm font-semibold mb-1">
          Correlation evidence
        </h4>
        <p className="text-ep-xs text-text-secondary flex items-center gap-1.5">
          Association:{' '}
          <EvidenceBadge
            confidence={event.association === 'SESSION' ? 'STRONG' : 'POSSIBLE'}
            compact
          />
          ({event.association})
        </p>
      </section>

      {event.errors.length > 0 && (
        <section className="text-error text-ep-xs">
          <h4 className="font-semibold">Errors</h4>
          <ul className="list-disc pl-4">
            {event.errors.map((err, index) => (
              <li key={index}>{err}</li>
            ))}
          </ul>
        </section>
      )}
    </aside>
  );
}

function IeTree({ nodes, depth = 0 }: { nodes: InformationElement[]; depth?: number }) {
  return (
    <ul>
      {nodes.map((node, index) => (
        <IeTreeNode key={`${depth}-${index}-${node.name}`} node={node} depth={depth} />
      ))}
    </ul>
  );
}

function IeTreeNode({ node, depth }: { node: InformationElement; depth: number }) {
  const [open, setOpen] = useState(depth < 1);
  const hasChildren = (node.children?.length ?? 0) > 0;
  return (
    <li className="text-ep-xs">
      <div
        className="flex items-center gap-1 py-0.5 px-2 hover:bg-canvas"
        style={{ paddingLeft: `${depth * 12 + 8}px` }}
      >
        {hasChildren ? (
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            aria-label={open ? `Collapse ${node.name}` : `Expand ${node.name}`}
            className="text-text-secondary"
          >
            {open ? (
              <ChevronDown width={10} height={10} />
            ) : (
              <ChevronRight width={10} height={10} />
            )}
          </button>
        ) : (
          <span style={{ width: 10 }} />
        )}
        <span className="font-medium">{node.name}</span>
        {node.value && (
          <span className="mono text-text-secondary truncate" title={node.value}>
            = {node.value}
          </span>
        )}
        {node.status !== 'DECODED' && (
          <span className="ep-badge ml-auto text-[10px]">{node.status}</span>
        )}
      </div>
      {open && hasChildren && node.children && (
        <IeTree nodes={node.children} depth={depth + 1} />
      )}
    </li>
  );
}
