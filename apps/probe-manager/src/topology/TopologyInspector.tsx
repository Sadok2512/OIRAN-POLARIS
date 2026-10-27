import { X } from 'lucide-react';
import type { Node } from '@xyflow/react';
import type { TopologyNodeData } from './types';
import { StatusIndicator } from '@/ui/StatusIndicator';

const EVIDENCE_DESCRIPTION: Record<TopologyNodeData['evidence'], string> = {
  DISCOVERED: 'Reported by the backend (API evidence).',
  CONFIGURED:
    'Declared by an operator-reviewed configuration mapping (not independently verified live).',
  INFERRED:
    'Added from the 5G SA reference topology or inferred from an interface name — no backend-verified mapping.',
  UNKNOWN: 'Observed with insufficient evidence to classify.',
};

export function TopologyInspector({
  node,
  onClose,
}: {
  node: Node<TopologyNodeData> | null;
  onClose: () => void;
}) {
  if (!node) return null;
  const { data } = node;
  return (
    <aside
      className="ep-card w-[320px] max-w-full h-full flex flex-col gap-4 p-4 overflow-y-auto"
      aria-label="Topology inspector"
      data-testid="topology-inspector"
    >
      <header className="flex items-start justify-between gap-2">
        <div>
          <p className="text-ep-xs uppercase tracking-wider text-text-secondary">
            Inspector
          </p>
          <h2 className="text-ep-lg font-semibold">{data.label}</h2>
          <p className="text-ep-xs text-text-secondary">{data.kind}</p>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="ep-button ep-button-sm"
          aria-label="Close inspector"
        >
          <X width={14} height={14} aria-hidden="true" />
        </button>
      </header>

      <section className="flex flex-col gap-1 text-ep-sm">
        <p>
          <StatusIndicator state={data.evidence} />
        </p>
        <p className="text-ep-xs text-text-secondary">
          {EVIDENCE_DESCRIPTION[data.evidence]}
        </p>
      </section>

      {data.status && (
        <section>
          <p className="text-ep-xs uppercase tracking-wider text-text-secondary">
            Status
          </p>
          <StatusIndicator state={data.status} />
        </section>
      )}

      {data.sublabel && (
        <section>
          <p className="text-ep-xs uppercase tracking-wider text-text-secondary">
            Context
          </p>
          <p className="text-ep-sm text-text-primary">{data.sublabel}</p>
        </section>
      )}

      {data.details && (
        <section>
          <p className="text-ep-xs uppercase tracking-wider text-text-secondary mb-1">
            Details
          </p>
          <dl className="grid grid-cols-2 gap-x-3 gap-y-1 text-ep-sm">
            {Object.entries(data.details).map(([key, value]) => (
              <div key={key} className="contents">
                <dt className="text-text-secondary">{key}</dt>
                <dd className="num break-words">
                  {value == null || value === ''
                    ? 'Not available'
                    : String(value)}
                </dd>
              </div>
            ))}
          </dl>
        </section>
      )}
    </aside>
  );
}
