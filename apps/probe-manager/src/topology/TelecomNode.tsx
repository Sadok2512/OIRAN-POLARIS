import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import {
  Smartphone,
  RadioTower,
  Server,
  CircuitBoard,
  Database,
  Cable,
  Cpu,
  CloudCog,
} from 'lucide-react';
import clsx from 'clsx';
import type { TopologyNodeData, TopologyNodeKind } from './types';
import { toneFor } from '@/ui/StatusIndicator';

const KIND_LABEL: Record<TopologyNodeKind, string> = {
  UE: 'User Equipment',
  RAN: 'RAN',
  GNB: 'gNB',
  ENB: 'eNB',
  AMF: 'Access & Mobility',
  SMF: 'Session Management',
  UPF: 'User Plane',
  OTHER_NF: 'Network Function',
  PROBE_PHYSICAL: 'Physical probe',
  PROBE_VIRTUAL: 'Virtual probe',
  INTERFACE: 'Capture point',
};

const KIND_ICON: Record<TopologyNodeKind, typeof Smartphone> = {
  UE: Smartphone,
  RAN: RadioTower,
  GNB: RadioTower,
  ENB: RadioTower,
  AMF: Server,
  SMF: CircuitBoard,
  UPF: Database,
  OTHER_NF: CloudCog,
  PROBE_PHYSICAL: Cpu,
  PROBE_VIRTUAL: Cpu,
  INTERFACE: Cable,
};

const EVIDENCE_TONE = {
  DISCOVERED: 'border-success/50 bg-success/5',
  CONFIGURED: 'border-primary/40 bg-primary/5',
  INFERRED: 'border-border bg-canvas',
  UNKNOWN: 'border-warning/40 bg-warning/5',
} as const;

export const TelecomNode = memo(function TelecomNode({
  data,
  selected,
}: NodeProps) {
  const d = data as TopologyNodeData;
  const Icon = KIND_ICON[d.kind];
  const tone = toneFor(d.status);
  const toneDot = {
    success: 'bg-success',
    warning: 'bg-warning',
    danger: 'bg-error',
    info: 'bg-primary',
    neutral: 'bg-text-secondary',
  }[tone];
  return (
    <div
      className={clsx(
        'min-w-[150px] max-w-[200px] rounded-md border-2 bg-surface px-3 py-2 shadow-[0_1px_2px_rgba(23,40,63,0.06)] text-ep-xs',
        EVIDENCE_TONE[d.evidence],
        selected ? 'ring-2 ring-primary' : '',
      )}
      data-testid={`topology-node-${d.kind}`}
    >
      <Handle type="target" position={Position.Left} />
      <div className="flex items-center gap-2">
        <Icon width={14} height={14} className="text-text-secondary shrink-0" />
        <div className="min-w-0">
          <p className="font-semibold text-text-primary truncate">{d.label}</p>
          <p className="text-text-secondary truncate">
            {KIND_LABEL[d.kind]}
          </p>
        </div>
        {d.status && (
          <span
            className={clsx('h-2 w-2 rounded-full', toneDot)}
            aria-label={d.status}
          />
        )}
      </div>
      {d.sublabel && (
        <p className="text-text-secondary text-[10px] mt-1 truncate">
          {d.sublabel}
        </p>
      )}
      <p className="mt-1 text-[10px] uppercase tracking-wider text-text-secondary">
        {d.evidence}
      </p>
      <Handle type="source" position={Position.Right} />
    </div>
  );
});
