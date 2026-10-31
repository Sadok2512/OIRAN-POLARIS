import clsx from 'clsx';
import type { ReactNode } from 'react';

export function Field({
  k,
  v,
  mono,
  title,
}: {
  k: string;
  v: ReactNode;
  mono?: boolean;
  title?: string;
}) {
  return (
    <div className="min-w-0">
      <dt className="text-xs2 uppercase tracking-wider text-mute">{k}</dt>
      <dd className={clsx('truncate', mono && 'mono text-sm2')} title={title ?? (typeof v === 'string' ? v : undefined)}>
        {v}
      </dd>
    </div>
  );
}

export type IeNode = { name: string; value: string | null; status: string; children?: IeNode[] };

export function IeTree({ nodes, depth = 0 }: { nodes: IeNode[]; depth?: number }) {
  return (
    <ul className={depth ? 'ml-4 border-l border-line pl-3' : ''}>
      {nodes.map((n, i) => (
        <li key={`${n.name}-${i}`} className="py-1">
          <div className="flex items-center justify-between gap-3">
            <span className="text-sm2">{n.name}</span>
            <span className="flex items-center gap-2 min-w-0">
              {n.value != null ? <span className="mono text-xs2 truncate">{n.value}</span> : null}
              {n.status !== 'DECODED' ? (
                <span className="mono text-xs2 text-mute">{n.status}</span>
              ) : null}
            </span>
          </div>
          {n.children ? <IeTree nodes={n.children} depth={depth + 1} /> : null}
        </li>
      ))}
    </ul>
  );
}
