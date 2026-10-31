import { Lock } from 'lucide-react';
import type { ReactNode } from 'react';

export function Locked({
  children,
  reason,
  'data-testid': testId,
}: {
  children: ReactNode;
  reason: string;
  'data-testid'?: string;
}) {
  return (
    <button
      type="button"
      disabled
      title={reason}
      aria-label={typeof children === 'string' ? `${children} — ${reason}` : reason}
      data-testid={testId}
      className="inline-flex items-center gap-1.5 h-8 px-3 rounded-md border border-dashed border-line text-ep-sm text-mute cursor-not-allowed"
    >
      <Lock width={12} height={12} aria-hidden="true" />
      {children}
    </button>
  );
}
