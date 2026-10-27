import clsx from 'clsx';
import type { Confidence } from '@shared/types';

const TONE: Record<Confidence, string> = {
  EXACT: 'bg-success/10 text-success border-success/30',
  STRONG: 'bg-primary/10 text-primary border-primary/30',
  POSSIBLE: 'bg-warning/10 text-warning border-warning/30',
  UNKNOWN: 'bg-canvas text-text-secondary border-border',
};

const DESCRIPTION: Record<Confidence, string> = {
  EXACT: 'Verified identifier bridge connects both sides.',
  STRONG: 'Multiple matching identifiers, no exact tunnel/context bridge.',
  POSSIBLE: 'Weak signals (time proximity, partial IDs).',
  UNKNOWN: 'No sufficient evidence to classify.',
};

export function EvidenceBadge({
  confidence,
  compact,
}: {
  confidence: Confidence | undefined;
  compact?: boolean;
}) {
  const value: Confidence = confidence ?? 'UNKNOWN';
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1 rounded-sm border font-medium',
        compact ? 'px-1.5 py-0 text-[10px]' : 'px-2 py-0.5 text-ep-xs',
        TONE[value],
      )}
      title={DESCRIPTION[value]}
      data-testid={`evidence-${value}`}
    >
      {value}
    </span>
  );
}

export const EVIDENCE_DESCRIPTION = DESCRIPTION;
