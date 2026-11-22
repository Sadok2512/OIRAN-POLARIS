import clsx from 'clsx';

export type Tone = 'success' | 'warning' | 'danger' | 'info' | 'neutral';

const DOT: Record<Tone, string> = {
  success: 'bg-success',
  warning: 'bg-warning',
  danger: 'bg-error',
  info: 'bg-primary',
  neutral: 'bg-text-secondary',
};

export function toneFor(value: string | undefined | null): Tone {
  if (!value) return 'neutral';
  const s = value.toUpperCase();
  if (
    [
      'OK',
      'ONLINE',
      'HEALTHY',
      'READY',
      'COMPLETED',
      'ACTIVE',
      'RUNNING',
      'VALIDATED_READ_ONLY',
      'INFORMATION',
    ].includes(s)
  )
    return 'success';
  if (['CAPTURING', 'STARTING', 'STOPPING', 'PROCESSING'].includes(s))
    return 'info';
  if (
    [
      'WARNING',
      'DEGRADED',
      'INSUFFICIENT_RESOURCES',
      'VALIDATION_REQUIRED',
      'COMPLETED_EMPTY',
    ].includes(s)
  )
    return 'warning';
  if (
    [
      'FAILED',
      'UNHEALTHY',
      'OFFLINE',
      'DISK_HARD_LIMIT',
      'BLOCKED',
      'ERROR',
    ].includes(s) ||
    s.startsWith('BLOCKED_')
  )
    return 'danger';
  return 'neutral';
}

export function StatusIndicator({
  state,
  label,
  tone,
  compact,
}: {
  state?: string;
  label?: string;
  tone?: Tone;
  compact?: boolean;
}) {
  const resolved: Tone = tone ?? toneFor(state);
  const displayed = label ?? state ?? '—';
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 text-ep-xs font-medium',
        compact ? '' : 'ep-badge',
      )}
    >
      <span
        className={clsx('h-2 w-2 rounded-full', DOT[resolved])}
        aria-hidden="true"
      />
      <span>{displayed}</span>
    </span>
  );
}
