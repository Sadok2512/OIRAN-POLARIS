import type { AppHealth } from '@/config/usePortalConfig';

export function StatusDot({ state }: { state: AppHealth['state'] }) {
  const label =
    state === 'ok'
      ? 'Reachable'
      : state === 'degraded'
        ? 'Degraded'
        : 'Unknown';
  const colorClass =
    state === 'ok'
      ? 'bg-success'
      : state === 'degraded'
        ? 'bg-warning'
        : 'bg-text-secondary';

  return (
    <span className="inline-flex items-center gap-1.5" aria-label={label}>
      <span
        className={`h-2 w-2 rounded-full ${colorClass}`}
        aria-hidden="true"
      />
      <span className="text-ep-xs text-text-secondary">{label}</span>
    </span>
  );
}
