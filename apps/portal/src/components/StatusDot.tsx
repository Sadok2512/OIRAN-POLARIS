import type { AppHealth } from '@/config/usePortalConfig';

type DotSpec = { label: string; color: string };

const SPECS: Record<AppHealth['state'], DotSpec> = {
  ok: { label: 'Healthy', color: 'bg-success' },
  'auth-required': {
    label: 'Auth required',
    color: 'bg-warning',
  },
  degraded: { label: 'Degraded', color: 'bg-error' },
  unknown: { label: 'Unknown', color: 'bg-text-secondary' },
};

export function StatusDot({ state }: { state: AppHealth['state'] }) {
  const spec = SPECS[state];
  return (
    <span className="inline-flex items-center gap-1.5" aria-label={spec.label}>
      <span
        className={`h-2 w-2 rounded-full ${spec.color}`}
        aria-hidden="true"
      />
      <span className="text-ep-xs text-text-secondary">{spec.label}</span>
    </span>
  );
}
