import clsx from 'clsx';
import type { ReactNode } from 'react';

export type PillTone = 'ok' | 'warn' | 'bad' | 'brand' | 'vio' | 'mute';

const TONES: Record<PillTone, string> = {
  ok: 'bg-ok-soft text-ok',
  warn: 'bg-warn-soft text-warn',
  bad: 'bg-bad-soft text-bad',
  brand: 'bg-brand-soft text-brand',
  vio: 'bg-vio-soft text-vio',
  mute: 'bg-track text-mute',
};

export function Pill({
  tone = 'mute',
  children,
  dot,
  className,
}: {
  tone?: PillTone;
  children: ReactNode;
  dot?: 'live' | boolean;
  className?: string;
}) {
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-ep-xs font-semibold tracking-wide',
        TONES[tone],
        className,
      )}
    >
      {dot ? (
        <span className={clsx('h-1.5 w-1.5 rounded-full bg-current', dot === 'live' && 'live-dot')} />
      ) : null}
      {children}
    </span>
  );
}

export function regTone(state: string | null | undefined): PillTone {
  const map: Record<string, PillTone> = {
    REGISTERED: 'ok',
    REGISTERING: 'warn',
    STOPPED: 'mute',
    FAILED: 'bad',
    ACTIVE: 'ok',
    VERIFIED: 'ok',
    PROVISIONING_REQUIRED: 'warn',
    PLANNED: 'brand',
    HEALTHY: 'ok',
    SUCCESS: 'ok',
    UP: 'ok',
    RUNNING: 'brand',
    PENDING: 'brand',
    COMPLETED: 'ok',
    DEGRADED: 'warn',
    OFFLINE: 'bad',
  };
  return map[state ?? ''] ?? 'mute';
}
