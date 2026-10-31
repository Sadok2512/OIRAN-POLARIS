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
        'inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs2 font-semibold tracking-wide whitespace-nowrap',
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

export function confTone(c: string | null | undefined): PillTone {
  return ({ EXACT: 'ok', STRONG: 'ok', POSSIBLE: 'warn', UNKNOWN: 'mute' } as const)[(c ?? '').toUpperCase() as 'EXACT'] ?? 'mute';
}

export function decTone(d: string | null | undefined): PillTone {
  return (
    {
      DECODED: 'ok',
      PARTIAL: 'warn',
      UNSUPPORTED: 'mute',
      MALFORMED: 'bad',
      ENCRYPTED_OR_PROTECTED: 'vio',
    } as const
  )[(d ?? '').toUpperCase() as 'DECODED'] ?? 'mute';
}

export function kindTone(k: string | null | undefined): PillTone {
  return (
    { CAPTURED_LIVE: 'ok', HISTORICAL: 'mute', RECOVERED: 'warn' } as const
  )[(k ?? '').toUpperCase() as 'CAPTURED_LIVE'] ?? 'mute';
}

export function ifTone(i: string): PillTone {
  return ({ N2: 'brand', SBI: 'ok', N4: 'warn', N3: 'vio' } as const)[i as 'N2'] ?? 'mute';
}

/** 2.4.0 — Compact monospace interface chip reused across every page. */
export function IfChip({ i, className }: { i: string; className?: string }) {
  return (
    <span
      className={clsx(
        'mono text-xs2 font-semibold rounded px-1.5 py-0.5',
        TONES[ifTone(i)],
        className,
      )}
    >
      {i}
    </span>
  );
}
