import clsx from 'clsx';
import type { ReactNode } from 'react';
import { Card } from './Card';

export function Stat({
  label,
  value,
  sub,
  tone,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  tone?: 'ok' | 'warn' | 'bad' | 'brand';
}) {
  return (
    <Card className="p-4 flex flex-col gap-1">
      <p className="text-ep-xs font-semibold uppercase tracking-wider text-mute">{label}</p>
      <p
        className={clsx(
          'num text-[26px] leading-tight font-medium',
          tone === 'ok' && 'text-ok',
          tone === 'warn' && 'text-warn',
          tone === 'bad' && 'text-bad',
          tone === 'brand' && 'text-brand',
        )}
      >
        {value}
      </p>
      {sub ? <p className="text-ep-sm text-mute">{sub}</p> : null}
    </Card>
  );
}
