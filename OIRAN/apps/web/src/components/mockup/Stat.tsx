import type { ReactNode } from 'react';
import { Card } from './Card';

export function Stat({
  label,
  value,
  sub,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
}) {
  return (
    <Card className="p-4 flex flex-col gap-1">
      <p className="text-xs2 font-semibold uppercase tracking-wider text-mute">{label}</p>
      <p className="mono text-[26px] leading-tight font-medium">{value}</p>
      {sub ? <p className="text-sm2 text-mute">{sub}</p> : null}
    </Card>
  );
}
