import type { ReactNode } from 'react';

export function PageHeader({
  eyebrow,
  title,
  desc,
  actions,
}: {
  eyebrow: string;
  title: string;
  desc?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header
      className="flex flex-wrap items-end justify-between gap-3"
      data-testid="page-header"
    >
      <div className="min-w-0">
        <p className="text-ep-xs font-semibold uppercase tracking-wider text-mute">{eyebrow}</p>
        <h1 className="text-ep-h1 font-semibold">{title}</h1>
        {desc ? <p className="mt-1 text-ep-md text-mute max-w-[70ch]">{desc}</p> : null}
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </header>
  );
}
