import clsx from 'clsx';

export function Tabs<T extends string>({
  tabs,
  value,
  onChange,
  label,
}: {
  tabs: [T, string][];
  value: T;
  onChange: (next: T) => void;
  label: string;
}) {
  return (
    <div role="tablist" aria-label={label} className="flex flex-wrap gap-1 border-b border-line">
      {tabs.map(([v, l]) => (
        <button
          key={v}
          type="button"
          role="tab"
          aria-selected={value === v}
          onClick={() => onChange(v)}
          className={clsx(
            'h-9 px-3 -mb-px border-b-2 text-sm2 whitespace-nowrap',
            value === v
              ? 'border-brand text-brand font-semibold'
              : 'border-transparent text-mute hover:text-ink',
          )}
        >
          {l}
        </button>
      ))}
    </div>
  );
}
