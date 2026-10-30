// 0.10.0 — Overflow "⋯" menu for the UE Manager row actions.
//
// The Actions column now shows Start/Stop (state-driven) + Run inline, and
// pushes Edit / Clone / Delete into this overflow menu so the row fits
// 1440 and 1920 widths without horizontal scroll.

import { useEffect, useRef, useState } from 'react';
import clsx from 'clsx';
import { MoreHorizontal } from 'lucide-react';

export interface RowActionMenuItem {
  key: string;
  label: string;
  onSelect: () => void;
  disabled?: boolean;
  disabledReason?: string;
  tone?: 'default' | 'danger';
  testid?: string;
  icon?: React.ReactNode;
}

export function RowActionMenu({
  items,
  ariaLabel,
  testid,
}: {
  items: RowActionMenuItem[];
  ariaLabel: string;
  testid?: string;
}) {
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    function handleClick(event: MouseEvent) {
      if (!containerRef.current) return;
      if (!containerRef.current.contains(event.target as Node)) setOpen(false);
    }
    function handleKey(event: KeyboardEvent) {
      if (event.key === 'Escape') setOpen(false);
    }
    document.addEventListener('mousedown', handleClick);
    document.addEventListener('keydown', handleKey);
    return () => {
      document.removeEventListener('mousedown', handleClick);
      document.removeEventListener('keydown', handleKey);
    };
  }, [open]);

  return (
    <div ref={containerRef} className="relative inline-block">
      <button
        type="button"
        className="ep-button ep-button-sm"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={ariaLabel}
        onClick={() => setOpen((prev) => !prev)}
        data-testid={testid}
      >
        <MoreHorizontal width={13} height={13} aria-hidden="true" />
      </button>
      {open && (
        <div
          role="menu"
          className="absolute right-0 mt-1 z-20 min-w-[9rem] rounded-md border border-border bg-surface shadow-md py-1"
          data-testid={testid ? `${testid}-list` : undefined}
        >
          {items.map((item) => (
            <button
              key={item.key}
              type="button"
              role="menuitem"
              className={clsx(
                'w-full text-left text-ep-sm px-3 py-1.5 flex items-center gap-2',
                item.disabled
                  ? 'text-text-secondary cursor-not-allowed'
                  : item.tone === 'danger'
                    ? 'text-error hover:bg-error/10'
                    : 'hover:bg-primary/5 text-text-primary',
              )}
              onClick={() => {
                if (item.disabled) return;
                setOpen(false);
                item.onSelect();
              }}
              disabled={item.disabled}
              title={item.disabled ? item.disabledReason : undefined}
              data-testid={item.testid}
            >
              {item.icon}
              <span>{item.label}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
