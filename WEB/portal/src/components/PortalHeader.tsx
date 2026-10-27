import { Sun, Moon, Monitor } from 'lucide-react';
import { useTheme } from '@/hooks/useTheme';
import type { ThemePreference } from '@shared/theme';

const options: { value: ThemePreference; label: string; Icon: typeof Sun }[] = [
  { value: 'light', label: 'Light', Icon: Sun },
  { value: 'dark', label: 'Dark', Icon: Moon },
  { value: 'system', label: 'System', Icon: Monitor },
];

export function PortalHeader() {
  const theme = useTheme();
  return (
    <header
      className="border-b border-border bg-surface/80 backdrop-blur-sm sticky top-0 z-10"
      data-testid="portal-header"
    >
      <div className="mx-auto max-w-6xl px-6 h-14 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div
            className="h-7 w-7 rounded-sm bg-primary text-white flex items-center justify-center text-ep-sm font-semibold"
            aria-hidden="true"
          >
            T
          </div>
          <div>
            <p className="text-ep-xs uppercase tracking-wider text-text-secondary">
              Telecom Platform
            </p>
            <p className="text-ep-sm font-medium text-text-primary leading-tight">
              Portal
            </p>
          </div>
        </div>
        <div
          className="inline-flex items-center gap-1 rounded-md border border-border bg-canvas p-0.5"
          role="radiogroup"
          aria-label="Theme"
          data-testid="theme-switch"
        >
          {options.map((option) => {
            const selected = theme.preference === option.value;
            const { Icon } = option;
            return (
              <button
                key={option.value}
                type="button"
                role="radio"
                aria-checked={selected}
                aria-label={option.label}
                className={`inline-flex items-center justify-center h-7 w-7 rounded-sm transition-colors ${
                  selected
                    ? 'bg-surface text-text-primary shadow-[0_1px_2px_rgba(0,0,0,0.08)]'
                    : 'text-text-secondary hover:text-text-primary'
                }`}
                onClick={() => theme.setPreference(option.value)}
              >
                <Icon width={14} height={14} aria-hidden="true" />
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
}
