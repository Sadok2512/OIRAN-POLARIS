import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { PanelLeftClose, PanelLeftOpen, Sun, Moon, Monitor } from 'lucide-react';
import clsx from 'clsx';
import { SidebarNavigation } from './SidebarNavigation';
import { useTheme } from '@/hooks/useTheme';
import type { ThemePreference } from '@shared/theme';

const THEME_OPTIONS: { value: ThemePreference; label: string; Icon: typeof Sun }[] = [
  { value: 'light', label: 'Light', Icon: Sun },
  { value: 'dark', label: 'Dark', Icon: Moon },
  { value: 'system', label: 'System', Icon: Monitor },
];

export function AppShell() {
  const [collapsed, setCollapsed] = useState(false);
  const theme = useTheme();

  return (
    <div
      className={clsx(
        'grid min-h-screen',
        collapsed
          ? 'grid-cols-[56px_minmax(0,1fr)]'
          : 'grid-cols-[240px_minmax(0,1fr)]',
      )}
      data-testid="app-shell"
    >
      <aside
        className="bg-sidebar border-r border-border flex flex-col"
        aria-label="Primary navigation"
      >
        <div
          className={clsx(
            'flex items-center h-14 border-b border-border px-3 gap-2.5',
            collapsed && 'justify-center px-0',
          )}
        >
          <div
            className="h-7 w-7 rounded-sm bg-primary text-white flex items-center justify-center text-ep-sm font-semibold"
            aria-hidden="true"
          >
            P
          </div>
          {!collapsed && (
            <div className="leading-tight">
              <p className="text-ep-xs uppercase tracking-wider text-text-secondary">
                POLARIS
              </p>
              <p className="text-ep-sm font-medium">Simulator Control</p>
            </div>
          )}
        </div>
        <SidebarNavigation collapsed={collapsed} />
        <button
          type="button"
          className={clsx(
            'mt-auto border-t border-border py-2 text-text-secondary hover:text-text-primary text-ep-xs flex items-center gap-2',
            collapsed ? 'justify-center' : 'px-3',
          )}
          onClick={() => setCollapsed((v) => !v)}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          data-testid="sidebar-toggle"
        >
          {collapsed ? (
            <PanelLeftOpen width={14} height={14} />
          ) : (
            <>
              <PanelLeftClose width={14} height={14} />
              <span>Collapse</span>
            </>
          )}
        </button>
      </aside>
      <main className="flex flex-col min-w-0">
        <header className="h-14 border-b border-border bg-surface flex items-center justify-between px-5">
          <div className="text-ep-sm text-text-secondary">
            Enterprise Precision ·{' '}
            <span className="text-text-primary">POLARIS Simulator Control V1</span>
          </div>
          <div
            className="inline-flex items-center gap-1 rounded-md border border-border bg-canvas p-0.5"
            role="radiogroup"
            aria-label="Theme"
            data-testid="theme-switch"
          >
            {THEME_OPTIONS.map((option) => {
              const selected = theme.preference === option.value;
              const { Icon } = option;
              return (
                <button
                  key={option.value}
                  type="button"
                  role="radio"
                  aria-checked={selected}
                  aria-label={option.label}
                  className={clsx(
                    'inline-flex items-center justify-center h-7 w-7 rounded-sm transition-colors',
                    selected
                      ? 'bg-surface text-text-primary shadow-[0_1px_2px_rgba(0,0,0,0.08)]'
                      : 'text-text-secondary hover:text-text-primary',
                  )}
                  onClick={() => theme.setPreference(option.value)}
                >
                  <Icon width={14} height={14} aria-hidden="true" />
                </button>
              );
            })}
          </div>
        </header>
        <div className="flex-1 min-h-0 overflow-y-auto px-5 py-5">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
