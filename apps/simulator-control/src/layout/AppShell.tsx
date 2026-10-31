import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { PanelLeftClose, PanelLeftOpen, Sun, Moon, Antenna } from 'lucide-react';
import clsx from 'clsx';
import { SidebarNavigation } from './SidebarNavigation';
import { useTheme } from '@/hooks/useTheme';
import { useAuth } from '@/data/queries';
import { SessionExpiredBanner } from '@/ui/SessionExpiredBanner';
import { useLabTopbarState } from './LabTopbarState';

const HEALTH_TONE: Record<string, string> = {
  healthy: 'bg-ok text-ok',
  degraded: 'bg-warn text-warn',
  offline: 'bg-bad text-bad',
  unknown: 'bg-track text-mute',
};

const HEALTH_LABEL: Record<string, string> = {
  healthy: 'Core healthy',
  degraded: 'Core degraded',
  offline: 'Core offline',
  unknown: 'Core status unknown',
};

export function AppShell() {
  const [collapsed, setCollapsed] = useState(false);
  const theme = useTheme();
  const auth = useAuth();
  const lab = useLabTopbarState();

  const isDark = theme.resolved === 'dark';
  const toggleTheme = () => theme.setPreference(isDark ? 'light' : 'dark');

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
        className="bg-sidebar border-r border-line flex flex-col"
        aria-label="Primary navigation"
      >
        <div
          className={clsx(
            'flex items-center gap-2.5 py-4 px-4',
            collapsed && 'justify-center px-0',
          )}
        >
          <div
            className="grid place-items-center h-8 w-8 rounded-lg bg-brand text-white"
            aria-hidden="true"
          >
            <Antenna width={17} height={17} />
          </div>
          {!collapsed && (
            <div className="leading-tight">
              <p className="text-ep-md font-semibold">POLARIS</p>
              <p className="text-ep-sm text-mute">5G lab control</p>
            </div>
          )}
        </div>
        <SidebarNavigation collapsed={collapsed} />
        <button
          type="button"
          className={clsx(
            'border-t border-line py-2 text-mute hover:text-ink text-ep-xs flex items-center gap-2',
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
        <header
          className="flex flex-wrap items-center justify-between gap-3 border-b border-line bg-surface py-2.5 px-5"
          data-testid="topbar"
        >
          <div className="flex flex-wrap items-center gap-3 text-ep-sm text-mute">
            <span className="inline-flex items-center gap-1.5" data-testid="core-health">
              <span
                className={clsx(
                  'h-2 w-2 rounded-full',
                  HEALTH_TONE[lab.coreHealth].split(' ')[0],
                  lab.coreHealth === 'healthy' && 'live-dot',
                )}
              />
              <span className="text-ink">{HEALTH_LABEL[lab.coreHealth]}</span>
            </span>
            <span className="num" data-testid="plmn-tac">
              PLMN {lab.plmn} · TAC {lab.tac}
            </span>
            <span className="num" data-testid="live-ues">
              Live UEs {lab.liveUes} / {lab.maxUes || '—'}
            </span>
            {auth.data?.authenticated ? (
              <span
                className="rounded border border-line px-1.5 py-0.5 text-ep-xs"
                data-testid="header-identity"
              >
                {auth.data.username} · {auth.data.role}
              </span>
            ) : (
              <span
                className="rounded border border-warn/40 text-warn px-1.5 py-0.5 text-ep-xs"
                data-testid="header-identity"
              >
                Not signed in
              </span>
            )}
          </div>
          <button
            type="button"
            onClick={toggleTheme}
            className="inline-flex items-center gap-2 h-8 px-3 rounded-md border border-line text-ep-sm hover:bg-canvas"
            aria-label="Toggle colour theme"
            data-testid="theme-toggle"
          >
            {isDark ? <Sun width={14} height={14} /> : <Moon width={14} height={14} />}
            {isDark ? 'Light' : 'Dark'}
          </button>
        </header>
        <div className="flex-1 min-h-0 overflow-y-auto px-5 py-6">
          <SessionExpiredBanner />
          <div className="flex flex-col gap-5">
            <Outlet />
          </div>
        </div>
      </main>
    </div>
  );
}
