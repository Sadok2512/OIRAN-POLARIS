// 2.4.0 — AppShell rebuilt against docs/ui-mockups/oiran-analyzer.html.
// Sidebar collapses to the 2 mockup sections (Investigate / Evidence) with
// the 7 mockup items; Probe Manager, Live Monitoring, Settings and Module
// Versions stay reachable by direct URL for backward-compat. Topbar
// collapses to the mockup row: search + vProbe live-dot + 5G SA chip +
// Light/Dark 2-state toggle. The identity note stays in the sidebar
// footer: subscriber identities are never stored or shown.

import { useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import {
  Activity, BarChart3, ChevronLeft, ChevronRight, Database,
  Download, FileSearch, Link as LinkIcon, Menu, Moon, Radio, Search,
  Shield, Sun, Waypoints,
} from 'lucide-react';
import { api } from '../services/api';
import type { AuthState, Metrics } from '../types/api';

type Theme = 'light' | 'dark';

const NAV: {
  id: string;
  to: string;
  label: string;
  Icon: typeof BarChart3;
  section: 'Investigate' | 'Evidence';
}[] = [
  { id: 'overview', to: '/overview', label: 'Overview', Icon: BarChart3, section: 'Investigate' },
  { id: 'sessions', to: '/investigation/sessions', label: 'Sessions', Icon: Activity, section: 'Investigate' },
  { id: 'callflow', to: '/investigation/callflow', label: 'Call flow', Icon: Waypoints, section: 'Investigate' },
  { id: 'correlation', to: '/investigation/correlation', label: 'Correlation', Icon: LinkIcon, section: 'Investigate' },
  { id: 'packets', to: '/analysis/packets', label: 'Packets', Icon: FileSearch, section: 'Evidence' },
  { id: 'datasets', to: '/evidence/datasets', label: 'Datasets', Icon: Database, section: 'Evidence' },
  { id: 'exports', to: '/reports/exports', label: 'Exports', Icon: Download, section: 'Evidence' },
];

export function AppShell() {
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem('oiran.sidebar') === 'collapsed',
  );
  const [theme, setTheme] = useState<Theme>(
    () => ((localStorage.getItem('oiran.theme') as Theme) || 'dark'),
  );
  const [search, setSearch] = useState('');
  const navigate = useNavigate();
  const location = useLocation();

  const metrics = useQuery({
    queryKey: ['shell-metrics'],
    queryFn: () => api<Metrics>('/metrics').then((value) => value.data),
    refetchInterval: 5000,
  });
  const auth = useQuery({
    queryKey: ['auth'],
    queryFn: () => api<AuthState>('/auth/me').then((value) => value.data),
  });

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    localStorage.setItem('oiran.theme', theme);
  }, [theme]);

  const isDark = theme === 'dark';
  function submit(event: React.FormEvent) {
    event.preventDefault();
    navigate(`/investigation/sessions?search=${encodeURIComponent(search)}`);
  }

  // Live-dot colour: ok when any metric is non-null (API reachable), mute otherwise.
  const vprobeOnline = metrics.data != null;

  return (
    <div
      className="min-h-screen flex flex-col md:flex-row bg-canvas text-ink"
      data-testid="oiran-shell"
    >
      <aside
        className={clsx(
          'shrink-0 bg-sidebar border-b md:border-b-0 md:border-r border-line md:min-h-screen flex flex-col',
          collapsed ? 'md:w-16' : 'md:w-56',
        )}
        aria-label="Primary navigation"
      >
        <div className="flex items-center gap-2.5 py-4 px-4">
          <div
            className="grid place-items-center h-8 w-8 rounded-lg bg-ok text-white"
            aria-hidden="true"
          >
            <Radio width={17} height={17} />
          </div>
          {!collapsed ? (
            <div className="leading-tight">
              <p className="text-md2 font-semibold">OIRAN Analyzer</p>
              <p className="text-sm2 text-mute">Signalling evidence</p>
            </div>
          ) : null}
        </div>
        <nav
          className="flex md:flex-col gap-1 overflow-x-auto md:overflow-visible pb-3 md:pb-0 flex-1 px-3"
          aria-label="Primary"
        >
          {(['Investigate', 'Evidence'] as const).map((section) => (
            <div key={section} className="flex md:flex-col gap-1 md:mb-3">
              {!collapsed ? (
                <p className="hidden md:block px-2 py-1 text-xs2 font-semibold uppercase tracking-wider text-mute">
                  {section}
                </p>
              ) : null}
              {NAV.filter((n) => n.section === section).map(({ id, to, label, Icon }) => (
                <NavLink
                  key={id}
                  to={to}
                  title={collapsed ? label : undefined}
                  className={({ isActive }) =>
                    clsx(
                      'flex items-center gap-2.5 whitespace-nowrap rounded-md px-2.5 py-2 text-md2 transition-colors',
                      isActive
                        ? 'bg-surface text-ink font-medium shadow-e1'
                        : 'text-mute hover:text-ink hover:bg-surface',
                    )
                  }
                >
                  <Icon width={16} height={16} aria-hidden="true" />
                  {!collapsed ? <span>{label}</span> : null}
                </NavLink>
              ))}
            </div>
          ))}
          {!collapsed ? (
            <div className="hidden md:flex mt-2 mx-2 border-t border-line pt-3 gap-2 text-sm2 text-mute">
              <Shield width={15} height={15} className="shrink-0 mt-0.5" />
              <span>
                Subscriber identities (IMSI, IMEI, TMSI, GUTI) are never stored or shown.
              </span>
            </div>
          ) : null}
        </nav>
        <button
          type="button"
          onClick={() =>
            setCollapsed((value) => {
              localStorage.setItem('oiran.sidebar', !value ? 'collapsed' : 'open');
              return !value;
            })
          }
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          data-testid="sidebar-toggle"
          className="border-t border-line py-2 text-mute hover:text-ink text-xs2 flex items-center justify-center gap-2"
        >
          {collapsed ? (
            <ChevronRight width={14} height={14} />
          ) : (
            <>
              <ChevronLeft width={14} height={14} />
              <span>Collapse</span>
            </>
          )}
        </button>
      </aside>
      <section className="flex-1 min-w-0 flex flex-col">
        <header
          className="flex flex-wrap items-center justify-between gap-3 border-b border-line bg-surface py-2.5 px-4"
          data-testid="topbar"
        >
          <button
            type="button"
            className="md:hidden text-mute hover:text-ink"
            aria-label="Menu"
          >
            <Menu width={18} height={18} />
          </button>
          <form onSubmit={submit} className="relative flex-1 min-w-[220px] max-w-md">
            <label className="sr-only" htmlFor="oiran-topbar-search">
              Search sessions
            </label>
            <Search
              width={15}
              height={15}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-mute"
              aria-hidden
            />
            <input
              id="oiran-topbar-search"
              placeholder="Session ID, UE pseudonym or procedure"
              className="w-full h-9 pl-9 pr-3 rounded-md border border-line bg-canvas text-md2 placeholder:text-mute text-ink"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </form>
          <div className="flex flex-wrap items-center gap-3 text-sm2 text-mute">
            <span
              className="inline-flex items-center gap-1.5"
              data-testid="vprobe-status"
            >
              <span
                className={clsx(
                  'h-2 w-2 rounded-full',
                  vprobeOnline ? 'bg-ok live-dot' : 'bg-mute',
                )}
                aria-hidden
              />
              <span className="text-ink">
                {vprobeOnline ? 'vProbe connected' : 'vProbe unreachable'}
              </span>
            </span>
            <span className="num" data-testid="topbar-tech">
              5G SA
            </span>
            {auth.data?.role ? (
              <span
                className="rounded border border-line px-1.5 py-0.5 text-xs2"
                data-testid="header-identity"
              >
                {auth.data.role}
              </span>
            ) : null}
            <button
              type="button"
              onClick={() => setTheme(isDark ? 'light' : 'dark')}
              className="inline-flex items-center gap-2 h-8 px-3 rounded-md border border-line text-sm2 text-ink hover:bg-canvas"
              aria-label="Toggle colour theme"
              data-testid="theme-toggle"
            >
              {isDark ? (
                <Sun width={14} height={14} />
              ) : (
                <Moon width={14} height={14} />
              )}
              {isDark ? 'Light' : 'Dark'}
            </button>
          </div>
        </header>
        <main
          className="flex-1 min-w-0 flex flex-col gap-5 px-4 md:px-6 py-6"
          data-testid="main"
        >
          <Outlet />
        </main>
        <p className="sr-only" data-testid="active-route">
          {location.pathname}
        </p>
      </section>
    </div>
  );
}
