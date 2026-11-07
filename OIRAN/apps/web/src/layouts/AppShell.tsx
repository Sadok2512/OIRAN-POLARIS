import { useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  Activity, BarChart3, Braces, ChevronLeft, ChevronRight, CircleUserRound,
  Download, FileSearch, GitBranch, Menu, Network, RadioTower, Search,
  Settings, Waypoints,
} from 'lucide-react';
import { api } from '../services/api';
import type { AuthState, Dataset, Metrics, Module, Probe, VersionInfo } from '../types/api';

type Theme = 'light' | 'dark' | 'system';

const icons: Record<string, typeof Activity> = {
  overview: BarChart3,
  'probe-manager': RadioTower,
  'session-explorer': Activity,
  'callflow-viewer': Waypoints,
  'correlation-studio': Network,
  'packet-analyzer': FileSearch,
  'export-reports': Download,
  'live-monitoring': Activity,
  settings: Settings,
  'module-versions': Braces,
};

// LOT 3 — docs/ui-mockups/oiran-analyzer.html: the Analyzer sidebar now
// splits into two groups ("Investigate" and "Evidence"). Probe Manager
// has its own app (apps/probe-manager) and no longer appears here; the
// `operations` section is intentionally omitted from `ordered` below so
// any module the backend still tags that way is filtered out of the nav.
const sections: Record<string, string> = {
  overview: 'INVESTIGATE',
  investigation: 'INVESTIGATE',
  analysis: 'INVESTIGATE',
  reports: 'EVIDENCE',
  platform: 'SYSTEM',
};

const bytes = (value: number | null | undefined) =>
  value == null ? '—' : `${(value / 1073741824).toFixed(1)}G`;

export function AppShell() {
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem('oiran.sidebar') === 'collapsed',
  );
  const [theme, setTheme] = useState<Theme>(
    () => (localStorage.getItem('oiran.theme') as Theme) || 'dark',
  );
  const [search, setSearch] = useState('');
  const navigate = useNavigate();
  const location = useLocation();
  const modules = useQuery({
    queryKey: ['modules'],
    queryFn: () => api<Module[]>('/modules').then((value) => value.data),
  });
  const metrics = useQuery({
    queryKey: ['shell-metrics'],
    queryFn: () => api<Metrics>('/metrics').then((value) => value.data),
    refetchInterval: 5000,
  });
  const auth = useQuery({
    queryKey: ['auth'],
    queryFn: () => api<AuthState>('/auth/me').then((value) => value.data),
  });
  const probes = useQuery({
    queryKey: ['shell-probes'],
    queryFn: () => api<Probe[]>('/probes').then((value) => value.data),
    refetchInterval: 5000,
  });
  const datasets = useQuery({
    queryKey: ['shell-datasets'],
    queryFn: () => api<Dataset[]>('/datasets?page_size=100').then((value) => value.data),
    staleTime: 30_000,
  });

  useEffect(() => {
    const media = window.matchMedia?.('(prefers-color-scheme: dark)') ?? {
      matches: false,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
    };
    const apply = () => {
      const resolved = theme === 'system' ? (media.matches ? 'dark' : 'light') : theme;
      document.documentElement.dataset.theme = resolved;
      document.documentElement.style.colorScheme = resolved;
    };
    localStorage.setItem('oiran.theme', theme);
    apply();
    media.addEventListener('change', apply);
    return () => media.removeEventListener('change', apply);
  }, [theme]);

  const breadcrumb = location.pathname
    .split('/')
    .filter(Boolean)
    .map((part) => part.replaceAll('-', ' '));
  // "operations" (Probe Manager) is excluded on purpose — see sections map.
  const ordered = ['overview', 'investigation', 'analysis', 'reports', 'platform'];
  const onlineProbes = probes.data?.filter((probe) => probe.online) ?? [];
  const probeLabel = probes.isError
    ? 'vProbe UNKNOWN'
    : onlineProbes.length > 0
      ? `${onlineProbes.length} vProbe connected`
      : probes.data?.length
        ? 'vProbe not connected'
        : 'vProbe UNKNOWN';
  const observedTechnologies = [...new Set(datasets.data?.map((item) => item.technology).filter(Boolean) ?? [])];

  function submit(event: React.FormEvent) {
    event.preventDefault();
    navigate(`/investigation/sessions?search=${encodeURIComponent(search)}`);
  }

  return (
    <div className={`app-shell ${collapsed ? 'sidebar-collapsed' : ''}`}>
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span className="logo-mark small"><RadioTower size={18} /></span>
          {!collapsed && <div><b>OIRAN</b><span>Signaling Intelligence</span></div>}
        </div>
        <nav aria-label="Primary navigation">
          {ordered.map((section, index) => {
            const items = modules.data?.filter(
              (module) => module.navigation.section === section && module.enabled,
            ) ?? [];
            if (!items.length) return null;
            const showLabel = index === 0 || sections[ordered[index - 1]] !== sections[section];
            return (
              <div className="nav-section" key={section}>
                {!collapsed && showLabel && <div className="nav-label">{sections[section]}</div>}
                {items.map((module) => {
                  const Icon = icons[module.module_id] ?? GitBranch;
                  return (
                    <NavLink to={module.route} key={module.module_id} title={module.navigation.label}>
                      <Icon size={17} />
                      {!collapsed && <span>{module.navigation.label}</span>}
                    </NavLink>
                  );
                })}
              </div>
            );
          })}
        </nav>
        <button
          className="collapse"
          aria-label="Toggle sidebar"
          onClick={() => setCollapsed((value) => {
            localStorage.setItem('oiran.sidebar', !value ? 'collapsed' : 'open');
            return !value;
          })}
        >
          {collapsed ? <ChevronRight /> : <><ChevronLeft /><span>Collapse</span></>}
        </button>
      </aside>
      <section className="workspace">
        <header className="topbar">
          <button className="mobile-menu" aria-label="Menu"><Menu /></button>
          <div className="product-title"><b>OIRAN Analyzer</b><small>{breadcrumb.at(-1) ?? 'overview'}</small></div>
          <form className="global-search" onSubmit={submit}>
            <Search size={15} />
            <input aria-label="Global search" placeholder="Search session or message" value={search} onChange={(event) => setSearch(event.target.value)} />
          </form>
          <select aria-label="Environment"><option>Certified Lab</option></select>
          <span className="observed-technology" data-testid="observed-technologies">
            {observedTechnologies.length ? `Observed: ${observedTechnologies.join(' / ')}` : 'Technology UNKNOWN'}
          </span>
          <span className={`connection ${onlineProbes.length ? '' : 'connection-unknown'}`} data-testid="probe-connection"><i />{probeLabel}</span>
          <div className="interface-indicators">
            {metrics.data?.interfaces.map((item) => <span key={item.interface}><i />{item.interface} {item.state}</span>)}
          </div>
          <div className="resource-summary">
            <span>Disk <b>{metrics.data?.disk ? `${metrics.data.disk.usage_percent.toFixed(0)}%` : '—'}</b></span>
            <span>CPU <b>{metrics.data?.cpu.usage_percent == null ? `L${metrics.data?.cpu.load_one ?? '—'}` : `${metrics.data.cpu.usage_percent.toFixed(0)}%`}</b></span>
            <span>RAM <b>{bytes(metrics.data?.memory.available_bytes)}</b></span>
          </div>
          <label className="theme-select">
            <span>Theme</span>
            <select aria-label="Theme" value={theme} onChange={(event) => setTheme(event.target.value as Theme)}>
              <option value="dark">Dark</option>
              <option value="light">Light</option>
              <option value="system">System</option>
            </select>
          </label>
          <div className="user"><CircleUserRound /><span>{auth.data?.role === 'viewer' ? 'Public viewer' : auth.data?.role ?? 'Unknown'}</span></div>
        </header>
        <main className="page"><Outlet /></main>
        <VersionFooter />
      </section>
    </div>
  );
}

// 2.9.0 (#9): the Analyzer footer now exposes BOTH versions on screen.
// The web bundle's `__WEB_VERSION__` is injected by Vite at build time
// so it survives a cache-busted rebuild; the API version is fetched
// from `/api/v1/version` under the ETag flow so the panel re-renders
// only after a backend bump.
export function VersionFooter() {
  const versions = useQuery({
    queryKey: ['version'],
    queryFn: () => api<VersionInfo>('/version').then((value) => value.data),
    staleTime: 60_000,
  });
  const web = (import.meta.env.VITE_WEB_VERSION as string | undefined) ?? '0.0.0';
  const api_version = versions.data?.backend_api ?? '…';
  return (
    <footer className="app-footer" data-testid="version-footer">
      <span>OIRAN Analyzer</span>
      <span>
        web <b data-testid="web-version">{web}</b>
      </span>
      <span>
        API <b data-testid="api-version">{api_version}</b>
      </span>
    </footer>
  );
}
