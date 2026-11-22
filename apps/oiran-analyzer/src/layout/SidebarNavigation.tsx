import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Database,
  Users,
  Network,
  Share2,
  Gauge,
  FileSearch,
  Workflow,
} from 'lucide-react';
import clsx from 'clsx';

const NAV = [
  { to: '/overview', label: 'Overview', Icon: LayoutDashboard, section: 'ANALYSIS' },
  { to: '/datasets', label: 'Datasets', Icon: Database, section: 'ANALYSIS' },
  { to: '/investigation/sessions', label: 'Session Explorer', Icon: Users, section: 'INVESTIGATION' },
  { to: '/investigation/signaling', label: 'Signaling', Icon: Workflow, section: 'INVESTIGATION' },
  { to: '/investigation/user-plane', label: 'User Plane', Icon: Network, section: 'INVESTIGATION' },
  { to: '/investigation/correlation', label: 'Correlation Studio', Icon: Share2, section: 'INVESTIGATION' },
  { to: '/analysis/packets', label: 'Packet Analyzer', Icon: FileSearch, section: 'ANALYSIS' },
  { to: '/analysis/kpi', label: 'KPI / Performance', Icon: Gauge, section: 'ANALYSIS' },
] as const;

const SECTIONS = ['INVESTIGATION', 'ANALYSIS'] as const;

export function SidebarNavigation({ collapsed }: { collapsed: boolean }) {
  return (
    <nav
      className={clsx(
        'flex flex-col gap-3 py-3 overflow-y-auto',
        collapsed ? 'px-2' : 'px-3',
      )}
      aria-label="Primary"
    >
      {SECTIONS.map((section) => (
        <div key={section} className="flex flex-col gap-1">
          {!collapsed && (
            <p className="text-ep-xs font-semibold tracking-wider uppercase text-text-secondary px-2 py-1">
              {section}
            </p>
          )}
          {NAV.filter((item) => item.section === section).map(
            ({ to, label, Icon }) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) =>
                  clsx(
                    'flex items-center gap-2.5 rounded-md px-2 py-1.5 text-ep-sm',
                    'text-text-secondary hover:text-text-primary hover:bg-canvas transition-colors',
                    isActive && 'bg-canvas text-text-primary font-medium',
                  )
                }
                title={collapsed ? label : undefined}
              >
                <Icon width={16} height={16} aria-hidden="true" />
                {!collapsed && <span>{label}</span>}
              </NavLink>
            ),
          )}
        </div>
      ))}
    </nav>
  );
}
