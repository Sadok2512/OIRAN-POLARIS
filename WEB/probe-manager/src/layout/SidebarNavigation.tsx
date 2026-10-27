import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Network,
  Radio,
  Cable,
  Activity,
  FolderOpen,
  Settings,
} from 'lucide-react';
import clsx from 'clsx';

const NAV = [
  { to: '/overview', label: 'Overview', Icon: LayoutDashboard, section: 'OPERATIONS' },
  { to: '/topology', label: 'Network Topology', Icon: Network, section: 'OPERATIONS' },
  { to: '/probes', label: 'Probes', Icon: Radio, section: 'OPERATIONS' },
  { to: '/interfaces', label: 'Interfaces', Icon: Cable, section: 'OPERATIONS' },
  { to: '/live-captures', label: 'Live Captures', Icon: Activity, section: 'CAPTURE' },
  { to: '/capture-library', label: 'Capture Library', Icon: FolderOpen, section: 'CAPTURE' },
  { to: '/settings', label: 'Settings', Icon: Settings, section: 'PLATFORM' },
] as const;

const SECTIONS = ['OPERATIONS', 'CAPTURE', 'PLATFORM'] as const;

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
