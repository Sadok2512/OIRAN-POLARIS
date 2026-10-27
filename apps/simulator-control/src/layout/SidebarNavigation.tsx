import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Smartphone,
  Workflow,
  Activity,
  History,
  Settings as SettingsIcon,
} from 'lucide-react';
import clsx from 'clsx';

const NAV = [
  { to: '/console', label: 'Console', Icon: LayoutDashboard, section: 'OPERATIONS' },
  { to: '/ues', label: 'UE Manager', Icon: Smartphone, section: 'OPERATIONS' },
  { to: '/scenarios', label: 'Scenarios', Icon: Workflow, section: 'WORKFLOWS' },
  { to: '/scenarios/monitor', label: 'Execution Monitor', Icon: Activity, section: 'WORKFLOWS' },
  { to: '/history', label: 'History', Icon: History, section: 'REVIEW' },
  { to: '/settings', label: 'Settings', Icon: SettingsIcon, section: 'PLATFORM' },
] as const;

const SECTIONS = ['OPERATIONS', 'WORKFLOWS', 'REVIEW', 'PLATFORM'] as const;

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
          {NAV.filter((item) => item.section === section).map(({ to, label, Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/scenarios'}
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
          ))}
        </div>
      ))}
    </nav>
  );
}
