import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Smartphone,
  Workflow,
  Activity,
  History,
  Antenna,
  Cpu,
  Network,
} from 'lucide-react';
import clsx from 'clsx';

const NAV = [
  { to: '/console', label: 'Console', Icon: LayoutDashboard, section: 'Network' },
  { to: '/network/topology', label: 'Topology', Icon: Network, section: 'Network' },
  { to: '/network/core', label: 'Core · Open5GS', Icon: Cpu, section: 'Network' },
  { to: '/network/gnbs', label: 'gNodeBs', Icon: Antenna, section: 'Network' },
  { to: '/ues', label: 'UE Manager', Icon: Smartphone, section: 'Simulation' },
  { to: '/scenarios', label: 'Scenarios', Icon: Workflow, section: 'Simulation' },
  { to: '/scenarios/monitor', label: 'Execution monitor', Icon: Activity, section: 'Simulation' },
  { to: '/history', label: 'History', Icon: History, section: 'Review' },
] as const;

const SECTIONS = ['Network', 'Simulation', 'Review'] as const;

export function SidebarNavigation({ collapsed }: { collapsed: boolean }) {
  return (
    <nav
      className={clsx(
        'flex-1 flex flex-col gap-3 py-3 overflow-y-auto',
        collapsed ? 'px-2' : 'px-3',
      )}
      aria-label="Primary"
    >
      {SECTIONS.map((section) => (
        <div key={section} className="flex flex-col gap-1">
          {!collapsed && (
            <p className="px-2 py-1 text-ep-xs font-semibold uppercase tracking-wider text-mute">
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
                  'flex items-center gap-2.5 whitespace-nowrap rounded-md px-2.5 py-2 text-ep-md transition-colors',
                  isActive
                    ? 'bg-surface text-ink font-medium shadow-e1'
                    : 'text-mute hover:text-ink hover:bg-surface',
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
      {!collapsed && (
        <p className="mt-2 mx-2 border-t border-line pt-3 text-ep-sm text-mute">
          Probes and captures are managed in the OIRAN Probe Manager.
        </p>
      )}
    </nav>
  );
}
