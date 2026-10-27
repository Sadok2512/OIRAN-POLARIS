import { Activity, Radio, SlidersHorizontal } from 'lucide-react';
import type { ComponentType, SVGProps } from 'react';

export type AppHealthEndpoint = {
  /** OIRAN v1-style health path reachable via the configured API base. */
  path: string;
  /** API base; defaults to `/api/v1`. Can be overridden per app. */
  base?: string;
};

export type AppDescriptor = {
  id: 'simulator' | 'probe-manager' | 'oiran-analyzer';
  name: string;
  tagline: string;
  description: string;
  Icon: ComponentType<SVGProps<SVGSVGElement>>;
  openUrl: string;
  health?: AppHealthEndpoint;
  accent: 'blue' | 'purple' | 'teal';
};

// URLs are overridable from the environment at build time. Falling back to
// hash-routed defaults assumes each app is served behind the same host under
// a per-app path.
const env = import.meta.env ?? {};

const APP_URLS = {
  simulator: env.VITE_APP_SIMULATOR_URL ?? '/polaris/',
  probeManager: env.VITE_APP_PROBE_MANAGER_URL ?? '/probe-manager/',
  oiranAnalyzer: env.VITE_APP_OIRAN_URL ?? '/oiran/',
} as const;

export const APPS: AppDescriptor[] = [
  {
    id: 'simulator',
    name: 'Simulator Control',
    tagline: 'POLARIS Control · 5G SA UERANSIM',
    description:
      'Operate the certified laboratory simulator: configure UE profiles, run bounded traffic, inspect scenario state.',
    Icon: SlidersHorizontal,
    openUrl: APP_URLS.simulator,
    health: { path: '/system/health' },
    accent: 'blue',
  },
  {
    id: 'probe-manager',
    name: 'Probe Manager',
    tagline: 'Topology · Probes · Live captures',
    description:
      'Visualize probes, interfaces and capture jobs. Start, stop and audit N2/N3/N4/SBI bounded captures.',
    Icon: Radio,
    openUrl: APP_URLS.probeManager,
    health: { path: '/health' },
    accent: 'purple',
  },
  {
    id: 'oiran-analyzer',
    name: 'OIRAN Analyzer',
    tagline: 'Call flow · Correlation · Packet forensics',
    description:
      'Reconstruct sessions, inspect decoded IE trees, correlate N2 ↔ SBI ↔ N4 ↔ N3 evidence across datasets.',
    Icon: Activity,
    openUrl: APP_URLS.oiranAnalyzer,
    health: { path: '/health' },
    accent: 'teal',
  },
];
