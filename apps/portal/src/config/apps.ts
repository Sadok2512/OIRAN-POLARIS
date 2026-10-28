import { Activity, Radio, SlidersHorizontal } from 'lucide-react';
import type { ComponentType, SVGProps } from 'react';
import type { AuthScope } from '@shared/api';

export type AppHealthEndpoint = {
  /** Health path (e.g. `/health`, `/system/health`). */
  path: string;
  /** API base; defaults to each app's own `base`. */
  base?: string;
};

export type AppDescriptor = {
  id: 'simulator' | 'probe-manager' | 'oiran-analyzer';
  name: string;
  tagline: string;
  description: string;
  /** Short scope chips shown under the description (mockup 0.2.0). */
  scope: string[];
  Icon: ComponentType<SVGProps<SVGSVGElement>>;
  openUrl: string;
  /** API base owned by this app. Health probes default to this base. */
  apiBase: string;
  /** Scope that owns this app's authentication token. */
  authScope: AuthScope;
  health?: AppHealthEndpoint;
  accent: 'blue' | 'purple' | 'teal';
};

// URLs are overridable from the environment at build time. Each app also
// owns an API base — the Portal must NOT reuse OIRAN's base when checking
// POLARIS, otherwise the OIRAN access token would leak to the POLARIS
// origin (see docs/contracts/AUTHENTICATION_BOUNDARIES.md and the PR #2
// review Section 3).
const env = import.meta.env ?? {};

const APP_URLS = {
  simulator: env.VITE_APP_SIMULATOR_URL ?? '/simulator/',
  probeManager: env.VITE_APP_PROBE_MANAGER_URL ?? '/probe-manager/',
  oiranAnalyzer: env.VITE_APP_OIRAN_URL ?? '/analyzer/',
} as const;

const API_BASES = {
  simulator: env.VITE_API_BASE_SIMULATOR ?? '/polaris-api/v1',
  probeManager: env.VITE_API_BASE_PROBE_MANAGER ?? '/api/v1',
  oiranAnalyzer: env.VITE_API_BASE_OIRAN ?? '/api/v1',
} as const;

export const APPS: AppDescriptor[] = [
  {
    id: 'simulator',
    // Mockup 0.2.0: the brick is "POLARIS Control" (the backend product),
    // not "Simulator Control" (its old umbrella name).
    name: 'POLARIS Control',
    tagline: 'Core · RAN · UE · Scenarios',
    description:
      'Operate the 5G SA lab: Open5GS core functions, gNodeBs and eNB, network topology, UE profiles and bounded scenarios.',
    scope: ['Open5GS', 'gNB / eNB', 'Topology', 'UE Manager', 'Scenarios'],
    Icon: SlidersHorizontal,
    openUrl: APP_URLS.simulator,
    apiBase: API_BASES.simulator,
    authScope: 'polaris',
    health: { path: '/system/health' },
    accent: 'blue',
  },
  {
    id: 'probe-manager',
    name: 'Probe Manager',
    tagline: 'vProbes · Physical probes · Captures',
    description:
      'Register and supervise probes, each with several capture interfaces. Follow live captures, disk budget and the capture library. Topology moved to POLARIS.',
    scope: ['Probes', 'Interfaces', 'Live captures', 'Library'],
    Icon: Radio,
    openUrl: APP_URLS.probeManager,
    apiBase: API_BASES.probeManager,
    authScope: 'probe-manager',
    health: { path: '/health' },
    accent: 'purple',
  },
  {
    id: 'oiran-analyzer',
    name: 'OIRAN Analyzer',
    tagline: 'Call flow · Correlation · Packet forensics',
    description:
      'Reconstruct sessions, inspect decoded IE trees, correlate N2 ↔ SBI ↔ N4 ↔ N3 evidence across datasets.',
    scope: ['Sessions', 'Call flow', 'Correlation', 'Packets', 'Datasets'],
    Icon: Activity,
    openUrl: APP_URLS.oiranAnalyzer,
    apiBase: API_BASES.oiranAnalyzer,
    authScope: 'oiran',
    health: { path: '/health' },
    accent: 'teal',
  },
];
