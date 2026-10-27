# Component inventory

All components are TypeScript + React 18 with Tailwind CSS. Shared code
lives in `packages/ui/src`; per-app code lives in `apps/portal/src` or
`apps/probe-manager/src`. Nothing is pulled from `node_modules` beyond
listed deps.

## Shared (`packages/ui/src`)

| File       | Purpose                                                  |
| ---------- | -------------------------------------------------------- |
| `tokens.ts`| Enterprise Precision color / spacing / typography tokens |
| `api.ts`   | Fetch wrapper, `ApiError`, session token helpers         |
| `types.ts` | Mirror of OIRAN v1 contract types                        |
| `theme.ts` | React-free theme persistence helpers                     |

## Portal (`apps/portal/src`)

| File                               | Component / module    | Notes                                                  |
| ---------------------------------- | --------------------- | ------------------------------------------------------ |
| `main.tsx`                         | Entry                 | QueryClient + React.StrictMode                         |
| `app/App.tsx`                      | `App`                 | Grid layout                                            |
| `app/App.test.tsx`                 | tests                 | 4 Vitest tests                                         |
| `components/AppLauncher.tsx`       | `AppLauncher`         | Launcher card                                          |
| `components/PortalHeader.tsx`      | `PortalHeader`        | Brand + theme switch                                   |
| `components/PortalFooter.tsx`      | `PortalFooter`        | Static footer                                          |
| `components/StatusDot.tsx`         | `StatusDot`           | Three-state reachability dot                           |
| `config/apps.ts`                   | `APPS` registry       | Descriptor + env-override URLs                         |
| `config/usePortalConfig.ts`        | `usePortalConfig`     | Query hook for health polling                          |
| `hooks/useTheme.ts`                | `useTheme`            | Preference persistence + media listener                |
| `styles/globals.css`               | tokens + classes      | Tailwind layers + CSS variables                        |
| `test/setup.ts`                    | test setup            | `matchMedia` polyfill                                  |

## Probe Manager (`apps/probe-manager/src`)

### Shell

| File                                     | Component                              |
| ---------------------------------------- | -------------------------------------- |
| `layout/AppShell.tsx`                    | `AppShell` + top bar + theme switch    |
| `layout/SidebarNavigation.tsx`           | `SidebarNavigation` (Operations / Capture / Platform) |

### UI primitives

| File                           | Exports                                                        |
| ------------------------------ | -------------------------------------------------------------- |
| `ui/PageHeader.tsx`            | `PageHeader`                                                   |
| `ui/StatusIndicator.tsx`       | `StatusIndicator`, `toneFor`                                   |
| `ui/EmptyErrorLoading.tsx`     | `EmptyState`, `ErrorState`, `LoadingSkeleton`, `Unavailable`   |
| `ui/ConfirmDialog.tsx`         | `ConfirmDialog`                                                |

### Pages

| File                                 | Component                 |
| ------------------------------------ | ------------------------- |
| `pages/Overview.tsx`                 | `OverviewPage`            |
| `pages/NetworkTopology.tsx`          | `NetworkTopologyPage`     |
| `pages/Probes.tsx`                   | `ProbesPage`              |
| `pages/Interfaces.tsx`               | `InterfacesPage`          |
| `pages/LiveCaptures.tsx`             | `LiveCapturesPage`        |
| `pages/CaptureLibrary.tsx`           | `CaptureLibraryPage`      |
| `pages/Settings.tsx`                 | `SettingsPage`            |

### Inspectors & topology

| File                                      | Export                   |
| ----------------------------------------- | ------------------------ |
| `components/ProbeInspector.tsx`           | `ProbeInspector`         |
| `components/InterfaceInspector.tsx`       | `InterfaceInspector`     |
| `topology/types.ts`                       | TypeScript types         |
| `topology/buildTopology.ts`               | `buildTopology`          |
| `topology/TelecomNode.tsx`                | `TelecomNode`            |
| `topology/TopologyInspector.tsx`          | `TopologyInspector`      |

### Data layer

| File                                | Hooks                                           |
| ----------------------------------- | ----------------------------------------------- |
| `data/queries.ts`                   | `useProbes`, `useInterfaces`, `useCaptures`, `useDiskSafety`, `useMetrics`, `useAuth` |
| `data/format.ts`                    | `bytes`, `bits`, `pps`, `percent`, `count`, `epochToLocal`, `isoToLocal`, `durationSeconds` |

### Tests

| File                                       | Suite                       | Tests |
| ------------------------------------------ | --------------------------- | ----- |
| `app/App.test.tsx`                         | Routing + nav + theme       | 5     |
| `pages/Overview.test.tsx`                  | Empty + unavailable states  | 2     |
| `pages/CaptureLibrary.test.tsx`            | Columns + filter + empty    | 4     |
| `topology/buildTopology.test.ts`           | Scaffold + discovery        | 2     |
| Portal `app/App.test.tsx`                  | Cards + health              | 4     |

Total **17 Vitest tests** (4 portal + 13 probe-manager) + **65 Playwright
screenshot specs** (every route × 4 viewports × 2 themes + 1 empty-state
capture).
