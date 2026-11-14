import { Navigate, Route, Routes } from 'react-router-dom';
import { lazy, Suspense } from 'react';
import { AppShell } from '@/layout/AppShell';
const ConsolePage = lazy(() => import('@/pages/Console').then((m) => ({ default: m.ConsolePage })));
const TopologyPage = lazy(() => import('@/pages/Topology').then((m) => ({ default: m.TopologyPage })));
const CoreOpen5gsPage = lazy(() => import('@/pages/CoreOpen5gs').then((m) => ({ default: m.CoreOpen5gsPage })));
const GnbsPage = lazy(() => import('@/pages/Gnbs').then((m) => ({ default: m.GnbsPage })));
const UeManagerPage = lazy(() => import('@/pages/UeManager').then((m) => ({ default: m.UeManagerPage })));
const UeDetailPage = lazy(() => import('@/pages/UeDetail').then((m) => ({ default: m.UeDetailPage })));
const UeActivityPage = lazy(() => import('@/pages/UeActivity').then((m) => ({ default: m.UeActivityPage })));
const TrafficPage = lazy(() => import('@/pages/Traffic').then((m) => ({ default: m.TrafficPage })));
const TrafficSessionsPage = lazy(() => import('@/pages/TrafficSessions').then((m) => ({ default: m.TrafficSessionsPage })));
const ScenariosLibraryPage = lazy(() => import('@/pages/ScenariosLibrary').then((m) => ({ default: m.ScenariosLibraryPage })));
const ScenarioBuilderPage = lazy(() => import('@/pages/ScenarioBuilder').then((m) => ({ default: m.ScenarioBuilderPage })));
const ExecutionMonitorPage = lazy(() => import('@/pages/ExecutionMonitor').then((m) => ({ default: m.ExecutionMonitorPage })));
const HistoryPage = lazy(() => import('@/pages/History').then((m) => ({ default: m.HistoryPage })));
const ProvisioningPage = lazy(() => import('@/pages/Provisioning').then((m) => ({ default: m.ProvisioningPage })));
const SettingsPage = lazy(() => import('@/pages/Settings').then((m) => ({ default: m.SettingsPage })));
const LabUesPage = lazy(() => import('@/lab/LabUes').then((m) => ({ default: m.LabUesPage })));
const LabUeMonitorPage = lazy(() => import('@/lab/LabUeMonitor').then((m) => ({ default: m.LabUeMonitorPage })));
const LabScenariosPage = lazy(() => import('@/lab/LabScenarios').then((m) => ({ default: m.LabScenariosPage })));

const Loading = () => <p className="p-6 text-mute">Chargement…</p>;

export function App() {
  return (
    <Suspense fallback={<Loading />}>
    <Routes>
      <Route element={<AppShell />}>
        {/* 0.36.0 — simplified lab pages (user mockup). */}
        <Route path="/lab/ues" element={<LabUesPage />} />
        <Route path="/lab/ues/:ueId" element={<LabUeMonitorPage />} />
        <Route path="/lab/scenarios" element={<LabScenariosPage />} />
        <Route index element={<Navigate to="/lab/ues" replace />} />
        <Route path="/console" element={<ConsolePage />} />
        {/* Network section (new in 0.4.0). Composed from /lab + /nodes + /ues. */}
        <Route path="/network/topology" element={<TopologyPage />} />
        <Route path="/network/core" element={<CoreOpen5gsPage />} />
        <Route path="/network/gnbs" element={<GnbsPage />} />
        {/* Legacy /nodes stays alive and redirects into the new section. */}
        <Route path="/nodes" element={<Navigate to="/network/gnbs" replace />} />
        <Route path="/ues" element={<UeManagerPage />} />
        <Route path="/ues/:ueId" element={<UeDetailPage />} />
        {/* 0.11.0 (#37) — Per-UE Activity page, SSE-backed. */}
        <Route path="/ues/:ueId/activity" element={<UeActivityPage />} />
        <Route path="/provisioning" element={<ProvisioningPage />} />
        <Route path="/traffic" element={<TrafficPage />} />
        {/* 0.13.0 (#47) — Traffic Generator against polaris-api 0.20.0. */}
        <Route path="/traffic/sessions" element={<TrafficSessionsPage />} />
        <Route path="/scenarios" element={<ScenariosLibraryPage />} />
        <Route path="/scenarios/new" element={<ScenarioBuilderPage />} />
        <Route path="/scenarios/:scenarioId/edit" element={<ScenarioBuilderPage />} />
        <Route path="/scenarios/monitor" element={<ExecutionMonitorPage />} />
        <Route path="/history" element={<HistoryPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/console" replace />} />
      </Route>
    </Routes>
    </Suspense>
  );
}
