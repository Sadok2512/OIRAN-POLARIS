import { Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from '@/layout/AppShell';
import { ConsolePage } from '@/pages/Console';
import { TopologyPage } from '@/pages/Topology';
import { CoreOpen5gsPage } from '@/pages/CoreOpen5gs';
import { GnbsPage } from '@/pages/Gnbs';
import { UeManagerPage } from '@/pages/UeManager';
import { UeDetailPage } from '@/pages/UeDetail';
import { UeActivityPage } from '@/pages/UeActivity';
import { TrafficPage } from '@/pages/Traffic';
import { TrafficSessionsPage } from '@/pages/TrafficSessions';
import { ScenariosLibraryPage } from '@/pages/ScenariosLibrary';
import { ScenarioBuilderPage } from '@/pages/ScenarioBuilder';
import { ExecutionMonitorPage } from '@/pages/ExecutionMonitor';
import { HistoryPage } from '@/pages/History';
import { ProvisioningPage } from '@/pages/Provisioning';
import { SettingsPage } from '@/pages/Settings';

export function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Navigate to="/console" replace />} />
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
  );
}
