import { Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from '@/layout/AppShell';
import { ConsolePage } from '@/pages/Console';
import { TopologyPage } from '@/pages/Topology';
import { CoreOpen5gsPage } from '@/pages/CoreOpen5gs';
import { GnbsPage } from '@/pages/Gnbs';
import { UeManagerPage } from '@/pages/UeManager';
import { TrafficPage } from '@/pages/Traffic';
import { ScenariosLibraryPage } from '@/pages/ScenariosLibrary';
import { ScenarioBuilderPage } from '@/pages/ScenarioBuilder';
import { ExecutionMonitorPage } from '@/pages/ExecutionMonitor';
import { HistoryPage } from '@/pages/History';
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
        <Route path="/traffic" element={<TrafficPage />} />
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
