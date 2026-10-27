import { Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from '@/layout/AppShell';
import { ConsolePage } from '@/pages/Console';
import { UeManagerPage } from '@/pages/UeManager';
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
        <Route path="/ues" element={<UeManagerPage />} />
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
