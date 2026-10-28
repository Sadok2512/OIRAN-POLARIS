import { Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from '@/layout/AppShell';
import { OverviewPage } from '@/pages/Overview';
import { ProbesPage } from '@/pages/Probes';
import { InterfacesPage } from '@/pages/Interfaces';
import { LiveCapturesPage } from '@/pages/LiveCaptures';
import { CaptureLibraryPage } from '@/pages/CaptureLibrary';
import { SettingsPage } from '@/pages/Settings';
import { TopologyMovedPage } from '@/pages/TopologyMoved';

export function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Navigate to="/overview" replace />} />
        <Route path="/overview" element={<OverviewPage />} />
        {/* Topology moved to POLARIS Simulator Control (LOT 1, 0.2.0). */}
        <Route path="/topology" element={<TopologyMovedPage />} />
        <Route path="/probes" element={<ProbesPage />} />
        <Route path="/probes/:probeId" element={<ProbesPage />} />
        <Route path="/interfaces" element={<InterfacesPage />} />
        <Route path="/interfaces/:interfaceId" element={<InterfacesPage />} />
        <Route path="/live-captures" element={<LiveCapturesPage />} />
        <Route path="/capture-library" element={<CaptureLibraryPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/overview" replace />} />
      </Route>
    </Routes>
  );
}
