import { Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from '@/layout/AppShell';
import { OverviewPage } from '@/pages/Overview';
import { DatasetsPage } from '@/pages/Datasets';
import { SessionExplorerPage } from '@/pages/SessionExplorer';
import { SignalingPage } from '@/pages/Signaling';
import { UserPlanePage } from '@/pages/UserPlane';
import { CorrelationStudioPage } from '@/pages/CorrelationStudio';
import { PacketAnalyzerPage } from '@/pages/PacketAnalyzer';
import { KpiPage } from '@/pages/Kpi';

export function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Navigate to="/overview" replace />} />
        <Route path="/overview" element={<OverviewPage />} />
        <Route path="/datasets" element={<DatasetsPage />} />
        <Route path="/investigation/sessions" element={<SessionExplorerPage />} />
        <Route
          path="/investigation/sessions/:sessionId"
          element={<SessionExplorerPage />}
        />
        <Route path="/investigation/signaling" element={<SignalingPage />} />
        <Route
          path="/investigation/signaling/:sessionId"
          element={<SignalingPage />}
        />
        <Route path="/investigation/user-plane" element={<UserPlanePage />} />
        <Route
          path="/investigation/correlation"
          element={<CorrelationStudioPage />}
        />
        <Route
          path="/investigation/correlation/:sessionId"
          element={<CorrelationStudioPage />}
        />
        <Route path="/analysis/packets" element={<PacketAnalyzerPage />} />
        <Route path="/analysis/kpi" element={<KpiPage />} />
        <Route path="*" element={<Navigate to="/overview" replace />} />
      </Route>
    </Routes>
  );
}
