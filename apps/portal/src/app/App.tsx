import { AppLauncher } from '@/components/AppLauncher';
import { PortalHeader } from '@/components/PortalHeader';
import { PortalFooter } from '@/components/PortalFooter';
import { usePortalConfig } from '@/config/usePortalConfig';

export function App() {
  const { apps, loading, error } = usePortalConfig();

  return (
    <div className="min-h-screen flex flex-col">
      <PortalHeader />
      <main className="flex-1">
        <section className="mx-auto max-w-6xl px-6 py-10">
          <header className="mb-8">
            <p className="text-ep-xs font-semibold tracking-wider text-text-secondary uppercase">
              Telecom Platform
            </p>
            <h1 className="text-ep-h1 font-semibold text-text-primary mt-1">
              Choose a workspace
            </h1>
            <p className="text-ep-md text-text-secondary mt-2 max-w-2xl">
              Three independent applications share a common authentication,
              design system and API contract. Each opens in its own tab; the
              portal only displays reachability and does not embed them.
            </p>
          </header>

          {error && (
            <div
              role="alert"
              className="ep-card border-error/30 mb-6 p-4 text-ep-sm"
            >
              <strong className="text-error">
                Portal configuration unavailable.
              </strong>
              <span className="ml-2 text-text-secondary">
                Static defaults are being used. Error: {error.message}
              </span>
            </div>
          )}

          <div
            className="grid gap-5 grid-cols-1 md:grid-cols-2 lg:grid-cols-3"
            data-testid="app-grid"
          >
            {apps.map((app) => (
              <AppLauncher key={app.id} app={app} loading={loading} />
            ))}
          </div>

          <section
            className="ep-card mt-8 p-4 text-ep-sm text-text-secondary flex flex-col gap-1"
            data-testid="responsibilities"
            aria-label="Responsibilities"
          >
            <p className="font-medium text-text-primary">Responsibilities</p>
            <p>
              <span className="text-text-primary font-medium">POLARIS Control</span> drives the
              lab network: Open5GS core, gNodeBs and eNB, topology, UEs and scenarios.
            </p>
            <p>
              <span className="text-text-primary font-medium">Probe Manager</span> manages probes
              only — virtual and physical, several interfaces each. Topology moved to POLARIS.
            </p>
            <p>
              <span className="text-text-primary font-medium">OIRAN Analyzer</span> replays
              captured sessions: call flow, correlation and packet forensics across datasets.
            </p>
            <p>
              Health is an anonymous <code className="mono">GET</code> on each app's own API
              base; no token is ever sent to a sibling app.
            </p>
          </section>
        </section>
      </main>
      <PortalFooter />
    </div>
  );
}
