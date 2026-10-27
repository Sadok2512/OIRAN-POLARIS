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
        </section>
      </main>
      <PortalFooter />
    </div>
  );
}
