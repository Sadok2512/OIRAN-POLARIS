import { PageHeader } from '@/ui/PageHeader';
import { StatusIndicator } from '@/ui/StatusIndicator';
import { EmptyState, LoadingSkeleton, Unavailable } from '@/ui/EmptyErrorLoading';
import { useAuth, useCapabilities, useScenarioCapabilities } from '@/data/queries';
import { useAssignments, useScenarios } from '@/scenarios/store';

export function SettingsPage() {
  const auth = useAuth();
  const capabilities = useCapabilities();
  const scenarioCapabilities = useScenarioCapabilities();
  const library = useScenarios();
  const assignments = useAssignments();

  return (
    <>
      <PageHeader
        eyebrow="Platform"
        title="Settings"
        description="Deployment-controlled toggles are read-only from this UI. The frontend never writes permissions."
      />
      <div className="grid gap-4 md:grid-cols-2">
        <section className="ep-card p-5">
          <h2 className="text-ep-md font-semibold mb-2">Operator account</h2>
          {auth.isLoading ? (
            <LoadingSkeleton label="Loading" />
          ) : auth.data?.authenticated ? (
            <dl className="grid grid-cols-2 gap-x-5 gap-y-1 text-ep-sm">
              <dt className="text-text-secondary">Username</dt>
              <dd>{auth.data.username}</dd>
              <dt className="text-text-secondary">Role</dt>
              <dd>{auth.data.role}</dd>
              <dt className="text-text-secondary">Can start</dt>
              <dd>{auth.data.can_start ? 'Yes' : 'No'}</dd>
              <dt className="text-text-secondary">Manage permissions</dt>
              <dd>{auth.data.can_manage_permissions ? 'Yes' : 'No'}</dd>
            </dl>
          ) : (
            <EmptyState
              title="Not authenticated"
              description="Sign in through the POLARIS operator flow to enable write actions."
            />
          )}
        </section>

        <section className="ep-card p-5">
          <h2 className="text-ep-md font-semibold mb-2">Scenario execution policy</h2>
          {scenarioCapabilities.isLoading ? (
            <LoadingSkeleton label="Loading" />
          ) : scenarioCapabilities.data ? (
            <dl className="grid grid-cols-2 gap-x-5 gap-y-1 text-ep-sm">
              <dt className="text-text-secondary">Execution status</dt>
              <dd>
                <StatusIndicator state={scenarioCapabilities.data.execution_status} compact />
              </dd>
              <dt className="text-text-secondary">Reason</dt>
              <dd>{scenarioCapabilities.data.reason}</dd>
              <dt className="text-text-secondary">Role seen by backend</dt>
              <dd>{scenarioCapabilities.data.role}</dd>
              <dt className="text-text-secondary">Certified profiles</dt>
              <dd className="num">{scenarioCapabilities.data.items.length}</dd>
            </dl>
          ) : (
            <Unavailable reason="Backend did not return scenario capabilities." />
          )}
        </section>

        <section className="ep-card p-5">
          <h2 className="text-ep-md font-semibold mb-2">Local scenario catalog</h2>
          <dl className="grid grid-cols-2 gap-x-5 gap-y-1 text-ep-sm">
            <dt className="text-text-secondary">Scenarios saved locally</dt>
            <dd className="num">{library.scenarios.length}</dd>
            <dt className="text-text-secondary">UE assignments</dt>
            <dd className="num">{assignments.assignments.length}</dd>
            <dt className="text-text-secondary">Persistence</dt>
            <dd>localStorage (polaris.scenarios.v1 / polaris.assignments.v1)</dd>
            <dt className="text-text-secondary">Server-side CRUD</dt>
            <dd>Not available — see docs</dd>
          </dl>
          <p className="text-ep-xs text-text-secondary mt-2">
            A dedicated backend contract (`GET/POST/PUT/DELETE /scenarios/definitions`) is required to move the catalog
            off the browser. See <code className="mono">docs/frontend/SIMULATOR_SCENARIO_BUILDER.md</code>.
          </p>
        </section>

        <section className="ep-card p-5">
          <h2 className="text-ep-md font-semibold mb-2">Approved destinations</h2>
          {capabilities.data?.approved_destinations?.length ? (
            <ul className="flex flex-wrap gap-1 text-ep-xs">
              {capabilities.data.approved_destinations.map((destination) => (
                <li key={destination}>
                  <span className="ep-badge mono">{destination}</span>
                </li>
              ))}
            </ul>
          ) : (
            <Unavailable reason="Backend did not report approved destinations." />
          )}
        </section>
      </div>
    </>
  );
}
