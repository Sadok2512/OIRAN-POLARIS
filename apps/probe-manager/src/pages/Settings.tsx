import { PageHeader } from '@/ui/PageHeader';
import { StatusIndicator } from '@/ui/StatusIndicator';
import { EmptyState } from '@/ui/EmptyErrorLoading';
import { useAuth } from '@/data/queries';

export function SettingsPage() {
  const auth = useAuth();

  return (
    <>
      <PageHeader
        eyebrow="Platform"
        title="Settings"
        description="Deployment-controlled toggles are read-only from this UI. The frontend does not write capture permissions."
      />
      <div className="grid gap-4 md:grid-cols-2">
        <article className="ep-card p-5">
          <h2 className="text-ep-md font-semibold mb-3">Authentication</h2>
          {auth.data?.authenticated ? (
            <dl className="grid grid-cols-2 gap-x-5 gap-y-1 text-ep-sm">
              <dt className="text-text-secondary">Status</dt>
              <dd>
                <StatusIndicator state="AUTHENTICATED" tone="success" compact />
              </dd>
              <dt className="text-text-secondary">Role</dt>
              <dd>{auth.data.role}</dd>
              <dt className="text-text-secondary">Permissions</dt>
              <dd>{auth.data.permissions.join(', ') || '—'}</dd>
              <dt className="text-text-secondary">Capture control</dt>
              <dd>{auth.data.capture_control ? 'Granted' : 'Denied'}</dd>
              <dt className="text-text-secondary">Execution gate</dt>
              <dd>{auth.data.capture_execution_enabled ? 'Enabled' : 'Disabled'}</dd>
              <dt className="text-text-secondary">Reason</dt>
              <dd className="break-words">{auth.data.reason || '—'}</dd>
            </dl>
          ) : (
            <EmptyState
              title="Not authenticated"
              description="Operator permissions require validation through the Operator Login control. Login remains disabled on public HTTP and requires HTTPS or a private localhost tunnel."
            />
          )}
        </article>

        <article className="ep-card p-5">
          <h2 className="text-ep-md font-semibold mb-3">
            Operational boundaries
          </h2>
          <ul className="text-ep-sm text-text-secondary list-disc pl-5 flex flex-col gap-1">
            <li>No capture command is executed from this UI during review.</li>
            <li>Start/Stop requests are built on the client and sent to the backend only after an explicit confirmation.</li>
            <li>Original PCAPs remain immutable. The Capture Library preserves <code className="mono">capture_id</code> and <code className="mono">dataset_id</code> when opening the Analyzer.</li>
            <li>Fixture data is only used in isolated Storybook/tests. Production views stay honest: unknown counters render as <em>Not available</em>.</li>
          </ul>
        </article>
      </div>
    </>
  );
}
