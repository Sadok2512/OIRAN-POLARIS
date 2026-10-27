import { useState } from 'react';
import { PageHeader } from '@/ui/PageHeader';
import { StatusIndicator } from '@/ui/StatusIndicator';
import { LoadingSkeleton, Unavailable } from '@/ui/EmptyErrorLoading';
import {
  useAuth,
  useCapabilities,
  useLogin,
  useLogout,
  useScenarioCapabilities,
} from '@/data/queries';
import { useAssignments, useScenarios } from '@/scenarios/store';

export function SettingsPage() {
  const auth = useAuth();
  const capabilities = useCapabilities();
  const scenarioCapabilities = useScenarioCapabilities();
  const library = useScenarios();
  const assignments = useAssignments();
  const login = useLogin();
  const logout = useLogout();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState<string | null>(null);

  const secureTransport =
    typeof window === 'undefined' ||
    window.location.protocol === 'https:' ||
    window.location.hostname === '127.0.0.1' ||
    window.location.hostname === 'localhost';

  async function handleLogin(event: React.FormEvent) {
    event.preventDefault();
    setMessage(null);
    try {
      await login.mutateAsync({ username: username.trim(), password });
      setPassword('');
      setMessage(`Signed in as ${username}.`);
    } catch (error) {
      setMessage((error as Error).message.replaceAll('_', ' '));
      setPassword('');
    }
  }

  async function handleLogout() {
    setMessage(null);
    try {
      await logout.mutateAsync();
      setMessage('Signed out.');
    } catch (error) {
      setMessage((error as Error).message.replaceAll('_', ' '));
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Platform"
        title="Settings"
        description="Deployment-controlled toggles are read-only from this UI. The frontend never writes permissions."
      />
      <div className="grid gap-4 md:grid-cols-2">
        <section className="ep-card p-5" data-testid="operator-account">
          <h2 className="text-ep-md font-semibold mb-2">Operator account</h2>
          {auth.isLoading ? (
            <LoadingSkeleton label="Loading" />
          ) : auth.data?.authenticated ? (
            <>
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
              <button
                type="button"
                className="ep-button ep-button-sm mt-3"
                onClick={() => void handleLogout()}
                disabled={logout.isPending}
                data-testid="operator-logout"
              >
                Sign out
              </button>
            </>
          ) : (
            <form className="flex flex-col gap-2" onSubmit={handleLogin} data-testid="operator-login-form">
              {!secureTransport && (
                <p className="text-ep-xs text-error">
                  Operator sign-in requires HTTPS or localhost — the browser URL does not meet that requirement.
                </p>
              )}
              <label className="flex flex-col gap-1 text-ep-sm">
                <span className="text-text-secondary">Username</span>
                <input
                  className="ep-input"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  autoComplete="username"
                  disabled={!secureTransport}
                  data-testid="operator-login-username"
                />
              </label>
              <label className="flex flex-col gap-1 text-ep-sm">
                <span className="text-text-secondary">Password</span>
                <input
                  type="password"
                  className="ep-input"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  autoComplete="current-password"
                  disabled={!secureTransport}
                  data-testid="operator-login-password"
                />
              </label>
              <button
                type="submit"
                className="ep-button ep-button-sm ep-button-primary mt-1"
                disabled={!secureTransport || login.isPending || !username.trim() || !password}
                data-testid="operator-login-submit"
              >
                {login.isPending ? 'Signing in…' : 'Sign in securely'}
              </button>
            </form>
          )}
          {message && (
            <p className="text-ep-xs text-text-secondary mt-2" data-testid="operator-login-feedback">
              {message}
            </p>
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
