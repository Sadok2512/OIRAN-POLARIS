import { PageHeader } from '@/ui/PageHeader';
import { StatusIndicator } from '@/ui/StatusIndicator';
import {
  EmptyState,
  ErrorState,
  LoadingSkeleton,
  Unavailable,
} from '@/ui/EmptyErrorLoading';
import {
  useAuth,
  useCapabilities,
  useLab,
  useScenarioRuntime,
  useSystemHealth,
  useTraffic,
  useUes,
} from '@/data/queries';
import { useScenarios } from '@/scenarios/store';
import { bytes, count, percent } from '@/data/format';

function Tile({ label, value, sub, state }: { label: string; value: string; sub?: string; state?: string }) {
  return (
    <div className="ep-card p-4 flex flex-col gap-1" data-testid="metric-tile">
      <div className="flex items-center justify-between">
        <span className="text-ep-xs uppercase tracking-wider text-text-secondary">{label}</span>
        {state && <StatusIndicator state={state} compact />}
      </div>
      <strong className="text-ep-xl num">{value}</strong>
      {sub && <span className="text-ep-xs text-text-secondary">{sub}</span>}
    </div>
  );
}

export function ConsolePage() {
  const auth = useAuth();
  const capabilities = useCapabilities();
  const lab = useLab();
  const health = useSystemHealth();
  const ues = useUes();
  const runtime = useScenarioRuntime();
  const traffic = useTraffic();
  const library = useScenarios();

  const loading = capabilities.isLoading || lab.isLoading || health.isLoading;
  const error = capabilities.error || lab.error || health.error;

  const active = runtime.data?.active_job;

  return (
    <>
      <PageHeader
        eyebrow="Operations"
        title="Console"
        description="Live lab state and certified scenario capability from POLARIS Control. Every counter is backend-reported; absent values render as 'Not available'."
        actions={
          <StatusIndicator
            state={auth.data?.authenticated ? 'OPERATOR_READY' : 'VIEWER_READONLY'}
            tone={auth.data?.can_start ? 'success' : 'warning'}
            label={auth.data?.authenticated ? `Signed in as ${auth.data.username}` : 'Not authenticated'}
          />
        }
      />

      {loading && !lab.data && <LoadingSkeleton label="Loading lab state" />}
      {error && !loading && (
        <ErrorState
          title="Could not load POLARIS console"
          detail={(error as Error).message}
          onRetry={() => {
            void capabilities.refetch();
            void lab.refetch();
            void health.refetch();
          }}
        />
      )}

      {!loading && !error && (
        <div className="grid gap-4 grid-cols-2 md:grid-cols-4">
          <Tile
            label="Configured UEs"
            value={count(lab.data?.ue_count)}
            sub={`${lab.data?.observed_total_running ?? 0} running`}
          />
          <Tile
            label="Registered UEs"
            value={count(ues.data?.registered_count)}
            sub={`${ues.data?.pdu_session_count ?? 0} PDU active`}
          />
          <Tile
            label="Scenario mode"
            value={capabilities.data?.live_control ? 'LIVE' : 'READ_ONLY'}
            sub={capabilities.data?.approval_state ?? ''}
          />
          <Tile
            label="Scenario library"
            value={count(library.scenarios.length)}
            sub="local, see docs"
          />
          <Tile
            label="CPU usage"
            value={percent(health.data?.cpu?.usage_percent)}
            sub={`${health.data?.cpu?.logical_cpus ?? 0} logical CPUs`}
          />
          <Tile
            label="Memory available"
            value={bytes(health.data?.memory.available_bytes)}
            sub={`disk ${percent(health.data?.disk?.usage_percent)}`}
          />
          <Tile
            label="Active scenario"
            value={active?.scenario_id ?? 'None'}
            sub={active ? `${active.target_ue_id ?? ''} · ${active.state}` : 'idle'}
            state={active ? 'RUNNING' : undefined}
          />
          <Tile
            label="Traffic state"
            value={traffic.data?.state ?? 'UNKNOWN'}
            sub={
              traffic.data?.packets_sent != null
                ? `${count(traffic.data.packets_sent)} / ${count(traffic.data.packets_requested)} sent`
                : 'No traffic observed'
            }
          />
        </div>
      )}

      {!loading && !error && (
        <section className="mt-6 ep-card p-5">
          <h2 className="text-ep-md font-semibold mb-2">Certified scenario profiles</h2>
          {!capabilities.data?.profiles?.length ? (
            <Unavailable reason="POLARIS did not expose any certified scenario profile." />
          ) : (
            <ul className="flex flex-wrap gap-2 text-ep-xs">
              {capabilities.data.profiles.map((profile) => (
                <li key={profile.id} className="ep-badge mono">
                  {profile.name} · {profile.source}
                  {profile.subscription_verified ? ' · verified' : ''}
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      {!loading && !error && library.scenarios.length === 0 && (
        <EmptyState
          title="No user scenario yet"
          description="Create a scenario in the Scenarios page to compose a multi-step mobile workflow."
        />
      )}
    </>
  );
}
