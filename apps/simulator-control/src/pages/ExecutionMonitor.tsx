import { useMemo } from 'react';
import { AlertTriangle, Info } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import { StatusIndicator } from '@/ui/StatusIndicator';
import { EmptyState, LoadingSkeleton } from '@/ui/EmptyErrorLoading';
import {
  useAuth,
  useScenarioRuntime,
  useStopScenario,
  useTraffic,
} from '@/data/queries';
import { useAssignments } from '@/scenarios/store';
import { useScenarioLibrary } from '@/scenarios/library';
import { ScenarioTimeline } from '@/components/ScenarioTimeline';
import { count, isoToLocal } from '@/data/format';
import { useFeatureFlag } from '@/data/featureFlags';
import { useScenarioSteps } from '@/data/scenarioApi';
import { epochSecondsToLocal, type WireScenarioStepStatus } from '@/scenarios/wireCodec';

export function ExecutionMonitorPage() {
  const auth = useAuth();
  const runtime = useScenarioRuntime();
  const traffic = useTraffic();
  const library = useScenarioLibrary();
  const assignments = useAssignments();
  const stopScenario = useStopScenario();
  const scenarioBackend = useFeatureFlag('scenarioBackend');

  const active = runtime.data?.active_job;
  const terminal = runtime.data?.latest_terminal_job;
  const current = active ?? terminal;
  // Definition jobs may already be terminal (mock mode completes synchronously), so follow the
  // current job — active, else latest terminal — rather than the active one only.
  const steps = useScenarioSteps(scenarioBackend ? current?.job_id ?? null : null);

  const scenarioForActive = useMemo(() => {
    if (!active?.target_ue_id) return null;
    const assignment = assignments.assignments.find(
      (item) => item.ueId === active.target_ue_id,
    );
    return assignment ? library.scenarios.find((s) => s.id === assignment.scenarioId) : null;
  }, [active?.target_ue_id, assignments.assignments, library.scenarios]);

  return (
    <>
      <PageHeader
        eyebrow="Workflows"
        title="Execution Monitor"
        description="Real backend scenario runtime (POLARIS /scenarios/status + /traffic/status). The local timeline is a projection of the assigned scenario definition — not an authoritative execution log."
        actions={
          <StatusIndicator
            state={auth.data?.can_start ? 'OPERATOR_READY' : 'VIEWER_READONLY'}
            tone={auth.data?.can_start ? 'success' : 'warning'}
            label={auth.data?.can_start ? 'Operator can stop' : 'Read-only'}
          />
        }
      />

      {runtime.isLoading && !runtime.data && <LoadingSkeleton label="Loading scenario runtime" />}

      {!runtime.isLoading && !active && !terminal && (
        <EmptyState
          title="No scenario run"
          description="No controller-owned job has been recorded by POLARIS yet. Start a scenario from UE Manager."
        />
      )}

      {current && (
        <>
          <section className="ep-card p-5 mb-4">
            <header className="flex items-start justify-between gap-3 mb-3">
              <div>
                <p className="text-ep-xs uppercase tracking-wider text-text-secondary">
                  Scenario Run
                </p>
                <h2 className="text-ep-h2 font-semibold">
                  {current.scenario_id}
                </h2>
                <p className="text-ep-xs text-text-secondary mt-0.5">
                  {current.technology} · {current.simulator}
                </p>
              </div>
              <StatusIndicator state={current.state} />
            </header>
            <dl className="grid grid-cols-2 md:grid-cols-4 gap-x-6 gap-y-1 text-ep-sm">
              <dt className="text-text-secondary">Job ID</dt>
              <dd className="mono text-ep-xs">{current.job_id ?? '—'}</dd>
              <dt className="text-text-secondary">Target UE</dt>
              <dd>{current.target_ue_id ?? '—'}</dd>
              <dt className="text-text-secondary">Started</dt>
              <dd>{isoToLocal(current.started_at)}</dd>
              <dt className="text-text-secondary">Duration</dt>
              <dd className="num">{current.duration_seconds}s</dd>
              <dt className="text-text-secondary">Registered UEs</dt>
              <dd className="num">{current.registered_ues}</dd>
              <dt className="text-text-secondary">Active PDU sessions</dt>
              <dd className="num">{current.active_pdu_sessions}</dd>
              <dt className="text-text-secondary">Traffic state</dt>
              <dd>{current.traffic_state}</dd>
              <dt className="text-text-secondary">Packets sent</dt>
              <dd className="num">
                {count(current.packets_sent)} / {count(current.packets_requested)}
              </dd>
              <dt className="text-text-secondary">CPU budget</dt>
              <dd>{current.cpu}</dd>
              <dt className="text-text-secondary">RAM budget</dt>
              <dd>{current.memory}</dd>
              <dt className="text-text-secondary">Terminal result</dt>
              <dd>{current.terminal_result ?? '—'}</dd>
              <dt className="text-text-secondary">Controller-owned</dt>
              <dd>{current.controller_owned ? 'Yes' : 'No'}</dd>
            </dl>

            {active && (
              <footer className="flex items-center justify-end gap-2 mt-3 border-t border-border pt-3">
                <span className="text-ep-xs text-text-secondary mr-auto">
                  Stop only affects the controller-owned job. The UE and its PDU stay running unless the scenario explicitly includes a stop and the backend authorizes it.
                </span>
                <button
                  type="button"
                  className="ep-button ep-button-sm ep-button-danger"
                  disabled={!auth.data?.can_start || !active.job_id || stopScenario.isPending}
                  onClick={() => active.job_id && stopScenario.mutate(active.job_id)}
                  data-testid="monitor-stop"
                >
                  Stop scenario
                </button>
              </footer>
            )}
          </section>

          <section className="ep-card p-5 mb-4">
            <header className="flex items-center justify-between mb-2">
              <h3 className="text-ep-md font-semibold">Traffic generator (POLARIS /traffic/status)</h3>
              <StatusIndicator state={traffic.data?.state ?? 'UNKNOWN'} compact />
            </header>
            {!traffic.data ? (
              <LoadingSkeleton label="Loading traffic" />
            ) : (
              <dl className="grid grid-cols-2 md:grid-cols-4 gap-x-6 gap-y-1 text-ep-sm">
                <dt className="text-text-secondary">Packets requested</dt>
                <dd className="num">{count(traffic.data.packets_requested)}</dd>
                <dt className="text-text-secondary">Packets sent</dt>
                <dd className="num">{count(traffic.data.packets_sent)}</dd>
                <dt className="text-text-secondary">Packets received</dt>
                <dd className="num">{count(traffic.data.packets_received)}</dd>
                <dt className="text-text-secondary">Bytes</dt>
                <dd className="num">{count(traffic.data.bytes)}</dd>
                <dt className="text-text-secondary">Current rate</dt>
                <dd className="num">
                  {traffic.data.current_rate_pps != null
                    ? `${traffic.data.current_rate_pps} pps`
                    : '—'}
                </dd>
                <dt className="text-text-secondary">TUN interface</dt>
                <dd className="mono">{traffic.data.tun_interface ?? '—'}</dd>
                <dt className="text-text-secondary">Target UE</dt>
                <dd>{traffic.data.target_ue_id ?? '—'}</dd>
                <dt className="text-text-secondary">Accounting source</dt>
                <dd>{traffic.data.accounting_source}</dd>
              </dl>
            )}
          </section>

          {scenarioBackend ? (
            <section className="ep-card p-5 mb-4" data-testid="backend-steps">
              <header className="flex items-center justify-between mb-2 gap-2">
                <h3 className="text-ep-md font-semibold">
                  Step execution (backend /scenarios/:job_id/steps)
                </h3>
                <StatusIndicator
                  state={steps.data ? 'LIVE' : steps.isLoading ? 'LOADING' : 'IDLE'}
                  tone={steps.data ? 'success' : 'neutral'}
                  compact
                />
              </header>
              {steps.data?.state ? (
                <dl className="grid grid-cols-2 md:grid-cols-4 gap-x-6 gap-y-1 text-ep-sm mb-3">
                  <dt className="text-text-secondary">Backend state</dt>
                  <dd data-testid="backend-steps-state">{steps.data.state}</dd>
                  <dt className="text-text-secondary">Started</dt>
                  <dd data-testid="backend-steps-started">
                    {steps.data.started_at
                      ? epochSecondsToLocal(steps.data.started_at)
                      : '—'}
                  </dd>
                  <dt className="text-text-secondary">Duration</dt>
                  <dd className="num" data-testid="backend-steps-duration">
                    {formatDurationMs(steps.data.duration_ms)}
                  </dd>
                  <dt className="text-text-secondary">Terminal step</dt>
                  <dd className="mono text-ep-xs" data-testid="backend-steps-failed-step">
                    {steps.data.failure?.step_id ?? '—'}
                  </dd>
                </dl>
              ) : null}
              {steps.data?.failure ? (
                <article
                  className="ep-card border-danger/40 bg-danger/5 p-3 mb-3 flex flex-col gap-2"
                  data-testid="backend-steps-failure"
                >
                  <header className="flex items-center gap-2 text-ep-sm">
                    <AlertTriangle className="text-danger" width={14} height={14} />
                    <span className="font-semibold">Scenario failed</span>
                    <span className="mono text-ep-xs">
                      {steps.data.failure.code ?? 'UNKNOWN_ERROR'}
                    </span>
                  </header>
                  {steps.data.failure.message ? (
                    <p className="text-ep-sm" data-testid="backend-steps-failure-message">
                      {steps.data.failure.message}
                    </p>
                  ) : null}
                  <dl className="grid grid-cols-2 md:grid-cols-4 gap-x-6 gap-y-1 text-ep-xs">
                    <dt className="text-text-secondary">Step name</dt>
                    <dd>{steps.data.failure.step_name ?? '—'}</dd>
                    <dt className="text-text-secondary">Started</dt>
                    <dd>
                      {steps.data.failure.started_at
                        ? epochSecondsToLocal(steps.data.failure.started_at)
                        : '—'}
                    </dd>
                    <dt className="text-text-secondary">Duration</dt>
                    <dd className="num">{formatDurationMs(steps.data.failure.duration_ms)}</dd>
                    <dt className="text-text-secondary">Ended</dt>
                    <dd>
                      {steps.data.failure.ended_at
                        ? epochSecondsToLocal(steps.data.failure.ended_at)
                        : '—'}
                    </dd>
                  </dl>
                  {steps.data.failure.failure_evidence ? (
                    <details className="text-ep-xs">
                      <summary className="cursor-pointer text-text-secondary">
                        failure_evidence (bounded)
                      </summary>
                      <pre
                        className="mono text-ep-xs mt-1 whitespace-pre-wrap"
                        data-testid="backend-steps-failure-evidence"
                      >
                        {JSON.stringify(steps.data.failure.failure_evidence, null, 2)}
                      </pre>
                    </details>
                  ) : null}
                </article>
              ) : null}
              {steps.isLoading && !steps.data && <LoadingSkeleton label="Loading /steps" />}
              {steps.error && (
                <p className="text-ep-xs text-error">
                  Could not load /scenarios/{current?.job_id}/steps:{' '}
                  {(steps.error as Error).message}
                </p>
              )}
              {steps.data && steps.data.steps.length === 0 && (
                <p className="text-ep-xs text-text-secondary">
                  Backend returned no step yet for job {current?.job_id ?? '—'}.
                </p>
              )}
              {steps.data && steps.data.steps.length > 0 && (
                <ol className="flex flex-col gap-1 text-ep-sm" data-testid="backend-steps-list">
                  {steps.data.steps.map((step) => (
                    <BackendStepRow
                      key={`${step.scenario_loop.iteration}-${step.index}-${step.step_loop.iteration}`}
                      step={step}
                    />
                  ))}
                </ol>
              )}
            </section>
          ) : (
            <>
              <section className="ep-card p-5 mb-4">
                <header className="flex items-center justify-between mb-2 gap-2">
                  <h3 className="text-ep-md font-semibold">Local timeline projection</h3>
                  <span className="ep-badge flex items-center gap-1 border-primary/40 text-primary">
                    <Info width={11} height={11} />
                    Frontend projection — not a backend execution log
                  </span>
                </header>
                {scenarioForActive ? (
                  <ScenarioTimeline scenario={scenarioForActive} />
                ) : (
                  <p className="text-ep-xs text-text-secondary">
                    No local scenario definition linked to this run (assignment cleared, or scenario built on another host).
                  </p>
                )}
              </section>

              <section className="ep-card border-warning/30 p-4 text-ep-xs text-text-secondary flex items-start gap-2">
                <AlertTriangle className="text-warning mt-0.5" width={13} height={13} />
                <span>
                  Step-level `PENDING / RUNNING / WAITING / PASS / FAIL / SKIPPED / STOPPED` statuses require the backend
                  contract (`/scenarios/:job_id/steps`). Enable the flag in Settings → “Use backend scenario catalog
                  (0.9.0)” to switch this panel to live backend data.
                </span>
              </section>
            </>
          )}
        </>
      )}
    </>
  );
}

function formatDurationMs(duration: number | null | undefined): string {
  if (duration == null) return '—';
  if (duration < 1000) return `${duration} ms`;
  const seconds = duration / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds - minutes * 60);
  return `${minutes}m ${rest}s`;
}

function BackendStepRow({ step }: { step: WireScenarioStepStatus }) {
  const resolved = Object.entries(step.resolved_parameters);
  return (
    <li
      className="border border-border rounded-md px-3 py-2 flex flex-col gap-1"
      data-testid={`backend-step-${step.scenario_loop.iteration}-${step.index}-${step.step_loop.iteration}`}
    >
      <div className="flex items-center gap-2 flex-wrap">
        <span className="mono text-ep-xs text-text-secondary">#{step.index}</span>
        <span className="font-medium mono">{step.type}</span>
        <span className="text-ep-xs text-text-secondary">
          scenario loop {step.scenario_loop.iteration}/{step.scenario_loop.count} · step loop{' '}
          {step.step_loop.iteration}/{step.step_loop.count}
        </span>
        <StatusIndicator state={step.state} compact />
        {step.started_at && (
          <span className="text-ep-xs text-text-secondary">
            started {epochSecondsToLocal(step.started_at)}
          </span>
        )}
        {step.ended_at && (
          <span className="text-ep-xs text-text-secondary">
            ended {epochSecondsToLocal(step.ended_at)}
          </span>
        )}
      </div>
      {resolved.length > 0 && (
        <ul className="text-ep-xs text-text-secondary mono flex flex-wrap gap-2">
          {resolved.map(([key, value]) => (
            <li key={key} data-testid={`resolved-${step.scenario_loop.iteration}-${step.index}-${step.step_loop.iteration}-${key}`}>
              {key} = {value}
            </li>
          ))}
        </ul>
      )}
      {step.error && (
        <p className="text-ep-xs text-error" data-testid={`step-error-${step.index}`}>
          {step.error}
        </p>
      )}
    </li>
  );
}
