import { useMemo, useState } from 'react';
import { AlertTriangle, PlayCircle, RotateCcw, StopCircle } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import { StatusIndicator } from '@/ui/StatusIndicator';
import { EmptyState, ErrorState, LoadingSkeleton } from '@/ui/EmptyErrorLoading';
import { ConfirmDialog } from '@/ui/ConfirmDialog';
import {
  useAuth,
  useStartScenario,
  useStartUe,
  useStopScenario,
  useStopUe,
  useScenarioRuntime,
  useUes,
} from '@/data/queries';
import { useAssignments, useScenarios } from '@/scenarios/store';
import {
  certifiedProfileFor,
  type Scenario,
} from '@/scenarios/model';
import type { UeState } from '@/data/polarisTypes';

export function UeManagerPage() {
  const auth = useAuth();
  const ues = useUes();
  const library = useScenarios();
  const assignments = useAssignments();
  const runtime = useScenarioRuntime();
  const startScenario = useStartScenario();
  const stopScenario = useStopScenario();
  const startUe = useStartUe();
  const stopUe = useStopUe();
  const [confirmRun, setConfirmRun] = useState<{ ue: UeState; scenario: Scenario } | null>(null);
  const [confirmStop, setConfirmStop] = useState<UeState | null>(null);
  const [feedback, setFeedback] = useState('');

  const canOperate = auth.data?.can_start === true;

  const assignmentByUe = useMemo(
    () => new Map(assignments.assignments.map((a) => [a.ueId, a])),
    [assignments.assignments],
  );

  const scenarioById = useMemo(
    () => new Map(library.scenarios.map((scenario) => [scenario.id, scenario])),
    [library.scenarios],
  );

  async function runScenarioOn(ue: UeState) {
    const assignment = assignmentByUe.get(ue.id);
    if (!assignment) return;
    const scenario = scenarioById.get(assignment.scenarioId);
    if (!scenario) return;
    const profile = certifiedProfileFor(scenario);
    if (!profile) {
      setFeedback(
        `${scenario.name}: shape not supported by any certified backend profile. Backend contract required before Run Scenario can be dispatched.`,
      );
      return;
    }
    setFeedback('');
    try {
      await startScenario.mutateAsync({
        scenario_id: `${scenario.id}-${Date.now()}`,
        scenario_type: profile.scenario_type,
        target_ue_id: ue.internal_ue_id ?? ue.id,
      });
      setFeedback(`Scenario ${scenario.name} requested for ${ue.id}.`);
    } catch (error) {
      setFeedback((error as Error).message);
    }
  }

  async function stopAssignedScenario(ue: UeState) {
    const active = runtime.data?.active_job;
    if (!active?.job_id) {
      setFeedback('No active job to stop.');
      return;
    }
    if (active.target_ue_id && active.target_ue_id !== (ue.internal_ue_id ?? ue.id)) {
      setFeedback('Active job is not owned by this UE; stop ignored.');
      return;
    }
    try {
      await stopScenario.mutateAsync(active.job_id);
      setFeedback(`Stop sent for job ${active.job_id}.`);
    } catch (error) {
      setFeedback((error as Error).message);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Operations"
        title="UE Manager"
        description="POLARIS UE inventory with scenario assignment. Scenarios are declarative definitions saved locally; Run Scenario only fires when the scenario shape matches a certified backend profile (currently bounded-controller-ue-udp-v1)."
        actions={
          <StatusIndicator
            state={canOperate ? 'OPERATOR_READY' : 'VIEWER_READONLY'}
            tone={canOperate ? 'success' : 'warning'}
            label={canOperate ? 'Operator role active' : 'Viewer — read-only'}
          />
        }
      />

      {ues.isLoading && !ues.data && <LoadingSkeleton label="Loading UE inventory" />}
      {ues.error && (
        <ErrorState
          title="Could not load UE inventory"
          detail={(ues.error as Error).message}
          onRetry={() => void ues.refetch()}
        />
      )}

      {ues.data && ues.data.items.length === 0 && (
        <EmptyState
          title="No UE configured"
          description="POLARIS has not reported any UE. Configure UE profiles from the certified lab console."
        />
      )}

      {ues.data && ues.data.items.length > 0 && (
        <div className="ep-card overflow-hidden">
          <table className="ep-table" data-testid="ue-table">
            <thead>
              <tr>
                <th>UE</th>
                <th>Process</th>
                <th>Registration</th>
                <th>PDU</th>
                <th>Traffic</th>
                <th>Assigned scenario</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {ues.data.items.map((ue) => {
                const assignment = assignmentByUe.get(ue.id);
                const scenario = assignment ? scenarioById.get(assignment.scenarioId) : undefined;
                const profile = scenario ? certifiedProfileFor(scenario) : null;
                const isShared = !ue.controller_owned;
                const activeJob = runtime.data?.active_job;
                const isActiveForUe =
                  activeJob?.target_ue_id === (ue.internal_ue_id ?? ue.id);
                return (
                  <tr key={ue.id} data-testid={`ue-row-${ue.id}`}>
                    <td>
                      <div className="flex flex-col">
                        <span className="font-medium">{ue.id}</span>
                        {ue.internal_ue_id && (
                          <span className="text-text-secondary text-ep-xs mono truncate">
                            {ue.internal_ue_id}
                          </span>
                        )}
                        {isShared && (
                          <span className="text-ep-xs text-warning flex items-center gap-1">
                            <AlertTriangle width={10} height={10} />
                            shared — protected
                          </span>
                        )}
                      </div>
                    </td>
                    <td><StatusIndicator state={ue.process_state ?? 'UNKNOWN'} compact /></td>
                    <td><StatusIndicator state={ue.registration_state} compact /></td>
                    <td><StatusIndicator state={ue.pdu_session} compact /></td>
                    <td>{ue.traffic_state}</td>
                    <td>
                      <div className="flex flex-col gap-1">
                        <select
                          className="ep-input text-ep-sm"
                          value={assignment?.scenarioId ?? ''}
                          onChange={(event) => {
                            if (event.target.value === '') {
                              assignments.clear(ue.id);
                            } else {
                              assignments.assign(ue.id, event.target.value, assignment?.autoRun ?? false);
                            }
                          }}
                          disabled={!canOperate || isShared}
                          data-testid={`assign-select-${ue.id}`}
                        >
                          <option value="">— None —</option>
                          {library.scenarios.map((item) => (
                            <option key={item.id} value={item.id}>
                              {item.name} (v{item.version})
                            </option>
                          ))}
                        </select>
                        {scenario && (
                          <label className="flex items-center gap-1 text-ep-xs text-text-secondary">
                            <input
                              type="checkbox"
                              checked={assignment?.autoRun ?? false}
                              onChange={(event) =>
                                assignments.assign(ue.id, scenario.id, event.target.checked)
                              }
                              disabled={!canOperate || isShared}
                              data-testid={`autorun-${ue.id}`}
                            />
                            Auto-run on UE start (requires backend auto-run endpoint)
                          </label>
                        )}
                        {scenario && !profile && (
                          <span className="text-ep-xs text-warning flex items-center gap-1">
                            <AlertTriangle width={10} height={10} />
                            Backend support required for this shape.
                          </span>
                        )}
                      </div>
                    </td>
                    <td>
                      <div className="flex items-center gap-1">
                        <button
                          type="button"
                          className="ep-button ep-button-sm"
                          onClick={() => startUe.mutate(ue.internal_ue_id ?? ue.id)}
                          disabled={!canOperate || isShared || !ue.actions?.start || startUe.isPending}
                          title={!ue.actions?.start ? ue.actions?.reason : undefined}
                          aria-label={`Start ${ue.id}`}
                          data-testid={`ue-start-${ue.id}`}
                        >
                          <PlayCircle width={13} height={13} />
                          Start UE
                        </button>
                        <button
                          type="button"
                          className="ep-button ep-button-sm"
                          onClick={() => scenario && setConfirmRun({ ue, scenario })}
                          disabled={!canOperate || isShared || !scenario || !profile}
                          title={!scenario ? 'No scenario assigned' : !profile ? 'Backend support required' : undefined}
                          aria-label={`Run scenario on ${ue.id}`}
                          data-testid={`ue-run-${ue.id}`}
                        >
                          <RotateCcw width={13} height={13} />
                          Run Scenario
                        </button>
                        <button
                          type="button"
                          className="ep-button ep-button-sm ep-button-danger"
                          onClick={() => setConfirmStop(ue)}
                          disabled={!canOperate || isShared || !isActiveForUe || stopScenario.isPending}
                          title={
                            isShared
                              ? 'Shared UE — protected'
                              : !isActiveForUe
                                ? 'No active job owned by this UE'
                                : undefined
                          }
                          aria-label={`Stop scenario on ${ue.id}`}
                          data-testid={`ue-stop-${ue.id}`}
                        >
                          <StopCircle width={13} height={13} />
                          Stop
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {feedback && (
            <div className="border-t border-border px-3 py-2 text-ep-xs text-text-secondary" data-testid="ue-feedback">
              {feedback}
            </div>
          )}
        </div>
      )}

      <ConfirmDialog
        open={confirmRun != null}
        title="Run scenario"
        description={
          confirmRun
            ? `Dispatch ${confirmRun.scenario.name} (v${confirmRun.scenario.version}) to ${confirmRun.ue.id} via the certified backend profile. The frontend neither samples step-level random values nor runs the loop locally — those execute server-side.`
            : ''
        }
        confirmLabel="Confirm run"
        onCancel={() => setConfirmRun(null)}
        onConfirm={() => {
          if (confirmRun) void runScenarioOn(confirmRun.ue);
          setConfirmRun(null);
        }}
        busy={startScenario.isPending}
      />

      <ConfirmDialog
        open={confirmStop != null}
        title="Stop scenario"
        description={
          confirmStop
            ? `Send a stop request for the active controller-owned job targeting ${confirmStop.id}. The UE itself and its PDU session stay running unless the scenario explicitly includes a stop step and the backend authorizes it.`
            : ''
        }
        confirmLabel="Confirm stop"
        tone="danger"
        onCancel={() => setConfirmStop(null)}
        onConfirm={() => {
          if (confirmStop) void stopAssignedScenario(confirmStop);
          setConfirmStop(null);
        }}
        busy={stopScenario.isPending}
      />

      {/* Local UE action placeholder so the Stop UE action remains honest — we never run it blindly. */}
      <noscript className="hidden">
        {stopUe.isPending ? 'stopping ue' : 'idle'}
      </noscript>
    </>
  );
}
