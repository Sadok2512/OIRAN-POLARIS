// 0.36.0 — « UE du lab » : the simplified UE list from the user's mockup.
// Per row: IMSI, subscriber, live state, a scenario picker and ONE action
// (Lancer / Arrêter). Lancer = live grant for this UE (15 min) + start of
// the chosen definition; the row then shows « En cours ». Clicking the UE
// opens its monitoring page. No auto-opening of the monitor.

import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Card, PageHeader } from '@/components/mockup';
import { useStopScenario, useUes } from '@/data/queries';
import { fetchScenarioSteps, useScenarioDefinitions, useStartScenarioRun } from '@/data/scenarioApi';
import { useCreateLiveGrant } from '@/data/liveGrantApi';
import type { UeState } from '@/data/polarisTypes';
import { enterQuiet, leaveQuiet } from '@/data/quietMode';
import { Badge, needsTwoUes, reasonFr, stepsSummary, type Tone } from './labShared';

type Row = UeState & { subscriber_identity?: string | null; scenario_id?: string | null };

const TERMINAL = new Set(['COMPLETED', 'FAILED', 'STOPPED', 'CANCELLED', 'ABORTED', 'SUCCEEDED']);

/** Local run memory: UE id → job started from this page. */
export interface LocalRun {
  jobId: string;
  scenarioName: string;
  state: string;
}

export function ueKey(row: Row): string {
  return row.id;
}

export function rowState(row: Row, run: LocalRun | undefined): { tone: Tone; label: string; pulse?: boolean } {
  if (run && !TERMINAL.has(run.state)) return { tone: 'run', label: `En cours · ${run.scenarioName}`, pulse: true };
  if (row.process_state === 'STOP_INCOMPLETE') return { tone: 'bad', label: 'Arrêt incomplet' };
  if (row.process_state === 'RUNNING' || row.registration_state === 'REGISTERED') {
    return { tone: 'ok', label: row.registration_state === 'REGISTERED' ? 'Enregistré' : 'Démarré' };
  }
  if (run && TERMINAL.has(run.state)) {
    return run.state === 'FAILED' ? { tone: 'bad', label: 'Échec' } : { tone: 'ok', label: 'Terminé' };
  }
  return { tone: 'idle', label: 'Arrêté' };
}

export function LabUesPage() {
  const ues = useUes();
  const defs = useScenarioDefinitions();
  const createGrant = useCreateLiveGrant();
  const startRun = useStartScenarioRun();
  const stopRun = useStopScenario();
  const [choice, setChoice] = useState<Record<string, string>>({});
  const [runs, setRuns] = useState<Record<string, LocalRun>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const rows: Row[] = useMemo(() => (ues.data?.items ?? []) as Row[], [ues.data]);
  const runnable = useMemo(
    () =>
      (defs.data?.items ?? []).filter(
        (d) => d.backend_support === 'SUPPORTED' && (d as { executable?: boolean }).executable !== false && !needsTwoUes(d),
      ),
    [defs.data],
  );

  // Poll the jobs started here until they are terminal (one light call per active job).
  useEffect(() => {
    const active = Object.entries(runs).filter(([, r]) => !TERMINAL.has(r.state));
    if (active.length === 0) {
      leaveQuiet();
      return;
    }
    const timer = window.setInterval(async () => {
      enterQuiet(10_000); // keep background polling off while a run is active
      for (const [ue, r] of active) {
        try {
          const steps = await fetchScenarioSteps(r.jobId);
          const state = steps.state ?? (steps.steps.every((s) => TERMINAL.has(s.state)) ? 'COMPLETED' : 'RUNNING');
          if (state !== r.state) setRuns((prev) => ({ ...prev, [ue]: { ...prev[ue], state } }));
        } catch {
          /* keep last known state; the monitor page shows the detail */
        }
      }
    }, 3000);
    return () => window.clearInterval(timer);
  }, [runs]);

  async function launch(row: Row) {
    const id = ueKey(row);
    const defId = choice[id] ?? row.scenario_id ?? '';
    const def = runnable.find((d) => d.id === defId);
    if (!def) return;
    setBusy(id);
    setMessage(null);
    enterQuiet(60_000);
    try {
      await createGrant.mutateAsync({ ue_ids: [id], duration_minutes: 15 });
      const job = await startRun.mutateAsync({ scenario_definition_id: def.id, ue_ids: [id] });
      setRuns((prev) => ({ ...prev, [id]: { jobId: job.job_id, scenarioName: def.name, state: job.state || 'RUNNING' } }));
      setMessage(`« ${def.name} » lancé sur ${id}. Clique sur ${id} pour suivre en direct.`);
    } catch (error) {
      const e = error as { code?: string; message?: string; status?: number };
      setMessage(`${id} : lancement refusé — ${reasonFr(e.code) || e.message || 'erreur'}${e.status ? ` (HTTP ${e.status})` : ''}`);
    } finally {
      setBusy(null);
    }
  }

  async function stop(id: string) {
    const run = runs[id];
    if (!run) return;
    setBusy(id);
    try {
      await stopRun.mutateAsync(run.jobId);
      setRuns((prev) => ({ ...prev, [id]: { ...prev[id], state: 'STOPPED' } }));
    } catch (error) {
      setMessage(`${id} : arrêt refusé — ${(error as Error).message}`);
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Lab"
        title="UE du lab"
        desc="Choisis un scénario sur la ligne de l’UE, puis Lancer. La ligne passe « En cours ». Clique sur le nom de l’UE pour son suivi en direct."
        actions={
          <Link
            to="/ues"
            className="inline-flex items-center h-10 px-4 rounded-md bg-brand text-white text-ep-md font-semibold"
            data-testid="lab-add-ue"
          >
            + Ajouter un UE
          </Link>
        }
      />
      {message && (
        <p role="status" className="text-ep-sm rounded-md border border-line bg-surface px-3 py-2" data-testid="lab-message">
          {message}
        </p>
      )}
      <Card className="overflow-x-auto">
        <table className="w-full min-w-[720px] text-ep-sm" data-testid="lab-ue-table">
          <thead>
            <tr className="text-left text-ep-xs uppercase tracking-wider text-mute">
              <th className="px-3 py-3 font-semibold">UE</th>
              <th className="px-3 py-3 font-semibold">IMSI</th>
              <th className="px-3 py-3 font-semibold">Abonné</th>
              <th className="px-3 py-3 font-semibold">État</th>
              <th className="px-3 py-3 font-semibold">Scénario</th>
              <th className="px-4 py-3 font-semibold text-right">Action</th>
            </tr>
          </thead>
          <tbody>
            {ues.isLoading && (
              <tr><td colSpan={6} className="px-4 py-6 text-mute">Chargement des UE…</td></tr>
            )}
            {ues.isError && (
              <tr><td colSpan={6} className="px-4 py-6 text-bad">Inventaire indisponible : {(ues.error as Error).message}</td></tr>
            )}
            {rows.map((row) => {
              const id = ueKey(row);
              const run = runs[id];
              const st = rowState(row, run);
              const running = st.tone === 'run';
              const lte = row.technology === 'LTE 4G' || row.simulator === 'srsRAN';
              const verified = row.subscription_status === 'VERIFIED';
              const pilotable = row.controller_owned && verified && !lte;
              const selected = choice[id] ?? row.scenario_id ?? '';
              const selectable = runnable.some((d) => d.id === selected);
              const reason = row.last_event
                ? reasonFr(row.last_event)
                : !row.controller_owned
                ? reasonFr(row.actions?.reason)
                : lte
                  ? reasonFr(row.actions?.reason || 'LTE_E2E_CERTIFICATION_REQUIRED')
                  : !verified
                    ? 'Abonné non vérifié dans Open5GS'
                    : !selectable
                      ? 'Choisis un scénario'
                      : '';
              return (
                <tr key={id} className="border-t border-line" data-testid={`lab-ue-row-${id}`}>
                  <td className="px-4 py-3">
                    <Link to={`/lab/ues/${encodeURIComponent(id)}`} className="font-semibold text-brand underline underline-offset-2">
                      {id}
                    </Link>
                    <div className="text-ep-xs text-mute whitespace-nowrap">{row.technology ?? '5G SA'} · {row.serving_node ?? '--'}</div>
                  </td>
                  <td className="px-3 py-3 font-mono text-ep-sm">{row.subscriber_identity && row.subscriber_identity !== 'PROTECTED' ? row.subscriber_identity : '-- (protégé)'}</td>
                  <td className="px-3 py-3">
                    {verified ? <Badge tone="ok">Vérifié</Badge> : <Badge tone="warn">{row.subscription_status ?? 'Inconnu'}</Badge>}
                  </td>
                  <td className="px-3 py-3"><Badge tone={st.tone} pulse={st.pulse}>{st.label}</Badge></td>
                  <td className="px-3 py-3">
                    <select
                      aria-label={`Scénario pour ${id}`}
                      className="h-10 w-full max-w-[210px] rounded-md border border-line bg-surface px-2 text-ep-sm"
                      value={selectable ? selected : ''}
                      disabled={!pilotable || running}
                      onChange={(e) => setChoice((prev) => ({ ...prev, [id]: e.target.value }))}
                    >
                      <option value="">— choisir un scénario —</option>
                      {runnable.filter((d) => d.rat !== 'LTE').map((d) => (
                        <option key={d.id} value={d.id} title={stepsSummary(d)}>{d.name}</option>
                      ))}
                    </select>
                  </td>
                  <td className="px-4 py-3 text-right">
                    {running ? (
                      <button
                        type="button"
                        className="h-10 px-4 rounded-md border border-bad text-bad font-semibold"
                        disabled={busy === id}
                        onClick={() => void stop(id)}
                      >
                        Arrêter
                      </button>
                    ) : (
                      <button
                        type="button"
                        className="h-10 px-5 rounded-md bg-brand text-white font-semibold disabled:bg-track disabled:text-mute"
                        disabled={!pilotable || !selectable || busy === id}
                        onClick={() => void launch(row)}
                        data-testid={`lab-run-${id}`}
                      >
                        {busy === id ? 'Lancement…' : 'Lancer'}
                      </button>
                    )}
                    {!running && reason && <div className="text-ep-xs text-mute mt-1 max-w-[180px] ml-auto">{reason}</div>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Card>
      <p className="text-ep-xs text-mute">
        L’appel voix entre deux UE se lance depuis <Link to="/lab/scenarios" className="underline">Scénarios</Link>. Le lancement crée une autorisation live de 15 min pour l’UE.
      </p>
    </>
  );
}
