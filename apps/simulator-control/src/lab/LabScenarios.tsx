// 0.36.0 — « Scénarios » simplifiés (maquette utilisateur) :
//   1. Créer : nom + étapes cochées → POST /scenario-definitions → apparaît dans la liste.
//   2. Liste : seulement les scénarios exécutables (pas les restes de test anr2-*,
//      pas les modèles LTE / non supportés).
//   3. Appel voix entre 2 UE : choisir A et B → autorisation live des deux → Lancer.

import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Card, PageHeader } from '@/components/mockup';
import { useUes } from '@/data/queries';
import { useCreateScenarioDefinition, useScenarioDefinitions, useStartScenarioRun } from '@/data/scenarioApi';
import { useCreateLiveGrant } from '@/data/liveGrantApi';
import type { WireScenarioDefinition, WireScenarioStep } from '@/scenarios/wireCodec';
import { Badge, needsTwoUes, reasonFr, stepsSummary } from './labShared';

const MB = 1024 * 1024;

export interface BuilderForm {
  name: string;
  start: boolean;
  pdu: boolean;
  dnn: string;
  ulMb: number;
  dlMb: number;
  ims: boolean;
  detach: boolean;
}

export const DEFAULT_FORM: BuilderForm = { name: '', start: true, pdu: true, dnn: 'internet', ulMb: 1, dlMb: 1, ims: false, detach: true };

const step = (type: string, parameters: WireScenarioStep['parameters'] = {}): WireScenarioStep => ({ type, loop_count: 1, parameters });

/** Pure: form → wire steps, in the order the backend expects. */
export function buildSteps(f: BuilderForm): WireScenarioStep[] {
  const out: WireScenarioStep[] = [];
  if (f.start) out.push(step('ue_start'));
  if (f.pdu) out.push(step('pdu_establish', { dnn: { fixed: f.dnn || 'internet' } }));
  if (f.pdu && f.ulMb > 0) out.push(step('traffic_ul', { bytes: { fixed: Math.round(f.ulMb * MB) } }));
  if (f.pdu && f.dlMb > 0) out.push(step('traffic_dl', { bytes: { fixed: Math.round(f.dlMb * MB) } }));
  if (f.ims) out.push(step('ims_register'));
  if (f.detach) out.push(step('detach'));
  return out;
}

export function slugify(name: string): string {
  const base = name
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
  return `lab-${base || 'scenario'}`;
}

/** What the simplified list shows: runnable 5G scenarios, no test leftovers. */
export function isListed(d: WireScenarioDefinition): boolean {
  if (d.id.startsWith('anr2-') || d.id.startsWith('test-')) return false;
  if (d.rat === 'LTE') return false;
  if (d.backend_support && d.backend_support !== 'SUPPORTED') return false;
  return (d as { executable?: boolean }).executable !== false;
}

export function LabScenariosPage() {
  const defs = useScenarioDefinitions();
  const ues = useUes();
  const create = useCreateScenarioDefinition();
  const grant = useCreateLiveGrant();
  const start = useStartScenarioRun();
  const [form, setForm] = useState<BuilderForm>(DEFAULT_FORM);
  const [msg, setMsg] = useState<string | null>(null);
  const [callA, setCallA] = useState('');
  const [callB, setCallB] = useState('');
  const [callBusy, setCallBusy] = useState(false);

  const list = useMemo(() => (defs.data?.items ?? []).filter(isListed), [defs.data]);
  const voiceDef = list.find((d) => needsTwoUes(d));
  const pilotable = useMemo(
    () =>
      (ues.data?.items ?? []).filter(
        (u) => u.controller_owned && u.subscription_status === 'VERIFIED' && u.technology !== 'LTE 4G',
      ),
    [ues.data],
  );
  const steps = buildSteps(form);
  const set = <K extends keyof BuilderForm>(k: K, v: BuilderForm[K]) => setForm((p) => ({ ...p, [k]: v }));

  async function save() {
    if (!form.name.trim() || steps.length === 0) return;
    setMsg(null);
    try {
      const saved = await create.mutateAsync({
        id: slugify(form.name),
        name: form.name.trim(),
        loop_count: 1,
        steps,
        rat: '5G_SA',
        simulator: 'UERANSIM',
        description: stepsSummary({ steps }),
      });
      setMsg(`Scénario « ${saved.name ?? form.name} » ajouté. Choisis-le sur la ligne d’un UE dans « UE du lab ».`);
      setForm(DEFAULT_FORM);
    } catch (error) {
      const e = error as { code?: string; message?: string };
      setMsg(`Création refusée — ${reasonFr(e.code) || e.message}`);
    }
  }

  async function launchCall() {
    if (!voiceDef || !callA || !callB || callA === callB) return;
    setCallBusy(true);
    setMsg(null);
    try {
      await grant.mutateAsync({ ue_ids: [callA, callB], duration_minutes: 15 });
      const job = await start.mutateAsync({ scenario_definition_id: voiceDef.id, ue_ids: [callA, callB] });
      setMsg(`Appel ${callA} → ${callB} lancé (job ${job.job_id}). Suivi : clique sur ${callA} ou ${callB}.`);
    } catch (error) {
      const e = error as { code?: string; message?: string; status?: number };
      setMsg(`Appel refusé — ${reasonFr(e.code) || e.message}${e.status ? ` (HTTP ${e.status})` : ''}`);
    } finally {
      setCallBusy(false);
    }
  }

  const field = 'h-10 rounded-md border border-line bg-surface px-2 text-ep-sm';

  return (
    <>
      <PageHeader eyebrow="Lab" title="Scénarios" desc="Crée un scénario, il apparaît dans la liste et dans le choix de chaque UE." />
      {msg && <p role="status" className="text-ep-sm rounded-md border border-line bg-surface px-3 py-2" data-testid="lab-scn-message">{msg}</p>}

      <div className="grid gap-3 lg:grid-cols-[1fr_1.4fr]">
        <Card className="p-4 flex flex-col gap-3" data-testid="lab-scn-builder">
          <h2 className="text-ep-lg font-semibold">Nouveau scénario</h2>
          <label className="flex flex-col gap-1 text-ep-sm">
            Nom
            <input className={field} value={form.name} onChange={(e) => set('name', e.target.value)} placeholder="ex. Data 5 Mo" aria-label="Nom du scénario" />
          </label>
          <label className="flex items-center gap-2 text-ep-sm"><input type="checkbox" checked={form.start} onChange={(e) => set('start', e.target.checked)} /> Démarrer l’UE (RRC + enregistrement)</label>
          <label className="flex items-center gap-2 text-ep-sm"><input type="checkbox" checked={form.pdu} onChange={(e) => set('pdu', e.target.checked)} /> Session PDU
            <input className={`${field} w-28`} value={form.dnn} onChange={(e) => set('dnn', e.target.value)} disabled={!form.pdu} aria-label="DNN" />
          </label>
          <div className="flex gap-3 text-ep-sm">
            <label className="flex flex-col gap-1">UL (Mo)
              <input type="number" min={0} max={100} className={`${field} w-24`} value={form.ulMb} disabled={!form.pdu} onChange={(e) => set('ulMb', Number(e.target.value))} aria-label="UL Mo" />
            </label>
            <label className="flex flex-col gap-1">DL (Mo)
              <input type="number" min={0} max={100} className={`${field} w-24`} value={form.dlMb} disabled={!form.pdu} onChange={(e) => set('dlMb', Number(e.target.value))} aria-label="DL Mo" />
            </label>
          </div>
          <label className="flex items-center gap-2 text-ep-sm"><input type="checkbox" checked={form.ims} onChange={(e) => set('ims', e.target.checked)} /> Enregistrement voix (IMS)</label>
          <label className="flex items-center gap-2 text-ep-sm"><input type="checkbox" checked={form.detach} onChange={(e) => set('detach', e.target.checked)} /> Détacher à la fin</label>
          <p className="text-ep-xs text-mute" data-testid="lab-scn-preview">{stepsSummary({ steps }) || 'aucune étape'}</p>
          <button
            type="button"
            className="h-10 rounded-md bg-brand text-white font-semibold disabled:bg-track disabled:text-mute"
            disabled={!form.name.trim() || steps.length === 0 || create.isPending}
            onClick={() => void save()}
            data-testid="lab-scn-save"
          >
            {create.isPending ? 'Enregistrement…' : 'Ajouter à la liste'}
          </button>
        </Card>

        <div className="flex flex-col gap-3">
          <Card className="p-4">
            <h2 className="text-ep-lg font-semibold mb-2">Liste ({list.length})</h2>
            {defs.isLoading && <p className="text-mute text-ep-sm">Chargement…</p>}
            <ul className="flex flex-col divide-y divide-line" data-testid="lab-scn-list">
              {list.map((d) => (
                <li key={d.id} className="py-2.5 flex flex-col gap-0.5">
                  <div className="flex items-center gap-2">
                    <strong className="text-ep-md">{d.name}</strong>
                    <Badge tone={d.catalog_scope === 'SYSTEM' ? 'idle' : 'run'}>{d.catalog_scope === 'SYSTEM' ? 'modèle' : 'perso'}</Badge>
                    {needsTwoUes(d) && <Badge tone="warn">2 UE</Badge>}
                  </div>
                  <span className="text-ep-xs text-mute">{stepsSummary(d)}</span>
                </li>
              ))}
            </ul>
          </Card>

          <Card className="p-4 flex flex-col gap-2" data-testid="lab-call">
            <h2 className="text-ep-lg font-semibold">Appel voix entre 2 UE</h2>
            {!voiceDef ? (
              <p className="text-ep-sm text-mute">-- (aucun scénario d’appel exécutable)</p>
            ) : (
              <div className="flex flex-wrap items-end gap-2 text-ep-sm">
                <label className="flex flex-col gap-1">Appelant
                  <select className={field} value={callA} onChange={(e) => setCallA(e.target.value)} aria-label="Appelant">
                    <option value="">—</option>
                    {pilotable.map((u) => <option key={u.id} value={u.id}>{u.id}</option>)}
                  </select>
                </label>
                <label className="flex flex-col gap-1">Appelé
                  <select className={field} value={callB} onChange={(e) => setCallB(e.target.value)} aria-label="Appelé">
                    <option value="">—</option>
                    {pilotable.map((u) => <option key={u.id} value={u.id}>{u.id}</option>)}
                  </select>
                </label>
                <button
                  type="button"
                  className="h-10 px-5 rounded-md bg-brand text-white font-semibold disabled:bg-track disabled:text-mute"
                  disabled={!callA || !callB || callA === callB || callBusy}
                  onClick={() => void launchCall()}
                  data-testid="lab-call-run"
                >
                  {callBusy ? 'Lancement…' : 'Lancer l’appel'}
                </button>
                {callA && callB && (
                  <span className="text-ep-xs text-mute">
                    Suivi : <Link className="underline" to={`/lab/ues/${encodeURIComponent(callA)}`}>{callA}</Link> · <Link className="underline" to={`/lab/ues/${encodeURIComponent(callB)}`}>{callB}</Link>
                  </span>
                )}
              </div>
            )}
          </Card>
        </div>
      </div>
    </>
  );
}
