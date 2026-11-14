import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Copy,
  Download,
  Edit,
  FileJson,
  Plus,
  Search,
  Trash2,
  Upload,
  Workflow,
} from 'lucide-react';
import { PageHeader } from '@/components/mockup';
import { EmptyState, LoadingSkeleton, Unavailable } from '@/ui/EmptyErrorLoading';
import { ConfirmDialog } from '@/ui/ConfirmDialog';
import { useAssignments } from '@/scenarios/store';
import { useScenarioLibrary } from '@/scenarios/library';
import { emptyScenario, type LoopMode, type Scenario } from '@/scenarios/model';
import { decodeDefinition } from '@/scenarios/wireCodec';
import { isoToLocal } from '@/data/format';
import { useFeatureFlag } from '@/data/featureFlags';
import {
  defaultFilename,
  downloadScenarioExport,
  useScenarioEstimate,
  useScenarioTemplates,
  type ScenarioTemplateDescriptor,
} from '@/data/scenarioTemplatesApi';
import { useStartScenarioRun } from '@/data/scenarioApi';
import { useUes } from '@/data/queries';
import { useCreateLiveGrant } from '@/data/liveGrantApi';
import type { WireScenarioDefinition } from '@/scenarios/wireCodec';
import { ApiError } from '@shared/api';
import { ImportScenarioDialog } from '@/scenarios/ImportScenarioDialog';

type Tab = 'library' | 'templates';

export const SIMPLE_SCENARIO_IDS = [
  'simple-data-ul-dl',
  'simple-voice-register',
  'simple-voice-call',
] as const;

function loopLabel(loop: LoopMode): string {
  switch (loop.kind) {
    case 'ONCE':
      return 'Once';
    case 'FIXED':
      return `×${loop.cycles}`;
    case 'RANDOM':
      return `Random ${loop.min}..${loop.max}`;
    case 'INFINITE':
      return 'Infinite (until stopped)';
  }
}

export function ScenariosLibraryPage() {
  const navigate = useNavigate();
  const library = useScenarioLibrary();
  const assignments = useAssignments();
  const scenarioTemplatesFlag = useFeatureFlag('scenarioTemplates');
  const [search, setSearch] = useState('');
  const [confirmDelete, setConfirmDelete] = useState<Scenario | null>(null);
  const [tab, setTab] = useState<Tab>('library');
  const [importOpen, setImportOpen] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [caller, setCaller] = useState('');
  const [callee, setCallee] = useState('');
  const [callResult, setCallResult] = useState('');
  const ues = useUes();
  const createGrant = useCreateLiveGrant();
  const startRun = useStartScenarioRun();

  const callableUes = useMemo(
    () => (ues.data?.items ?? []).filter(
      (ue) => ue.controller_owned && ue.subscription_status === 'VERIFIED',
    ),
    [ues.data?.items],
  );

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const simple = library.scenarios.filter((scenario) =>
      SIMPLE_SCENARIO_IDS.includes(scenario.id as (typeof SIMPLE_SCENARIO_IDS)[number]),
    );
    if (!needle) return simple;
    return simple.filter((scenario) =>
      [scenario.name, scenario.description ?? '', scenario.id]
        .join(' ')
        .toLowerCase()
        .includes(needle),
    );
  }, [library.scenarios, search]);

  async function startVoiceCall() {
    setCallResult('');
    if (!caller || !callee || caller === callee) {
      setCallResult('Choisissez deux UE différents.');
      return;
    }
    try {
      await createGrant.mutateAsync({ ue_ids: [caller, callee], duration_minutes: 15 });
      const result = await startRun.mutateAsync({
        scenario_definition_id: 'simple-voice-call',
        ue_ids: [caller, callee],
      });
      setCallResult(`Appel lancé · ${result.job_id} · ${result.state}`);
    } catch (error) {
      setCallResult(`Appel indisponible · ${(error as Error).message}`);
    }
  }

  function createScenario() {
    if (library.backend) {
      navigate('/scenarios/new');
      return;
    }
    const scenario = emptyScenario('Untitled scenario');
    void library.save(scenario);
    navigate(`/scenarios/${scenario.id}/edit`);
  }

  function assignedCount(scenarioId: string): number {
    return assignments.assignments.filter((a) => a.scenarioId === scenarioId).length;
  }

  return (
    <>
      <PageHeader
        eyebrow="Simulation"
        title="Scenarios"
        desc="Saved on the controller with versions. Six V1 step types; numeric parameters can be fixed or random."
        actions={
          <div className="flex items-center gap-2">
            <label className="relative">
              <Search
                className="absolute left-2 top-1/2 -translate-y-1/2 text-text-secondary"
                width={13}
                height={13}
                aria-hidden="true"
              />
              <input
                className="ep-input pl-7"
                placeholder="Search scenarios"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                aria-label="Search scenarios"
                data-testid="scenarios-search"
              />
            </label>
            <button
              type="button"
              className="ep-button ep-button-sm"
              onClick={() => setImportOpen(true)}
              disabled={!scenarioTemplatesFlag}
              title={
                scenarioTemplatesFlag
                  ? 'Import a polaris.scenario-definition.v2 JSON file.'
                  : 'Enable "Scenario templates (0.5.0)" in Settings first.'
              }
              data-testid="scenarios-import"
            >
              <Upload width={13} height={13} /> Import JSON
            </button>
            <button
              type="button"
              className="ep-button ep-button-primary"
              onClick={createScenario}
              data-testid="scenarios-create"
            >
              <Plus width={14} height={14} aria-hidden="true" />
              Create scenario
            </button>
          </div>
        }
      />

      <div
        role="tablist"
        aria-label="Scenarios sections"
        className="flex gap-2 border-b border-border mb-4"
      >
        {(['library', 'templates'] as Tab[]).map((value) => (
          <button
            key={value}
            type="button"
            role="tab"
            aria-selected={tab === value}
            onClick={() => setTab(value)}
            className={`h-9 px-3 -mb-px text-ep-sm border-b-2 ${
              tab === value
                ? 'border-primary text-primary font-semibold'
                : 'border-transparent text-text-secondary hover:text-text-primary'
            }`}
            data-testid={`scenarios-tab-${value}`}
          >
            {value === 'library' ? 'My scenarios' : 'Templates (tpl-*)'}
          </button>
        ))}
      </div>

      {downloadError && (
        <div
          role="alert"
          className="ep-card border-error/30 p-3 mb-3 text-ep-sm text-error"
          data-testid="download-error"
        >
          {downloadError}
        </div>
      )}

      {tab === 'library' && (
        <div className="ep-card p-4 mb-4" data-testid="simple-call-panel">
          <h2 className="font-semibold">Appel voix entre 2 UE</h2>
          <p className="text-ep-sm text-text-secondary mt-1">
            Choisissez l'appelant et l'appelé, puis lancez l'appel. Seuls les UE vérifiés et contrôlables sont proposés.
          </p>
          <div className="flex flex-wrap items-end gap-2 mt-3">
            <label className="text-ep-sm">UE A
              <select className="ep-input block mt-1" value={caller} onChange={(event) => setCaller(event.target.value)} data-testid="call-caller">
                <option value="">Choisir</option>
                {callableUes.map((ue) => <option key={ue.id} value={ue.id}>{ue.id}</option>)}
              </select>
            </label>
            <label className="text-ep-sm">UE B
              <select className="ep-input block mt-1" value={callee} onChange={(event) => setCallee(event.target.value)} data-testid="call-callee">
                <option value="">Choisir</option>
                {callableUes.map((ue) => <option key={ue.id} value={ue.id}>{ue.id}</option>)}
              </select>
            </label>
            <button
              type="button"
              className="ep-button ep-button-primary"
              onClick={() => void startVoiceCall()}
              disabled={callableUes.length < 2 || createGrant.isPending || startRun.isPending}
              title={callableUes.length < 2 ? 'Second UE non prêt (VOICE_SECOND_UE_NOT_READY)' : undefined}
              data-testid="call-submit"
            >
              Appeler
            </button>
          </div>
          {callableUes.length < 2 && (
            <p className="text-ep-sm text-warn mt-2" data-testid="call-prerequisite-error">
              Second UE non prêt (VOICE_SECOND_UE_NOT_READY)
            </p>
          )}
          {callResult && <p className="text-ep-sm mt-2" role="status">{callResult}</p>}
        </div>
      )}

      {tab === 'library' && (
        <>
          {library.scenarios.length === 0 && (
            <EmptyState
              title="No scenarios yet"
              description="Create your first scenario to design a reusable mobile workflow (registration, PDU establishment, traffic, loops…)."
              action={
                <button
                  type="button"
                  className="ep-button ep-button-sm ep-button-primary"
                  onClick={createScenario}
                >
                  Create scenario
                </button>
              }
            />
          )}
          {library.scenarios.length > 0 && filtered.length === 0 && (
            <EmptyState title="No scenarios match" description="Adjust the search." />
          )}
          {filtered.length > 0 && (
            <div className="ep-card overflow-hidden">
              <table className="ep-table" data-testid="scenarios-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Steps</th>
                    <th>Loop</th>
                    <th>Version</th>
                    <th>Assigned UEs</th>
                    <th>Updated</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((scenario) => (
                    <tr
                      key={scenario.id}
                      onClick={() => navigate(`/scenarios/${scenario.id}/edit`)}
                      className="cursor-pointer"
                      data-testid={`scenario-row-${scenario.id}`}
                    >
                      <td>
                        <div className="flex items-center gap-2">
                          <Workflow width={14} height={14} className="text-text-secondary" />
                          <div className="min-w-0">
                            <div className="font-medium truncate">{scenario.name}</div>
                            <div className="mono text-ep-xs text-text-secondary truncate">
                              {scenario.id}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="num">{scenario.steps.length}</td>
                      <td>{loopLabel(scenario.loop)}</td>
                      <td className="num">v{scenario.version}</td>
                      <td className="num">{assignedCount(scenario.id)}</td>
                      <td>{isoToLocal(new Date(scenario.updatedAt).toISOString())}</td>
                      <td>
                        <div
                          className="flex items-center gap-1"
                          onClick={(event) => event.stopPropagation()}
                        >
                          <button
                            type="button"
                            className="ep-button ep-button-sm"
                            aria-label={`Edit ${scenario.name}`}
                            onClick={() => navigate(`/scenarios/${scenario.id}/edit`)}
                            data-testid={`scenario-edit-${scenario.id}`}
                          >
                            <Edit width={13} height={13} />
                          </button>
                          <button
                            type="button"
                            className="ep-button ep-button-sm"
                            aria-label={`Duplicate ${scenario.name}`}
                            onClick={() => void library.duplicate(scenario.id)}
                            data-testid={`scenario-duplicate-${scenario.id}`}
                          >
                            <Copy width={13} height={13} />
                          </button>
                          <button
                            type="button"
                            className="ep-button ep-button-sm ep-button-danger"
                            aria-label={`Delete ${scenario.name}`}
                            onClick={() => setConfirmDelete(scenario)}
                            data-testid={`scenario-delete-${scenario.id}`}
                          >
                            <Trash2 width={13} height={13} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {tab === 'templates' && (
        <TemplatesTab
          onError={setDownloadError}
          onClearError={() => setDownloadError(null)}
        />
      )}

      <ConfirmDialog
        open={confirmDelete != null}
        title="Delete scenario"
        description={`Remove "${
          confirmDelete?.name ?? ''
        }" from the ${
          library.backend ? 'backend catalog' : 'local library'
        }. Any UE assignment pointing at it will also be cleared. This action cannot be undone.`}
        confirmLabel="Delete"
        tone="danger"
        onCancel={() => setConfirmDelete(null)}
        onConfirm={() => {
          if (confirmDelete) void library.delete(confirmDelete.id);
          setConfirmDelete(null);
        }}
      />

      <ImportScenarioDialog
        open={importOpen}
        onClose={() => setImportOpen(false)}
        onImported={(id) => navigate(`/scenarios/${id}/edit`)}
      />
    </>
  );
}

function TemplatesTab({
  onError,
  onClearError,
}: {
  onError: (message: string) => void;
  onClearError: () => void;
}) {
  const flag = useFeatureFlag('scenarioTemplates');
  const templates = useScenarioTemplates();

  if (!flag) {
    return (
      <Unavailable
        reason="Backend pending — enable 'Scenario templates (0.5.0)' in Settings once Codex pushes feat/polaris-traffic-templates. Nothing is fetched while the flag is OFF."
      />
    );
  }
  if (templates.isLoading) return <LoadingSkeleton label="Loading the backend scenario catalogue" />;
  if (templates.error) {
    const code =
      templates.error instanceof ApiError
        ? (templates.error as ApiError).code
        : 'TEMPLATE_FETCH_FAILED';
    return (
      <Unavailable reason={`${code} · ${(templates.error as Error).message}`} />
    );
  }
  if (!templates.data || templates.data.items.length === 0) {
    return (
      <EmptyState
        title="No backend templates available"
        description="The real POLARIS catalogue returned no immutable tpl-* definition. No browser fallback is used."
      />
    );
  }

  return (
    <div className="ep-card overflow-hidden">
      <table className="ep-table" data-testid="templates-table">
        <thead>
          <tr>
            <th>Template</th>
            <th>Steps</th>
            <th>Loop</th>
            <th>Estimated duration</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {templates.data.items.map((item) => {
            const definition = definitionFromTemplateDescriptor(item);
            return (
            <TemplateRow
              key={item.template_id}
              definition={definition}
              onError={onError}
              onClearError={onClearError}
            />
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function definitionFromTemplateDescriptor(
  descriptor: ScenarioTemplateDescriptor,
): WireScenarioDefinition {
  const label = descriptor.template_id
    .replace(/^tpl-/, '')
    .split('-')
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
  const major = Number.parseInt(descriptor.version.split('.')[0] ?? '1', 10);
  return {
    id: descriptor.template_id,
    name: label || descriptor.template_id,
    version: Number.isFinite(major) && major > 0 ? major : 1,
    loop_count: 1,
    steps: descriptor.steps,
    rat: descriptor.rat,
    simulator: descriptor.simulator,
    description: descriptor.description,
    catalog_scope: 'SYSTEM',
    mutable: false,
    cloneable: true,
    backend_support: descriptor.backend_support,
  };
}

function TemplateRow({
  definition,
  onError,
  onClearError,
}: {
  definition: WireScenarioDefinition;
  onError: (message: string) => void;
  onClearError: () => void;
}) {
  const navigate = useNavigate();
  const estimate = useScenarioEstimate(definition.id);
  const [downloading, setDownloading] = useState(false);

  // 0.6.0 — "Clone" no longer POSTs to /scenario-definitions/:id/clone and
  // navigates to the server-side result. Instead it decodes the template
  // (which is read-only, tpl-* backed by the backend) and hands the Builder
  // a seeded draft via route state. The operator reviews, edits and clicks
  // Save, which creates a brand-new definition — Clone becomes a real "copy
  // and edit" instead of a silent backend duplication.
  function openCloneInBuilder() {
    onClearError();
    try {
      const seedFromTemplate = decodeDefinition(definition);
      navigate('/scenarios/new', { state: { seedFromTemplate } });
    } catch (error) {
      const code = error instanceof ApiError ? (error as ApiError).code : 'CLONE_DECODE_FAILED';
      onError(`Clone of ${definition.id} refused · ${code} · ${(error as Error).message}`);
    }
  }

  async function download() {
    onClearError();
    setDownloading(true);
    try {
      const { payload, filename } = await downloadScenarioExport(definition.id);
      const expectedFilename = defaultFilename(payload.definition);
      const resolved = filename && filename !== 'export.json' ? filename : expectedFilename;
      const blob = new Blob([JSON.stringify(payload, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = resolved;
      anchor.rel = 'noopener';
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      const code = error instanceof ApiError ? (error as ApiError).code : 'DOWNLOAD_FAILED';
      onError(`Download ${definition.id} failed · ${code}`);
    } finally {
      setDownloading(false);
    }
  }

  return (
    <tr data-testid={`template-row-${definition.id}`}>
      <td>
        <div className="flex items-center gap-2">
          <FileJson width={14} height={14} className="text-primary" />
          <div className="min-w-0">
            <div className="font-medium truncate">{definition.name}</div>
            <div className="mono text-ep-xs text-text-secondary truncate">
              {definition.id} · v{definition.version ?? '?'}
            </div>
          </div>
        </div>
      </td>
      <td className="num">{definition.steps.length}</td>
      <td>× {definition.loop_count ?? 1}</td>
      <td className="mono text-ep-xs" data-testid={`template-estimate-${definition.id}`}>
        {estimate.isLoading
          ? 'estimating…'
          : estimate.data
            ? `${(estimate.data.duration_ms / 1000).toFixed(1)} s`
            : '—'}
      </td>
      <td>
        <div className="flex flex-wrap items-center gap-1">
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={download}
            disabled={downloading}
            data-testid={`template-download-${definition.id}`}
          >
            <Download width={13} height={13} />
            {downloading ? 'Downloading…' : 'Download JSON'}
          </button>
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={openCloneInBuilder}
            data-testid={`template-clone-${definition.id}`}
            title="Open an editable copy in the Scenario Builder. Save creates a new definition; the template stays read-only."
          >
            <Copy width={13} height={13} /> Clone
          </button>
        </div>
      </td>
    </tr>
  );
}
