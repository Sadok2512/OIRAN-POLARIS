import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Copy,
  Edit,
  FileJson,
  Lock,
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
import { isoToLocal } from '@/data/format';
import { useFeatureFlag } from '@/data/featureFlags';
import { useScenarioTemplates } from '@/data/scenarioTemplatesApi';
import { ImportScenarioDialog } from '@/scenarios/ImportScenarioDialog';
import {
  DEFAULT_SCENARIO_TEMPLATES,
  scenarioFromSystemTemplate,
  templateFromDescriptor,
  templateSupport,
  type ScenarioTemplateCategory,
  type ScenarioTemplateRat,
  type ScenarioTemplateSupport,
  type SystemScenarioTemplate,
} from '@/scenarios/defaultTemplates';

type Tab = 'library' | 'templates';

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

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return library.scenarios;
    return library.scenarios.filter((scenario) =>
      [scenario.name, scenario.description ?? '', scenario.id]
        .join(' ')
        .toLowerCase()
        .includes(needle),
    );
  }, [library.scenarios, search]);

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
            {value === 'library' ? 'My scenarios' : 'Templates LTE / 5G'}
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
  const [rat, setRat] = useState<'ALL' | ScenarioTemplateRat>('ALL');
  const [category, setCategory] = useState<'ALL' | ScenarioTemplateCategory>('ALL');

  const catalog = useMemo(
    () => templates.data?.schema_version === 'polaris.scenario-template-catalog.v1'
      ? templates.data.items.map(templateFromDescriptor)
      : DEFAULT_SCENARIO_TEMPLATES,
    [templates.data],
  );
  const visible = useMemo(
    () => catalog.filter((item) =>
      (rat === 'ALL' || item.rat === rat) &&
      (category === 'ALL' || item.category === category)),
    [catalog, category, rat],
  );

  if (!flag) {
    return (
      <Unavailable
        reason="Template API disabled in Settings. The system catalog remains immutable and no backend request is issued."
      />
    );
  }

  return (
    <div className="space-y-4" data-testid="templates-catalog">
      <section className="ep-card p-4 flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h2 className="text-ep-md font-semibold">System templates</h2>
          <p className="text-ep-sm text-text-secondary mt-1">
            Immutable starting points. Use or customize always creates a new editable copy.
          </p>
        </div>
        <div className="flex flex-wrap gap-3">
          <label className="flex flex-col gap-1 text-ep-xs text-text-secondary">
            RAT
            <select className="ep-input min-w-48" value={rat} onChange={(event) => setRat(event.target.value as typeof rat)} aria-label="Template RAT filter">
              <option value="ALL">All RATs</option>
              <option value="LTE">LTE 4G · srsRAN</option>
              <option value="5G_SA">5G SA · UERANSIM</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-ep-xs text-text-secondary">
            Category
            <select className="ep-input min-w-48" value={category} onChange={(event) => setCategory(event.target.value as typeof category)} aria-label="Template category filter">
              <option value="ALL">All categories</option>
              {(['Connectivity', 'Session', 'Data UL/DL', 'Full Session', 'Multi-UE'] as ScenarioTemplateCategory[]).map((value) => <option key={value}>{value}</option>)}
            </select>
          </label>
        </div>
      </section>

      {templates.isLoading && <LoadingSkeleton label="Checking backend template contract" />}
      {templates.error && (
        <div className="ep-card border-warning/30 p-3 text-ep-sm text-warning" role="status">
          Backend template contract unavailable · system templates remain draft-only.
        </div>
      )}
      {!templates.isLoading && !templates.error && (
        <p className="text-ep-xs text-text-secondary" data-testid="backend-template-sync">
          ANR1 catalogue synchronized · {templates.data?.items.length ?? 0} immutable descriptor(s) · {templates.data?.schema_version}.
        </p>
      )}

      <div className="grid gap-4 xl:grid-cols-2" data-testid="templates-grid">
        {visible.map((item) => (
          <TemplateCard
            key={item.id}
            item={item}
            support={templateSupport(item)}
            onError={onError}
            onClearError={onClearError}
          />
        ))}
      </div>
      {visible.length === 0 && <EmptyState title="No template matches" description="Adjust RAT or category filters." />}
    </div>
  );
}

function TemplateCard({
  item,
  support,
  onError,
  onClearError,
}: {
  item: SystemScenarioTemplate;
  support: ScenarioTemplateSupport;
  onError: (message: string) => void;
  onClearError: () => void;
}) {
  const navigate = useNavigate();
  function openInBuilder(action: 'use' | 'customize') {
    onClearError();
    try {
      const seedFromTemplate = scenarioFromSystemTemplate(item);
      navigate('/scenarios/new', {
        state: {
          seedFromTemplate,
          systemTemplate: { id: item.id, name: item.name, action, support },
        },
      });
    } catch (error) {
      onError(`Template ${item.id} refused · ${(error as Error).message}`);
    }
  }

  return (
    <article className="ep-card p-5 flex flex-col gap-4" data-testid={`template-card-${item.id}`}>
      <header className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <FileJson width={15} height={15} className="text-primary" />
            <span className="ep-badge">{item.category}</span>
            <span className="ep-badge">{item.rat === 'LTE' ? 'LTE 4G' : '5G SA'}</span>
            <SupportBadge value={support} />
          </div>
          <h3 className="text-ep-md font-semibold">{item.name}</h3>
          <p className="mono text-ep-xs text-text-secondary">{item.id} · {item.simulator} · system/read-only</p>
        </div>
        <Lock width={15} height={15} className="text-text-secondary shrink-0" aria-label="Immutable system template" />
      </header>
      <p className="text-ep-sm text-text-secondary">{item.description}</p>
      <dl className="grid grid-cols-2 gap-2 text-ep-sm sm:grid-cols-4">
        <div><dt className="text-ep-xs text-text-secondary">Steps</dt><dd className="font-semibold">{item.definition.steps.length}</dd></div>
        <div><dt className="text-ep-xs text-text-secondary">Duration</dt><dd className="font-semibold">{item.durationSeconds}s</dd></div>
        <div><dt className="text-ep-xs text-text-secondary">Throughput</dt><dd className="font-semibold">{item.throughputKbps ? `≤ ${item.throughputKbps} kbit/s` : 'None'}</dd></div>
        <div><dt className="text-ep-xs text-text-secondary">Loop</dt><dd className="font-semibold">× {item.definition.loop_count}</dd></div>
      </dl>
      <div>
        <p className="text-ep-xs uppercase tracking-wider text-text-secondary mb-2">Steps</p>
        <ol className="flex flex-wrap gap-1" aria-label={`${item.name} steps`}>
          {item.definition.steps.map((entry, index) => <li key={`${entry.type}-${index}`} className="ep-badge">{index + 1}. {entry.type}</li>)}
        </ol>
      </div>
      <div>
        <p className="text-ep-xs uppercase tracking-wider text-text-secondary mb-1">Prerequisites</p>
        <ul className="text-ep-xs text-text-secondary list-disc pl-4">{item.prerequisites.map((value) => <li key={value}>{value}</li>)}</ul>
      </div>
      <footer className="mt-auto flex flex-wrap items-center gap-2 border-t border-border pt-3">
          <button
            type="button"
            className="ep-button ep-button-sm ep-button-primary"
            onClick={() => openInBuilder('use')}
            data-testid={`template-use-${item.id}`}
          >
            Use Template
          </button>
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={() => openInBuilder('customize')}
            data-testid={`template-customize-${item.id}`}
            title="Open an editable copy. The system template remains immutable."
          >
            <Copy width={13} height={13} /> Customize
          </button>
      </footer>
    </article>
  );
}

function SupportBadge({ value }: { value: ScenarioTemplateSupport }) {
  const tone = value === 'SUPPORTED' ? 'text-success' : value === 'CERTIFICATION_REQUIRED' ? 'text-warning' : 'text-text-secondary';
  return <span className={`ep-badge ${tone}`} data-testid={`support-${value}`}>{value}</span>;
}
