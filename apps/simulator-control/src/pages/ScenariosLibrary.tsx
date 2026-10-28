import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Copy, Edit, Plus, Search, Trash2, Workflow } from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import { EmptyState } from '@/ui/EmptyErrorLoading';
import { ConfirmDialog } from '@/ui/ConfirmDialog';
import { useAssignments } from '@/scenarios/store';
import { useScenarioLibrary } from '@/scenarios/library';
import { emptyScenario, type LoopMode, type Scenario } from '@/scenarios/model';
import { isoToLocal } from '@/data/format';

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
  const [search, setSearch] = useState('');
  const [confirmDelete, setConfirmDelete] = useState<Scenario | null>(null);

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
    // The backend rejects an empty definition (no steps), so in backend mode the new
    // scenario is created on first save from the builder rather than here.
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
        eyebrow="Workflows"
        title="Scenarios"
        description="Reusable mobile scenarios composed from step primitives. Definitions live in the browser until a backend scenario CRUD contract is published — see docs/frontend/SIMULATOR_SCENARIO_BUILDER.md."
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
                    <div className="flex items-center gap-1" onClick={(event) => event.stopPropagation()}>
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

      <ConfirmDialog
        open={confirmDelete != null}
        title="Delete scenario"
        description={`Remove "${confirmDelete?.name ?? ''}" from the ${library.backend ? 'backend catalog' : 'local library'}. Any UE assignment pointing at it will also be cleared. This action cannot be undone.`}
        confirmLabel="Delete"
        tone="danger"
        onCancel={() => setConfirmDelete(null)}
        onConfirm={() => {
          if (confirmDelete) void library.delete(confirmDelete.id);
          setConfirmDelete(null);
        }}
      />
    </>
  );
}
