import { useEffect, useState } from 'react';
import { X } from 'lucide-react';
import type { Scenario } from '@/scenarios/model';

export function AssignScenarioDialog({
  open,
  selectedCount,
  scenarios,
  busy,
  onSubmit,
  onCancel,
}: {
  open: boolean;
  selectedCount: number;
  scenarios: Scenario[];
  busy?: boolean;
  onSubmit: (payload: { scenarioId: string | null; autoRun: boolean }) => void;
  onCancel: () => void;
}) {
  const [scenarioId, setScenarioId] = useState<string>('');
  const [autoRun, setAutoRun] = useState(false);

  useEffect(() => {
    if (!open) return;
    setScenarioId(scenarios[0]?.id ?? '');
    setAutoRun(false);
  }, [open, scenarios]);

  if (!open) return null;

  const canSubmit = selectedCount > 0 && !busy;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="assign-scenario-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
      data-testid="assign-scenario-dialog"
    >
      <form
        className="ep-card w-full max-w-md p-5 flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          onSubmit({ scenarioId: scenarioId || null, autoRun });
        }}
      >
        <header className="flex items-center justify-between">
          <h2 id="assign-scenario-title" className="text-ep-lg font-semibold">
            Assign scenario
          </h2>
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={onCancel}
            aria-label="Close"
          >
            <X width={13} height={13} />
          </button>
        </header>

        <p className="text-ep-sm text-text-secondary">
          Assign one scenario to <span className="mono">{selectedCount}</span> selected UE profile
          {selectedCount === 1 ? '' : 's'}. Choose <em>None</em> to clear any existing assignment.
        </p>

        <label className="flex flex-col gap-1 text-ep-sm">
          <span className="text-ep-xs uppercase tracking-wider text-text-secondary">Scenario</span>
          <select
            className="ep-input"
            value={scenarioId}
            onChange={(event) => setScenarioId(event.target.value)}
            data-testid="assign-scenario-select"
          >
            <option value="">— None (clear) —</option>
            {scenarios.map((scenario) => (
              <option key={scenario.id} value={scenario.id}>
                {scenario.name} (v{scenario.version})
              </option>
            ))}
          </select>
          {scenarios.length === 0 && (
            <span className="text-ep-xs text-warning">
              No scenarios in the library yet — create one in the Scenario Builder first.
            </span>
          )}
        </label>

        <label className="flex items-center gap-2 text-ep-sm">
          <input
            type="checkbox"
            checked={autoRun}
            onChange={(event) => setAutoRun(event.target.checked)}
            disabled={!scenarioId}
            data-testid="assign-scenario-autorun"
          />
          <span>Auto-run on UE start (requires backend auto-run endpoint)</span>
        </label>

        <footer className="flex justify-end gap-2 pt-2 border-t border-border mt-1">
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={onCancel}
            disabled={busy}
          >
            Cancel
          </button>
          <button
            type="submit"
            className="ep-button ep-button-sm ep-button-primary"
            disabled={!canSubmit}
            data-testid="assign-scenario-submit"
          >
            {busy ? 'Applying…' : scenarioId ? 'Assign' : 'Clear assignments'}
          </button>
        </footer>
      </form>
    </div>
  );
}
