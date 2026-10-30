import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, FileJson, Lock, Upload, X } from 'lucide-react';
import { ApiError } from '@shared/api';
import { INTERNAL_STEP_KIND, STEP_METADATA } from '@/scenarios/model';
import {
  SCENARIO_SCHEMA_VERSION,
  type WireScenarioExportFile,
  type WireScenarioStep,
} from '@/scenarios/wireCodec';
import {
  isTemplateId,
  useScenarioImport,
  type ImportMode,
} from '@/data/scenarioTemplatesApi';

/**
 * 0.5.0 — Import a scenario-definition v2 JSON file.
 *
 * Pipeline:
 *   1. local parse + local schema_version check (fail-fast UX, no network)
 *   2. preview the structural step tree BEFORE the operator hits "Import"
 *   3. POST /scenario-definitions/import; surface the backend code verbatim
 *   4. on 409, offer "Import as new version" or "Rename and import"
 *   5. 413 and 422 surface with their exact code (no translation)
 *
 * Nothing is persisted locally — the dialog never falls back to a fake
 * success and never fabricates a definition when the backend refuses.
 */
export function ImportScenarioDialog({
  open,
  onClose,
  onImported,
}: {
  open: boolean;
  onClose: () => void;
  onImported?: (importedId: string) => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [payload, setPayload] = useState<WireScenarioExportFile | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState('');
  const importMutation = useScenarioImport();

  useEffect(() => {
    if (!open) {
      setFile(null);
      setPayload(null);
      setParseError(null);
      setRenameValue('');
      importMutation.reset();
    }
    // We intentionally omit `importMutation` from deps — resetting it is
    // part of the "closed state" cleanup.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  async function pickFile(fileHandle: File | undefined) {
    setParseError(null);
    setPayload(null);
    importMutation.reset();
    if (!fileHandle) return;
    setFile(fileHandle);
    try {
      const text = await fileHandle.text();
      const parsed = JSON.parse(text) as WireScenarioExportFile;
      if (!parsed || typeof parsed !== 'object') {
        throw new Error('File does not contain a JSON object');
      }
      if (parsed.schema_version !== SCENARIO_SCHEMA_VERSION) {
        setParseError(
          `SCHEMA_UNKNOWN · expected "${SCENARIO_SCHEMA_VERSION}", got "${
            parsed.schema_version ?? 'none'
          }".`,
        );
        return;
      }
      if (!parsed.definition || !Array.isArray(parsed.definition.steps)) {
        setParseError('definition.steps is missing from the import file.');
        return;
      }
      setPayload(parsed);
      setRenameValue(`${parsed.definition.id}-copy`);
    } catch (error) {
      setParseError(
        error instanceof SyntaxError
          ? `JSON parse error · ${error.message}`
          : (error as Error).message,
      );
    }
  }

  const definition = payload?.definition;
  const errorCode = importMutation.error instanceof ApiError
    ? (importMutation.error as ApiError).code
    : null;
  const errorStatus = importMutation.error instanceof ApiError
    ? (importMutation.error as ApiError).status
    : null;
  const needsCollisionResolution =
    errorStatus === 409 &&
    (errorCode === 'SCENARIO_ID_EXISTS' || errorCode === 'TEMPLATE_ID_RESERVED');

  async function doImport(mode: ImportMode) {
    if (!payload) return;
    try {
      const created = await importMutation.mutateAsync({ file: payload, mode });
      onImported?.(created.id);
      onClose();
    } catch {
      // Error state is read from importMutation.error below.
    }
  }

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="import-scenario-title"
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/40 p-4"
      data-testid="import-scenario-dialog"
    >
      <form
        className="ep-card w-full max-w-2xl p-5 flex flex-col gap-3 my-4"
        onSubmit={(event) => {
          event.preventDefault();
          void doImport({ kind: 'reject-collision' });
        }}
      >
        <header className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileJson className="text-primary" width={18} height={18} />
            <h2 id="import-scenario-title" className="text-ep-lg font-semibold">
              Import scenario (v2)
            </h2>
          </div>
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={onClose}
            aria-label="Close"
          >
            <X width={13} height={13} />
          </button>
        </header>
        <p className="text-ep-xs text-text-secondary">
          Expects a <code className="mono">polaris.scenario-definition.v2</code> file (same shape as
          <code className="mono"> GET /scenario-definitions/:id/export</code>). Validation runs on
          the backend; this dialog only shows a structural preview before posting.
        </p>

        <label className="flex items-center gap-2 text-ep-sm" data-testid="import-file-input">
          <span className="ep-button ep-button-sm cursor-pointer">
            <Upload width={13} height={13} /> Choose JSON file
          </span>
          <input
            type="file"
            accept="application/json,.json"
            onChange={(event) => void pickFile(event.target.files?.[0])}
            className="sr-only"
            data-testid="import-file-field"
          />
          <span className="text-ep-xs text-text-secondary mono truncate">
            {file ? file.name : 'no file selected'}
          </span>
        </label>

        {parseError && (
          <p
            role="alert"
            className="text-ep-xs text-error flex items-start gap-1"
            data-testid="import-parse-error"
          >
            <AlertTriangle width={11} height={11} className="mt-0.5 shrink-0" />
            {parseError}
          </p>
        )}

        {definition && (
          <section
            className="border border-border rounded-md bg-canvas/40 p-3 flex flex-col gap-2"
            data-testid="import-preview"
          >
            <header className="flex items-center justify-between gap-2">
              <div>
                <p className="text-ep-xs uppercase tracking-wider text-text-secondary">
                  Preview
                </p>
                <p className="text-ep-md font-semibold">
                  {definition.name}{' '}
                  <span className="text-text-secondary text-ep-xs mono">
                    · {definition.id} · v{definition.version ?? '?'}
                  </span>
                </p>
              </div>
              <span className="ep-badge">
                loop_count × {definition.loop_count ?? 1}
              </span>
            </header>
            <StepTree steps={definition.steps} />
            {isTemplateId(definition.id) && (
              <p className="text-ep-xs text-warning flex items-start gap-1">
                <Lock width={11} height={11} className="mt-0.5 shrink-0" />
                This id is reserved for backend-seeded templates (<span className="mono">tpl-*</span>).
                The backend will refuse with 409 <span className="mono">TEMPLATE_ID_RESERVED</span>;
                use rename to import under a different id.
              </p>
            )}
          </section>
        )}

        {importMutation.error && errorCode && (
          <div
            role="alert"
            className="ep-card border-error/30 p-3 text-ep-sm text-error flex flex-col gap-2"
            data-testid="import-backend-error"
          >
            <p>
              <strong>HTTP {errorStatus}</strong> · <span className="mono">{errorCode}</span>
            </p>
            <p className="text-ep-xs text-text-secondary">
              {(importMutation.error as Error).message}
            </p>
          </div>
        )}

        {needsCollisionResolution && (
          <section
            className="border border-warning/40 rounded-md p-3 flex flex-col gap-2"
            data-testid="import-collision"
          >
            <p className="text-ep-sm">
              A definition with id <span className="mono">{definition?.id}</span> already exists.
            </p>
            <div className="flex items-center gap-2 flex-wrap">
              <button
                type="button"
                className="ep-button ep-button-sm"
                onClick={() => void doImport({ kind: 'new_version' })}
                disabled={importMutation.isPending}
                data-testid="import-new-version"
              >
                Import as new version
              </button>
              <label className="flex items-center gap-2 text-ep-sm">
                <input
                  className="ep-input text-ep-sm py-1 h-8 mono"
                  value={renameValue}
                  onChange={(event) => setRenameValue(event.target.value)}
                  aria-label="New scenario id"
                  data-testid="import-rename-field"
                />
                <button
                  type="button"
                  className="ep-button ep-button-sm ep-button-primary"
                  onClick={() => void doImport({ kind: 'rename', target_id: renameValue.trim() })}
                  disabled={importMutation.isPending || !renameValue.trim()}
                  data-testid="import-rename-submit"
                >
                  Rename &amp; import
                </button>
              </label>
            </div>
          </section>
        )}

        <footer className="flex items-center justify-end gap-2 pt-2 border-t border-border">
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={onClose}
            disabled={importMutation.isPending}
          >
            Cancel
          </button>
          <button
            type="submit"
            className="ep-button ep-button-sm ep-button-primary"
            disabled={!payload || !!parseError || importMutation.isPending}
            data-testid="import-submit"
          >
            {importMutation.isPending ? 'Importing…' : 'Import'}
          </button>
        </footer>
      </form>
    </div>
  );
}

function StepTree({ steps, depth = 0 }: { steps: WireScenarioStep[]; depth?: number }) {
  if (steps.length === 0) return <p className="text-ep-xs text-text-secondary">no step</p>;
  const prefix = useMemo(() => '▸ '.repeat(depth), [depth]);
  return (
    <ul
      className="flex flex-col gap-1 text-ep-xs"
      data-testid={`import-step-tree-${depth}`}
    >
      {steps.map((step, index) => {
        const kind = INTERNAL_STEP_KIND[step.type];
        const label = kind ? STEP_METADATA[kind].label : step.type;
        const paramKeys = Object.keys(step.parameters ?? {});
        return (
          <li
            key={`${depth}-${index}`}
            className="border border-border rounded-md px-2 py-1 flex flex-col gap-1"
            data-testid={`import-step-${depth}-${index}`}
          >
            <div className="flex items-center gap-2">
              <span className="mono text-text-secondary">{prefix}#{index + 1}</span>
              <span className="font-medium">{label}</span>
              <span className="mono text-text-secondary">{step.type}</span>
              {step.loop_count && step.loop_count !== 1 && (
                <span className="ep-badge">× {step.loop_count}</span>
              )}
            </div>
            {paramKeys.length > 0 && (
              <ul className="flex flex-wrap gap-1 text-ep-xs text-text-secondary">
                {paramKeys.map((key) => (
                  <li key={key} className="mono">
                    {key}
                  </li>
                ))}
              </ul>
            )}
            {step.steps && step.steps.length > 0 && (
              <div className="pl-3 border-l border-border">
                <StepTree steps={step.steps} depth={depth + 1} />
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
}
