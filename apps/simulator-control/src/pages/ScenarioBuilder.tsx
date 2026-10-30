import { useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowDown,
  ArrowLeft,
  ArrowUp,
  CheckCircle2,
  Copy,
  Lock,
  Plus,
  Save,
  Trash2,
} from 'lucide-react';
import { PageHeader } from '@/ui/PageHeader';
import { EmptyState } from '@/ui/EmptyErrorLoading';
import { useScenarioLibrary } from '@/scenarios/library';
import { isLoopRepresentable } from '@/scenarios/wireCodec';
import { useCapabilities } from '@/data/queries';
import {
  PARAM_META,
  STEP_METADATA,
  emptyScenario,
  isStepKindExecutable,
  newStepId,
  validateScenario,
  type FixedOrRandom,
  type LoopMode,
  type Scenario,
  type ScenarioStep,
  type ScenarioStepKind,
  type StepParams,
} from '@/scenarios/model';
import { StepEditor } from '@/components/StepEditor';
import { LoopEditor } from '@/components/LoopEditor';
import { ScenarioTimeline } from '@/components/ScenarioTimeline';

export function ScenarioBuilderPage() {
  const { scenarioId } = useParams<{ scenarioId: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const library = useScenarioLibrary();
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  // 0.6.0 — Template Clone navigates here with `state.seedFromTemplate`
  // carrying a decoded Scenario. The Builder consumes it ONCE on mount
  // (so a page refresh falls back to the empty draft) and clears the id
  // so Save creates a brand-new definition rather than updating the
  // template.
  const seededFromTemplate = (location.state as { seedFromTemplate?: Scenario } | null)
    ?.seedFromTemplate;

  const [draft, setDraft] = useState<Scenario>(() => {
    if (seededFromTemplate) {
      return { ...seededFromTemplate, id: emptyScenario().id, version: 1 };
    }
    const existing = scenarioId
      ? library.scenarios.find((item) => item.id === scenarioId)
      : null;
    return existing ?? emptyScenario();
  });

  useEffect(() => {
    if (!scenarioId) return;
    const existing = library.scenarios.find((item) => item.id === scenarioId);
    if (existing) setDraft(existing);
  }, [scenarioId, library.scenarios]);

  const issues = useMemo(() => validateScenario(draft), [draft]);
  const errors = issues.filter((issue) => issue.level === 'error');

  // 0.5.2 — The three new-contract kinds (TRAFFIC_UL, DETACH, REPEAT) are
  // metadata-flagged `backendCertified: false` until the backend advertises
  // them. `GET /capabilities.scenario_step_kinds` is the single source of
  // truth: when it names a wire type, the matching kind is promoted to
  // "Supported" without touching STEP_METADATA.
  const capabilities = useCapabilities();
  const advertisedKinds = capabilities.data?.scenario_step_kinds;

  const paletteGroups = useMemo(() => {
    const supported: ScenarioStepKind[] = [];
    const locked: ScenarioStepKind[] = [];
    for (const kind of Object.keys(STEP_METADATA) as ScenarioStepKind[]) {
      if (isStepKindExecutable(kind, advertisedKinds)) supported.push(kind);
      else locked.push(kind);
    }
    return { supported, locked };
  }, [advertisedKinds]);

  const hasLockedStep = useMemo(
    () => draft.steps.some((step) => !isStepKindExecutable(step.kind, advertisedKinds)),
    [draft.steps, advertisedKinds],
  );

  function updateDraft(update: Partial<Scenario>) {
    setDraft((prev) => ({ ...prev, ...update }));
  }

  function addStep(kind: ScenarioStepKind) {
    const defaultParams: StepParams = {};
    const paramKeys = STEP_METADATA[kind].defaultParams ?? [];
    for (const key of paramKeys) {
      const paramMeta = PARAM_META[key as keyof StepParams];
      defaultParams[key as keyof StepParams] = { mode: 'fixed', value: paramMeta.min };
    }
    const step: ScenarioStep = { id: newStepId(), kind, params: defaultParams };
    setDraft((prev) => ({ ...prev, steps: [...prev.steps, step] }));
  }

  function updateStep(stepId: string, patch: Partial<ScenarioStep>) {
    setDraft((prev) => ({
      ...prev,
      steps: prev.steps.map((step) => (step.id === stepId ? { ...step, ...patch } : step)),
    }));
  }

  function removeStep(stepId: string) {
    setDraft((prev) => ({
      ...prev,
      steps: prev.steps.filter((step) => step.id !== stepId),
    }));
  }

  function duplicateStep(stepId: string) {
    setDraft((prev) => {
      const source = prev.steps.find((step) => step.id === stepId);
      if (!source) return prev;
      const index = prev.steps.findIndex((step) => step.id === stepId);
      const copy: ScenarioStep = { ...source, id: newStepId(), params: { ...source.params } };
      const next = [...prev.steps];
      next.splice(index + 1, 0, copy);
      return { ...prev, steps: next };
    });
  }

  function moveStep(stepId: string, direction: -1 | 1) {
    setDraft((prev) => {
      const index = prev.steps.findIndex((step) => step.id === stepId);
      if (index < 0) return prev;
      const next = [...prev.steps];
      const target = index + direction;
      if (target < 0 || target >= next.length) return prev;
      [next[index], next[target]] = [next[target], next[index]];
      return { ...prev, steps: next };
    });
  }

  function updateParam(stepId: string, key: keyof StepParams, value: FixedOrRandom | undefined) {
    setDraft((prev) => ({
      ...prev,
      steps: prev.steps.map((step) =>
        step.id !== stepId
          ? step
          : {
              ...step,
              params: value ? { ...step.params, [key]: value } : removeKey(step.params, key),
            },
      ),
    }));
  }

  const backendBlocked =
    library.backend && (!isLoopRepresentable(draft.loop.kind) || hasLockedStep);

  // 0.10.0 — Save disable reason, surfaced inline next to the button so
  // the operator sees WHY Save is grayed without having to hover for the
  // native tooltip. Order matches the disable predicate below.
  const saveBlockReason: string | null = saving
    ? null
    : errors.length > 0
      ? `${errors.length} erreur${errors.length > 1 ? 's' : ''} de validation à corriger.`
      : library.backend && hasLockedStep
        ? 'Au moins une étape non certifiée côté backend — à retirer avant Save.'
        : library.backend && !isLoopRepresentable(draft.loop.kind)
          ? 'Mode de boucle non représentable dans le catalog backend.'
          : null;

  async function save() {
    if (errors.length > 0 || backendBlocked || saving) return;
    setSaveError(null);
    setSaving(true);
    try {
      const saved = await library.save(draft);
      setDraft(saved);
      navigate(`/scenarios/${saved.id}/edit`, { replace: true });
    } catch (error) {
      const code = (error as { code?: string }).code;
      setSaveError(code ? `${code} — ${(error as Error).message}` : (error as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Workflows"
        title="Scenario Builder"
        description="Design a reusable scenario. Steps are declarative — randomization and loop execution run server-side once the matching backend contract exists. Backend-unsupported steps surface an honest 'Backend support required' notice."
        actions={
          <div className="flex items-center gap-2">
            <button
              type="button"
              className="ep-button"
              onClick={() => navigate('/scenarios')}
              data-testid="builder-back"
            >
              <ArrowLeft width={14} height={14} aria-hidden="true" />
              Back to library
            </button>
            {saveBlockReason && (
              <span
                className="text-ep-xs text-warning flex items-center gap-1 max-w-xs"
                data-testid="builder-save-reason"
                role="status"
              >
                <AlertTriangle width={12} height={12} className="shrink-0" aria-hidden="true" />
                <span>{saveBlockReason}</span>
              </span>
            )}
            <button
              type="button"
              className="ep-button ep-button-primary"
              onClick={() => void save()}
              disabled={errors.length > 0 || backendBlocked || saving}
              data-testid="builder-save"
              title={saveBlockReason ?? undefined}
            >
              <Save width={14} height={14} aria-hidden="true" />
              {saving ? 'Saving…' : library.backend ? 'Save to backend' : 'Save scenario'}
            </button>
          </div>
        }
      />

      {saveError && (
        <section
          className="ep-card border-error/40 p-4 mb-4 text-ep-sm text-error flex items-start gap-2"
          role="alert"
          data-testid="builder-save-error"
        >
          <AlertTriangle width={14} height={14} className="mt-0.5 shrink-0" aria-hidden="true" />
          <span>Save failed: {saveError}</span>
        </section>
      )}

      <section className="ep-card p-5 mb-4 grid gap-3 md:grid-cols-2">
        <label className="flex flex-col gap-1">
          <span className="text-ep-xs uppercase tracking-wider text-text-secondary">Name</span>
          <input
            className="ep-input"
            value={draft.name}
            onChange={(event) => updateDraft({ name: event.target.value })}
            data-testid="scenario-name"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-ep-xs uppercase tracking-wider text-text-secondary">Version</span>
          <input className="ep-input mono" value={`v${draft.version}`} readOnly />
        </label>
        <label className="flex flex-col gap-1 md:col-span-2">
          <span className="text-ep-xs uppercase tracking-wider text-text-secondary">Description</span>
          <textarea
            className="ep-input py-2 h-20 resize-none"
            value={draft.description ?? ''}
            onChange={(event) => updateDraft({ description: event.target.value })}
            data-testid="scenario-description"
          />
        </label>
      </section>

      <section className="ep-card p-5 mb-4">
        <h2 className="text-ep-md font-semibold mb-2">Loop configuration</h2>
        <p className="text-ep-xs text-text-secondary mb-3">
          Random cycle count is sampled once per scenario run. Infinite loops require a manual Stop and server-side execution limits.
        </p>
        <LoopEditor
          loop={draft.loop}
          onChange={(loop: LoopMode) => updateDraft({ loop })}
          backendOnly={library.backend}
        />
      </section>

      <section className="ep-card p-5 mb-4">
        <header className="flex flex-col gap-2 mb-3">
          <div className="flex items-center justify-between">
            <h2 className="text-ep-md font-semibold">Steps · {draft.steps.length}</h2>
            {!library.backend && (
              <span className="ep-badge" data-testid="builder-offline-draft-badge">
                Offline draft
              </span>
            )}
          </div>
          <div className="flex flex-col gap-2" data-testid="step-palette">
            <div className="flex flex-wrap gap-1" data-testid="step-palette-supported">
              <span className="text-ep-xs uppercase tracking-wider text-text-secondary mr-1">
                Supported
              </span>
              {paletteGroups.supported.map((kind) => (
                <button
                  key={kind}
                  type="button"
                  className="ep-badge cursor-pointer hover:bg-primary/10"
                  onClick={() => addStep(kind)}
                  title={`Add ${STEP_METADATA[kind].label}`}
                  data-testid={`add-step-${kind}`}
                >
                  <Plus width={10} height={10} />
                  {STEP_METADATA[kind].label}
                </button>
              ))}
            </div>
            {paletteGroups.locked.length > 0 && (
              <div
                className="flex flex-wrap gap-1 border-t border-border pt-2"
                data-testid="step-palette-locked"
              >
                <span className="text-ep-xs uppercase tracking-wider text-warning mr-1 flex items-center gap-1">
                  <Lock width={11} height={11} />
                  Not supported yet
                </span>
                {paletteGroups.locked.map((kind) => {
                  const meta = STEP_METADATA[kind];
                  const reason = meta.backendNote ?? 'Not accepted by polaris-control-api.';
                  return (
                    <span
                      key={kind}
                      className="ep-badge opacity-60 cursor-not-allowed"
                      title={reason}
                      aria-disabled="true"
                      data-testid={`locked-step-${kind}`}
                    >
                      <Lock width={10} height={10} />
                      {meta.label}
                    </span>
                  );
                })}
              </div>
            )}
          </div>
        </header>

        {hasLockedStep && library.backend && (
          <div
            role="alert"
            className="ep-card border-warning/40 p-3 mb-3 text-ep-sm text-warning flex items-start gap-2"
            data-testid="builder-locked-step-banner"
          >
            <AlertTriangle width={14} height={14} className="mt-0.5 shrink-0" aria-hidden="true" />
            <span>
              This draft contains a step the backend will refuse. Remove it, or switch to
              <strong> Offline draft </strong> in Settings. Save is blocked until the draft only
              contains backend-certified steps.
            </span>
          </div>
        )}

        {draft.steps.length === 0 ? (
          <EmptyState title="No step yet" description="Add steps from the palette above." />
        ) : (
          <ol className="flex flex-col gap-2">
            {draft.steps.map((step, index) => (
              <li key={step.id} className="border border-border rounded-md" data-testid={`step-row-${step.id}`}>
                <StepEditor
                  index={index + 1}
                  step={step}
                  onUpdate={(patch) => updateStep(step.id, patch)}
                  onParam={(key, value) => updateParam(step.id, key, value)}
                  actions={
                    <div className="flex items-center gap-1">
                      <button
                        type="button"
                        className="ep-button ep-button-sm"
                        onClick={() => moveStep(step.id, -1)}
                        disabled={index === 0}
                        aria-label="Move step up"
                        data-testid={`step-up-${step.id}`}
                      >
                        <ArrowUp width={13} height={13} />
                      </button>
                      <button
                        type="button"
                        className="ep-button ep-button-sm"
                        onClick={() => moveStep(step.id, 1)}
                        disabled={index === draft.steps.length - 1}
                        aria-label="Move step down"
                        data-testid={`step-down-${step.id}`}
                      >
                        <ArrowDown width={13} height={13} />
                      </button>
                      <button
                        type="button"
                        className="ep-button ep-button-sm"
                        onClick={() => duplicateStep(step.id)}
                        aria-label="Duplicate step"
                        data-testid={`step-duplicate-${step.id}`}
                      >
                        <Copy width={13} height={13} />
                      </button>
                      <button
                        type="button"
                        className="ep-button ep-button-sm ep-button-danger"
                        onClick={() => removeStep(step.id)}
                        aria-label="Remove step"
                        data-testid={`step-remove-${step.id}`}
                      >
                        <Trash2 width={13} height={13} />
                      </button>
                    </div>
                  }
                />
              </li>
            ))}
          </ol>
        )}
      </section>

      <section className="ep-card p-5 mb-4">
        <h2 className="text-ep-md font-semibold mb-2">Timeline preview</h2>
        <ScenarioTimeline scenario={draft} />
      </section>

      <section className="ep-card p-5">
        <h2 className="text-ep-md font-semibold mb-2">Validation</h2>
        {issues.length === 0 ? (
          <p className="flex items-center gap-2 text-ep-sm text-success">
            <CheckCircle2 width={14} height={14} /> Scenario is valid.
          </p>
        ) : (
          <ul className="flex flex-col gap-1 text-ep-sm" data-testid="validation-issues">
            {issues.map((issue, index) => (
              <li
                key={`${issue.path}-${index}`}
                className={`flex items-start gap-2 ${issue.level === 'error' ? 'text-error' : 'text-warning'}`}
              >
                <AlertTriangle width={13} height={13} className="mt-0.5 shrink-0" />
                <span>
                  <code className="mono text-ep-xs mr-2">{issue.path}</code>
                  {issue.message}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </>
  );
}

function removeKey<T extends object>(object: T, key: keyof T): T {
  const next = { ...object };
  delete next[key];
  return next;
}
