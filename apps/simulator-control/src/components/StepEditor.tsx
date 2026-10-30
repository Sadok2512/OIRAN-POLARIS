import { AlertTriangle, Plus, Trash2 } from 'lucide-react';
import {
  MAX_REPEAT_NESTING,
  PARAM_META,
  STEP_METADATA,
  newStepId,
  type FixedOrRandom,
  type ScenarioStep,
  type ScenarioStepKind,
  type StepParams,
} from '@/scenarios/model';

export function StepEditor({
  index,
  step,
  onUpdate,
  onParam,
  actions,
  depth = 0,
}: {
  index: number;
  step: ScenarioStep;
  onUpdate: (patch: Partial<ScenarioStep>) => void;
  onParam: (key: keyof StepParams, value: FixedOrRandom | undefined) => void;
  actions?: React.ReactNode;
  depth?: number;
}) {
  const meta = STEP_METADATA[step.kind];
  const paramKeys = Object.keys(step.params) as (keyof StepParams)[];
  const supportedKeys = meta.defaultParams ?? [];
  const isRepeat = step.kind === 'REPEAT';
  const nestedSteps = step.steps ?? [];
  const canNestFurther = depth + 1 < MAX_REPEAT_NESTING;

  function updateNestedStep(stepId: string, patch: Partial<ScenarioStep>) {
    onUpdate({
      steps: nestedSteps.map((child) => (child.id === stepId ? { ...child, ...patch } : child)),
    });
  }

  function updateNestedParam(stepId: string, key: keyof StepParams, value: FixedOrRandom | undefined) {
    onUpdate({
      steps: nestedSteps.map((child) =>
        child.id !== stepId
          ? child
          : {
              ...child,
              params: value ? { ...child.params, [key]: value } : removeKey(child.params, key),
            },
      ),
    });
  }

  function removeNestedStep(stepId: string) {
    onUpdate({ steps: nestedSteps.filter((child) => child.id !== stepId) });
  }

  function addNestedStep(kind: ScenarioStepKind) {
    const defaultParams: StepParams = {};
    for (const key of STEP_METADATA[kind].defaultParams ?? []) {
      const paramMeta = PARAM_META[key as keyof StepParams];
      defaultParams[key as keyof StepParams] = { mode: 'fixed', value: paramMeta.min };
    }
    const child: ScenarioStep = { id: newStepId(), kind, params: defaultParams };
    onUpdate({ steps: [...nestedSteps, child] });
  }

  return (
    <article className="p-3 flex flex-col gap-2" data-testid={`step-editor-depth-${depth}`}>
      <header className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="ep-badge mono shrink-0">#{index}</span>
          <select
            className="ep-input text-ep-sm"
            value={step.kind}
            onChange={(event) =>
              onUpdate({ kind: event.target.value as ScenarioStepKind, params: {}, steps: undefined })
            }
            aria-label={`Step ${index} kind`}
          >
            {(Object.keys(STEP_METADATA) as ScenarioStepKind[])
              .filter((kind) => (depth === 0 ? true : kind !== 'REPEAT' || canNestFurther))
              .map((kind) => (
                <option key={kind} value={kind}>
                  {STEP_METADATA[kind].label}
                </option>
              ))}
          </select>
          <span className="ep-badge">{meta.family}</span>
        </div>
        {actions}
      </header>

      {!meta.backendCertified && (
        <div className="flex items-start gap-2 text-ep-xs text-warning" data-testid="step-backend-notice">
          <AlertTriangle width={12} height={12} className="mt-0.5 shrink-0" />
          <span>
            Backend support required: {meta.backendNote ?? 'this step is not implemented in POLARIS /scenarios/*.'}
            {' '}The scenario stays saveable, but Run Scenario stays disabled until the backend contract exists.
          </span>
        </div>
      )}

      {supportedKeys.length > 0 ? (
        <div className="grid gap-2 md:grid-cols-2">
          {supportedKeys.map((key) => (
            <ParamEditor
              key={key as string}
              paramKey={key as keyof StepParams}
              value={step.params[key as keyof StepParams]}
              onChange={(value) => onParam(key as keyof StepParams, value)}
            />
          ))}
        </div>
      ) : (
        <p className="text-ep-xs text-text-secondary">No parameter for this step.</p>
      )}

      {paramKeys
        .filter((key) => !(supportedKeys as string[]).includes(key as string))
        .map((key) => (
          <p key={key as string} className="text-ep-xs text-warning">
            Unused parameter: <code className="mono">{key}</code>
          </p>
        ))}

      {isRepeat && (
        <section
          className="border-l-2 border-primary/40 pl-3 ml-1 flex flex-col gap-2"
          data-testid={`repeat-body-${step.id}`}
        >
          <header className="flex items-center justify-between gap-2">
            <p className="text-ep-xs uppercase tracking-wider text-text-secondary">
              Nested steps · depth {depth + 1} / {MAX_REPEAT_NESTING}
            </p>
            <div className="flex flex-wrap gap-1" data-testid={`repeat-palette-${step.id}`}>
              {(Object.keys(STEP_METADATA) as ScenarioStepKind[])
                .filter((kind) => kind !== 'REPEAT' || canNestFurther)
                .map((kind) => (
                  <button
                    key={kind}
                    type="button"
                    className="ep-badge cursor-pointer hover:bg-primary/10"
                    onClick={() => addNestedStep(kind)}
                    title={`Add ${STEP_METADATA[kind].label} inside repeat`}
                    data-testid={`repeat-add-${kind}-${step.id}`}
                  >
                    <Plus width={10} height={10} />
                    {STEP_METADATA[kind].label}
                  </button>
                ))}
            </div>
          </header>
          {!canNestFurther && (
            <p className="text-ep-xs text-warning flex items-start gap-1">
              <AlertTriangle width={11} height={11} className="mt-0.5 shrink-0" />
              REPEAT nesting cap reached (MAX_REPEAT_NESTING = {MAX_REPEAT_NESTING}). Deeper trees are refused by the backend
              with REPEAT_NESTING_TOO_DEEP.
            </p>
          )}
          {nestedSteps.length === 0 ? (
            <p className="text-ep-xs text-text-secondary">No nested step yet.</p>
          ) : (
            <ol className="flex flex-col gap-2">
              {nestedSteps.map((child, childIndex) => (
                <li
                  key={child.id}
                  className="border border-border rounded-md"
                  data-testid={`nested-step-row-${child.id}`}
                >
                  <StepEditor
                    index={childIndex + 1}
                    step={child}
                    depth={depth + 1}
                    onUpdate={(patch) => updateNestedStep(child.id, patch)}
                    onParam={(key, value) => updateNestedParam(child.id, key, value)}
                    actions={
                      <button
                        type="button"
                        className="ep-button ep-button-sm ep-button-danger"
                        onClick={() => removeNestedStep(child.id)}
                        aria-label="Remove nested step"
                        data-testid={`nested-step-remove-${child.id}`}
                      >
                        <Trash2 width={13} height={13} />
                      </button>
                    }
                  />
                </li>
              ))}
            </ol>
          )}
        </section>
      )}
    </article>
  );
}

function removeKey<T extends object>(object: T, key: keyof T): T {
  const next = { ...object };
  delete next[key];
  return next;
}

function ParamEditor({
  paramKey,
  value,
  onChange,
}: {
  paramKey: keyof StepParams;
  value: FixedOrRandom | undefined;
  onChange: (value: FixedOrRandom | undefined) => void;
}) {
  const meta = PARAM_META[paramKey];
  const mode = value?.mode ?? 'fixed';
  return (
    <div className="flex flex-col gap-1" data-testid={`param-${paramKey}`}>
      <div className="flex items-center justify-between">
        <span className="text-ep-xs uppercase tracking-wider text-text-secondary">
          {meta.label} ({meta.unit})
        </span>
        <select
          className="ep-input text-ep-xs h-7"
          value={mode}
          onChange={(event) => {
            const nextMode = event.target.value as 'fixed' | 'random';
            if (nextMode === mode) return;
            if (nextMode === 'fixed') {
              onChange({ mode: 'fixed', value: value?.mode === 'random' ? value.min : (value?.value ?? meta.min) });
            } else {
              onChange({ mode: 'random', min: value?.mode === 'fixed' ? value.value : meta.min, max: meta.min });
            }
          }}
          aria-label={`${meta.label} mode`}
          data-testid={`param-mode-${paramKey}`}
        >
          <option value="fixed">Fixed</option>
          <option value="random">Random</option>
        </select>
      </div>
      {value?.mode === 'random' ? (
        <div className="grid grid-cols-2 gap-2">
          <label className="flex flex-col">
            <span className="text-[10px] text-text-secondary">Min</span>
            <input
              type="number"
              className="ep-input"
              value={value.min}
              min={meta.min}
              max={meta.max}
              step={meta.integer ? 1 : 'any'}
              onChange={(event) => onChange({ ...value, min: Number(event.target.value) })}
              data-testid={`param-min-${paramKey}`}
            />
          </label>
          <label className="flex flex-col">
            <span className="text-[10px] text-text-secondary">Max</span>
            <input
              type="number"
              className="ep-input"
              value={value.max}
              min={meta.min}
              max={meta.max}
              step={meta.integer ? 1 : 'any'}
              onChange={(event) => onChange({ ...value, max: Number(event.target.value) })}
              data-testid={`param-max-${paramKey}`}
            />
          </label>
        </div>
      ) : (
        <input
          type="number"
          className="ep-input"
          value={value?.mode === 'fixed' ? value.value : meta.min}
          min={meta.min}
          max={meta.max}
          step={meta.integer ? 1 : 'any'}
          onChange={(event) => onChange({ mode: 'fixed', value: Number(event.target.value) })}
          data-testid={`param-value-${paramKey}`}
        />
      )}
    </div>
  );
}
