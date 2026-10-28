import { AlertTriangle } from 'lucide-react';
import type { LoopMode } from '@/scenarios/model';
import { MAX_WIRE_LOOP_COUNT } from '@/scenarios/wireCodec';

const PRESETS: { label: string; make: () => LoopMode }[] = [
  { label: 'Once', make: () => ({ kind: 'ONCE' }) },
  { label: '×50', make: () => ({ kind: 'FIXED', cycles: 50 }) },
  { label: '×100', make: () => ({ kind: 'FIXED', cycles: 100 }) },
  { label: 'Infinite', make: () => ({ kind: 'INFINITE' }) },
];

const V2_BADGE = 'V2 — backend required';

export function LoopEditor({
  loop,
  onChange,
  backendOnly = false,
}: {
  loop: LoopMode;
  onChange: (loop: LoopMode) => void;
  /**
   * When the scenario is saved to the backend catalog, only integer loops exist
   * (definition loop_count 1..=10000). Random and Infinite are then disabled
   * instead of being converted into something the operator did not ask for.
   */
  backendOnly?: boolean;
}) {
  const unsupported = backendOnly && (loop.kind === 'RANDOM' || loop.kind === 'INFINITE');
  return (
    <div className="flex flex-col gap-3" data-testid="loop-editor">
      <div className="flex flex-wrap gap-1">
        {PRESETS.map((preset) => {
          const disabled = backendOnly && preset.label === 'Infinite';
          return (
            <button
              key={preset.label}
              type="button"
              className={`ep-badge ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer hover:bg-primary/10'}`}
              onClick={() => onChange(preset.make())}
              disabled={disabled}
              title={disabled ? V2_BADGE : undefined}
              data-testid={`loop-preset-${preset.label.toLowerCase()}`}
            >
              {preset.label}
              {disabled && <span className="ml-1 text-ep-xs">· V2</span>}
            </button>
          );
        })}
        <button
          type="button"
          className="ep-badge cursor-pointer hover:bg-primary/10"
          onClick={() => onChange({ kind: 'FIXED', cycles: loop.kind === 'FIXED' ? loop.cycles : 10 })}
          data-testid="loop-preset-custom"
        >
          Custom
        </button>
        <button
          type="button"
          className={`ep-badge ${backendOnly ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer hover:bg-primary/10'}`}
          onClick={() => onChange({ kind: 'RANDOM', min: loop.kind === 'RANDOM' ? loop.min : 1, max: loop.kind === 'RANDOM' ? loop.max : 10 })}
          disabled={backendOnly}
          title={backendOnly ? V2_BADGE : undefined}
          data-testid="loop-preset-random"
        >
          Random
          {backendOnly && <span className="ml-1 text-ep-xs">· V2</span>}
        </button>
      </div>
      {unsupported && (
        <div className="flex items-start gap-2 text-ep-xs text-error" data-testid="loop-unsupported">
          <AlertTriangle width={13} height={13} className="mt-0.5 shrink-0" />
          <span>
            This loop mode cannot be saved to the backend catalog. Choose Once, ×50, ×100 or Custom
            (1–{MAX_WIRE_LOOP_COUNT.toLocaleString()}).
          </span>
        </div>
      )}
      {loop.kind === 'FIXED' && (
        <label className="flex items-center gap-2 text-ep-sm">
          <span>Cycles</span>
          <input
            type="number"
            min={1}
            max={backendOnly ? MAX_WIRE_LOOP_COUNT : undefined}
            className="ep-input w-28"
            value={loop.cycles}
            onChange={(event) => onChange({ kind: 'FIXED', cycles: Number(event.target.value) })}
            data-testid="loop-cycles"
          />
        </label>
      )}
      {loop.kind === 'RANDOM' && (
        <div className="grid grid-cols-2 gap-2 max-w-xs">
          <label className="flex flex-col text-ep-xs">
            <span className="text-text-secondary">Min</span>
            <input
              type="number"
              min={1}
              className="ep-input"
              value={loop.min}
              onChange={(event) => onChange({ ...loop, min: Number(event.target.value) })}
              data-testid="loop-random-min"
            />
          </label>
          <label className="flex flex-col text-ep-xs">
            <span className="text-text-secondary">Max</span>
            <input
              type="number"
              min={1}
              className="ep-input"
              value={loop.max}
              onChange={(event) => onChange({ ...loop, max: Number(event.target.value) })}
              data-testid="loop-random-max"
            />
          </label>
        </div>
      )}
      {loop.kind === 'INFINITE' && (
        <div className="flex items-start gap-2 text-ep-xs text-warning" data-testid="loop-infinite-warning">
          <AlertTriangle width={13} height={13} className="mt-0.5 shrink-0" />
          <span>
            Infinite loops require a manual Stop. The frontend NEVER spawns infinite tight loops; the backend must own
            execution limits, cancellation and CPU/RAM safety budgets before this mode can start.
          </span>
        </div>
      )}
    </div>
  );
}
