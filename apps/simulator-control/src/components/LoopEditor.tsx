import { AlertTriangle } from 'lucide-react';
import type { LoopMode } from '@/scenarios/model';

const PRESETS: { label: string; make: () => LoopMode }[] = [
  { label: 'Once', make: () => ({ kind: 'ONCE' }) },
  { label: '×50', make: () => ({ kind: 'FIXED', cycles: 50 }) },
  { label: '×100', make: () => ({ kind: 'FIXED', cycles: 100 }) },
  { label: 'Infinite', make: () => ({ kind: 'INFINITE' }) },
];

export function LoopEditor({
  loop,
  onChange,
}: {
  loop: LoopMode;
  onChange: (loop: LoopMode) => void;
}) {
  return (
    <div className="flex flex-col gap-3" data-testid="loop-editor">
      <div className="flex flex-wrap gap-1">
        {PRESETS.map((preset) => (
          <button
            key={preset.label}
            type="button"
            className="ep-badge cursor-pointer hover:bg-primary/10"
            onClick={() => onChange(preset.make())}
            data-testid={`loop-preset-${preset.label.toLowerCase()}`}
          >
            {preset.label}
          </button>
        ))}
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
          className="ep-badge cursor-pointer hover:bg-primary/10"
          onClick={() => onChange({ kind: 'RANDOM', min: loop.kind === 'RANDOM' ? loop.min : 1, max: loop.kind === 'RANDOM' ? loop.max : 10 })}
          data-testid="loop-preset-random"
        >
          Random
        </button>
      </div>
      {loop.kind === 'FIXED' && (
        <label className="flex items-center gap-2 text-ep-sm">
          <span>Cycles</span>
          <input
            type="number"
            min={1}
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
