import clsx from 'clsx';
import { STEP_METADATA, type FixedOrRandom, type Scenario, type StepParams } from '@/scenarios/model';

function paramLabel(value: FixedOrRandom | undefined, unit: string): string {
  if (!value) return '—';
  if (value.mode === 'fixed') return `${value.value} ${unit}`;
  return `Random ${value.min}–${value.max} ${unit}`;
}

function stepSummary(step: Scenario['steps'][number]): string[] {
  const result: string[] = [];
  const paramKeys = Object.keys(step.params) as (keyof StepParams)[];
  for (const key of paramKeys) {
    switch (key) {
      case 'duration_s':
        result.push(`duration ${paramLabel(step.params.duration_s, 's')}`);
        break;
      case 'packet_count':
        result.push(`${paramLabel(step.params.packet_count, 'pkt')}`);
        break;
      case 'packet_size_bytes':
        result.push(`size ${paramLabel(step.params.packet_size_bytes, 'B')}`);
        break;
      case 'packet_interval_ms':
        result.push(`interval ${paramLabel(step.params.packet_interval_ms, 'ms')}`);
        break;
      case 'target_bitrate_kbps':
        result.push(`bitrate ${paramLabel(step.params.target_bitrate_kbps, 'kbit/s')}`);
        break;
      case 'delay_before_ms':
        result.push(`delay ${paramLabel(step.params.delay_before_ms, 'ms')}`);
        break;
      case 'retry_interval_ms':
        result.push(`retry ${paramLabel(step.params.retry_interval_ms, 'ms')}`);
        break;
      case 'timeout_s':
        result.push(`timeout ${paramLabel(step.params.timeout_s, 's')}`);
        break;
    }
  }
  return result;
}

export function ScenarioTimeline({
  scenario,
  currentStepId,
  stepStatus,
}: {
  scenario: Scenario;
  currentStepId?: string;
  stepStatus?: Record<string, 'PENDING' | 'RUNNING' | 'WAITING' | 'PASS' | 'FAIL' | 'SKIPPED' | 'STOPPED'>;
}) {
  if (scenario.steps.length === 0) {
    return <p className="text-ep-xs text-text-secondary">No step defined yet.</p>;
  }
  return (
    <ol className="flex flex-col gap-2" data-testid="scenario-timeline">
      {scenario.steps.map((step, index) => {
        const meta = STEP_METADATA[step.kind];
        const summary = stepSummary(step);
        const status = stepStatus?.[step.id] ?? 'PENDING';
        const current = currentStepId === step.id;
        return (
          <li
            key={step.id}
            className={clsx(
              'flex items-start gap-3 rounded border px-3 py-2',
              current ? 'border-primary bg-primary/5' : 'border-border',
            )}
            data-testid={`timeline-step-${step.id}`}
            data-current={current ? 'true' : 'false'}
          >
            <span className="ep-badge mono shrink-0">{index + 1}</span>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-medium">{meta.label}</span>
                <span className="ep-badge">{meta.family}</span>
                {!meta.backendCertified && (
                  <span className="ep-badge border-warning/40 text-warning">backend-pending</span>
                )}
              </div>
              {summary.length > 0 && (
                <p className="text-ep-xs text-text-secondary mt-0.5">{summary.join(' · ')}</p>
              )}
            </div>
            <span
              className={clsx(
                'ep-badge mono shrink-0',
                status === 'RUNNING' && 'border-primary/40 text-primary',
                status === 'PASS' && 'border-success/40 text-success',
                status === 'FAIL' && 'border-error/40 text-error',
                status === 'WAITING' && 'border-warning/40 text-warning',
              )}
            >
              {status}
            </span>
          </li>
        );
      })}
      <li className="text-ep-xs text-text-secondary mt-1">
        Loop:{' '}
        {scenario.loop.kind === 'ONCE'
          ? 'runs once'
          : scenario.loop.kind === 'FIXED'
            ? `×${scenario.loop.cycles} cycles`
            : scenario.loop.kind === 'RANDOM'
              ? `Random ${scenario.loop.min}..${scenario.loop.max} (sampled once per run)`
              : 'Infinite — until stopped'}
      </li>
    </ol>
  );
}
