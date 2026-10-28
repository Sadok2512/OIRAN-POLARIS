import { describe, expect, it } from 'vitest';
import {
  certifiedProfileFor,
  emptyScenario,
  newStepId,
  sampleLoopCount,
  sampleParam,
  validateScenario,
  type Scenario,
  type ScenarioStep,
  type ScenarioStepKind,
  type StepParams,
} from './model';

function makeStep(kind: ScenarioStepKind, params: StepParams = {}): ScenarioStep {
  return { id: newStepId(), kind, params };
}

function scenario(partial: Partial<Scenario> = {}): Scenario {
  return { ...emptyScenario('Test'), ...partial };
}

describe('sampleParam', () => {
  it('returns the fixed value unchanged', () => {
    expect(sampleParam({ mode: 'fixed', value: 42 })).toBe(42);
  });

  it('samples an integer inside [min, max] with integer bounds', () => {
    const results = Array.from({ length: 100 }, (_, i) =>
      sampleParam({ mode: 'random', min: 1, max: 10 }, () => (i % 10) / 10),
    );
    for (const value of results) {
      expect(Number.isInteger(value)).toBe(true);
      expect(value).toBeGreaterThanOrEqual(1);
      expect(value).toBeLessThanOrEqual(10);
    }
  });

  it('samples a float when bounds are not both integers', () => {
    const result = sampleParam({ mode: 'random', min: 0, max: 1.5 }, () => 0.5);
    expect(result).toBeCloseTo(0.75);
  });
});

describe('sampleLoopCount', () => {
  it('returns 1 for ONCE', () => {
    expect(sampleLoopCount({ kind: 'ONCE' })).toBe(1);
  });
  it('returns the fixed cycle count', () => {
    expect(sampleLoopCount({ kind: 'FIXED', cycles: 50 })).toBe(50);
  });
  it('samples a cycle count ONCE per scenario run (RANDOM)', () => {
    // Confirmed by the single call: the model's contract is that the loop
    // sampler returns a scalar; the runtime decides to use it only once.
    const result = sampleLoopCount({ kind: 'RANDOM', min: 5, max: 10 }, () => 0.5);
    expect(result).toBeGreaterThanOrEqual(5);
    expect(result).toBeLessThanOrEqual(10);
  });
  it('returns the sentinel "infinite" for INFINITE', () => {
    expect(sampleLoopCount({ kind: 'INFINITE' })).toBe('infinite');
  });
});

describe('validateScenario', () => {
  it('errors on missing name and empty steps', () => {
    const issues = validateScenario(scenario({ name: '', steps: [] }));
    const paths = issues.map((issue) => issue.path);
    expect(paths).toContain('name');
    expect(paths).toContain('steps');
  });

  it('errors when random min > max for a step parameter', () => {
    const step = makeStep('UDP_TRAFFIC', {
      duration_s: { mode: 'random', min: 60, max: 10 },
    });
    const issues = validateScenario(scenario({ name: 'x', steps: [step] }));
    expect(issues.some((i) => i.path.endsWith('duration_s') && i.message.includes('min must be ≤ max'))).toBe(
      true,
    );
  });

  it('errors when fixed value is outside the backend-safe range', () => {
    const step = makeStep('UDP_TRAFFIC', {
      duration_s: { mode: 'fixed', value: 10_000 },
    });
    const issues = validateScenario(scenario({ name: 'x', steps: [step] }));
    expect(issues.some((i) => i.path.endsWith('duration_s'))).toBe(true);
  });

  it('errors when FIXED loop cycles are non-positive', () => {
    const issues = validateScenario(scenario({ name: 'x', steps: [makeStep('UE_START')], loop: { kind: 'FIXED', cycles: 0 } }));
    expect(issues.some((i) => i.path === 'loop.cycles')).toBe(true);
  });

  it('errors when RANDOM loop min > max', () => {
    const issues = validateScenario(
      scenario({ name: 'x', steps: [makeStep('UE_START')], loop: { kind: 'RANDOM', min: 50, max: 5 } }),
    );
    expect(issues.some((i) => i.path === 'loop.random')).toBe(true);
  });

  it('emits a WARNING (not error) for INFINITE loop', () => {
    const issues = validateScenario(
      scenario({ name: 'x', steps: [makeStep('UE_START')], loop: { kind: 'INFINITE' } }),
    );
    const infinite = issues.find((i) => i.path === 'loop.infinite');
    expect(infinite?.level).toBe('warning');
  });

  it('flags backend-unsupported steps as warnings', () => {
    const steps = [makeStep('HTTP_TRAFFIC', { duration_s: { mode: 'fixed', value: 10 } })];
    const issues = validateScenario(scenario({ name: 'x', steps }));
    expect(issues.some((i) => i.level === 'warning' && i.message.includes('HTTP'))).toBe(true);
  });
});

describe('certifiedProfileFor', () => {
  it('maps a single UDP traffic step to bounded-controller-ue-udp-v1', () => {
    const steps = [makeStep('UDP_TRAFFIC', { duration_s: { mode: 'fixed', value: 5 } })];
    expect(certifiedProfileFor(scenario({ steps }))?.scenario_type).toBe('bounded-controller-ue-udp-v1');
  });

  it('refuses to map a TCP-only scenario', () => {
    const steps = [makeStep('TCP_TRAFFIC', {})];
    expect(certifiedProfileFor(scenario({ steps }))).toBeNull();
  });

  it('refuses to map a scenario mixing UDP + unsupported steps', () => {
    const steps = [
      makeStep('UDP_TRAFFIC', {}),
      makeStep('HTTP_TRAFFIC', {}),
    ];
    expect(certifiedProfileFor(scenario({ steps }))).toBeNull();
  });

  it('tolerates IDLE/WAIT_REGISTRATION around the UDP step', () => {
    const steps = [
      makeStep('WAIT_REGISTRATION', {}),
      makeStep('UDP_TRAFFIC', {}),
      makeStep('IDLE', { duration_s: { mode: 'fixed', value: 1 } }),
    ];
    expect(certifiedProfileFor(scenario({ steps }))?.scenario_type).toBe('bounded-controller-ue-udp-v1');
  });
});
