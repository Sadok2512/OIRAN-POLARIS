import { describe, expect, it } from 'vitest';
import {
  NonIntegerRandomRangeError,
  UnsupportedLoopError,
  UnsupportedStepTypeError,
  decodeDefinition,
  decodeParam,
  decodeStep,
  encodeDefinition,
  encodeParam,
  encodeStep,
  epochSecondsToLocal,
  isLoopRepresentable,
  type WireScenarioDefinition,
  type WireScenarioStep,
} from './wireCodec';
import { emptyScenario, newStepId, type Scenario } from './model';

describe('wireCodec — parameter shape (scenario_definitions.rs ParameterSpec)', () => {
  it('encodes a fixed value as {"fixed": value} — a bare number is rejected by the backend', () => {
    expect(encodeParam('duration_s', { mode: 'fixed', value: 5 })).toEqual({ fixed: 5 });
  });

  it('encodes random as {"random":{"min","max"}} with integer bounds', () => {
    expect(encodeParam('duration_s', { mode: 'random', min: 10, max: 20 })).toEqual({
      random: { min: 10, max: 20 },
    });
  });

  it('refuses non-integer random bounds (backend RandomRange is i64)', () => {
    expect(() => encodeParam('duration_s', { mode: 'random', min: 1.5, max: 3 })).toThrow(
      NonIntegerRandomRangeError,
    );
  });

  it('decodes {"fixed"} and {"random"} and round-trips both modes', () => {
    expect(decodeParam({ fixed: 5 })).toEqual({ mode: 'fixed', value: 5 });
    expect(decodeParam(encodeParam('p', { mode: 'random', min: 1, max: 7 }))).toEqual({
      mode: 'random',
      min: 1,
      max: 7,
    });
  });
});

describe('wireCodec — step types (6-type whitelist)', () => {
  const certifiedPairs: [string, string][] = [
    ['UE_START', 'ue_start'],
    ['UE_STOP', 'ue_stop'],
    ['PDU_ESTABLISH', 'pdu_establish'],
    ['PDU_RELEASE', 'pdu_release'],
    ['UDP_TRAFFIC', 'udp_traffic'],
    ['WAIT', 'wait'],
  ];

  it.each(certifiedPairs)('encodes %s as wire type "%s" with step loop_count 1', (kind, wire) => {
    const step = { id: newStepId(), kind: kind as never, params: {} };
    expect(encodeStep(step)).toEqual({ type: wire, loop_count: 1, parameters: {} });
  });

  it('refuses to encode a step outside the whitelist', () => {
    expect(() => encodeStep({ id: 's1', kind: 'REGISTER_5G', params: {} })).toThrow(
      UnsupportedStepTypeError,
    );
    expect(() => encodeStep({ id: 's2', kind: 'TCP_TRAFFIC', params: {} })).toThrow(
      UnsupportedStepTypeError,
    );
  });

  it('refuses to decode an unknown wire type', () => {
    const wire: WireScenarioStep = { type: 'rrc_idle', loop_count: 1, parameters: {} };
    expect(() => decodeStep(wire)).toThrow(UnsupportedStepTypeError);
  });
});

describe('wireCodec — scenario loop (definition loop_count)', () => {
  function scenarioWith(loop: Scenario['loop']): Scenario {
    const scenario = emptyScenario('loop test');
    scenario.steps = [{ id: newStepId(), kind: 'WAIT', params: { duration_s: { mode: 'fixed', value: 5 } } }];
    scenario.loop = loop;
    return scenario;
  }

  it('maps ONCE → 1 and FIXED → cycles at the DEFINITION level, never on steps', () => {
    expect(encodeDefinition(scenarioWith({ kind: 'ONCE' })).loop_count).toBe(1);
    const fixed = encodeDefinition(scenarioWith({ kind: 'FIXED', cycles: 50 }));
    expect(fixed.loop_count).toBe(50);
    expect(fixed.steps.every((step) => step.loop_count === 1)).toBe(true);
  });

  it('refuses RANDOM and INFINITE loops instead of converting them silently', () => {
    expect(() => encodeDefinition(scenarioWith({ kind: 'RANDOM', min: 1, max: 9 }))).toThrow(
      UnsupportedLoopError,
    );
    expect(() => encodeDefinition(scenarioWith({ kind: 'INFINITE' }))).toThrow(UnsupportedLoopError);
    expect(isLoopRepresentable('RANDOM')).toBe(false);
    expect(isLoopRepresentable('INFINITE')).toBe(false);
    expect(isLoopRepresentable('FIXED')).toBe(true);
  });

  it('refuses a FIXED loop outside 1..=10000', () => {
    expect(() => encodeDefinition(scenarioWith({ kind: 'FIXED', cycles: 10_001 }))).toThrow(
      UnsupportedLoopError,
    );
  });

  it('produces exactly the mutation body the backend accepts', () => {
    const scenario = scenarioWith({ kind: 'FIXED', cycles: 2 });
    scenario.id = 'scenario-contract';
    scenario.name = 'Contract scenario';
    expect(encodeDefinition(scenario)).toEqual({
      id: 'scenario-contract',
      name: 'Contract scenario',
      loop_count: 2,
      steps: [{ type: 'wait', loop_count: 1, parameters: { duration_s: { fixed: 5 } } }],
    });
  });
});

describe('wireCodec — definition decoding (measured contract response)', () => {
  // Response of POST /api/v1/scenario-definitions in scenario-definitions.contract.md.
  const measured: WireScenarioDefinition = {
    created_at_epoch_s: 1793186621,
    id: 'scenario-contract',
    loop_count: 2,
    name: 'Contract scenario',
    steps: [{ loop_count: 2, parameters: { duration_ms: { fixed: 5 } }, type: 'wait' }],
    updated_at_epoch_s: 1793186621,
    version: 1,
  };

  it('decodes loop_count, steps and epoch-second timestamps', () => {
    const scenario = decodeDefinition(measured);
    expect(scenario.loop).toEqual({ kind: 'FIXED', cycles: 2 });
    expect(scenario.steps[0].kind).toBe('WAIT');
    expect(scenario.createdAt).toBe(1793186621 * 1000);
    expect(scenario.version).toBe(1);
  });

  it('decodes loop_count 1 as ONCE', () => {
    expect(decodeDefinition({ ...measured, loop_count: 1 }).loop).toEqual({ kind: 'ONCE' });
  });

  it('formats epoch seconds, not milliseconds', () => {
    expect(epochSecondsToLocal(1793186621)).toBe(new Date(1793186621 * 1000).toLocaleString());
    expect(epochSecondsToLocal(null)).toBe('—');
  });
});
