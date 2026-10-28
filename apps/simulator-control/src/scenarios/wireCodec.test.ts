import { describe, expect, it } from 'vitest';
import {
  InfiniteLoopUnsupportedError,
  UnsupportedStepTypeError,
  decodeDefinition,
  decodeParam,
  decodeStep,
  encodeDefinition,
  encodeParam,
  encodeStep,
  type WireScenarioDefinition,
  type WireScenarioStep,
} from './wireCodec';
import { emptyScenario, newStepId } from './model';

describe('wireCodec — parameter shape', () => {
  it('encodes a fixed value as a bare number', () => {
    expect(encodeParam({ mode: 'fixed', value: 100 })).toBe(100);
  });

  it('encodes random as { random: { min, max } } — contract example', () => {
    // Example from the contract: "duration_ms": {"random":{"min":10,"max":20}}
    expect(encodeParam({ mode: 'random', min: 10, max: 20 })).toEqual({
      random: { min: 10, max: 20 },
    });
  });

  it('round-trips both modes', () => {
    expect(decodeParam(encodeParam({ mode: 'fixed', value: 42 }))).toEqual({
      mode: 'fixed',
      value: 42,
    });
    expect(decodeParam(encodeParam({ mode: 'random', min: 1, max: 7 }))).toEqual({
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
    ['IDLE', 'wait'],
  ];

  it.each(certifiedPairs)(
    'encodes %s as wire type "%s"',
    (kind, wire) => {
      const step = { id: newStepId(), kind: kind as never, params: {} };
      expect(encodeStep(step, 1).type).toBe(wire);
    },
  );

  it('refuses to encode a step outside the whitelist', () => {
    expect(() =>
      encodeStep({ id: 's1', kind: 'REGISTER_5G', params: {} }, 1),
    ).toThrow(UnsupportedStepTypeError);
    expect(() =>
      encodeStep({ id: 's2', kind: 'TCP_TRAFFIC', params: {} }, 1),
    ).toThrow(UnsupportedStepTypeError);
  });

  it('refuses to decode an unknown wire type', () => {
    const wire: WireScenarioStep = {
      type: 'tcp_traffic',
      loop_count: 1,
      parameters: {},
    };
    expect(() => decodeStep(wire)).toThrow(UnsupportedStepTypeError);
  });
});

describe('wireCodec — definition shape', () => {
  it('matches the contract example {id, name, version, steps:[{type, loop_count, parameters}]}', () => {
    const scenario = {
      ...emptyScenario('contract-sample'),
      version: 1,
      steps: [
        {
          id: 's1',
          kind: 'UDP_TRAFFIC' as const,
          params: {
            duration_s: { mode: 'random', min: 10, max: 20 } as const,
            packet_count: { mode: 'fixed', value: 500 } as const,
          },
        },
      ],
      loop: { kind: 'ONCE' as const },
    };
    const wire = encodeDefinition(scenario);
    expect(wire).toEqual({
      id: scenario.id,
      name: 'contract-sample',
      version: 1,
      steps: [
        {
          type: 'udp_traffic',
          loop_count: 1,
          parameters: {
            duration_s: { random: { min: 10, max: 20 } },
            packet_count: 500,
          },
        },
      ],
    });
  });

  it('rejects INFINITE loop (positive-integer per-step contract)', () => {
    const scenario = {
      ...emptyScenario('infinite'),
      steps: [{ id: 's1', kind: 'UDP_TRAFFIC' as const, params: {} }],
      loop: { kind: 'INFINITE' as const },
    };
    expect(() => encodeDefinition(scenario)).toThrow(InfiniteLoopUnsupportedError);
  });

  it('decodes a backend definition into the local model with ONCE fallback', () => {
    const wire: WireScenarioDefinition = {
      id: 'scn-be-1',
      name: 'from-backend',
      version: 3,
      steps: [
        { type: 'ue_start', loop_count: 1, parameters: {} },
        {
          type: 'udp_traffic',
          loop_count: 2,
          parameters: {
            duration_ms: { random: { min: 10, max: 20 } },
          },
        },
      ],
    };
    const decoded = decodeDefinition(wire);
    expect(decoded.name).toBe('from-backend');
    expect(decoded.version).toBe(3);
    expect(decoded.steps[0].kind).toBe('UE_START');
    expect(decoded.steps[1].kind).toBe('UDP_TRAFFIC');
    expect(decoded.steps[1].params).toEqual({
      duration_ms: { mode: 'random', min: 10, max: 20 },
    });
    // scenario-level loop_count is OPEN in the contract; UI falls back to ONCE
    expect(decoded.loop).toEqual({ kind: 'ONCE' });
  });
});
