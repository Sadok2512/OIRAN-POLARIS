// Codec between the frontend scenario model and the polaris-control-api
// 0.9.0 wire shape. Grounded strictly on the published examples:
//
//   Definition  : { id, name, version, steps: [{ type, loop_count, parameters }] }
//   Step types  : ue_start, ue_stop, pdu_establish, pdu_release, udp_traffic, wait
//   Random param: { "random": { "min": a, "max": b } }
//   Fixed param : <number>
//
// Nothing in this file invents fields outside that contract. Scenario-
// level loop_count is marked OPEN until Codex confirms (see
// CHANGELOG.md and the BLOCKERS section).

import {
  INTERNAL_STEP_KIND,
  WIRE_STEP_TYPE,
  type FixedOrRandom,
  type Scenario,
  type ScenarioStep,
  type StepParams,
  newStepId,
} from './model';

/* --------------------------- Wire types (0.9.0) --------------------------- */

export type WireNumericParam = number | { random: { min: number; max: number } };

export interface WireScenarioStep {
  type: string;
  loop_count: number;
  parameters: Record<string, WireNumericParam>;
}

export interface WireScenarioDefinition {
  id: string;
  name: string;
  version: number;
  steps: WireScenarioStep[];
}

export interface WireScenarioStepStatus {
  index: number;
  type: string;
  loop: number;
  state: string;
  started_at: string | null;
  ended_at: string | null;
  error: string | null;
  resolved_parameters: Record<string, number>;
}

export interface WireStartScenarioRequest {
  scenario_definition_id: string;
  ue_ids: string[];
}

/* ----------------------------- Parameter codec ---------------------------- */

export function encodeParam(value: FixedOrRandom): WireNumericParam {
  if (value.mode === 'fixed') return value.value;
  return { random: { min: value.min, max: value.max } };
}

export function decodeParam(value: WireNumericParam): FixedOrRandom {
  if (typeof value === 'number') return { mode: 'fixed', value };
  const { min, max } = value.random;
  return { mode: 'random', min, max };
}

/* ------------------------------- Step codec ------------------------------- */

export class UnsupportedStepTypeError extends Error {
  constructor(public kind: string) {
    super(`Step kind "${kind}" is not in polaris-control-api 0.9.0 (6-type whitelist).`);
    this.name = 'UnsupportedStepTypeError';
  }
}

export function encodeStep(step: ScenarioStep, loopCount: number): WireScenarioStep {
  const type = WIRE_STEP_TYPE[step.kind];
  if (!type) throw new UnsupportedStepTypeError(step.kind);
  const parameters: Record<string, WireNumericParam> = {};
  (Object.keys(step.params) as (keyof StepParams)[]).forEach((key) => {
    const value = step.params[key];
    if (value) parameters[key] = encodeParam(value);
  });
  return { type, loop_count: loopCount, parameters };
}

export function decodeStep(wire: WireScenarioStep): ScenarioStep {
  const kind = INTERNAL_STEP_KIND[wire.type];
  if (!kind) throw new UnsupportedStepTypeError(wire.type);
  const params: StepParams = {};
  for (const [key, value] of Object.entries(wire.parameters)) {
    (params as Record<string, FixedOrRandom>)[key] = decodeParam(value);
  }
  return { id: newStepId(), kind, params };
}

/* ----------------------------- Definition codec --------------------------- */

/**
 * Encode a frontend scenario to the wire format accepted by
 * polaris-control-api 0.9.0.
 *
 * NOTE — scenario-level loop_count is pending clarification from Codex
 * (declared OPEN in CHANGELOG.md). Until it ships, the encoder spreads
 * the scenario's loop across every step: FIXED/ONCE use their numeric
 * cycle count, RANDOM uses `max` as an upper bound, INFINITE is rejected
 * because the per-step contract requires a positive integer. The caller
 * is expected to surface the INFINITE case in UI.
 */
export function encodeDefinition(scenario: Scenario): WireScenarioDefinition {
  const loopPerStep = resolvePerStepLoop(scenario);
  return {
    id: scenario.id,
    name: scenario.name,
    version: scenario.version,
    steps: scenario.steps.map((step) => encodeStep(step, loopPerStep)),
  };
}

export function decodeDefinition(wire: WireScenarioDefinition): Scenario {
  const now = Date.now();
  return {
    id: wire.id,
    name: wire.name,
    description: '',
    version: wire.version,
    createdAt: now,
    updatedAt: now,
    steps: wire.steps.map(decodeStep),
    // Scenario-level loop is not exposed on the wire yet; fall back to ONCE.
    loop: { kind: 'ONCE' },
  };
}

export class InfiniteLoopUnsupportedError extends Error {
  constructor() {
    super(
      'Infinite loop is not representable in polaris-control-api 0.9.0 step.loop_count (positive integer).',
    );
    this.name = 'InfiniteLoopUnsupportedError';
  }
}

function resolvePerStepLoop(scenario: Scenario): number {
  switch (scenario.loop.kind) {
    case 'ONCE':
      return 1;
    case 'FIXED':
      return scenario.loop.cycles;
    case 'RANDOM':
      return scenario.loop.max;
    case 'INFINITE':
      throw new InfiniteLoopUnsupportedError();
  }
}
