// Codec between the frontend scenario model and polaris-control-api 0.10.0+.
//
// Every shape below was checked against the Rust source
// (apps/api/src/scenario_definitions.rs, apps/api/src/lib.rs) and the measured
// examples in POLARIS_CONTROL/docs/api/scenario-definitions.contract.md:
//
//   Definition     : { id, name, version, loop_count, steps, created_at_epoch_s, updated_at_epoch_s }
//   Mutation       : { id, name, loop_count, steps }
//   Step           : { type, loop_count, parameters }
//   Parameter      : { "fixed": <value> } | { "random": { "min": <int>, "max": <int> } }
//   List           : { items: Definition[], total, schema_version }
//   Clone input    : { target_id }
//   Steps response : { job_id, scenario_definition_id, steps: StepState[] }
//   Times          : epoch SECONDS (numbers), not ISO strings
//   Errors         : { "error": "CODE" }
//
// Loops: the definition `loop_count` repeats the whole scenario N times; each
// step's `loop_count` repeats that step M times inside an iteration. Both are
// integers in 1..=10000 and default to 1. A random or infinite scenario loop
// has NO wire representation, so encoding one is refused — it is never
// silently converted into a fixed count.

import {
  INTERNAL_STEP_KIND,
  WIRE_STEP_TYPE,
  type FixedOrRandom,
  type Scenario,
  type ScenarioStep,
  type StepParams,
  newStepId,
} from './model';

export const MAX_WIRE_LOOP_COUNT = 10_000;

/* ------------------------------- Wire types ------------------------------- */

export type WireNumericParam =
  | { fixed: number }
  | { random: { min: number; max: number } };

export interface WireScenarioStep {
  type: string;
  loop_count: number;
  parameters: Record<string, WireNumericParam>;
  /**
   * 0.5.0 — nested step list, used by `type: "repeat"`. Absent on every
   * other step type; the backend validator refuses it elsewhere.
   */
  steps?: WireScenarioStep[];
}

/**
 * 0.5.0 — Shape of the scenario-definition v2 import / export file, as
 * delivered by `GET /scenario-definitions/:id/export` and consumed by
 * `POST /scenario-definitions/import`. The JSON Schema that Codex will
 * publish lives in `docs/api/scenario-definition.v2.schema.json`.
 */
export const SCENARIO_SCHEMA_VERSION = 'polaris.scenario-definition.v2' as const;

export interface WireScenarioExportFile {
  schema_version: typeof SCENARIO_SCHEMA_VERSION;
  exported_at_epoch_s?: number;
  definition: WireScenarioDefinition;
}

export interface WireScenarioMutation {
  id: string;
  name: string;
  loop_count: number;
  steps: WireScenarioStep[];
}

export interface WireScenarioDefinition extends WireScenarioMutation {
  version: number;
  created_at_epoch_s?: number;
  updated_at_epoch_s?: number;
}

export interface WireScenarioDefinitionList {
  items: WireScenarioDefinition[];
  total: number;
  schema_version: number;
}

export interface WireLoopPosition {
  count: number;
  iteration: number;
}

export interface WireScenarioStepStatus {
  index: number;
  type: string;
  state: string;
  scenario_loop: WireLoopPosition;
  step_loop: WireLoopPosition;
  /** Epoch seconds. */
  started_at: number | null;
  /** Epoch seconds. */
  ended_at: number | null;
  error: string | null;
  resolved_parameters: Record<string, number>;
}

/** 0.17.0 — job-level failure summary surfaced on GET /scenarios/:id/steps. */
export interface WireScenarioJobFailure {
  step_id: string | number | null;
  step_name: string | null;
  code: string | null;
  message: string | null;
  failure_evidence: unknown | null;
  started_at: number | null;
  ended_at: number | null;
  duration_ms: number | null;
}

export interface WireScenarioStepsResponse {
  job_id: string;
  scenario_definition_id: string | null;
  steps: WireScenarioStepStatus[];
  /** 0.17.0 — present when the job is in a terminal state. */
  state?: string;
  started_at?: number | null;
  ended_at?: number | null;
  duration_ms?: number | null;
  failure?: WireScenarioJobFailure | null;
}

export interface WireStartScenarioRequest {
  scenario_definition_id: string;
  ue_ids: string[];
}

/* ------------------------------ Error classes ----------------------------- */

export class UnsupportedStepTypeError extends Error {
  constructor(public kind: string) {
    super(`Step kind "${kind}" is not accepted by polaris-control-api (6-type V1 whitelist).`);
    this.name = 'UnsupportedStepTypeError';
  }
}

export class UnsupportedLoopError extends Error {
  constructor(public kind: string) {
    super(
      `A ${kind.toLowerCase()} scenario loop has no polaris-control-api representation (integer loop_count only).`,
    );
    this.name = 'UnsupportedLoopError';
  }
}

export class NonIntegerRandomRangeError extends Error {
  constructor(public param: string) {
    super(`Random range for "${param}" must use integer bounds (backend contract).`);
    this.name = 'NonIntegerRandomRangeError';
  }
}

/* ----------------------------- Parameter codec ---------------------------- */

export function encodeParam(name: string, value: FixedOrRandom): WireNumericParam {
  if (value.mode === 'fixed') return { fixed: value.value };
  if (!Number.isInteger(value.min) || !Number.isInteger(value.max)) {
    throw new NonIntegerRandomRangeError(name);
  }
  return { random: { min: value.min, max: value.max } };
}

export function decodeParam(value: WireNumericParam | number): FixedOrRandom {
  // A bare number is not produced by the backend; accepted defensively on read only.
  if (typeof value === 'number') return { mode: 'fixed', value };
  if ('fixed' in value) return { mode: 'fixed', value: Number(value.fixed) };
  return { mode: 'random', min: value.random.min, max: value.random.max };
}

/* ------------------------------- Step codec ------------------------------- */

export function encodeStep(step: ScenarioStep): WireScenarioStep {
  const type = WIRE_STEP_TYPE[step.kind];
  if (!type) throw new UnsupportedStepTypeError(step.kind);
  const parameters: Record<string, WireNumericParam> = {};
  (Object.keys(step.params) as (keyof StepParams)[]).forEach((key) => {
    if (step.kind === 'REPEAT' && key === 'loop_count') return;
    const value = step.params[key];
    if (value) parameters[key] = encodeParam(key, value);
  });
  const repeatCount = step.kind === 'REPEAT' && step.params.loop_count?.mode === 'fixed'
    ? step.params.loop_count.value
    : 1;
  return {
    type,
    loop_count: repeatCount,
    parameters,
    ...(step.kind === 'REPEAT' ? { steps: (step.steps ?? []).map(encodeStep) } : {}),
  };
}

export function decodeStep(wire: WireScenarioStep): ScenarioStep {
  const kind = INTERNAL_STEP_KIND[wire.type];
  if (!kind) throw new UnsupportedStepTypeError(wire.type);
  const params: StepParams = {};
  for (const [key, value] of Object.entries(wire.parameters)) {
    if ('fixed' in value && typeof value.fixed !== 'number') continue;
    (params as Record<string, FixedOrRandom>)[key] = decodeParam(value);
  }
  if (kind === 'REPEAT') params.loop_count = { mode: 'fixed', value: wire.loop_count ?? 1 };
  return {
    id: newStepId(),
    kind,
    params,
    ...(kind === 'REPEAT' ? { steps: (wire.steps ?? []).map(decodeStep) } : {}),
  };
}

/* ----------------------------- Definition codec --------------------------- */

export function encodeScenarioLoop(scenario: Scenario): number {
  switch (scenario.loop.kind) {
    case 'ONCE':
      return 1;
    case 'FIXED':
      if (
        !Number.isInteger(scenario.loop.cycles) ||
        scenario.loop.cycles < 1 ||
        scenario.loop.cycles > MAX_WIRE_LOOP_COUNT
      ) {
        throw new UnsupportedLoopError('FIXED');
      }
      return scenario.loop.cycles;
    case 'RANDOM':
    case 'INFINITE':
      throw new UnsupportedLoopError(scenario.loop.kind);
  }
}

/** Body for POST /scenario-definitions and PUT /scenario-definitions/:id. */
export function encodeDefinition(scenario: Scenario): WireScenarioMutation {
  return {
    id: scenario.id,
    name: scenario.name,
    loop_count: encodeScenarioLoop(scenario),
    steps: scenario.steps.map(encodeStep),
  };
}

export function decodeDefinition(wire: WireScenarioDefinition): Scenario {
  const created = (wire.created_at_epoch_s ?? 0) * 1000;
  const updated = (wire.updated_at_epoch_s ?? wire.created_at_epoch_s ?? 0) * 1000;
  const loopCount = wire.loop_count ?? 1;
  return {
    id: wire.id,
    name: wire.name,
    description: '',
    version: wire.version,
    createdAt: created,
    updatedAt: updated,
    steps: wire.steps.map(decodeStep),
    loop: loopCount > 1 ? { kind: 'FIXED', cycles: loopCount } : { kind: 'ONCE' },
  };
}

/** True when a loop mode can be saved to the backend. */
export function isLoopRepresentable(kind: Scenario['loop']['kind']): boolean {
  return kind === 'ONCE' || kind === 'FIXED';
}

/** Formats an epoch-seconds timestamp; `null` stays an em dash. */
export function epochSecondsToLocal(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—';
  return new Date(value * 1000).toLocaleString();
}
