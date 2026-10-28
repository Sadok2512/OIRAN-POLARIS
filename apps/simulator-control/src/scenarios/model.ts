// Declarative scenario model persisted by the frontend. Timing,
// randomization and loop execution are NEVER performed in the browser
// against a live UE — those run server-side once the matching backend
// contract exists (see docs/frontend/SIMULATOR_SCENARIO_BUILDER.md
// "Missing backend contracts"). Until then this model only drives:
//
//   * frontend-local scenario catalog (localStorage)
//   * mapping to pre-certified POLARIS profiles for /scenarios/start
//   * execution monitor timeline projection (clearly labeled)

export type ScenarioStepKind =
  | 'UE_START'
  | 'REGISTER_5G'
  | 'WAIT_REGISTRATION'
  | 'PDU_ESTABLISH'
  | 'UDP_TRAFFIC'
  | 'TCP_TRAFFIC'
  | 'ICMP_TRAFFIC'
  | 'HTTP_TRAFFIC'
  | 'IDLE'
  | 'WAIT_RRC_CONNECTED'
  | 'WAIT_RRC_IDLE'
  | 'PDU_RELEASE'
  | 'DEREGISTER'
  | 'UE_STOP';

export const STEP_METADATA: Record<
  ScenarioStepKind,
  { label: string; family: 'ACTION' | 'WAIT' | 'OBSERVATION'; defaultParams?: string[]; backendCertified: boolean; backendNote?: string }
> = {
  UE_START: { label: 'Start UE', family: 'ACTION', backendCertified: true },
  REGISTER_5G: { label: '5G Registration', family: 'ACTION', backendCertified: true },
  WAIT_REGISTRATION: {
    label: 'Wait: Registration complete',
    family: 'WAIT',
    defaultParams: ['timeout_s'],
    backendCertified: true,
  },
  PDU_ESTABLISH: { label: 'PDU Session Establishment', family: 'ACTION', backendCertified: true },
  UDP_TRAFFIC: {
    label: 'UDP Traffic',
    family: 'ACTION',
    defaultParams: ['duration_s', 'packet_count', 'packet_size_bytes', 'packet_interval_ms', 'target_bitrate_kbps'],
    backendCertified: true,
    backendNote: 'Mapped to bounded-controller-ue-udp-v1 when applicable.',
  },
  TCP_TRAFFIC: {
    label: 'TCP Traffic',
    family: 'ACTION',
    defaultParams: ['duration_s', 'packet_count', 'packet_size_bytes', 'target_bitrate_kbps'],
    backendCertified: false,
    backendNote: 'TCP generator not exposed by POLARIS /scenarios/* yet.',
  },
  ICMP_TRAFFIC: {
    label: 'ICMP Traffic',
    family: 'ACTION',
    defaultParams: ['duration_s', 'packet_count', 'packet_interval_ms'],
    backendCertified: false,
    backendNote: 'ICMP generator not exposed by POLARIS /scenarios/* yet.',
  },
  HTTP_TRAFFIC: {
    label: 'HTTP Traffic',
    family: 'ACTION',
    defaultParams: ['duration_s'],
    backendCertified: false,
    backendNote: 'HTTP generator not implemented in the backend.',
  },
  IDLE: {
    label: 'Idle / Wait',
    family: 'WAIT',
    defaultParams: ['duration_s'],
    backendCertified: true,
    backendNote: 'Pure wait between actions.',
  },
  WAIT_RRC_CONNECTED: {
    label: 'Wait: RRC Connected (observed)',
    family: 'OBSERVATION',
    defaultParams: ['timeout_s'],
    backendCertified: false,
    backendNote: 'RRC state is not exposed by POLARIS /ues; the UI cannot certify this observation yet.',
  },
  WAIT_RRC_IDLE: {
    label: 'Wait: RRC Idle (observed)',
    family: 'OBSERVATION',
    defaultParams: ['timeout_s'],
    backendCertified: false,
    backendNote: 'RRC state is not exposed by POLARIS /ues.',
  },
  PDU_RELEASE: { label: 'PDU Session Release', family: 'ACTION', backendCertified: true },
  DEREGISTER: { label: 'Deregistration / Detach', family: 'ACTION', backendCertified: true },
  UE_STOP: { label: 'Stop UE', family: 'ACTION', backendCertified: true },
};

export type FixedOrRandom =
  | { mode: 'fixed'; value: number }
  | { mode: 'random'; min: number; max: number };

export interface StepParams {
  duration_s?: FixedOrRandom;
  packet_count?: FixedOrRandom;
  packet_size_bytes?: FixedOrRandom;
  packet_interval_ms?: FixedOrRandom;
  target_bitrate_kbps?: FixedOrRandom;
  delay_before_ms?: FixedOrRandom;
  retry_interval_ms?: FixedOrRandom;
  timeout_s?: FixedOrRandom;
}

export const PARAM_META: Record<keyof StepParams, { label: string; unit: string; min: number; max: number; integer: boolean }> = {
  duration_s: { label: 'Duration', unit: 's', min: 1, max: 900, integer: true },
  packet_count: { label: 'Packets', unit: 'pkt', min: 1, max: 1_000_000, integer: true },
  packet_size_bytes: { label: 'Packet size', unit: 'B', min: 1, max: 65_535, integer: true },
  packet_interval_ms: { label: 'Interval', unit: 'ms', min: 1, max: 60_000, integer: true },
  target_bitrate_kbps: { label: 'Target bitrate', unit: 'kbit/s', min: 1, max: 1_000_000, integer: true },
  delay_before_ms: { label: 'Delay before', unit: 'ms', min: 0, max: 600_000, integer: true },
  retry_interval_ms: { label: 'Retry interval', unit: 'ms', min: 50, max: 60_000, integer: true },
  timeout_s: { label: 'Timeout', unit: 's', min: 1, max: 900, integer: true },
};

export interface ScenarioStep {
  id: string;
  kind: ScenarioStepKind;
  params: StepParams;
  note?: string;
}

export type LoopMode =
  | { kind: 'ONCE' }
  | { kind: 'FIXED'; cycles: number }
  | { kind: 'RANDOM'; min: number; max: number }
  | { kind: 'INFINITE' };

export interface Scenario {
  id: string;
  name: string;
  description?: string;
  version: number;
  createdAt: number;
  updatedAt: number;
  steps: ScenarioStep[];
  loop: LoopMode;
}

export interface ScenarioAssignment {
  ueId: string;
  scenarioId: string;
  autoRun: boolean;
  updatedAt: number;
}

export interface ValidationIssue {
  path: string;
  message: string;
  level: 'error' | 'warning';
}

export function validateScenario(scenario: Scenario): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  if (!scenario.name.trim()) {
    issues.push({ path: 'name', message: 'Scenario name is required', level: 'error' });
  }
  if (scenario.steps.length === 0) {
    issues.push({ path: 'steps', message: 'Scenario must have at least one step', level: 'error' });
  }
  // Loop validation.
  if (scenario.loop.kind === 'FIXED') {
    if (!Number.isInteger(scenario.loop.cycles) || scenario.loop.cycles < 1) {
      issues.push({ path: 'loop.cycles', message: 'Loop cycles must be a positive integer', level: 'error' });
    }
  } else if (scenario.loop.kind === 'RANDOM') {
    const { min, max } = scenario.loop;
    if (!Number.isInteger(min) || !Number.isInteger(max)) {
      issues.push({ path: 'loop.random', message: 'Random cycle bounds must be integers', level: 'error' });
    } else if (min < 1 || max < 1) {
      issues.push({ path: 'loop.random', message: 'Random cycle bounds must be positive', level: 'error' });
    } else if (min > max) {
      issues.push({ path: 'loop.random', message: 'Random min must be ≤ max', level: 'error' });
    }
  } else if (scenario.loop.kind === 'INFINITE') {
    issues.push({
      path: 'loop.infinite',
      message:
        'Infinite loop requires a manual Stop action and server-side execution limits. The UI does not spawn infinite loops client-side.',
      level: 'warning',
    });
  }
  // Step param validation.
  scenario.steps.forEach((step, index) => {
    const meta = STEP_METADATA[step.kind];
    if (!meta.backendCertified) {
      issues.push({
        path: `steps[${index}]`,
        message: `${meta.label}: ${meta.backendNote ?? 'Backend support required'}`,
        level: 'warning',
      });
    }
    (Object.keys(step.params) as (keyof StepParams)[]).forEach((key) => {
      const value = step.params[key];
      const paramMeta = PARAM_META[key];
      if (!value) return;
      if (value.mode === 'fixed') {
        if (!Number.isFinite(value.value)) {
          issues.push({ path: `steps[${index}].${key}`, message: `${paramMeta.label} must be a number`, level: 'error' });
          return;
        }
        if (paramMeta.integer && !Number.isInteger(value.value)) {
          issues.push({ path: `steps[${index}].${key}`, message: `${paramMeta.label} must be an integer`, level: 'error' });
        }
        if (value.value < paramMeta.min || value.value > paramMeta.max) {
          issues.push({
            path: `steps[${index}].${key}`,
            message: `${paramMeta.label} must be between ${paramMeta.min} and ${paramMeta.max} ${paramMeta.unit}`,
            level: 'error',
          });
        }
      } else {
        if (!Number.isFinite(value.min) || !Number.isFinite(value.max)) {
          issues.push({ path: `steps[${index}].${key}`, message: `${paramMeta.label} min/max must be numbers`, level: 'error' });
          return;
        }
        if (paramMeta.integer && (!Number.isInteger(value.min) || !Number.isInteger(value.max))) {
          issues.push({ path: `steps[${index}].${key}`, message: `${paramMeta.label} min/max must be integers`, level: 'error' });
        }
        if (value.min > value.max) {
          issues.push({ path: `steps[${index}].${key}`, message: `${paramMeta.label}: min must be ≤ max`, level: 'error' });
        }
        if (value.min < paramMeta.min || value.max > paramMeta.max) {
          issues.push({
            path: `steps[${index}].${key}`,
            message: `${paramMeta.label} must stay within ${paramMeta.min}–${paramMeta.max} ${paramMeta.unit}`,
            level: 'error',
          });
        }
      }
    });
  });
  return issues;
}

/**
 * Sample a FixedOrRandom. Used in two places:
 *   * step-param sampling: called ONCE for every execution of the step
 *   * loop-count sampling (RANDOM): called ONCE per scenario run
 *
 * `rand` lets tests inject a deterministic PRNG.
 */
export function sampleParam(value: FixedOrRandom, rand: () => number = Math.random): number {
  if (value.mode === 'fixed') return value.value;
  const min = Math.min(value.min, value.max);
  const max = Math.max(value.min, value.max);
  // Inclusive bounds, integer rounding when both bounds are integers.
  const integer = Number.isInteger(min) && Number.isInteger(max);
  if (integer) {
    return Math.floor(rand() * (max - min + 1)) + min;
  }
  return rand() * (max - min) + min;
}

export function sampleLoopCount(loop: LoopMode, rand: () => number = Math.random): number | 'infinite' {
  switch (loop.kind) {
    case 'ONCE':
      return 1;
    case 'FIXED':
      return loop.cycles;
    case 'RANDOM':
      return sampleParam({ mode: 'random', min: loop.min, max: loop.max }, rand);
    case 'INFINITE':
      return 'infinite';
  }
}

export function newScenarioId(): string {
  return `scn-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

export function newStepId(): string {
  return `step-${Math.random().toString(36).slice(2, 10)}`;
}

export function emptyScenario(name = 'New scenario'): Scenario {
  const now = Date.now();
  return {
    id: newScenarioId(),
    name,
    description: '',
    version: 1,
    createdAt: now,
    updatedAt: now,
    steps: [],
    loop: { kind: 'ONCE' },
  };
}

/**
 * Map a user-defined scenario onto a certified POLARIS profile. Only
 * returns a `scenario_type` when the step list matches one of the
 * profiles the backend currently supports. Otherwise returns null and
 * the UI must disable the "Run on certified backend" action.
 */
export function certifiedProfileFor(scenario: Scenario): { scenario_type: string; reason: string } | null {
  const steps = scenario.steps.map((s) => s.kind);
  const udpOnly = steps.filter((kind) => kind === 'UDP_TRAFFIC').length;
  // bounded-controller-ue-udp-v1 covers a single UDP traffic generation
  // on an already-running registered UE. We tolerate IDLE/WAIT around it.
  const nonWaitSteps = steps.filter((kind) => kind !== 'IDLE' && kind !== 'WAIT_REGISTRATION');
  if (udpOnly === 1 && nonWaitSteps.every((k) => k === 'UDP_TRAFFIC')) {
    return {
      scenario_type: 'bounded-controller-ue-udp-v1',
      reason: 'Single bounded UDP step on a registered controller-owned UE',
    };
  }
  return null;
}
