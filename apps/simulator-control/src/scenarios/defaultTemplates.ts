import { STEP_METADATA, newStepId, type Scenario, type ScenarioStep, type ScenarioStepKind, type StepParams } from './model';
import type { WireScenarioDefinition } from './wireCodec';
import type { ScenarioTemplateBackendSupport, ScenarioTemplateDescriptor } from '@/data/scenarioTemplatesApi';

export type ScenarioTemplateRat = 'LTE' | '5G_SA';
export type ScenarioTemplateCategory = 'Connectivity' | 'Session' | 'Data UL/DL' | 'Full Session' | 'Multi-UE';
export type ScenarioTemplateSupport = ScenarioTemplateBackendSupport;

export interface SystemScenarioTemplate {
  id: string;
  name: string;
  rat: ScenarioTemplateRat;
  simulator: 'srsRAN' | 'UERANSIM';
  category: ScenarioTemplateCategory;
  description: string;
  durationSeconds: number;
  throughputKbps: number | null;
  prerequisites: string[];
  support: ScenarioTemplateSupport;
  definition: WireScenarioDefinition;
  system: true;
}

const fixed = (value: number) => ({ fixed: value });
const step = (type: string, parameters: WireScenarioDefinition['steps'][number]['parameters'] = {}): WireScenarioDefinition['steps'][number] => ({ type, loop_count: 1, parameters });
function template(input: Omit<SystemScenarioTemplate, 'definition' | 'system'> & { steps: WireScenarioDefinition['steps'] }): SystemScenarioTemplate {
  return { ...input, system: true, definition: { id: input.id, name: input.name, version: 1, loop_count: 1, steps: input.steps } };
}

const LTE_BASE = ['LTE-SRSUE-TEST-01', 'Open5GS EPC', 'Valid Grant V2 for live execution'];
const NR_BASE = ['UERANSIM UE profile', 'Open5GS 5GC', 'Operator authorization for live execution'];
const TRAFFIC = { duration_s: fixed(60), packet_count: fixed(1_000), packet_size_bytes: fixed(512), packet_interval_ms: fixed(60), target_bitrate_kbps: fixed(1_000) };

// Exact offline mirror of the finalized ANR1 catalogue. The backend descriptor
// replaces display metadata when available; neither source authorizes a run.
export const DEFAULT_SCENARIO_TEMPLATES: readonly SystemScenarioTemplate[] = [
  template({ id: 'tpl-lte-attach', name: 'LTE Attach', rat: 'LTE', simulator: 'srsRAN', category: 'Connectivity', description: 'Attach one bounded srsUE to the EPC.', durationSeconds: 60, throughputKbps: null, prerequisites: LTE_BASE, support: 'CERTIFICATION_REQUIRED', steps: [step('lte_attach')] }),
  template({ id: 'tpl-lte-detach', name: 'LTE Detach', rat: 'LTE', simulator: 'srsRAN', category: 'Session', description: 'Detach one previously attached srsUE.', durationSeconds: 30, throughputKbps: null, prerequisites: LTE_BASE, support: 'CERTIFICATION_REQUIRED', steps: [step('lte_detach')] }),
  template({ id: 'tpl-lte-data-ul', name: 'LTE Data UL', rat: 'LTE', simulator: 'srsRAN', category: 'Data UL/DL', description: 'Bounded LTE uplink data profile.', durationSeconds: 60, throughputKbps: 1_000, prerequisites: [...LTE_BASE, 'Approved traffic endpoint'], support: 'BACKEND_REQUIRED', steps: [step('lte_traffic_ul', TRAFFIC)] }),
  template({ id: 'tpl-lte-data-dl', name: 'LTE Data DL', rat: 'LTE', simulator: 'srsRAN', category: 'Data UL/DL', description: 'Bounded LTE downlink data profile.', durationSeconds: 60, throughputKbps: 1_000, prerequisites: [...LTE_BASE, 'Approved traffic endpoint'], support: 'BACKEND_REQUIRED', steps: [step('lte_traffic_dl', TRAFFIC)] }),
  template({ id: 'tpl-lte-attach-data', name: 'LTE Attach + Data', rat: 'LTE', simulator: 'srsRAN', category: 'Data UL/DL', description: 'Attach and exchange bounded LTE UL/DL data.', durationSeconds: 180, throughputKbps: 1_000, prerequisites: [...LTE_BASE, 'Approved traffic endpoint'], support: 'BACKEND_REQUIRED', steps: [step('lte_attach'), step('lte_traffic_ul', TRAFFIC), step('lte_traffic_dl', TRAFFIC)] }),
  template({ id: 'tpl-lte-full-session', name: 'LTE Full Session', rat: 'LTE', simulator: 'srsRAN', category: 'Full Session', description: 'Attach, exchange bounded data and detach.', durationSeconds: 300, throughputKbps: 1_000, prerequisites: [...LTE_BASE, 'ANR1 LTE E2E certification'], support: 'BACKEND_REQUIRED', steps: [step('lte_attach'), step('lte_traffic_ul', TRAFFIC), step('lte_traffic_dl', TRAFFIC), step('wait', { duration_s: fixed(30) }), step('lte_detach')] }),
  template({ id: 'tpl-5g-registration', name: '5G SA Registration', rat: '5G_SA', simulator: 'UERANSIM', category: 'Connectivity', description: 'Register one UERANSIM UE.', durationSeconds: 60, throughputKbps: null, prerequisites: NR_BASE, support: 'SUPPORTED', steps: [step('ue_start')] }),
  template({ id: 'tpl-5g-deregistration', name: '5G SA Deregistration', rat: '5G_SA', simulator: 'UERANSIM', category: 'Session', description: 'Stop one registered UERANSIM UE.', durationSeconds: 30, throughputKbps: null, prerequisites: NR_BASE, support: 'SUPPORTED', steps: [step('ue_stop')] }),
  template({ id: 'tpl-5g-pdu-session', name: '5G SA PDU Session', rat: '5G_SA', simulator: 'UERANSIM', category: 'Session', description: 'Establish and release a PDU session.', durationSeconds: 90, throughputKbps: null, prerequisites: NR_BASE, support: 'SUPPORTED', steps: [step('pdu_establish'), step('wait', { duration_s: fixed(30) }), step('pdu_release')] }),
  template({ id: 'tpl-5g-data-ul', name: '5G SA Data UL', rat: '5G_SA', simulator: 'UERANSIM', category: 'Data UL/DL', description: 'Bounded 5G uplink data profile.', durationSeconds: 60, throughputKbps: 1_000, prerequisites: [...NR_BASE, 'Approved traffic endpoint'], support: 'BACKEND_REQUIRED', steps: [step('udp_traffic', TRAFFIC)] }),
  template({ id: 'tpl-5g-data-dl', name: '5G SA Data DL', rat: '5G_SA', simulator: 'UERANSIM', category: 'Data UL/DL', description: 'Bounded 5G downlink data profile.', durationSeconds: 60, throughputKbps: 1_000, prerequisites: [...NR_BASE, 'Approved traffic endpoint'], support: 'BACKEND_REQUIRED', steps: [step('udp_traffic', TRAFFIC)] }),
  template({ id: 'tpl-5g-registration-pdu-data', name: '5G Registration + PDU + Data', rat: '5G_SA', simulator: 'UERANSIM', category: 'Data UL/DL', description: 'Register, establish PDU and exchange bounded data.', durationSeconds: 180, throughputKbps: 1_000, prerequisites: NR_BASE, support: 'BACKEND_REQUIRED', steps: [step('ue_start'), step('pdu_establish'), step('udp_traffic', TRAFFIC)] }),
  template({ id: 'tpl-5g-full-session', name: '5G SA Full Session', rat: '5G_SA', simulator: 'UERANSIM', category: 'Full Session', description: 'Register, establish PDU, exchange bounded data and stop.', durationSeconds: 240, throughputKbps: 1_000, prerequisites: NR_BASE, support: 'BACKEND_REQUIRED', steps: [step('ue_start'), step('pdu_establish'), step('udp_traffic', TRAFFIC), step('pdu_release'), step('ue_stop')] }),
] as const;

export function templateFromDescriptor(descriptor: ScenarioTemplateDescriptor): SystemScenarioTemplate {
  const fallback = DEFAULT_SCENARIO_TEMPLATES.find((item) => item.id === descriptor.template_id);
  return template({
    id: descriptor.template_id,
    name: fallback?.name ?? descriptor.template_id.replace(/^tpl-/, '').replaceAll('-', ' '),
    rat: descriptor.rat,
    simulator: descriptor.simulator,
    category: fallback?.category ?? (descriptor.parameters.multi_ue ? 'Multi-UE' : 'Session'),
    description: descriptor.description,
    durationSeconds: descriptor.parameters.duration_seconds,
    throughputKbps: descriptor.parameters.rate_bps ? descriptor.parameters.rate_bps / 1_000 : null,
    prerequisites: descriptor.required_capabilities,
    support: descriptor.backend_support,
    steps: descriptor.steps,
  });
}

export function templateSupport(item: SystemScenarioTemplate): ScenarioTemplateSupport { return item.support; }

export function scenarioFromSystemTemplate(item: SystemScenarioTemplate): Scenario {
  const now = Date.now();
  return { id: item.id, name: `${item.name} copy`, description: item.description, version: 1, createdAt: now, updatedAt: now, technology: item.rat, loop: { kind: 'ONCE' }, steps: item.definition.steps.map(toScenarioStep) };
}

function toScenarioStep(entry: WireScenarioDefinition['steps'][number]): ScenarioStep {
  const wireToKind: Record<string, ScenarioStepKind> = { ue_start: 'UE_START', ue_stop: 'UE_STOP', pdu_establish: 'PDU_ESTABLISH', pdu_release: 'PDU_RELEASE', udp_traffic: 'UDP_TRAFFIC', wait: 'IDLE', lte_attach: 'LTE_ATTACH', lte_detach: 'LTE_DETACH', lte_traffic_ul: 'LTE_DATA_UL', lte_traffic_dl: 'LTE_DATA_DL' };
  const kind = wireToKind[entry.type];
  if (!kind || !STEP_METADATA[kind]) throw new Error(`SYSTEM_TEMPLATE_STEP_UNSUPPORTED:${entry.type}`);
  const params: StepParams = {};
  for (const [key, value] of Object.entries(entry.parameters)) {
    (params as Record<string, StepParams[keyof StepParams]>)[key] = 'fixed' in value ? { mode: 'fixed', value: value.fixed } : { mode: 'random', min: value.random.min, max: value.random.max };
  }
  return { id: newStepId(), kind, params };
}
