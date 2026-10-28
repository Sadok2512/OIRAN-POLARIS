// Typed client for the POLARIS UE profile surface (polaris-control-api 0.11.0).
// Every shape is taken from POLARIS_CONTROL/docs/api/ue-profiles.contract.md
// (measured curl outputs) and the Rust handlers. Reads never contain SUPI/K/OPc:
// they come back as the literal "PROTECTED".

import { polarisApi } from './polarisClient';

export interface WireUeProfile {
  ue_id: string;
  name: string;
  serving_gnb: string;
  plmn: { mcc: string; mnc: string };
  dnn: string;
  snssai: { sst: number; sd: string | null };
  pdu_session: { dnn: string; type: string };
  scenario_id: string | null;
  auto_run_scenario: boolean;
  subscription_status: 'VERIFIED' | 'PROVISIONING_REQUIRED' | string;
  subscriber_identity: 'PROTECTED';
  authentication_material: 'PROTECTED';
  profile: string;
  revision: number;
  updated_at_epoch_s: number;
}

export interface WireUeProfilePage {
  items: WireUeProfile[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
  max: number;
  secrets_exposed: boolean;
}

/** Body of POST /ue-profiles and PUT /ue-profiles/:ue_id. */
export interface WireUeProfileMutation {
  ue_id: string;
  name: string;
  /** Write-only. All three null on PUT = keep the existing material. */
  supi: string | null;
  authentication_key: string | null;
  opc: string | null;
  /** Creation only: bind to an already-provisioned subscriber instead of sending secrets. */
  provisioning_slot?: string | null;
  plmn_mcc: string;
  plmn_mnc: string;
  dnn: string;
  sst: number;
  sd: string | null;
  serving_gnb: string;
  scenario_id: string | null;
  auto_run_scenario: boolean;
}

/** Minimal API 0.15.2 create contract. Subscriber secrets are resolved server-side. */
export interface WireProvisionedUeProfileMutation {
  ue_id: string;
  name: string;
  gnb_id: string;
  owner: string;
  note: string;
  imsi: string;
}

export interface WireBulkProfileInput {
  count: 10 | 100 | 1000 | 10000;
  name_prefix: string;
  plmn_mcc: string;
  plmn_mnc: string;
  dnn: string;
  sst: number;
  sd: string | null;
  serving_gnb: string;
  scenario_id: string | null;
}

export interface WireProvisioningSlot {
  slot_id: string;
  bound_ue_id: string | null;
}

export interface WireProvisioningSlots {
  items: WireProvisioningSlot[];
  total: number;
  available: number;
  secrets_exposed: false;
}

export interface WireGnb {
  gnb_id: string;
  link_ip: string;
}

export interface WireGnbList {
  items: WireGnb[];
  total: number;
  source: 'LAB_DEFAULT' | 'CONFIGURED_REGISTRY' | string;
}

export const BULK_COUNTS = [10, 100, 1000, 10000] as const;
export const MAX_PAGE_SIZE = 500;
/** Backend UE ids: UE-NN (01–99) or UE-NNNNN (00100–10000). */
export const BACKEND_UE_ID_RE = /^UE-(?:\d{2}|\d{5})$/;

/** Reads every page (page_size 500 → at most 20 requests for the 10 000 cap). */
export async function fetchAllUeProfiles(): Promise<WireUeProfile[]> {
  const items: WireUeProfile[] = [];
  let page = 1;
  for (;;) {
    const body = await polarisApi<WireUeProfilePage>(
      `/ue-profiles?page=${page}&page_size=${MAX_PAGE_SIZE}`,
    );
    items.push(...body.items);
    if (page >= body.pages || body.items.length === 0) return items;
    page += 1;
  }
}

export function createUeProfile(body: WireUeProfileMutation) {
  return polarisApi<WireUeProfile>('/ue-profiles', { method: 'POST', body: JSON.stringify(body) });
}

export function createProvisionedUeProfile(body: WireProvisionedUeProfileMutation) {
  return polarisApi<WireUeProfile>('/ue-profiles', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export function updateUeProfile(ueId: string, body: WireUeProfileMutation) {
  return polarisApi<WireUeProfile>(`/ue-profiles/${encodeURIComponent(ueId)}`, {
    method: 'PUT',
    body: JSON.stringify(body),
  });
}

export function deleteUeProfile(ueId: string) {
  return polarisApi<{ deleted: string; profile_secret_deleted: boolean }>(
    `/ue-profiles/${encodeURIComponent(ueId)}`,
    { method: 'DELETE' },
  );
}

export function cloneUeProfile(ueId: string, targetUeId: string) {
  return polarisApi<WireUeProfile>(`/ue-profiles/${encodeURIComponent(ueId)}/clone`, {
    method: 'POST',
    body: JSON.stringify({ target_ue_id: targetUeId }),
  });
}

export function bulkCreateUeProfiles(body: WireBulkProfileInput) {
  return polarisApi<unknown>('/ue-profiles/bulk', { method: 'POST', body: JSON.stringify(body) });
}

export function validateUeProvisioning(ueId: string) {
  return polarisApi<unknown>(`/ue-profiles/${encodeURIComponent(ueId)}/validate-provisioning`, {
    method: 'POST',
    body: '{}',
  });
}

export function fetchProvisioningSlots() {
  return polarisApi<WireProvisioningSlots>('/ue-profiles/provisioning-slots');
}

export function fetchGnbs() {
  return polarisApi<WireGnbList>('/gnbs');
}

/** Public (non-secret) fields of a read record, as a mutation body with secrets preserved. */
export function mutationFromRecord(
  record: WireUeProfile,
  overrides: Partial<WireUeProfileMutation> = {},
): WireUeProfileMutation {
  return {
    ue_id: record.ue_id,
    name: record.name,
    supi: null,
    authentication_key: null,
    opc: null,
    plmn_mcc: record.plmn.mcc,
    plmn_mnc: record.plmn.mnc,
    dnn: record.dnn,
    sst: record.snssai.sst,
    sd: record.snssai.sd,
    serving_gnb: record.serving_gnb,
    scenario_id: record.scenario_id,
    auto_run_scenario: record.auto_run_scenario,
    ...overrides,
  };
}
