// 0.6.1 — client for the provisioning surface shipped by Codex on
// polaris-control-api 0.15.1 (fc6d8ed). The earlier /provisioning/import
// and /ue-profiles/import multipart stubs are removed; the real
// endpoints take raw CSV text bodies.
//
// Routes:
//   GET  /api/v1/owners                            → { items: Owner[] }
//   GET  /api/v1/plmns                             → { items: Plmn[] }
//   GET  /api/v1/dnns                              → { items: Dnn[] }
//   GET  /api/v1/subscribers                       → subscriber directory
//   POST /api/v1/subscribers         JSON {imsi, k, opc, sst, sd, dnns[], ambr{uplink,downlink}}
//   POST /api/v1/subscribers/bulk    text/csv: imsi,k,opc,sst,sd,dnns,ambr_uplink,ambr_downlink
//   POST /api/v1/ue-profiles/bulk    text/csv: ue_id,gnb_id,note,imsi
//   GET  /api/v1/ue-profiles/:ue_id                → detail card body
//
// All reads keep subscriber identity material opaque (IMSI, K and OPc
// are returned as the literal "PROTECTED"); this module never exposes
// a getter that would reveal them.

import { useQuery } from '@tanstack/react-query';
import { ApiError } from '@shared/api';
import { polarisApi, readCsrf } from './polarisClient';
import { useFeatureFlag } from './featureFlags';

export interface Owner {
  id: string;
  name: string;
  role: string;
  email: string | null;
}

export interface Plmn {
  id: string;
  mcc: string;
  mnc: string;
  display_name: string;
  home_network: boolean;
}

export interface Dnn {
  id: string;
  dnn: string;
  sst: number;
  sd: string | null;
  description: string;
}

export interface OwnerList {
  items: Owner[];
  total: number;
}

export interface PlmnList {
  items: Plmn[];
  total: number;
}

export interface DnnList {
  items: Dnn[];
  total: number;
}

export function useOwners() {
  const enabled = useFeatureFlag('polarisProvisioning');
  return useQuery({
    queryKey: ['polaris', 'owners'],
    queryFn: () => polarisApi<OwnerList>('/owners'),
    enabled,
    staleTime: enabled ? 60_000 : Infinity,
    retry: false,
  });
}

export function usePlmns() {
  const enabled = useFeatureFlag('polarisProvisioning');
  return useQuery({
    queryKey: ['polaris', 'plmns'],
    queryFn: () => polarisApi<PlmnList>('/plmns'),
    enabled,
    staleTime: enabled ? 60_000 : Infinity,
    retry: false,
  });
}

export function useDnns() {
  const enabled = useFeatureFlag('polarisProvisioning');
  return useQuery({
    queryKey: ['polaris', 'dnns'],
    queryFn: () => polarisApi<DnnList>('/dnns'),
    enabled,
    staleTime: enabled ? 60_000 : Infinity,
    retry: false,
  });
}

/**
 * 0.6.1 — Raw-body CSV upload. polaris-control-api 0.15.1 reads the
 * entire request body as `text/csv`; multipart form data is NOT
 * accepted. The expected columns depend on the target:
 *
 *   - `subscribers` → POST /subscribers/bulk
 *     `imsi,k,opc,sst,sd,dnns,ambr_uplink,ambr_downlink`
 *   - `ue-profiles` → POST /ue-profiles/bulk
 *     `ue_id,gnb_id,note,imsi`
 *
 * The server answers with a per-line report. Both endpoints cap the body
 * at 100 000 rows (backend-enforced); the UI pre-counts lines so the
 * operator is told up-front when the file is too big. We do NOT split
 * the file client-side — splitting would break the atomicity guarantees
 * of the backend transaction.
 */
export interface CsvImportReport {
  total: number;
  accepted: number;
  rejected: number;
  errors: { line: number; code: string; message: string }[];
}

export type CsvImportTarget = 'subscribers' | 'ue-profiles';

export async function uploadCsvImport(
  target: CsvImportTarget,
  file: File,
): Promise<CsvImportReport> {
  const path = target === 'subscribers' ? '/subscribers/bulk' : '/ue-profiles/bulk';
  const headers = new Headers({
    Accept: 'application/json',
    'Content-Type': 'text/csv',
  });
  const csrf = readCsrf();
  if (csrf) headers.set('x-csrf-token', csrf);
  const body = await file.text();
  const response = await fetch(`/polaris-api/v1${path}`, {
    method: 'POST',
    headers,
    body,
    credentials: 'same-origin',
  });
  if (!response.ok) {
    let code = 'CSV_IMPORT_FAILED';
    try {
      const payload = (await response.json()) as { error?: string | { code?: string } };
      if (typeof payload.error === 'string') code = payload.error;
      else if (payload.error && typeof payload.error === 'object' && payload.error.code)
        code = payload.error.code;
    } catch {
      // keep generic code
    }
    throw new ApiError(response.status, code, `HTTP ${response.status} ${code}`);
  }
  return (await response.json()) as CsvImportReport;
}

/**
 * 0.6.1 — JSON create for `POST /subscribers`. Secret material (K, OPc)
 * is write-only; the response body carries the backend-assigned slot id
 * plus the two literals `PROTECTED` so the operator can see the
 * subscriber is in place without ever seeing the key again.
 */
export interface SubscriberCreateInput {
  imsi: string;
  k: string;
  opc: string;
  sst: number;
  sd: string | null;
  dnns: string[];
  ambr: { uplink: number; downlink: number };
}

export interface SubscriberCreateResponse {
  slot_id: string;
  subscriber_id: string;
  imsi: 'PROTECTED';
  k: 'PROTECTED';
  opc: 'PROTECTED';
  sst: number;
  sd: string | null;
  dnns: string[];
  ambr: { uplink: number; downlink: number };
  created_at_epoch_s: number;
}

export async function createSubscriber(
  input: SubscriberCreateInput,
): Promise<SubscriberCreateResponse> {
  return polarisApi<SubscriberCreateResponse>('/subscribers', {
    method: 'POST',
    body: JSON.stringify(input),
    headers: { 'Content-Type': 'application/json' },
  });
}
