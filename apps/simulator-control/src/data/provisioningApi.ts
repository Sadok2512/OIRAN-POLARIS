// 0.6.0 — client for the richer provisioning surface Codex publishes on
// `feat/polaris-provisioning`. Everything here is gated by the
// `polarisProvisioning` feature flag so no request leaves the UI until
// an operator flips the flag in Settings.
//
// Routes (contract from the LOT prompt):
//   GET  /api/v1/owners                            → { items: Owner[] }
//   GET  /api/v1/plmns                             → { items: Plmn[] }
//   GET  /api/v1/dnns                              → { items: Dnn[] }
//   GET  /api/v1/ue-profiles/:ue_id                → detail card body
//   POST /api/v1/provisioning/import   (multipart, operator + CSRF)
//   POST /api/v1/ue-profiles/import    (multipart, operator + CSRF)
//
// All reads keep subscriber identity material opaque (SUPI, K and OPc
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
    queryFn: async () => {
      const body = await polarisApi<{ items: string[] }>('/owners');
      return {
        items: body.items.map((owner) => ({ id: owner, name: owner, role: owner, email: null })),
        total: body.items.length,
      } satisfies OwnerList;
    },
    enabled,
    staleTime: enabled ? 60_000 : Infinity,
    retry: false,
  });
}

export function usePlmns() {
  const enabled = useFeatureFlag('polarisProvisioning');
  return useQuery({
    queryKey: ['polaris', 'plmns'],
    queryFn: async () => {
      const body = await polarisApi<{ items: string[] }>('/plmns');
      return {
        items: body.items.map((plmn) => {
          const [mcc = '', mnc = ''] = plmn.split('-', 2);
          return { id: plmn, mcc, mnc, display_name: plmn, home_network: true };
        }),
        total: body.items.length,
      } satisfies PlmnList;
    },
    enabled,
    staleTime: enabled ? 60_000 : Infinity,
    retry: false,
  });
}

export function useDnns() {
  const enabled = useFeatureFlag('polarisProvisioning');
  return useQuery({
    queryKey: ['polaris', 'dnns'],
    queryFn: async () => {
      const body = await polarisApi<{ items: string[] }>('/dnns');
      return {
        items: body.items.map((dnn) => ({ id: dnn, dnn, sst: 0, sd: null, description: dnn })),
        total: body.items.length,
      } satisfies DnnList;
    },
    enabled,
    staleTime: enabled ? 60_000 : Infinity,
    retry: false,
  });
}

/**
 * 0.6.0 — Streaming multipart CSV upload.
 *
 * `target` picks the backend endpoint:
 *   - `provisioning` → `POST /provisioning/import` (subscriber bulk)
 *   - `ue-profiles`  → `POST /ue-profiles/import`  (UE bulk)
 *
 * The server answers with a per-line report. Both endpoints cap the body
 * at 100 000 rows (POLARIS backend-enforced); the UI pre-counts lines
 * before posting so the operator is told up-front when the file is too
 * big. We do NOT split the file client-side — splitting would break the
 * atomicity guarantees of the backend transaction.
 */
export interface CsvImportReport {
  total: number;
  accepted: number;
  rejected: number;
  errors: { line: number; code: string; message: string }[];
}

export async function uploadCsvImport(
  target: 'provisioning' | 'ue-profiles',
  file: File,
): Promise<CsvImportReport> {
  const path = target === 'provisioning' ? '/subscribers/bulk' : '/ue-profiles/bulk';
  const headers = new Headers({ Accept: 'application/json', 'Content-Type': 'text/csv' });
  const csrf = readCsrf();
  if (csrf) headers.set('x-csrf-token', csrf);
  const response = await fetch(`/polaris-api/v1${path}`, {
    method: 'POST',
    headers,
    body: file,
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
  const payload = (await response.json()) as {
    ok: number;
    errors: number;
    results: { row: number; ok: boolean; error?: string | null }[];
  };
  return {
    total: payload.ok + payload.errors,
    accepted: payload.ok,
    rejected: payload.errors,
    errors: payload.results
      .filter((row) => !row.ok)
      .map((row) => ({
        line: row.row,
        code: row.error ?? 'ROW_REJECTED',
        message: row.error ?? 'ROW_REJECTED',
      })),
  };
}
