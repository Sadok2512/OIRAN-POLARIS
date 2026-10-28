// Typed client for polaris-control-api 0.9.0 scenario surface.
//
// Routes (contract from Codex, commit f676ceb — not yet pushed to the
// shared remote at the time of writing):
//   GET    /api/v1/scenario-definitions
//   POST   /api/v1/scenario-definitions
//   GET    /api/v1/scenario-definitions/:id
//   PUT    /api/v1/scenario-definitions/:id
//   DELETE /api/v1/scenario-definitions/:id
//   POST   /api/v1/scenario-definitions/:id/clone
//   POST   /api/v1/scenarios/start   { scenario_definition_id, ue_ids[] }
//   GET    /api/v1/scenarios/:job_id/steps
//
// EVERY hook here is gated by `featureFlags.scenarioBackend`. When the
// flag is off the queries are disabled (`enabled: false`) so no request
// is issued and polaris.scenarios.v1 stays authoritative.
//
// Scope boundaries:
//   * UE profiles are NOT wired — their contract is still open.
//   * cache_version / cache_fresh on /ues are typed in polarisTypes.ts
//     but not consumed in UI (no field invented, strict read-only).

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, type ApiOptions } from '@shared/api';
import { useFeatureFlag } from './featureFlags';
import type {
  WireScenarioDefinition,
  WireScenarioStepStatus,
  WireStartScenarioRequest,
} from '@/scenarios/wireCodec';

const CSRF_KEY = 'polaris.csrf_token';

function readCsrf(): string | null {
  if (typeof sessionStorage === 'undefined') return null;
  return sessionStorage.getItem(CSRF_KEY);
}

// Same scope used by src/data/queries.ts — the shared client only
// attaches a POLARIS token to its allowlisted base.
const POLARIS_SCOPE: ApiOptions = {
  authScope: 'polaris',
  base: '/polaris-api/v1',
};

async function polarisApi<T>(
  path: string,
  extra: Omit<ApiOptions, 'authScope' | 'base'> = {},
): Promise<T> {
  const method = (extra.method ?? 'GET').toUpperCase();
  const extraHeaders = new Headers(extra.headers);
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const csrf = readCsrf();
    if (csrf) extraHeaders.set('x-csrf-token', csrf);
  }
  const envelope = await api<T>(path, { ...POLARIS_SCOPE, ...extra, headers: extraHeaders });
  return envelope.data;
}

/* ------------------------------- Error shape ------------------------------ */

/**
 * Backend error envelope. The exact JSON shape returned by 0.9.0 is still
 * being documented; the UI surfaces `.message` as a string so later
 * refinement does not require UI changes.
 */
export interface ScenarioApiError {
  code: string;
  message: string;
}

/* -------------------------------- Queries -------------------------------- */

export function useScenarioDefinitions() {
  const enabled = useFeatureFlag('scenarioBackend');
  return useQuery({
    queryKey: ['polaris', 'scenario-definitions'],
    queryFn: () => polarisApi<WireScenarioDefinition[]>('/scenario-definitions'),
    enabled,
    refetchInterval: enabled ? 10_000 : false,
  });
}

export function useScenarioDefinition(id: string | null) {
  const enabled = useFeatureFlag('scenarioBackend') && !!id;
  return useQuery({
    queryKey: ['polaris', 'scenario-definition', id],
    queryFn: () => polarisApi<WireScenarioDefinition>(`/scenario-definitions/${id}`),
    enabled,
  });
}

export function useScenarioSteps(jobId: string | null) {
  const enabled = useFeatureFlag('scenarioBackend') && !!jobId;
  return useQuery({
    queryKey: ['polaris', 'scenario-steps', jobId],
    queryFn: () =>
      polarisApi<WireScenarioStepStatus[]>(`/scenarios/${jobId}/steps`),
    enabled,
    refetchInterval: enabled ? 2_000 : false,
  });
}

/* ------------------------------- Mutations ------------------------------- */

export function useCreateScenarioDefinition() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: WireScenarioDefinition) =>
      polarisApi<WireScenarioDefinition>('/scenario-definitions', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['polaris', 'scenario-definitions'] });
    },
  });
}

export function useUpdateScenarioDefinition() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: WireScenarioDefinition }) =>
      // Contract 0.9.0 registers PUT (not PATCH) on /scenario-definitions/:id.
      polarisApi<WireScenarioDefinition>(`/scenario-definitions/${id}`, {
        method: 'PUT',
        body: JSON.stringify(body),
      }),
    onSuccess: async (_, variables) => {
      await client.invalidateQueries({ queryKey: ['polaris', 'scenario-definitions'] });
      await client.invalidateQueries({
        queryKey: ['polaris', 'scenario-definition', variables.id],
      });
    },
  });
}

export function useDeleteScenarioDefinition() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      polarisApi<unknown>(`/scenario-definitions/${id}`, { method: 'DELETE' }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['polaris', 'scenario-definitions'] });
    },
  });
}

export function useCloneScenarioDefinition() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      polarisApi<WireScenarioDefinition>(`/scenario-definitions/${id}/clone`, {
        method: 'POST',
        body: '{}',
      }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['polaris', 'scenario-definitions'] });
    },
  });
}

export function useStartScenarioRun() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: WireStartScenarioRequest) =>
      polarisApi<{ job_id: string }>('/scenarios/start', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['polaris', 'scenario-runtime'] });
      await client.invalidateQueries({ queryKey: ['polaris', 'scenario-history'] });
    },
  });
}
