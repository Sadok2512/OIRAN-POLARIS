// Typed client for polaris-control-api 0.10.0+ scenario surface.
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
import { polarisApi } from './polarisClient';
import { useFeatureFlag } from './featureFlags';
import type {
  WireScenarioDefinition,
  WireScenarioDefinitionList,
  WireScenarioMutation,
  WireScenarioStepsResponse,
  WireStartScenarioRequest,
} from '@/scenarios/wireCodec';





/* ------------------------------- Error shape ------------------------------ */

/**
 * POLARIS errors are `{"error":"CODE"}`. The shared client turns them into an
 * ApiError whose `.code` carries CODE (see polarisClient.ts).
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
    // Real body: { items, total, schema_version } — not a bare array.
    queryFn: () => polarisApi<WireScenarioDefinitionList>('/scenario-definitions'),
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
      // Real body: { job_id, scenario_definition_id, steps: [...] }.
      polarisApi<WireScenarioStepsResponse>(`/scenarios/${jobId}/steps`),
    enabled,
    refetchInterval: enabled ? 2_000 : false,
  });
}

/* ------------------------------- Mutations ------------------------------- */

export function useCreateScenarioDefinition() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: WireScenarioMutation) =>
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
    mutationFn: ({ id, body }: { id: string; body: WireScenarioMutation }) =>
      // The router registers PUT (not PATCH) on /scenario-definitions/:id.
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
      polarisApi<{ deleted: string }>(`/scenario-definitions/${id}`, { method: 'DELETE' }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['polaris', 'scenario-definitions'] });
    },
  });
}

export function useCloneScenarioDefinition() {
  const client = useQueryClient();
  return useMutation({
    // The backend requires the new definition id: { "target_id": "..." }.
    mutationFn: ({ id, targetId }: { id: string; targetId: string }) =>
      polarisApi<WireScenarioDefinition>(`/scenario-definitions/${id}/clone`, {
        method: 'POST',
        body: JSON.stringify({ target_id: targetId }),
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
      polarisApi<{ job_id: string; state: string; terminal_result?: string }>('/scenarios/start', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['polaris', 'scenario-runtime'] });
      await client.invalidateQueries({ queryKey: ['polaris', 'scenario-history'] });
    },
  });
}
