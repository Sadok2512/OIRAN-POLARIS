import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, type ApiOptions } from '@shared/api';
import type {
  Capabilities,
  LabConfiguration,
  PolarisAuthState,
  ScenarioCapabilities,
  ScenarioList,
  ScenarioRuntime,
  ScenarioState,
  SystemHealth,
  TrafficState,
  UeInventory,
  ValidationResult,
} from './polarisTypes';

// Every POLARIS request names the `polaris` auth scope so the shared
// client can only attach the POLARIS token (never an OIRAN one) and only
// to the POLARIS API base. See packages/ui/src/api.ts.
const POLARIS_SCOPE: ApiOptions = {
  authScope: 'polaris',
  base: '/polaris-api/v1',
};

async function polarisApi<T>(path: string, extra: Omit<ApiOptions, 'authScope' | 'base'> = {}) {
  const envelope = await api<T>(path, { ...POLARIS_SCOPE, ...extra });
  // POLARIS Rust backend may return the body directly (no envelope); the
  // shared `api()` wraps it as `{ data, meta }` so the data field is the
  // raw payload. Return `data` for consumer ergonomics.
  return envelope.data;
}

export function useAuth() {
  return useQuery({
    queryKey: ['polaris', 'auth'],
    queryFn: () => polarisApi<PolarisAuthState>('/auth/me'),
    refetchInterval: 15_000,
    retry: false,
  });
}

export function useCapabilities() {
  return useQuery({
    queryKey: ['polaris', 'capabilities'],
    queryFn: () => polarisApi<Capabilities>('/capabilities'),
    staleTime: 30_000,
  });
}

export function useScenarioCapabilities() {
  return useQuery({
    queryKey: ['polaris', 'scenario-capabilities'],
    queryFn: () => polarisApi<ScenarioCapabilities>('/scenario-capabilities'),
    staleTime: 10_000,
  });
}

export function useLab() {
  return useQuery({
    queryKey: ['polaris', 'lab'],
    queryFn: () => polarisApi<LabConfiguration>('/lab'),
    refetchInterval: 10_000,
  });
}

export function useSystemHealth() {
  return useQuery({
    queryKey: ['polaris', 'system-health'],
    queryFn: () => polarisApi<SystemHealth>('/system/health'),
    refetchInterval: 5_000,
  });
}

export function useUes() {
  return useQuery({
    queryKey: ['polaris', 'ues'],
    queryFn: () => polarisApi<UeInventory>('/ues'),
    refetchInterval: 4_000,
  });
}

export function useScenarioRuntime() {
  return useQuery({
    queryKey: ['polaris', 'scenario-runtime'],
    queryFn: () => polarisApi<ScenarioRuntime>('/scenarios/status'),
    refetchInterval: 2_000,
  });
}

export function useScenarioHistory() {
  return useQuery({
    queryKey: ['polaris', 'scenario-history'],
    queryFn: () => polarisApi<ScenarioList>('/scenarios/history'),
    refetchInterval: 10_000,
  });
}

export function useTraffic() {
  return useQuery({
    queryKey: ['polaris', 'traffic'],
    queryFn: () => polarisApi<TrafficState>('/traffic/status'),
    refetchInterval: 2_000,
  });
}

/* --------------------------- Write operations --------------------------- */

export function useValidateScenario() {
  return useMutation({
    mutationFn: (request: Record<string, unknown>) =>
      polarisApi<ValidationResult>('/scenarios/validate', {
        method: 'POST',
        body: JSON.stringify(request),
      }),
  });
}

export function useStartScenario() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (request: Record<string, unknown>) =>
      polarisApi<ScenarioState>('/scenarios/start', {
        method: 'POST',
        body: JSON.stringify(request),
      }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['polaris', 'scenario-runtime'] });
      await client.invalidateQueries({ queryKey: ['polaris', 'scenario-history'] });
    },
  });
}

export function useStopScenario() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (jobId: string) =>
      polarisApi<ScenarioState>('/scenarios/stop', {
        method: 'POST',
        body: JSON.stringify({ job_id: jobId }),
      }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['polaris', 'scenario-runtime'] });
      await client.invalidateQueries({ queryKey: ['polaris', 'scenario-history'] });
    },
  });
}

export function useStartUe() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (ueId: string) =>
      polarisApi<unknown>('/ues/start', {
        method: 'POST',
        body: JSON.stringify({ ue_id: ueId }),
      }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['polaris', 'ues'] });
    },
  });
}

export function useStopUe() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (ueId: string) =>
      polarisApi<unknown>('/ues/stop', {
        method: 'POST',
        body: JSON.stringify({ ue_id: ueId }),
      }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['polaris', 'ues'] });
    },
  });
}
