import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { polarisApi, writeCsrf } from './polarisClient';

export { writeCsrf };
import type {
  Capabilities,
  LabConfiguration,
  LoginRequest,
  LoginResult,
  NodeInventory,
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

/** Shape used by Core · Open5GS and Topology to render the NF containers. */
export interface WireContainerStatus {
  process_state: string;
  health: string;
  observed: boolean;
}
export interface WireLabObserved {
  ueransim_ue_profile?: boolean;
  ueransim_profile?: string;
  open5gs?: WireContainerStatus;
  ueransim_gnb?: WireContainerStatus;
  ueransim_ue?: WireContainerStatus;
  srsran_enb?: WireContainerStatus;
  srsran_ue?: WireContainerStatus;
  lte_attach?: string;
  controller_owned_active_jobs?: number;
}
export interface WireLabEnvelope {
  source?: string;
  configuration_changed?: boolean;
  observed?: WireLabObserved;
}
export function useLabObserved() {
  return useQuery({
    queryKey: ['polaris', 'lab-observed'],
    queryFn: () => polarisApi<WireLabEnvelope>('/lab'),
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

/** Backend contract: GET /ue-profiles/provisioning-slots → identity-free. */
export function useProvisioningSlots() {
  return useQuery({
    queryKey: ['polaris', 'provisioning-slots'],
    queryFn: async () => {
      const { fetchProvisioningSlots } = await import('./profileApi');
      return fetchProvisioningSlots();
    },
    staleTime: 30_000,
  });
}

/** Backend contract: GET /dnns → list of DNNs served by the lab. */
export function useDnns() {
  return useQuery({
    queryKey: ['polaris', 'dnns'],
    queryFn: async () => {
      const { fetchDnns } = await import('./profileApi');
      return fetchDnns();
    },
    staleTime: 60_000,
  });
}

/** Backend contract: GET /plmns → list of PLMNs served by the lab. */
export function usePlmns() {
  return useQuery({
    queryKey: ['polaris', 'plmns'],
    queryFn: async () => {
      const { fetchPlmns } = await import('./profileApi');
      return fetchPlmns();
    },
    staleTime: 60_000,
  });
}

/** Backend contract: GET /subscribers/:slot → PROTECTED subscriber record + linked UE ids. */
export function useSubscriberDetail(slot: string | null | undefined) {
  return useQuery({
    queryKey: ['polaris', 'subscribers', slot ?? ''],
    enabled: typeof slot === 'string' && slot.length > 0,
    queryFn: async () => {
      const { fetchSubscriberDetail } = await import('./profileApi');
      return fetchSubscriberDetail(slot as string);
    },
    staleTime: 15_000,
  });
}

/** Backend contract: PUT /subscribers/:slot (operator). K/OPc are write-only. */
export function useUpdateSubscriber() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (input: {
      slot: string;
      body: import('./profileApi').WireSubscriberUpdate;
    }) => {
      const { updateSubscriber } = await import('./profileApi');
      return updateSubscriber(input.slot, input.body);
    },
    onSuccess: (_result, variables) => {
      client.invalidateQueries({ queryKey: ['polaris', 'subscribers', variables.slot] });
      client.invalidateQueries({ queryKey: ['polaris', 'provisioning-slots'] });
    },
  });
}

/** Backend contract: POST /subscribers/generate (operator). CSPRNG K/OPc; never surfaced. */
export function useGenerateSubscribers() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (body: import('./profileApi').WireGenerateSubscribersRequest) => {
      const { generateSubscribers } = await import('./profileApi');
      return generateSubscribers(body);
    },
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ['polaris', 'provisioning-slots'] });
    },
  });
}

/** Backend contract: GET /gnbs → registry of serving-gnb targets. */
export function useGnbs() {
  return useQuery({
    queryKey: ['polaris', 'gnbs'],
    queryFn: async () => {
      const { fetchGnbs } = await import('./profileApi');
      return fetchGnbs();
    },
    staleTime: 30_000,
  });
}

export function useNodes() {
  return useQuery({
    queryKey: ['polaris', 'nodes'],
    queryFn: () => polarisApi<NodeInventory>('/nodes'),
    refetchInterval: 5_000,
  });
}

export function useLogin() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (request: LoginRequest) => {
      const result = await polarisApi<LoginResult>('/auth/login', {
        method: 'POST',
        body: JSON.stringify(request),
      });
      if (result.csrf_token) writeCsrf(result.csrf_token);
      return result;
    },
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['polaris', 'auth'] });
    },
  });
}

export function useLogout() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      await polarisApi<unknown>('/auth/logout', { method: 'POST', body: '{}' });
      writeCsrf(null);
    },
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['polaris', 'auth'] });
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
