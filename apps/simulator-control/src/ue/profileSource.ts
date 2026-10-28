// One UE-profile source for the UE Manager.
//
// Flag `profileBackend` OFF → the local store (polaris.ueProfiles.v1), unchanged.
// Flag ON → POLARIS /api/v1/ue-profiles (contract 0.11.0). In that mode nothing
// about a subscriber identity is written to browser storage: secrets travel
// once in the mutation body and are read back only as "PROTECTED".

import { useMemo } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useFeatureFlag } from '@/data/featureFlags';
import {
  bulkCreateUeProfiles,
  cloneUeProfile,
  createUeProfile,
  deleteUeProfile,
  fetchAllUeProfiles,
  fetchGnbs,
  fetchProvisioningSlots,
  mutationFromRecord,
  updateUeProfile,
  validateUeProvisioning,
  type WireBulkProfileInput,
  type WireGnb,
  type WireProvisioningSlot,
  type WireUeProfile,
  type WireUeProfileMutation,
} from '@/data/profileApi';
import type { UeProfileRecord } from './profileModel';

const PROFILES_KEY = ['polaris', 'ue-profiles'] as const;
const SLOTS_KEY = ['polaris', 'provisioning-slots'] as const;
const GNBS_KEY = ['polaris', 'gnbs'] as const;

export function recordFromWire(wire: WireUeProfile): UeProfileRecord {
  const updated = wire.updated_at_epoch_s * 1000;
  return {
    id: wire.ue_id,
    owner: wire.name,
    servingGnb: wire.serving_gnb,
    plmn: `${wire.plmn.mcc}${wire.plmn.mnc}`,
    apn: wire.dnn,
    createdAt: updated,
    updatedAt: updated,
    subscriptionStatus: wire.subscription_status,
    scenarioId: wire.scenario_id,
  };
}

export interface BackendProfileSource {
  enabled: boolean;
  profiles: UeProfileRecord[];
  wireById: Map<string, WireUeProfile>;
  loading: boolean;
  error: Error | null;
  slots: WireProvisioningSlot[];
  slotsError: Error | null;
  gnbs: WireGnb[];
  create: (body: WireUeProfileMutation) => Promise<WireUeProfile>;
  update: (ueId: string, body: WireUeProfileMutation) => Promise<WireUeProfile>;
  clone: (ueId: string, targetUeId: string) => Promise<WireUeProfile>;
  remove: (ueIds: string[]) => Promise<{ deleted: number; failures: string[] }>;
  bulk: (input: WireBulkProfileInput) => Promise<void>;
  assign: (ueIds: string[], scenarioId: string | null, autoRun: boolean) => Promise<string[]>;
  validate: (ueId: string) => Promise<void>;
}

export function useBackendProfiles(): BackendProfileSource {
  const enabled = useFeatureFlag('profileBackend');
  const client = useQueryClient();
  const list = useQuery({
    queryKey: PROFILES_KEY,
    queryFn: fetchAllUeProfiles,
    enabled,
    refetchInterval: enabled ? 15_000 : false,
  });
  const slots = useQuery({
    queryKey: SLOTS_KEY,
    queryFn: fetchProvisioningSlots,
    enabled,
    retry: false,
  });
  const gnbs = useQuery({ queryKey: GNBS_KEY, queryFn: fetchGnbs, enabled });

  const wireById = useMemo(
    () => new Map((list.data ?? []).map((item) => [item.ue_id, item])),
    [list.data],
  );
  const profiles = useMemo(() => (list.data ?? []).map(recordFromWire), [list.data]);

  async function refresh() {
    await client.invalidateQueries({ queryKey: PROFILES_KEY });
    await client.invalidateQueries({ queryKey: SLOTS_KEY });
  }

  async function withRefresh<T>(work: Promise<T>): Promise<T> {
    try {
      return await work;
    } finally {
      await refresh();
    }
  }

  return {
    enabled,
    profiles,
    wireById,
    loading: list.isLoading,
    error: (list.error as Error | null) ?? null,
    slots: slots.data?.items ?? [],
    slotsError: (slots.error as Error | null) ?? null,
    gnbs: gnbs.data?.items ?? [],
    create: (body) => withRefresh(createUeProfile(body)),
    update: (ueId, body) => withRefresh(updateUeProfile(ueId, body)),
    clone: (ueId, target) => withRefresh(cloneUeProfile(ueId, target)),
    remove: (ueIds) =>
      withRefresh(
        (async () => {
          const failures: string[] = [];
          let deleted = 0;
          for (const id of ueIds) {
            try {
              await deleteUeProfile(id);
              deleted += 1;
            } catch (error) {
              failures.push(`${id}: ${(error as { code?: string }).code ?? (error as Error).message}`);
            }
          }
          return { deleted, failures };
        })(),
      ),
    bulk: (input) => withRefresh(bulkCreateUeProfiles(input).then(() => undefined)),
    assign: (ueIds, scenarioId, autoRun) =>
      withRefresh(
        (async () => {
          const failures: string[] = [];
          for (const id of ueIds) {
            const record = wireById.get(id);
            if (!record) {
              failures.push(`${id}: UNKNOWN_UE_PROFILE`);
              continue;
            }
            try {
              await updateUeProfile(
                id,
                mutationFromRecord(record, {
                  scenario_id: scenarioId,
                  auto_run_scenario: scenarioId ? autoRun : false,
                }),
              );
            } catch (error) {
              failures.push(`${id}: ${(error as { code?: string }).code ?? (error as Error).message}`);
            }
          }
          return failures;
        })(),
      ),
    validate: (ueId) => withRefresh(validateUeProvisioning(ueId).then(() => undefined)),
  };
}
