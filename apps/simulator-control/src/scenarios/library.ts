// One scenario-library hook for every page.
//
// Flag `scenarioBackend` OFF → the local catalog (polaris.scenarios.v1), unchanged.
// Flag ON → the backend catalog (/api/v1/scenario-definitions), decoded with
// wireCodec. Pages call the same `scenarios / save / delete / duplicate`
// surface either way; mutations are async because the backend ones are.

import { useMemo } from 'react';
import { useFeatureFlag } from '@/data/featureFlags';
import {
  useCloneScenarioDefinition,
  useCreateScenarioDefinition,
  useDeleteScenarioDefinition,
  useScenarioDefinitions,
  useUpdateScenarioDefinition,
} from '@/data/scenarioApi';
import { useScenarios } from './store';
import type { Scenario } from './model';
import { decodeDefinition, encodeDefinition, type WireScenarioDefinition } from './wireCodec';

export interface ScenarioLibrary {
  backend: boolean;
  scenarios: Scenario[];
  loading: boolean;
  error: Error | null;
  /** Definitions the backend returned but this UI cannot represent (unknown step type). */
  undecodable: string[];
  save: (scenario: Scenario) => Promise<Scenario>;
  delete: (id: string) => Promise<void>;
  duplicate: (id: string) => Promise<Scenario | null>;
}

/** Backend ids are `[A-Za-z0-9_-]{1,64}`; clone targets must satisfy the same rule.
 *
 * 0.9.0 — the suffix combines a base-36 timestamp with a monotonic counter
 * so successive clones (even in the same millisecond) always produce a
 * distinct target id. Two consecutive clones of the same source therefore
 * never collide, which satisfies the recette requirement that every
 * cloned scenario has a unique name on screen.
 */
let cloneCounter = 0;
export function cloneTargetId(sourceId: string, now: number = Date.now()): string {
  cloneCounter = (cloneCounter + 1) % 1_296; // 36^2 — stays short in base36
  const suffix = `-copy-${now.toString(36)}-${cloneCounter.toString(36).padStart(2, '0')}`;
  return `${sourceId.slice(0, 64 - suffix.length)}${suffix}`;
}

/** Reset the clone counter — exercised by tests only. */
export function _resetCloneCounterForTests(): void {
  cloneCounter = 0;
}

function decodeAll(items: WireScenarioDefinition[] | undefined): {
  scenarios: Scenario[];
  undecodable: string[];
} {
  const scenarios: Scenario[] = [];
  const undecodable: string[] = [];
  for (const item of items ?? []) {
    try {
      scenarios.push(decodeDefinition(item));
    } catch {
      undecodable.push(item.id);
    }
  }
  return { scenarios, undecodable };
}

export function useScenarioLibrary(): ScenarioLibrary {
  const backend = useFeatureFlag('scenarioBackend');
  const local = useScenarios();
  const list = useScenarioDefinitions();
  const create = useCreateScenarioDefinition();
  const update = useUpdateScenarioDefinition();
  const remove = useDeleteScenarioDefinition();
  const clone = useCloneScenarioDefinition();

  // React Query keeps the same `data` reference when a refetch returns equal JSON,
  // so decoded scenarios (and their step ids) stay stable between polls.
  const decoded = useMemo(() => decodeAll(list.data?.items), [list.data]);

  if (!backend) {
    return {
      backend: false,
      scenarios: local.scenarios,
      loading: false,
      error: null,
      undecodable: [],
      save: async (scenario) => local.save(scenario),
      delete: async (id) => local.delete(id),
      duplicate: async (id) => local.duplicate(id),
    };
  }

  return {
    backend: true,
    scenarios: decoded.scenarios,
    loading: list.isLoading,
    error: (list.error as Error | null) ?? null,
    undecodable: decoded.undecodable,
    save: async (scenario) => {
      const body = encodeDefinition(scenario);
      const exists = (list.data?.items ?? []).some((item) => item.id === scenario.id);
      const saved = exists
        ? await update.mutateAsync({ id: scenario.id, body })
        : await create.mutateAsync(body);
      return decodeDefinition(saved);
    },
    delete: async (id) => {
      await remove.mutateAsync(id);
    },
    duplicate: async (id) => {
      const copy = await clone.mutateAsync({ id, targetId: cloneTargetId(id) });
      return decodeDefinition(copy);
    },
  };
}
