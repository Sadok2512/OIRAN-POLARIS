// Local-storage persistence for the scenario library and UE
// assignments. The browser is the only authority on these objects
// today — the real POLARIS backend does not expose a scenario CRUD or
// an assignment table yet (see
// docs/frontend/SIMULATOR_SCENARIO_BUILDER.md).
//
// When the backend contracts land, the same functions can be swapped
// for TanStack-Query hooks without changing the UI.

import { useCallback, useEffect, useState } from 'react';
import type { Scenario, ScenarioAssignment } from './model';

const LIBRARY_KEY = 'polaris.scenarios.v1';
const ASSIGNMENT_KEY = 'polaris.assignments.v1';

function safeRead<T>(key: string, fallback: T): T {
  if (typeof localStorage === 'undefined') return fallback;
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return fallback;
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function safeWrite<T>(key: string, value: T): void {
  if (typeof localStorage === 'undefined') return;
  localStorage.setItem(key, JSON.stringify(value));
}

/* ------------------------------- Scenarios ------------------------------- */

export function listScenarios(): Scenario[] {
  return safeRead<Scenario[]>(LIBRARY_KEY, []);
}

export function getScenario(id: string): Scenario | null {
  return listScenarios().find((scenario) => scenario.id === id) ?? null;
}

export function saveScenario(scenario: Scenario): Scenario {
  const now = Date.now();
  const existing = listScenarios();
  const prev = existing.find((item) => item.id === scenario.id);
  const next: Scenario = {
    ...scenario,
    version: prev ? prev.version + 1 : scenario.version,
    updatedAt: now,
    createdAt: prev?.createdAt ?? scenario.createdAt ?? now,
  };
  const remaining = existing.filter((item) => item.id !== scenario.id);
  const list = [...remaining, next].sort((a, b) => b.updatedAt - a.updatedAt);
  safeWrite(LIBRARY_KEY, list);
  return next;
}

export function deleteScenario(id: string): void {
  const list = listScenarios().filter((scenario) => scenario.id !== id);
  safeWrite(LIBRARY_KEY, list);
  // Also remove any assignment pointing at this scenario.
  const assignments = listAssignments().filter((a) => a.scenarioId !== id);
  safeWrite(ASSIGNMENT_KEY, assignments);
}

export function duplicateScenario(id: string): Scenario | null {
  const source = getScenario(id);
  if (!source) return null;
  const now = Date.now();
  const copy: Scenario = {
    ...source,
    id: `scn-${now.toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
    name: `${source.name} (copy)`,
    version: 1,
    createdAt: now,
    updatedAt: now,
    steps: source.steps.map((step) => ({
      ...step,
      id: `step-${Math.random().toString(36).slice(2, 10)}`,
    })),
  };
  return saveScenario(copy);
}

/** React hook that reflects the current scenario library. */
export function useScenarios() {
  const [list, setList] = useState<Scenario[]>(listScenarios);

  const refresh = useCallback(() => setList(listScenarios()), []);

  useEffect(() => {
    function onStorage(event: StorageEvent) {
      if (event.key === LIBRARY_KEY) refresh();
    }
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, [refresh]);

  return {
    scenarios: list,
    save: (scenario: Scenario) => {
      const saved = saveScenario(scenario);
      refresh();
      return saved;
    },
    delete: (id: string) => {
      deleteScenario(id);
      refresh();
    },
    duplicate: (id: string) => {
      const copy = duplicateScenario(id);
      refresh();
      return copy;
    },
    refresh,
  };
}

/* ------------------------------ Assignments ------------------------------ */

export function listAssignments(): ScenarioAssignment[] {
  return safeRead<ScenarioAssignment[]>(ASSIGNMENT_KEY, []);
}

export function getAssignment(ueId: string): ScenarioAssignment | null {
  return listAssignments().find((a) => a.ueId === ueId) ?? null;
}

export function assignScenario(ueId: string, scenarioId: string, autoRun: boolean): ScenarioAssignment {
  const assignment: ScenarioAssignment = { ueId, scenarioId, autoRun, updatedAt: Date.now() };
  const existing = listAssignments().filter((a) => a.ueId !== ueId);
  const list = [...existing, assignment];
  safeWrite(ASSIGNMENT_KEY, list);
  return assignment;
}

export function clearAssignment(ueId: string): void {
  const list = listAssignments().filter((a) => a.ueId !== ueId);
  safeWrite(ASSIGNMENT_KEY, list);
}

export function useAssignments() {
  const [list, setList] = useState<ScenarioAssignment[]>(listAssignments);

  const refresh = useCallback(() => setList(listAssignments()), []);

  useEffect(() => {
    function onStorage(event: StorageEvent) {
      if (event.key === ASSIGNMENT_KEY) refresh();
    }
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, [refresh]);

  return {
    assignments: list,
    assign: (ueId: string, scenarioId: string, autoRun: boolean) => {
      const result = assignScenario(ueId, scenarioId, autoRun);
      refresh();
      return result;
    },
    clear: (ueId: string) => {
      clearAssignment(ueId);
      refresh();
    },
    refresh,
  };
}

/* --------------------------- Testing utilities --------------------------- */

/** Clears all local persistence. Used by tests. */
export function _reset(): void {
  if (typeof localStorage === 'undefined') return;
  localStorage.removeItem(LIBRARY_KEY);
  localStorage.removeItem(ASSIGNMENT_KEY);
}
