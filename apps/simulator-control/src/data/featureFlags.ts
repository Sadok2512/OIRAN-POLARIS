// Minimal client-side feature-flag store.
//
// Flags live in localStorage so an operator can opt in / out from the
// Settings page without a redeploy. The default is OFF for every flag —
// nothing calls new backend contracts until the operator flips it. This
// is the one guard that keeps the local scenario catalog (polaris.
// scenarios.v1) authoritative while the backend 0.9.0 is still being
// pushed by Codex.

import { useCallback, useSyncExternalStore } from 'react';

const FLAGS_KEY = 'polaris.featureFlags.v1';

export interface FeatureFlags {
  /**
   * When true, the UI calls polaris-control-api 0.9.0:
   *   GET/POST/PUT/DELETE /api/v1/scenario-definitions
   *   POST /api/v1/scenarios/start
   *   GET  /api/v1/scenarios/:job_id/steps
   * When false, the UI stays on polaris.scenarios.v1 + the pre-0.9.0
   * /scenarios/start shape (certified-profile mapping).
   */
  scenarioBackend: boolean;
  /**
   * When true, UE profiles and their scenario assignment live in POLARIS
   * (/api/v1/ue-profiles, contract 0.11.0). SUPI/K/OPc are write-only and never
   * stored in the browser. When false, polaris.ueProfiles.v1 stays authoritative.
   */
  profileBackend: boolean;
}

const DEFAULTS: FeatureFlags = {
  scenarioBackend: false,
  profileBackend: false,
};

function read(): FeatureFlags {
  if (typeof localStorage === 'undefined') return DEFAULTS;
  try {
    const raw = localStorage.getItem(FLAGS_KEY);
    if (!raw) return DEFAULTS;
    const parsed = JSON.parse(raw) as Partial<FeatureFlags>;
    return { ...DEFAULTS, ...parsed };
  } catch {
    return DEFAULTS;
  }
}

function write(flags: FeatureFlags): void {
  if (typeof localStorage === 'undefined') return;
  localStorage.setItem(FLAGS_KEY, JSON.stringify(flags));
}

type Listener = () => void;
const listeners = new Set<Listener>();
let cache: FeatureFlags = read();

function notify(): void {
  cache = read();
  for (const listener of listeners) listener();
}

function subscribe(listener: Listener): () => void {
  listeners.add(listener);
  const onStorage = (event: StorageEvent) => {
    if (event.key === FLAGS_KEY) notify();
  };
  if (typeof window !== 'undefined') {
    window.addEventListener('storage', onStorage);
  }
  return () => {
    listeners.delete(listener);
    if (typeof window !== 'undefined') {
      window.removeEventListener('storage', onStorage);
    }
  };
}

export function getFlags(): FeatureFlags {
  return cache;
}

export function setFlag<K extends keyof FeatureFlags>(key: K, value: FeatureFlags[K]): void {
  write({ ...cache, [key]: value });
  notify();
}

export function useFeatureFlags(): FeatureFlags {
  const getSnapshot = useCallback(() => cache, []);
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}

export function useFeatureFlag<K extends keyof FeatureFlags>(key: K): FeatureFlags[K] {
  const flags = useFeatureFlags();
  return flags[key];
}

/* Test helpers. */
export function _resetFlags(): void {
  if (typeof localStorage !== 'undefined') localStorage.removeItem(FLAGS_KEY);
  notify();
}
