// Minimal client-side feature-flag store.
//
// Flags live in localStorage so an operator can opt in / out from the
// Settings page without a redeploy. API-backed scenarios and templates are
// enabled by default for the deployed API 0.13 contract; each remains
// independently reversible from Settings.

import { useCallback, useSyncExternalStore } from 'react';

const LEGACY_FLAGS_KEY = 'polaris.featureFlags.v1';
const FLAGS_KEY = 'polaris.featureFlags.v2';

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
  /**
   * 0.5.0 — When true, the UI calls the new scenario templates surface:
   *   GET  /scenario-definitions                     (tpl-* appear in the list)
   *   GET  /scenario-definitions/:id/estimate        → { duration_ms }
   *   GET  /scenario-definitions/:id/export          → attachment JSON v2
   *   POST /scenario-definitions/import              operator + CSRF
   * When false, the Templates tab shows a "Backend pending" placeholder
   * and no network call is issued. Default OFF until Codex pushes
   * `feat/polaris-traffic-templates`.
   */
  scenarioTemplates: boolean;
  /**
   * 0.6.0 — When true, the UI calls the richer provisioning surface
   * published by Codex on `feat/polaris-provisioning`:
   *   GET  /owners                                   → owner directory
   *   GET  /plmns                                    → allowed PLMNs
   *   GET  /dnns                                     → allowed DNNs
   *   POST /provisioning/import  (CSV, up to 100k rows)
   *   POST /ue-profiles/import   (CSV, up to 100k rows)
   *   GET  /ue-profiles/:ue_id                       → detail card body
   * When false, the Provisioning page shows "Backend pending" and
   * dropdowns fall back to free-text + warning text. profileBackend is
   * also forced ON (local UE form path becomes unreachable from the UI).
   * Default OFF until the backend branch is deployed.
   */
  polarisProvisioning: boolean;
}

// 0.5.1 — `scenarioBackend` defaults to ON so the honest Scenario Builder
// (certified-only palette + fixed-loop presets) is what the operator sees
// out of the box. Operators who want to draft against the local catalog
// toggle the flag off in Settings; the UI then clearly labels this as
// "offline draft" and reminds them that nothing will reach the backend.
const DEFAULTS: FeatureFlags = {
  scenarioBackend: true,
  profileBackend: true,
  scenarioTemplates: true,
  polarisProvisioning: true,
};

function read(): FeatureFlags {
  // 0.18.0 — operational builds are backend-only. Older releases allowed
  // localStorage to switch UE/scenario pages to browser fixtures. Keeping the
  // keys only lets us remove stale preferences without ever trusting them.
  if (import.meta.env.MODE === 'test' && typeof localStorage !== 'undefined') {
    try {
      const raw = localStorage.getItem(FLAGS_KEY);
      if (raw) return { ...DEFAULTS, ...(JSON.parse(raw) as Partial<FeatureFlags>) };
      if (localStorage.getItem(LEGACY_FLAGS_KEY) !== null) {
        localStorage.setItem(FLAGS_KEY, JSON.stringify(DEFAULTS));
      }
      return DEFAULTS;
    } catch {
      return DEFAULTS;
    }
  }
  if (typeof localStorage !== 'undefined') {
    localStorage.removeItem(FLAGS_KEY);
    localStorage.removeItem(LEGACY_FLAGS_KEY);
  }
  return DEFAULTS;
}

function write(flags: FeatureFlags): void {
  if (import.meta.env.MODE === 'test' && typeof localStorage !== 'undefined') {
    localStorage.setItem(FLAGS_KEY, JSON.stringify(flags));
  }
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
  // Kept as a source-compatible no-op for old components/tests. Real-lab
  // mode cannot be downgraded to a browser-local catalogue.
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
  if (typeof localStorage !== 'undefined') {
    localStorage.removeItem(FLAGS_KEY);
    localStorage.removeItem(LEGACY_FLAGS_KEY);
  }
  notify();
}
