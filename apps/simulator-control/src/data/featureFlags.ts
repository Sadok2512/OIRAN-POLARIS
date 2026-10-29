// Minimal client-side feature-flag store.
//
// Flags live in localStorage so an operator can opt in / out from the
// Settings page without a redeploy. API-backed scenarios and templates are
// enabled by default for the deployed API 0.13 contract; each remains
// independently reversible from Settings.

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
   * 0.6.0 — When true, the UI calls the richer provisioning surface:
   *   GET  /owners                                   → owner directory
   *   GET  /plmns                                    → allowed PLMNs
   *   GET  /dnns                                     → allowed DNNs
   *   POST /provisioning/import  (CSV, up to 100k rows)
   *   POST /ue-profiles/import   (CSV, up to 100k rows)
   *   GET  /ue-profiles/:ue_id                       → detail card body
   * When false, the Provisioning page falls back to the pre-0.6 flow.
   * If a required endpoint is genuinely unavailable at runtime, the
   * page surfaces the exact backend error (code + message) rather than
   * hiding it behind a "backend pending" placeholder.
   */
  polarisProvisioning: boolean;
}

// 0.5.1 — `scenarioBackend` defaults to ON so the honest Scenario Builder
// (certified-only palette + fixed-loop presets) is what the operator sees
// out of the box. Operators who want to draft against the local catalog
// toggle the flag off in Settings; the UI then clearly labels this as
// "offline draft" and reminds them that nothing will reach the backend.
// 0.9.2 — `polarisProvisioning` flips to ON by default (polaris-control-api
// 0.17.0 is deployed). See `read()` below for the one-shot migration that
// upgrades legacy localStorage shapes.
const DEFAULTS: FeatureFlags = {
  scenarioBackend: true,
  profileBackend: false,
  scenarioTemplates: true,
  polarisProvisioning: true,
};

/** Schema version persisted alongside the flags so we can tell apart
 * "operator explicitly disabled this flag" from "stored OFF because the
 * old default was OFF". Bumped to 2 in 0.9.2 to force-migrate
 * `polarisProvisioning` from the 0.6.0-era default. */
const SCHEMA_VERSION = 2;

interface StoredShape extends Partial<FeatureFlags> {
  _v?: number;
}

/** Apply the 0.9.2 migration to a parsed localStorage payload.
 *
 * The only field migrated here is `polarisProvisioning`: a stored `false`
 * that came from the 0.6.0-era default (no `_v` key, or `_v < 2`) is
 * promoted to `true` because the backend (polaris-control-api 0.17.0) is
 * now deployed. A `_v >= 2` payload is trusted verbatim — an operator who
 * explicitly turned the flag off keeps it off. */
export function migrateStoredFlags(parsed: StoredShape): FeatureFlags {
  const version = typeof parsed._v === 'number' ? parsed._v : 1;
  const migrated: StoredShape = { ...parsed };
  if (version < 2 && migrated.polarisProvisioning === false) {
    migrated.polarisProvisioning = true;
  }
  const { _v: _ignored, ...flags } = migrated;
  return { ...DEFAULTS, ...flags };
}

function read(): FeatureFlags {
  if (typeof localStorage === 'undefined') return DEFAULTS;
  try {
    const raw = localStorage.getItem(FLAGS_KEY);
    if (!raw) return DEFAULTS;
    const parsed = JSON.parse(raw) as StoredShape;
    return migrateStoredFlags(parsed);
  } catch {
    return DEFAULTS;
  }
}

function write(flags: FeatureFlags): void {
  if (typeof localStorage === 'undefined') return;
  const payload: StoredShape = { ...flags, _v: SCHEMA_VERSION };
  localStorage.setItem(FLAGS_KEY, JSON.stringify(payload));
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
