// Local-storage persistence for operator-authored UE profiles.
//
// Why this exists:
//   The POLARIS Rust backend does not yet expose a UE profile CRUD
//   contract (see docs/frontend/SIMULATOR_SCENARIO_BUILDER.md). The spec
//   for Simulator Control calls for 0–10,000 UE profiles with full CRUD
//   + bulk + CSV; we keep that authoritatively in the browser until the
//   backend contract lands. The UI labels this clearly.
//
// Scale note:
//   At 10,000 profiles the serialized JSON stays under ~2 MiB, within
//   localStorage quotas. The UI MUST render pages — never the whole set
//   — so DOM pressure stays bounded.

import { useCallback, useSyncExternalStore } from 'react';
import {
  MAX_PROFILES,
  type UeProfileDraft,
  type UeProfileRecord,
} from './profileModel';

const PROFILE_KEY = 'polaris.ueProfiles.v1';

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

/* --------------------------- Core operations --------------------------- */

export function listProfiles(): UeProfileRecord[] {
  return safeRead<UeProfileRecord[]>(PROFILE_KEY, []);
}

export function getProfile(id: string): UeProfileRecord | null {
  return listProfiles().find((profile) => profile.id === id) ?? null;
}

export class ProfileStoreError extends Error {
  constructor(public code: 'DUPLICATE_ID' | 'QUOTA_EXCEEDED' | 'NOT_FOUND', message: string) {
    super(message);
    this.name = 'ProfileStoreError';
  }
}

export function createProfile(draft: UeProfileDraft): UeProfileRecord {
  const existing = listProfiles();
  if (existing.some((profile) => profile.id === draft.id)) {
    throw new ProfileStoreError(
      'DUPLICATE_ID',
      `A UE profile with id "${draft.id}" already exists.`,
    );
  }
  if (existing.length >= MAX_PROFILES) {
    throw new ProfileStoreError(
      'QUOTA_EXCEEDED',
      `Maximum ${MAX_PROFILES.toLocaleString()} UE profiles reached.`,
    );
  }
  const now = Date.now();
  const record: UeProfileRecord = { ...draft, createdAt: now, updatedAt: now };
  safeWrite(PROFILE_KEY, [...existing, record]);
  notify();
  return record;
}

export function updateProfile(id: string, patch: UeProfileDraft): UeProfileRecord {
  const existing = listProfiles();
  const current = existing.find((profile) => profile.id === id);
  if (!current) {
    throw new ProfileStoreError('NOT_FOUND', `UE profile "${id}" not found.`);
  }
  if (patch.id !== id && existing.some((profile) => profile.id === patch.id)) {
    throw new ProfileStoreError(
      'DUPLICATE_ID',
      `Cannot rename to "${patch.id}" — that id is already in use.`,
    );
  }
  const next: UeProfileRecord = {
    ...current,
    ...patch,
    createdAt: current.createdAt,
    updatedAt: Date.now(),
  };
  const list = existing.map((profile) => (profile.id === id ? next : profile));
  safeWrite(PROFILE_KEY, list);
  notify();
  return next;
}

export function deleteProfiles(ids: string[]): number {
  if (ids.length === 0) return 0;
  const set = new Set(ids);
  const existing = listProfiles();
  const next = existing.filter((profile) => !set.has(profile.id));
  const removed = existing.length - next.length;
  if (removed > 0) {
    safeWrite(PROFILE_KEY, next);
    notify();
  }
  return removed;
}

export function cloneProfile(sourceId: string, newId: string): UeProfileRecord {
  const source = getProfile(sourceId);
  if (!source) {
    throw new ProfileStoreError('NOT_FOUND', `UE profile "${sourceId}" not found.`);
  }
  const draft: UeProfileDraft = {
    id: newId,
    owner: source.owner,
    servingGnb: source.servingGnb,
    imsi: source.imsi,
    plmn: source.plmn,
    apn: source.apn,
    ueIp: '',
    notes: source.notes,
  };
  return createProfile(draft);
}

export function bulkCreateProfiles(drafts: UeProfileDraft[]): {
  created: number;
  skipped: { id: string; reason: string }[];
} {
  const existing = listProfiles();
  const byId = new Map(existing.map((profile) => [profile.id, profile]));
  const skipped: { id: string; reason: string }[] = [];
  const now = Date.now();
  const additions: UeProfileRecord[] = [];
  const remainingSlots = MAX_PROFILES - existing.length;
  if (remainingSlots <= 0) {
    for (const draft of drafts) {
      skipped.push({ id: draft.id, reason: 'Profile quota reached' });
    }
    return { created: 0, skipped };
  }
  for (const draft of drafts) {
    if (byId.has(draft.id)) {
      skipped.push({ id: draft.id, reason: 'id already exists' });
      continue;
    }
    if (additions.length >= remainingSlots) {
      skipped.push({ id: draft.id, reason: 'Profile quota reached' });
      continue;
    }
    const record: UeProfileRecord = { ...draft, createdAt: now, updatedAt: now };
    additions.push(record);
    byId.set(record.id, record);
  }
  if (additions.length > 0) {
    safeWrite(PROFILE_KEY, [...existing, ...additions]);
    notify();
  }
  return { created: additions.length, skipped };
}

/* ------------------------------ Subscribers ------------------------------ */

type Listener = () => void;
const listeners = new Set<Listener>();

// `useSyncExternalStore` requires a stable reference across renders when
// nothing has changed. Keep a module-level cache so React doesn't tear
// at 10k entries.
let snapshotCache: UeProfileRecord[] = listProfiles();

function refreshSnapshot(): void {
  snapshotCache = listProfiles();
}

function notify() {
  refreshSnapshot();
  for (const listener of listeners) listener();
}

function subscribe(listener: Listener): () => void {
  listeners.add(listener);
  const onStorage = (event: StorageEvent) => {
    if (event.key === PROFILE_KEY) {
      refreshSnapshot();
      listener();
    }
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

/* -------------------------- Pagination hook ------------------------------ */

export interface ProfileListOptions {
  search?: string;
  owner?: string;
  servingGnb?: string;
  sortBy?: 'id' | 'owner' | 'servingGnb' | 'updatedAt';
  sortDirection?: 'asc' | 'desc';
  page: number;
  pageSize: number;
}

export interface ProfilePage {
  items: UeProfileRecord[];
  total: number;
  filteredTotal: number;
  page: number;
  pageSize: number;
  pageCount: number;
}

/**
 * React hook exposing the full profile list via useSyncExternalStore.
 * Pagination/filtering is applied in the caller so filters stay reactive
 * without reserializing localStorage on every keystroke.
 */
export function useProfiles(): UeProfileRecord[] {
  const getSnapshot = useCallback(() => snapshotCache, []);
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}

export function paginate(
  profiles: UeProfileRecord[],
  options: ProfileListOptions,
): ProfilePage {
  const total = profiles.length;
  const needle = options.search?.trim().toLowerCase() ?? '';
  const ownerFilter = options.owner?.trim().toLowerCase() ?? '';
  const gnbFilter = options.servingGnb?.trim().toLowerCase() ?? '';

  let filtered = profiles;
  if (needle || ownerFilter || gnbFilter) {
    filtered = profiles.filter((profile) => {
      if (needle) {
        // 0.10.0 — IMSI dropped from the search haystack (identity stays
        // PROTECTED; the UI never surfaces it, so searching by it was a lie).
        const hay = [
          profile.id,
          profile.owner,
          profile.servingGnb,
          profile.ueIp ?? '',
          profile.notes ?? '',
        ]
          .join(' ')
          .toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      if (ownerFilter && profile.owner.toLowerCase() !== ownerFilter) return false;
      if (gnbFilter && profile.servingGnb.toLowerCase() !== gnbFilter) return false;
      return true;
    });
  }

  const sortBy = options.sortBy ?? 'id';
  const direction = options.sortDirection === 'desc' ? -1 : 1;
  const sorted = [...filtered].sort((a, b) => {
    const left = a[sortBy];
    const right = b[sortBy];
    if (typeof left === 'number' && typeof right === 'number') {
      return (left - right) * direction;
    }
    const l = String(left ?? '').toLowerCase();
    const r = String(right ?? '').toLowerCase();
    if (l < r) return -1 * direction;
    if (l > r) return 1 * direction;
    return 0;
  });

  const pageSize = Math.max(1, options.pageSize);
  const pageCount = Math.max(1, Math.ceil(sorted.length / pageSize));
  const page = Math.min(Math.max(1, options.page), pageCount);
  const start = (page - 1) * pageSize;
  const items = sorted.slice(start, start + pageSize);
  return {
    items,
    total,
    filteredTotal: sorted.length,
    page,
    pageSize,
    pageCount,
  };
}

/* ------------------------------ Test helpers ------------------------------ */

export function _resetProfiles(): void {
  if (typeof localStorage !== 'undefined') {
    localStorage.removeItem(PROFILE_KEY);
  }
  notify();
}

export function _seedProfiles(records: UeProfileRecord[]): void {
  if (typeof localStorage !== 'undefined') {
    localStorage.setItem(PROFILE_KEY, JSON.stringify(records));
  }
  notify();
}
