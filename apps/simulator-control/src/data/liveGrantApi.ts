// 0.11.1 (#46) — Client for the backend's /live/grant surface.
//
// Three routes:
//   * GET    /polaris-api/v1/live/grant       — list active grants
//   * POST   /polaris-api/v1/live/grant       — create a grant
//   * DELETE /polaris-api/v1/live/grant/:id   — revoke a grant
//
// Grants carry a bounded TTL (max 60 min, enforced server-side).
// The UI shows a live countdown as long as at least one unexpired,
// non-revoked grant is in the list.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { polarisApi } from './polarisClient';

export interface LiveGrant {
  id: string;
  ue_ids: string[];
  duration_minutes: number;
  granted_at_epoch_ms: number;
  expires_at_epoch_ms: number;
  granted_by: string;
  granted_to?: string;
  revoked: boolean;
}

export interface LiveGrantList {
  grants: LiveGrant[];
  max_minutes: number;
  server_now_epoch_ms: string;
}

export interface LiveGrantRequest {
  ue_ids: string[];
  duration_minutes: number;
}

function grantNonce(): string {
  if (typeof globalThis.crypto?.randomUUID === 'function') return globalThis.crypto.randomUUID();
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

export function useLiveGrants() {
  return useQuery({
    queryKey: ['polaris', 'live-grants'],
    queryFn: () => polarisApi<LiveGrantList>('/live/grant'),
    refetchInterval: 10_000,
    staleTime: 5_000,
    retry: false,
  });
}

export function useCreateLiveGrant() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (input: LiveGrantRequest) =>
      polarisApi<LiveGrant>('/live/grant', {
        method: 'POST',
        body: JSON.stringify({ ...input, request_nonce: grantNonce() }),
      }),
    onSettled: () => {
      void client.invalidateQueries({ queryKey: ['polaris', 'live-grants'] });
    },
  });
}

export function useRevokeLiveGrant() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      polarisApi<{ id: string; revoked: boolean }>(
        `/live/grant/${encodeURIComponent(id)}`,
        { method: 'DELETE' },
      ),
    onSettled: () => {
      void client.invalidateQueries({ queryKey: ['polaris', 'live-grants'] });
    },
  });
}

/**
 * 0.11.1 — Return the latest active (non-revoked, non-expired) grant
 * from a `/live/grant` response. The frontend header shows ONE
 * countdown at a time; when multiple grants coexist we display the
 * farthest expiry so the operator sees the longest-remaining window.
 */
export function pickDisplayGrant(list: LiveGrantList | undefined): LiveGrant | null {
  if (!list) return null;
  // Defensive: the mocked /live/grant backends during tests return an
  // empty JSON body; `grants` is undefined there. Treat it as "no
  // active grant" rather than crashing the countdown chip.
  const grants = Array.isArray(list.grants) ? list.grants : [];
  const now = Number(list.server_now_epoch_ms) || Date.now();
  const active = grants.filter(
    (grant) => !grant.revoked && grant.expires_at_epoch_ms > now,
  );
  if (active.length === 0) return null;
  return active.reduce((prev, candidate) =>
    candidate.expires_at_epoch_ms > prev.expires_at_epoch_ms ? candidate : prev,
  );
}

/**
 * 0.11.1 — Human-readable "MM:SS" countdown from an epoch-ms expiry.
 * Returns `"00:00"` once the grant has expired.
 */
export function formatCountdown(expiresAtEpochMs: number, nowEpochMs: number): string {
  const remainingMs = Math.max(0, expiresAtEpochMs - nowEpochMs);
  const totalSeconds = Math.floor(remainingMs / 1_000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
}
