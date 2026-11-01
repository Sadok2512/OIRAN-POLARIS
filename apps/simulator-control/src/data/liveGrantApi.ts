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
  revoked: boolean;
}

export interface LiveGrantList {
  grants: LiveGrant[];
  lte_grants?: LteGrantV2[];
  max_minutes: number;
  server_now_epoch_ms: string;
}

export interface LteGrantV2 {
  schema_version: 'polaris.live-grant.v2';
  purpose: 'CERTIFICATION_RUN' | 'LIVE_OPERATIONAL';
  grant_id: string;
  state: 'ISSUED' | 'CONSUMED' | 'REVOKED' | 'EXPIRED' | 'REVOKED_RESTART' | 'RECOVERY_ONLY';
  expires_at_epoch_ms: number;
  run_id?: string | null;
}

export interface LteRun {
  run_id: string;
  grant_id: string;
  profile_id: 'LTE-SRSUE-TEST-01';
  state: string;
  deadline_at_epoch_ms: number;
  evidence_url: string;
  final_state?: 'COMPLETED' | 'FAILED' | 'CANCELLED' | 'RECOVERY_BLOCKED' | null;
  cleanup_required?: boolean;
  cancel_requested?: boolean;
  steps?: Array<{ index: number; type: string; state: string; reason_code: string | null }>;
}

export interface LteGrantProfileBinding {
  purpose: 'CERTIFICATION_RUN' | 'LIVE_OPERATIONAL';
  revision: number;
  configuration_sha256: string;
  compose_model_sha256: string;
  scenario_id: 'lte-e2e-certification-v1';
  scenario_revision: 1;
  scenario_sha256: string;
}

export interface LtePreparedAuthorization {
  grant: LteGrantV2;
  executionNonce: string;
}

export interface LteTemporaryActivation {
  profile_id: 'LTE-SRSUE-TEST-01';
  state: 'TEMPORARILY_ENABLED';
  grant_id: string;
  expires_at_epoch_ms: number;
  remaining_seconds: number;
  idempotent: boolean;
}

function randomToken(bytes: number): string {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  let binary = '';
  value.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function createLteGrant(profile: LteGrantProfileBinding): Promise<LtePreparedAuthorization> {
  const executionNonce = randomToken(32);
  const grant = await polarisApi<LteGrantV2>('/live/grant', {
    method: 'POST',
    headers: { 'Idempotency-Key': crypto.randomUUID() },
    body: JSON.stringify({
      schema_version: 'polaris.live-grant.v2',
      purpose: profile.purpose,
      target: {
        kind: 'srsran_lte_profile',
        profile_id: 'LTE-SRSUE-TEST-01',
        profile_revision: profile.revision,
        configuration_sha256: profile.configuration_sha256,
        compose_model_sha256: profile.compose_model_sha256,
      },
      scenario: {
        scenario_id: profile.scenario_id,
        scenario_revision: profile.scenario_revision,
        scenario_sha256: profile.scenario_sha256,
      },
      duration_seconds: 300,
      constraints: {
        max_ues: 1,
        allowed_actions: ['s1_setup', 'lte_attach', 'ping_ul', 'ping_dl', 'udp_ul', 'udp_dl', 'cleanup'],
        ping: { max_packets_per_direction: 5 },
        udp: {
          max_rate_bps_per_direction: 1_000_000,
          max_duration_seconds_per_direction: 10,
          max_payload_bytes: 1_200,
          max_parallel_streams: 1,
        },
        hard_deadline_behavior: 'STOP_TRAFFIC_AND_CLEANUP',
      },
      execution_nonce: executionNonce,
    }),
  });
  return { grant, executionNonce };
}

export function usePrepareLteCertificationGrant() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: createLteGrant,
    onSettled: async () => {
      await client.invalidateQueries({ queryKey: ['polaris', 'live-grants'] });
    },
  });
}

export function useActivateLteCertification() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ authorization }: { authorization: LtePreparedAuthorization }) =>
      polarisApi<LteTemporaryActivation>('/lte/profiles/LTE-SRSUE-TEST-01/certification-activation', {
        method: 'POST',
        headers: {
          'Idempotency-Key': crypto.randomUUID(),
          'X-Polaris-Grant-Nonce': authorization.executionNonce,
        },
        body: JSON.stringify({ grant_id: authorization.grant.grant_id }),
      }),
    onSettled: async () => {
      await client.invalidateQueries({ queryKey: ['polaris', 'live-grants'] });
      await client.invalidateQueries({ queryKey: ['polaris', 'lte-profile', 'LTE-SRSUE-TEST-01'] });
      await client.invalidateQueries({ queryKey: ['polaris', 'lte-status'] });
    },
  });
}

export function useStartLteCertifiedRun() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async ({
      profile,
      authorization,
    }: {
      profile: LteGrantProfileBinding;
      authorization?: LtePreparedAuthorization;
    }) => {
      const prepared = authorization ?? await createLteGrant(profile);
      return polarisApi<LteRun>('/lte/runs', {
        method: 'POST',
        headers: {
          'Idempotency-Key': crypto.randomUUID(),
          'X-Polaris-Grant-Nonce': prepared.executionNonce,
        },
        body: JSON.stringify({
          grant_id: prepared.grant.grant_id,
          profile_id: 'LTE-SRSUE-TEST-01',
          profile_revision: profile.revision,
          configuration_sha256: profile.configuration_sha256,
          compose_model_sha256: profile.compose_model_sha256,
          scenario_id: profile.scenario_id,
          scenario_revision: profile.scenario_revision,
          scenario_sha256: profile.scenario_sha256,
        }),
      });
    },
    onSettled: async () => {
      await client.invalidateQueries({ queryKey: ['polaris', 'live-grants'] });
      await client.invalidateQueries({ queryKey: ['polaris', 'lte-status'] });
    },
  });
}

export function useLteRun(runId: string | undefined) {
  return useQuery({
    queryKey: ['polaris', 'lte-run', runId],
    queryFn: () => polarisApi<LteRun>(`/lte/runs/${encodeURIComponent(runId!)}`),
    enabled: Boolean(runId),
    refetchInterval: (query) => query.state.data?.state === 'CLEAN' ? false : 1_000,
    retry: false,
  });
}

export function useEmergencyStopLteRun() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (runId: string) => polarisApi<LteRun>(
      `/lte/runs/${encodeURIComponent(runId)}/emergency-stop`,
      { method: 'POST', body: JSON.stringify({}) },
    ),
    onSettled: async (_data, _error, runId) => {
      await client.invalidateQueries({ queryKey: ['polaris', 'lte-run', runId] });
      await client.invalidateQueries({ queryKey: ['polaris', 'lte-status'] });
      await client.invalidateQueries({ queryKey: ['polaris', 'live-grants'] });
    },
  });
}

export interface LiveGrantRequest {
  ue_ids: string[];
  duration_minutes: number;
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
        body: JSON.stringify(input),
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
