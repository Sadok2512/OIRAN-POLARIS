// Pure helpers that translate the backend-reported `probe_state` /
// `online` / `last_heartbeat_epoch_s` triplet into something the UI can
// render honestly.
//
// Scope:
//   * `PENDING | ONLINE | DEGRADED` is the new vocabulary Codex is
//     migrating the backend to. The legacy string `PROBE_ONLINE` still
//     comes through today and is accepted as-is.
//   * `online = true` without a heartbeat is treated as PENDING, not
//     ONLINE — the UI never promotes "backend-reports-online" to a live
//     signal unless a heartbeat has actually been observed.
//   * `last_heartbeat_epoch_s = null` means the backend has never seen a
//     heartbeat; the UI must display "Awaiting heartbeat" (never now()).

import type { Probe } from '@shared/types';

export type ProbeLifecycle = 'PENDING' | 'ONLINE' | 'DEGRADED';

/** Resolve the normalised lifecycle state for a probe. */
export function probeLifecycle(probe: Probe): ProbeLifecycle {
  const explicit = probe.probe_state?.toUpperCase();
  if (explicit === 'PENDING') return 'PENDING';
  if (explicit === 'DEGRADED') return 'DEGRADED';
  if (explicit === 'ONLINE' || explicit === 'PROBE_ONLINE') return 'ONLINE';
  // Fallback: if the backend didn't send a lifecycle field, derive it
  // from online + heartbeat without inventing anything.
  if (probe.last_heartbeat_epoch_s == null) return 'PENDING';
  return probe.online ? 'ONLINE' : 'DEGRADED';
}

/** Tone key for StatusIndicator per lifecycle. */
export function probeLifecycleTone(
  lifecycle: ProbeLifecycle,
): 'success' | 'warning' | 'neutral' {
  switch (lifecycle) {
    case 'ONLINE':
      return 'success';
    case 'DEGRADED':
      return 'warning';
    case 'PENDING':
      return 'neutral';
  }
}

/**
 * Format the last-heartbeat timestamp honestly:
 *   null  → "Awaiting heartbeat" (never a now() stand-in)
 *   epoch → absolute local time + relative age ("3 s ago")
 */
export function formatHeartbeat(
  epochSeconds: number | null | undefined,
  nowMs: number = Date.now(),
): string {
  if (epochSeconds == null) return 'Awaiting heartbeat';
  const stamp = new Date(epochSeconds * 1000);
  if (Number.isNaN(stamp.getTime())) return 'Awaiting heartbeat';
  const ageSeconds = Math.max(0, Math.floor(nowMs / 1000 - epochSeconds));
  const relative =
    ageSeconds < 2
      ? 'just now'
      : ageSeconds < 60
        ? `${ageSeconds} s ago`
        : ageSeconds < 3600
          ? `${Math.round(ageSeconds / 60)} min ago`
          : `${Math.round(ageSeconds / 3600)} h ago`;
  return `${stamp.toLocaleString()} · ${relative}`;
}
