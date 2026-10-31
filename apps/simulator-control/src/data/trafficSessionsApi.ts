// 0.13.0 — Typed client for the Traffic Generator contract shipped by
// polaris-control-api 0.20.0 (#47).
// 0.13.1 — Adds the per-tick samples endpoint consumed by the live
// sparklines. The ring is bounded at `SAMPLES_RING_MAX = 60` entries
// server-side (polaris-api 0.20.1); the front polls at 1 s so a session
// never streams more than a few bytes per tick to the client.
//
// Rules mirrored from the backend (see
// POLARIS_CONTROL/apps/api/src/traffic_sessions.rs):
//   - rate_mbps ∈ [1, 50]; UDP lossless ceiling = 20 Mbit/s.
//   - duration_s ∈ [1, 600].
//   - direction ∈ UL | DL | BOTH; protocol ∈ TCP | UDP.
//   - START requires an operator role + an active grant covering every
//     UE in `ue_ids` (same gate as scenario start).
//   - STOP is always allowed, even for a viewer re-opening the detail.
//   - iperf3 is a measurement step: `warnings` carries the 0.19.8
//     IPERF3_* codes but never fails the session.

import { polarisApi } from './polarisClient';

export const TRAFFIC_RATE_MBPS_MIN = 1;
export const TRAFFIC_RATE_MBPS_MAX = 50;
export const TRAFFIC_DURATION_S_MIN = 1;
export const TRAFFIC_DURATION_S_MAX = 600;
export const UDP_LOSSLESS_CEILING_MBPS = 20;

export type TrafficDirection = 'UL' | 'DL' | 'BOTH';
export type TrafficProtocol = 'TCP' | 'UDP';
export type TrafficSessionState =
  | 'REQUESTED'
  | 'RUNNING'
  | 'COMPLETED'
  | 'STOPPED'
  | 'FAILED';

export interface TrafficSessionRequest {
  ue_ids: string[];
  direction: TrafficDirection;
  protocol: TrafficProtocol;
  rate_mbps: number;
  duration_s: number;
}

export interface TrafficUeCounters {
  ue_id: string;
  packets_ul: number;
  packets_dl: number;
  bytes_ul: number;
  bytes_dl: number;
  rate_ul_bps: number | null;
  rate_dl_bps: number | null;
  warnings: string[];
}

export interface TrafficSessionSnapshot {
  ue_ids: string[];
  direction: TrafficDirection;
  protocol: TrafficProtocol;
  rate_mbps: number;
  duration_s: number;
}

export interface TrafficSession {
  session_id: string;
  state: TrafficSessionState;
  request: TrafficSessionSnapshot;
  ue_counters: TrafficUeCounters[];
  started_at_epoch_s: number;
  ended_at_epoch_s: number | null;
  warnings: string[];
}

export interface TrafficSessionList {
  items: TrafficSession[];
  total: number;
}

export function startTrafficSession(body: TrafficSessionRequest) {
  return polarisApi<TrafficSession>('/traffic/sessions', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export function fetchTrafficSessions() {
  return polarisApi<TrafficSessionList>('/traffic/sessions');
}

export function fetchTrafficSession(sessionId: string) {
  return polarisApi<TrafficSession>(
    `/traffic/sessions/${encodeURIComponent(sessionId)}`,
  );
}

export function stopTrafficSession(sessionId: string) {
  return polarisApi<TrafficSession>(
    `/traffic/sessions/${encodeURIComponent(sessionId)}`,
    { method: 'DELETE' },
  );
}

// 0.13.1 — per-tick samples feeding the live chart.
export const TRAFFIC_SAMPLES_RING_MAX = 60;

export interface TrafficSample {
  epoch_s: number;
  bytes_ul_cum: number;
  bytes_dl_cum: number;
  rate_ul_bps: number | null;
  rate_dl_bps: number | null;
}

export interface TrafficSamplesResponse {
  items: TrafficSample[];
  session_id: string;
  samples_ring_max: number;
}

export function fetchTrafficSamples(sessionId: string) {
  return polarisApi<TrafficSamplesResponse>(
    `/traffic/sessions/${encodeURIComponent(sessionId)}/samples`,
  );
}

/** Client-side validation that mirrors the backend `validate()`. The
 * form submits only after this returns `null`. */
export function validateTrafficRequest(body: TrafficSessionRequest): string | null {
  if (!body.ue_ids || body.ue_ids.length === 0) return 'TRAFFIC_SESSION_UE_IDS_REQUIRED';
  const re = /^UE-(?:\d{2}|\d{5})$/;
  for (const id of body.ue_ids) {
    if (!re.test(id)) return 'TRAFFIC_SESSION_UE_ID_INVALID';
  }
  if (body.rate_mbps < TRAFFIC_RATE_MBPS_MIN || body.rate_mbps > TRAFFIC_RATE_MBPS_MAX) {
    return 'TRAFFIC_SESSION_RATE_OUT_OF_RANGE';
  }
  if (
    body.duration_s < TRAFFIC_DURATION_S_MIN ||
    body.duration_s > TRAFFIC_DURATION_S_MAX
  ) {
    return 'TRAFFIC_SESSION_DURATION_OUT_OF_RANGE';
  }
  return null;
}
