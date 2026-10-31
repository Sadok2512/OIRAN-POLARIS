// 0.13.0 — validateTrafficRequest contract tests. Mirrors the backend
// test matrix in POLARIS_CONTROL/apps/api/src/traffic_sessions.rs so a
// front refactor cannot drift from the server-side vocabulary.

import { describe, expect, it } from 'vitest';
import {
  TRAFFIC_DURATION_S_MAX,
  TRAFFIC_RATE_MBPS_MAX,
  UDP_LOSSLESS_CEILING_MBPS,
  validateTrafficRequest,
  type TrafficSessionRequest,
} from './trafficSessionsApi';

function req(overrides: Partial<TrafficSessionRequest> = {}): TrafficSessionRequest {
  return {
    ue_ids: ['UE-01', 'UE-02'],
    direction: 'BOTH',
    protocol: 'UDP',
    rate_mbps: 5,
    duration_s: 10,
    ...overrides,
  };
}

describe('validateTrafficRequest', () => {
  it('rejects an empty ue_ids list', () => {
    expect(validateTrafficRequest(req({ ue_ids: [] }))).toBe(
      'TRAFFIC_SESSION_UE_IDS_REQUIRED',
    );
  });

  it('rejects a malformed UE id (must be UE-NN or UE-NNNNN)', () => {
    expect(validateTrafficRequest(req({ ue_ids: ['UE-1'] }))).toBe(
      'TRAFFIC_SESSION_UE_ID_INVALID',
    );
    expect(validateTrafficRequest(req({ ue_ids: ['UE-ABC'] }))).toBe(
      'TRAFFIC_SESSION_UE_ID_INVALID',
    );
  });

  it('accepts both UE-NN and UE-NNNNN', () => {
    expect(validateTrafficRequest(req({ ue_ids: ['UE-07'] }))).toBeNull();
    expect(validateTrafficRequest(req({ ue_ids: ['UE-00042'] }))).toBeNull();
  });

  it('locks the rate window (1 ≤ rate_mbps ≤ 50)', () => {
    expect(validateTrafficRequest(req({ rate_mbps: 0 }))).toBe(
      'TRAFFIC_SESSION_RATE_OUT_OF_RANGE',
    );
    expect(validateTrafficRequest(req({ rate_mbps: 51 }))).toBe(
      'TRAFFIC_SESSION_RATE_OUT_OF_RANGE',
    );
    expect(validateTrafficRequest(req({ rate_mbps: 1 }))).toBeNull();
    expect(validateTrafficRequest(req({ rate_mbps: 50 }))).toBeNull();
  });

  it('locks the duration window (1 ≤ duration_s ≤ 600)', () => {
    expect(validateTrafficRequest(req({ duration_s: 0 }))).toBe(
      'TRAFFIC_SESSION_DURATION_OUT_OF_RANGE',
    );
    expect(validateTrafficRequest(req({ duration_s: 601 }))).toBe(
      'TRAFFIC_SESSION_DURATION_OUT_OF_RANGE',
    );
    expect(validateTrafficRequest(req({ duration_s: 600 }))).toBeNull();
  });

  it('exposes the lab UDP lossless ceiling (20 Mbit/s)', () => {
    expect(UDP_LOSSLESS_CEILING_MBPS).toBe(20);
    expect(TRAFFIC_RATE_MBPS_MAX).toBe(50);
    expect(TRAFFIC_DURATION_S_MAX).toBe(600);
  });
});
