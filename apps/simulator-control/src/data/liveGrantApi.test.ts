// 0.11.1 (#46) — Live grant helpers unit tests.
//
// `pickDisplayGrant` + `formatCountdown` are the two pure helpers
// the UeManager header + Activity page rely on; the dialog itself
// is exercised by the dedicated component test.

import { describe, expect, it } from 'vitest';
import {
  formatCountdown,
  pickDisplayGrant,
  type LiveGrantList,
} from './liveGrantApi';

const NOW = 1_730_000_000_000;

function list(partial: Partial<LiveGrantList>): LiveGrantList {
  return {
    grants: [],
    max_minutes: 60,
    server_now_epoch_ms: NOW.toString(),
    ...partial,
  };
}

describe('pickDisplayGrant', () => {
  it('returns null when the list is empty or missing', () => {
    expect(pickDisplayGrant(undefined)).toBeNull();
    expect(pickDisplayGrant(list({}))).toBeNull();
    expect(
      pickDisplayGrant(list({ grants: undefined as unknown as LiveGrantList['grants'] })),
    ).toBeNull();
  });

  it('ignores revoked and expired entries', () => {
    const picked = pickDisplayGrant(
      list({
        grants: [
          {
            id: 'g-revoked',
            ue_ids: ['UE-02'],
            duration_minutes: 30,
            granted_at_epoch_ms: NOW - 60_000,
            expires_at_epoch_ms: NOW + 60_000,
            granted_by: 'ops',
            revoked: true,
          },
          {
            id: 'g-expired',
            ue_ids: ['UE-02'],
            duration_minutes: 30,
            granted_at_epoch_ms: NOW - 7_200_000,
            expires_at_epoch_ms: NOW - 1_000,
            granted_by: 'ops',
            revoked: false,
          },
        ],
      }),
    );
    expect(picked).toBeNull();
  });

  it('picks the active grant with the farthest expiry', () => {
    const picked = pickDisplayGrant(
      list({
        grants: [
          {
            id: 'g-short',
            ue_ids: ['UE-02'],
            duration_minutes: 15,
            granted_at_epoch_ms: NOW - 60_000,
            expires_at_epoch_ms: NOW + 60_000,
            granted_by: 'ops',
            revoked: false,
          },
          {
            id: 'g-long',
            ue_ids: ['UE-03'],
            duration_minutes: 60,
            granted_at_epoch_ms: NOW - 60_000,
            expires_at_epoch_ms: NOW + 3_600_000,
            granted_by: 'ops',
            revoked: false,
          },
        ],
      }),
    );
    expect(picked?.id).toBe('g-long');
  });
});

describe('formatCountdown', () => {
  it('renders MM:SS down to zero', () => {
    expect(formatCountdown(NOW + 65_000, NOW)).toBe('01:05');
    expect(formatCountdown(NOW + 3_600_000, NOW)).toBe('60:00');
    expect(formatCountdown(NOW, NOW)).toBe('00:00');
  });

  it('clamps negative deltas (expired) to 00:00', () => {
    expect(formatCountdown(NOW - 1_000, NOW)).toBe('00:00');
  });
});
