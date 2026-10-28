import { describe, expect, it } from 'vitest';
import type { Probe } from '@shared/types';
import { formatHeartbeat, probeLifecycle, probeLifecycleTone } from './probeState';

function probe(partial: Partial<Probe>): Probe {
  return {
    probe_id: 'p',
    name: 'p',
    host: 'h',
    probe_type: 'Virtual',
    version: '0',
    health: 'ONLINE',
    online: true,
    connected_interfaces: [],
    capture_state: 'IDLE',
    packet_rate_pps: null,
    decode_rate_eps: null,
    packet_drops: null,
    cpu_usage_percent: null,
    memory_usage_bytes: null,
    disk_usage_percent: null,
    historical_packet_count: 0,
    telemetry_status: 'IDLE',
    distributed: false,
    ...partial,
  };
}

describe('probeLifecycle', () => {
  it('returns PENDING when the backend sends no state and no heartbeat', () => {
    expect(probeLifecycle(probe({ probe_state: undefined, online: true, last_heartbeat_epoch_s: null }))).toBe('PENDING');
    expect(probeLifecycle(probe({ probe_state: undefined, online: false, last_heartbeat_epoch_s: null }))).toBe('PENDING');
  });

  it('respects an explicit backend lifecycle', () => {
    expect(probeLifecycle(probe({ probe_state: 'PENDING' }))).toBe('PENDING');
    expect(probeLifecycle(probe({ probe_state: 'DEGRADED' }))).toBe('DEGRADED');
    expect(probeLifecycle(probe({ probe_state: 'ONLINE', last_heartbeat_epoch_s: 1 }))).toBe('ONLINE');
    // Legacy wire value from the pre-0.3.0 backend is accepted.
    expect(probeLifecycle(probe({ probe_state: 'PROBE_ONLINE', last_heartbeat_epoch_s: 1 }))).toBe('ONLINE');
  });

  it('derives DEGRADED when a heartbeat exists but online is false', () => {
    expect(probeLifecycle(probe({ probe_state: undefined, online: false, last_heartbeat_epoch_s: 1 }))).toBe('DEGRADED');
  });

  it('never promotes a probe to ONLINE without a heartbeat', () => {
    expect(probeLifecycle(probe({ probe_state: undefined, online: true, last_heartbeat_epoch_s: null }))).toBe('PENDING');
    expect(probeLifecycle(probe({ probe_state: undefined, online: true, last_heartbeat_epoch_s: undefined }))).toBe('PENDING');
  });
});

describe('probeLifecycleTone', () => {
  it('maps PENDING → neutral, ONLINE → success, DEGRADED → warning', () => {
    expect(probeLifecycleTone('PENDING')).toBe('neutral');
    expect(probeLifecycleTone('ONLINE')).toBe('success');
    expect(probeLifecycleTone('DEGRADED')).toBe('warning');
  });
});

describe('formatHeartbeat', () => {
  it('returns "Awaiting heartbeat" when the backend sent no epoch', () => {
    expect(formatHeartbeat(null)).toBe('Awaiting heartbeat');
    expect(formatHeartbeat(undefined)).toBe('Awaiting heartbeat');
  });

  it('formats a recent heartbeat with absolute + relative time', () => {
    const now = 1_793_000_000_000;
    const label = formatHeartbeat(now / 1000 - 5, now);
    expect(label).toMatch(/5 s ago$/);
  });

  it('uses minute granularity after 60 s', () => {
    const now = 1_793_000_000_000;
    expect(formatHeartbeat(now / 1000 - 300, now)).toMatch(/5 min ago$/);
  });
});
