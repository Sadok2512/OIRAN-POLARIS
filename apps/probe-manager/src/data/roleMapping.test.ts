import { describe, expect, it } from 'vitest';
import { bpfForRole, roleFor } from './roleMapping';

describe('roleFor', () => {
  it('reads an explicit capture_point first', () => {
    expect(roleFor({ capture_point: 'N2' })).toBe('N2');
    expect(roleFor({ capture_point: 'n4' })).toBe('N4');
    expect(roleFor({ capture_point: 'S1' })).toBe('S1');
  });

  it('maps the 4 certified protocols when capture_point is absent', () => {
    expect(roleFor({ protocol: 'NGAP' })).toBe('N2');
    expect(roleFor({ protocol: 'GTP-U' })).toBe('N3');
    expect(roleFor({ protocol: 'gtp' })).toBe('N3');
    expect(roleFor({ protocol: 'PFCP' })).toBe('N4');
    expect(roleFor({ protocol: 'S1AP' })).toBe('S1');
  });

  it('returns null when neither field is deterministic (UI must render "—")', () => {
    expect(roleFor({})).toBeNull();
    expect(roleFor({ protocol: 'SBI' })).toBeNull();
    expect(roleFor({ protocol: 'HTTP2', capture_point: 'MGMT' })).toBeNull();
  });
});

describe('bpfForRole', () => {
  it('uses 3GPP standard ports — not probe-reported values', () => {
    expect(bpfForRole('N2')).toBe('sctp port 38412');
    expect(bpfForRole('N3')).toBe('udp port 2152');
    expect(bpfForRole('N4')).toBe('udp port 8805');
    expect(bpfForRole('S1')).toBe('sctp port 36412');
    expect(bpfForRole(null)).toBe('');
  });
});
