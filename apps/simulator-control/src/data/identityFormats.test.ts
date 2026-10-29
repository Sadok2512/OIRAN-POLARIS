import { describe, expect, it } from 'vitest';
import {
  isImsiValid,
  isUeIdValid,
  normalizeImsi,
  UE_ID_RE,
} from './identityFormats';

describe('normalizeImsi (0.7.1)', () => {
  it('accepts raw 15-digit IMSI and prefixes it', () => {
    expect(normalizeImsi('001010000000201')).toBe('imsi-001010000000201');
    expect(normalizeImsi('  208930000000001  ')).toBe('imsi-208930000000001');
  });
  it('accepts already-prefixed IMSI unchanged', () => {
    expect(normalizeImsi('imsi-001010000000201')).toBe('imsi-001010000000201');
  });
  it('refuses non-digits and the wrong length', () => {
    expect(normalizeImsi('')).toBeNull();
    expect(normalizeImsi('imsi-123')).toBeNull();
    expect(normalizeImsi('abc')).toBeNull();
    expect(normalizeImsi('001')).toBeNull();
  });
  it('isImsiValid is the public truthy wrapper', () => {
    expect(isImsiValid('001010000000201')).toBe(true);
    expect(isImsiValid('imsi-001010000000201')).toBe(true);
    expect(isImsiValid('nope')).toBe(false);
  });
});

describe('isUeIdValid (0.7.1 — UE-NN or UE-NNNNN)', () => {
  it('accepts the two canonical forms', () => {
    expect(isUeIdValid('UE-01')).toBe(true);
    expect(isUeIdValid('UE-99')).toBe(true);
    expect(isUeIdValid('UE-00100')).toBe(true);
    expect(isUeIdValid('UE-10000')).toBe(true);
  });
  it('refuses out-of-range and malformed ids', () => {
    expect(isUeIdValid('UE-00')).toBe(false);
    expect(isUeIdValid('UE-100')).toBe(false); // 3 digits
    expect(isUeIdValid('UE-10001')).toBe(false);
    expect(isUeIdValid('UE-00099')).toBe(false); // 5 digits but < 100
    expect(isUeIdValid('ue-01')).toBe(false);
    expect(UE_ID_RE.test('UE-123')).toBe(false);
  });
});
