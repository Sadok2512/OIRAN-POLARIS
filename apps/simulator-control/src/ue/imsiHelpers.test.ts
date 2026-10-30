// 0.10.3 — IMSI helper tests.
//
// Why this file exists: 0.10.2 shipped the Create / Edit prefill with a
// hard-coded 999 prefix. The Open5GS lab serves MCC 001 / MNC 01, so a
// subscriber created with 99901… IMSI simply did not register. Every
// case below pins the honest behaviour: production uses the real PLMN
// pulled from /plmns (fallback 001-01), and 999… stays strictly in
// test fixtures.

import { describe, expect, it } from 'vitest';
import {
  DEFAULT_LAB_PLMN,
  FICTIVE_IMSI_PREFIX_FOR_TESTS,
  imsiPrefixFromPlmn,
  isLabFictiveImsi,
  nextFreeImsiFor,
  parsePlmnString,
} from './imsiHelpers';

describe('imsiHelpers (0.10.3)', () => {
  it('defaults to the real lab PLMN (001-01), never the fictive 999 prefix', () => {
    expect(DEFAULT_LAB_PLMN).toEqual({ mcc: '001', mnc: '01' });
    expect(imsiPrefixFromPlmn(DEFAULT_LAB_PLMN)).toBe('00101');
    const generated = nextFreeImsiFor('UE-07', DEFAULT_LAB_PLMN);
    expect(generated).toBe('imsi-001010000000007');
    // Explicit anti-regression: must NOT lead with the 999 prefix.
    expect(generated).not.toMatch(/^imsi-99901/);
  });

  it('parses the deployed /plmns string shape "MCC-MNC"', () => {
    expect(parsePlmnString('001-01')).toEqual({ mcc: '001', mnc: '01' });
    expect(parsePlmnString('208-10')).toEqual({ mcc: '208', mnc: '10' });
    expect(parsePlmnString('999-01')).toEqual({ mcc: '999', mnc: '01' });
    expect(parsePlmnString('bogus')).toBeNull();
    expect(parsePlmnString('')).toBeNull();
    expect(parsePlmnString(null)).toBeNull();
  });

  it('derives the IMSI from the UE id and the provided PLMN', () => {
    expect(nextFreeImsiFor('UE-01', { mcc: '001', mnc: '01' })).toBe('imsi-001010000000001');
    expect(nextFreeImsiFor('UE-99', { mcc: '001', mnc: '01' })).toBe('imsi-001010000000099');
    // 3-digit MNC → MSIN shrinks to 9 digits so the IMSI stays 15 wide.
    expect(nextFreeImsiFor('UE-07', { mcc: '208', mnc: '100' })).toBe('imsi-208100000000007');
    // Garbage ids return null — callers fall back to empty field.
    expect(nextFreeImsiFor('not-a-ue', DEFAULT_LAB_PLMN)).toBeNull();
    expect(nextFreeImsiFor('UE-00000', DEFAULT_LAB_PLMN)).toBeNull();
  });

  it('keeps the 999 prefix strictly for test fixtures', () => {
    expect(FICTIVE_IMSI_PREFIX_FOR_TESTS).toBe('99901');
    expect(isLabFictiveImsi('imsi-999010000000007')).toBe(true);
    expect(isLabFictiveImsi('999010000000007')).toBe(true);
    // Real lab IMSIs must never flag as fictive.
    expect(isLabFictiveImsi('imsi-001010000000007')).toBe(false);
    expect(isLabFictiveImsi(null)).toBe(false);
    expect(isLabFictiveImsi('')).toBe(false);
  });
});
