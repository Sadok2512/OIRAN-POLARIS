import { describe, expect, it } from 'vitest';
import type { InformationElement } from '../types/api';
import { isIdentityIe, withholdIdentity } from './identityIes';

function ie(name: string, children?: InformationElement[]): InformationElement {
  return {
    name,
    length: 0,
    value: 'x',
    raw_sha256: null,
    status: 'DECODED',
    ...(children ? { children } : {}),
  } as InformationElement;
}

describe('isIdentityIe (2.4.1 — CONTAINS semantics on decoder-sourced names)', () => {
  // Names below are the exact strings produced today by the OIRAN
  // decoders (decoder-ngap, decoder-nas, …). The list intentionally
  // covers the historical BC4 leaks: 5GS mobile identity on registration,
  // 5G-S-TMSI in NGAP, MaskedIMEISV in InitialContextSetup.
  it.each([
    // Decoder output: exact strings from decoder-nas / decoder-ngap.
    '5GS mobile identity',
    'nas-5gs-mobile-identity',
    'NAS_5GS_Mobile_Identity',
    'FiveG-S-TMSI',
    'five_g_s_tmsi',
    '5G-S-TMSI',
    'MaskedIMEISV',
    'Masked-IMEISV',
    'IMEISV',
    'IMEI',
    'IMSI',
    'imsi',
    'IMSISV',
    'TMSI',
    'M-TMSI',
    'P-TMSI',
    'S-TMSI',
    'GUTI',
    '5G-GUTI',
    '5g_guti',
    'SUPI',
    'suci',
    'SUCI',
    'MSISDN',
    'PEI',
    // Historical normalised exact names kept for backward compatibility.
    'RNTI',
    'c-rnti',
  ])('treats "%s" as an identity IE', (name) => {
    expect(isIdentityIe({ name })).toBe(true);
  });

  it.each([
    // *-NGAP-ID is a transport-layer handle, not a subscriber identity.
    'RAN UE NGAP ID',
    'AMF UE NGAP ID',
    'ran_ue_ngap_id',
    'amf_ue_ngap_id',
    // Pseudonyms are safe by construction — the backend already withheld
    // the real UE identity before publishing the pseudonym.
    'ue_identity_pseudonym',
    'UE Identity Pseudonym',
    // Common NGAP / NAS fields that must remain visible to the operator.
    'NAS-PDU',
    'UserLocationInformation',
    'SecurityKey',
    'AllowedNSSAI',
    'GUAMI',
    'RRCEstablishmentCause',
    'UEContextRequest',
  ])('does NOT withhold "%s" — these are not subscriber identities', (name) => {
    expect(isIdentityIe({ name })).toBe(false);
  });
});

describe('withholdIdentity', () => {
  it('returns an empty result for an empty tree', () => {
    expect(withholdIdentity([])).toEqual({ tree: [], withheldCount: 0 });
    expect(withholdIdentity(undefined)).toEqual({ tree: [], withheldCount: 0 });
  });

  it('removes an identity IE from the top level and counts it', () => {
    const input = [ie('RAN UE NGAP ID'), ie('IMSI'), ie('NAS-PDU')];
    const result = withholdIdentity(input);
    expect(result.tree.map((node) => node.name)).toEqual(['RAN UE NGAP ID', 'NAS-PDU']);
    expect(result.withheldCount).toBe(1);
  });

  it('removes a nested identity IE deep in the tree', () => {
    const input = [
      ie('OuterIE', [ie('ChildOk'), ie('IMEI')]),
      ie('Another', [ie('Nested', [ie('5G-GUTI')])]),
    ];
    const result = withholdIdentity(input);
    expect(result.withheldCount).toBe(2);
    const outer = result.tree.find((n) => n.name === 'OuterIE')!;
    expect(outer.children?.map((c) => c.name)).toEqual(['ChildOk']);
    const another = result.tree.find((n) => n.name === 'Another')!;
    expect(another.children?.[0].children ?? []).toEqual([]);
  });

  it('counts every identity child when the identity parent is dropped', () => {
    // A parent "GUTI" that itself carries sub-IEs (MCC, MNC, GUAMI, etc.):
    // removing the parent must count the parent AND every nested child.
    const input = [
      ie('GUTI', [ie('mcc'), ie('mnc'), ie('amf_region'), ie('M-TMSI')]),
    ];
    const result = withholdIdentity(input);
    expect(result.tree).toEqual([]);
    expect(result.withheldCount).toBe(5); // parent + 4 children
  });
});
