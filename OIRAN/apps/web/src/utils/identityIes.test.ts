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

describe('isIdentityIe', () => {
  it.each(['IMSI', 'imsi', '5G-GUTI', 'c-rnti', 'MaskedIMEISV', 'IMEI', 'TMSI', 'SUPI', 'SUCI', 'MSISDN'])(
    'treats "%s" as an identity IE',
    (name) => {
      expect(isIdentityIe({ name })).toBe(true);
    },
  );

  it.each(['RAN UE NGAP ID', 'AMF UE NGAP ID', 'NAS-PDU', 'UserLocationInformation', 'SecurityKey'])(
    'does NOT withhold "%s" — these are not subscriber identities',
    (name) => {
      expect(isIdentityIe({ name })).toBe(false);
    },
  );
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
