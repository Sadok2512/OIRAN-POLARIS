// Identity-IE withholding — LOT 3 / docs/ui-mockups/oiran-analyzer.html.
//
// Mobile subscriber / equipment identities must never be displayed to an
// Analyzer operator. The backend already pseudonymises most of them in the
// decoded tree, but the UI still has to filter the few that come through
// with a raw value and tell the operator how many were hidden. This file
// holds only pure helpers so the behaviour is testable without rendering.

import type { InformationElement } from '../types/api';

// Normalise a decoded IE name: lowercase, strip every character that is
// not a letter or digit. This collapses "5GS mobile identity",
// "5gs_mobile_identity", "5gs-mobile-identity", "nas-5GS-Mobile-Identity"
// into the same key so a single rule catches every decoder variant.
function normalize(value: string): string {
  return value.replace(/[^a-z0-9]+/gi, '').toLowerCase();
}

// 2.4.0 EXACT-match set. Kept intact so the previous contract is not
// relaxed by the new contains-matcher below.
const EXACT_IDENTITY_NAMES = new Set(
  ['RNTI', 'C-RNTI', 'MSISDN', 'PEI'].map(normalize),
);

// 2.4.1 CONTAINS-match fragments. Any decoded IE whose normalised name
// contains one of these fragments is withheld. Rationale:
//   * MOBILEIDENTITY → "5GS mobile identity", "nas-5gs-mobile-identity"
//   * IMSI          → "IMSI", "IMSISV"
//   * IMEI          → "IMEI", "IMEISV", "MASKED-IMEISV", "MaskedIMEISV"
//   * TMSI          → "TMSI", "M-TMSI", "P-TMSI", "S-TMSI", "5G-S-TMSI",
//                      "FiveG-S-TMSI", "five_g_s_tmsi"
//   * GUTI          → "GUTI", "5G-GUTI"
//   * SUPI, SUCI    → the names themselves
//   * MSISDN        → kept as exact + contains to catch "MSISDN sent"
// None of these fragments appear in `*-NGAP-ID` ("ranuengapid",
// "amfuengapid") or in `ue_identity_pseudonym` ("ueidentitypseudonym"),
// which stay in the tree (they are NOT subscriber identities).
const CONTAINS_IDENTITY_FRAGMENTS: readonly string[] = [
  'mobileidentity',
  'imsi',
  'imei',
  'tmsi',
  'guti',
  'supi',
  'suci',
  'msisdn',
];

// 2.4.1 EQUAL match (3-letter codes that would false-positive if used as
// substring — kept exact). The only one is PEI.
const EQUAL_IDENTITY_NAMES: readonly string[] = ['pei'];

/** True when an IE name is one of the subscriber / equipment identities. */
export function isIdentityIe(ie: Pick<InformationElement, 'name'>): boolean {
  if (!ie?.name) return false;
  const key = normalize(ie.name);
  if (!key) return false;
  if (EXACT_IDENTITY_NAMES.has(key)) return true;
  if (EQUAL_IDENTITY_NAMES.includes(key)) return true;
  for (const fragment of CONTAINS_IDENTITY_FRAGMENTS) {
    if (key.includes(fragment)) return true;
  }
  return false;
}

export interface WithholdResult {
  /** The input tree, with identity IEs removed (recursively). */
  tree: InformationElement[];
  /** How many identity IEs were removed (direct + nested). */
  withheldCount: number;
}

/**
 * Walk the IE tree and drop any node whose name is in the identity list.
 * Children of a withheld node don't get a free pass — the parent is cut
 * entirely, and every child it carried is counted (so the operator sees
 * the real number of identities the backend sent us).
 */
export function withholdIdentity(ies: InformationElement[] | undefined): WithholdResult {
  if (!ies || ies.length === 0) return { tree: [], withheldCount: 0 };
  let withheldCount = 0;
  function countAll(nodes: InformationElement[] | undefined): number {
    if (!nodes) return 0;
    let total = 0;
    for (const node of nodes) total += 1 + countAll(node.children);
    return total;
  }
  const tree: InformationElement[] = [];
  for (const ie of ies) {
    if (isIdentityIe(ie)) {
      withheldCount += 1 + countAll(ie.children);
      continue;
    }
    const result = withholdIdentity(ie.children);
    withheldCount += result.withheldCount;
    tree.push({ ...ie, children: result.tree });
  }
  return { tree, withheldCount };
}
