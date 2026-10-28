// Identity-IE withholding — LOT 3 / docs/ui-mockups/oiran-analyzer.html.
//
// Mobile subscriber / equipment identities must never be displayed to an
// Analyzer operator. The backend already pseudonymises most of them in the
// decoded tree, but the UI still has to filter the few that come through
// with a raw value and tell the operator how many were hidden. This file
// holds only pure helpers so the behaviour is testable without rendering.

import type { InformationElement } from '../types/api';

// Names are compared case-insensitively against the IE's `name` field.
// Normalisation strips spaces and hyphens so variants like "5G-GUTI" and
// "5G GUTI" collapse to the same key.
const IDENTITY_NAMES = new Set(
  [
    'IMSI',
    'IMSISV',
    'IMEI',
    'IMEISV',
    'MASKED_IMEISV',
    'MASKED IMEISV',
    'TMSI',
    'M-TMSI',
    'M_TMSI',
    'PTMSI',
    'P-TMSI',
    'GUTI',
    '5G-GUTI',
    '5G_GUTI',
    'S-TMSI',
    'S_TMSI',
    'RNTI',
    'C-RNTI',
    'SUPI',
    'SUCI',
    'MSISDN',
    'PEI',
  ].map(normalize),
);

function normalize(value: string): string {
  return value.replace(/[\s\-_]+/g, '').toUpperCase();
}

/** True when an IE name is one of the subscriber / equipment identities. */
export function isIdentityIe(ie: Pick<InformationElement, 'name'>): boolean {
  if (!ie?.name) return false;
  return IDENTITY_NAMES.has(normalize(ie.name));
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
