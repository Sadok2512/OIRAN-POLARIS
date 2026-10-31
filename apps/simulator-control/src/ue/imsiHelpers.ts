// 0.10.2 (#41) — IMSI helpers shared by UE Manager and the subscriber
// surfaces.
// 0.10.3 — Prefix sourced from the LAB PLMN, not the fictive 999 prefix.
// An IMSI starting with 99901 would not be served by the Open5GS lab
// (which runs on MCC 001 / MNC 01); using it as the Create / Edit
// default stranded operators with unserviceable subscribers.
//
// Rules:
//   * The lab's real PLMN is MCC 001 / MNC 01 — IMSIs land in the
//     001010000000NNN space. The exact prefix is pulled from /plmns at
//     render time; the fallback below is only used when /plmns has not
//     answered yet (so the prefilled value is still network-servable).
//   * The 999 prefix is kept as `FICTIVE_IMSI_PREFIX_FOR_TESTS` for use
//     in e2e mocks and unit-test fixtures. Production code MUST NOT
//     reach for it.
//   * The operator sees the full IMSI; the viewer only sees a mask.
//   * "Next free IMSI" is a deterministic function of the UE id so
//     operators can predict the identity before the backend assigns it.

/** Real lab PLMN prefix: MCC 001 (3 digits) + MNC 01 (2 digits). */
export const DEFAULT_LAB_PLMN = { mcc: '001', mnc: '01' } as const;

/**
 * Fictive IMSI prefix the lab is allowed to use ONLY in test mocks
 * (unit-test fixtures and Playwright `page.route` stubs). Production
 * code MUST build the prefix from the live /plmns answer instead.
 */
export const FICTIVE_IMSI_PREFIX_FOR_TESTS = '99901';

/** The full IMSI mask shown to viewers. */
export const IMSI_MASK = '•••••••••••••••';

export interface LabPlmn {
  mcc: string;
  mnc: string;
}

/**
 * Parse the deployed `/plmns` string shape (`"001-01"`) into an MCC/MNC
 * pair. Returns null when the input is empty or malformed so the caller
 * can fall back to [DEFAULT_LAB_PLMN].
 */
export function parsePlmnString(value: string | null | undefined): LabPlmn | null {
  if (!value) return null;
  const match = /^(\d{3})-(\d{2,3})$/.exec(value.trim());
  if (!match) return null;
  return { mcc: match[1], mnc: match[2] };
}

/** Normalise an MCC/MNC pair into the IMSI prefix (MCC + MNC, no dash). */
export function imsiPrefixFromPlmn(plmn: LabPlmn): string {
  return `${plmn.mcc}${plmn.mnc}`;
}

/**
 * Deterministic "next free IMSI" prefilled in Create / Edit dialogs. The
 * last three digits come from the UE id's numeric suffix so UE-07 maps
 * to `imsi-001010000000007` on the standard lab PLMN. Returns `null`
 * when the id does not match the UE-NN or UE-NNNNN pattern.
 *
 * The `plmn` argument is required so callers must consciously decide
 * which prefix to use (production: `/plmns` → `parsePlmnString`;
 * fallback: `DEFAULT_LAB_PLMN`; tests: fictive 99901 pair).
 */
export function nextFreeImsiFor(ueId: string, plmn: LabPlmn): string | null {
  const match = /^UE-(\d{2,5})$/i.exec(ueId.trim());
  if (!match) return null;
  const index = Number(match[1]);
  if (!Number.isInteger(index) || index < 1 || index > 99999) return null;
  const prefix = imsiPrefixFromPlmn(plmn);
  // Target 15 digits total → MSIN width = 15 − prefix.length.
  const msinWidth = Math.max(1, 15 - prefix.length);
  const msin = index.toString().padStart(msinWidth, '0');
  return `imsi-${prefix}${msin}`;
}

/** `true` when the string looks like one of the lab-permitted IMSIs. */
export function isLabFictiveImsi(value: string | null | undefined): boolean {
  if (!value) return false;
  const trimmed = value.trim().replace(/^imsi-/i, '');
  return trimmed.startsWith(FICTIVE_IMSI_PREFIX_FOR_TESTS) && /^\d{15}$/.test(trimmed);
}

/**
 * Format an IMSI for display given the viewer's role.
 *   * `canOperate = true` → the raw IMSI, with the `imsi-` prefix
 *     normalised so the column stays aligned.
 *   * `canOperate = false` → the solid mask (`•` dots), so the viewer
 *     sees that an IMSI is present without learning the identity.
 */
export function formatImsiForRole(
  value: string | null | undefined,
  canOperate: boolean,
): string {
  if (!value) return canOperate ? '—' : IMSI_MASK;
  const trimmed = value.trim();
  if (!canOperate) return IMSI_MASK;
  return trimmed.startsWith('imsi-') ? trimmed : `imsi-${trimmed}`;
}
