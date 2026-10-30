// 0.10.2 (#41) — IMSI helpers shared by UE Manager and the subscriber
// surfaces.
//
// Rules:
//   * The lab's fictive PLMN uses MCC 999 so no real identity ever
//     accidentally lands in a mock, test fixture or log.
//   * The operator sees the full IMSI; the viewer only sees a mask.
//   * "Next free IMSI" is a deterministic function of the UE id so
//     operators can predict the identity before the backend assigns it.

/** Fictive IMSI prefix the lab is allowed to use (MCC 999, MNC 01). */
export const LAB_IMSI_PREFIX = '999010000000';

/** The full IMSI mask shown to viewers. */
export const IMSI_MASK = '•••••••••••••••';

/**
 * Deterministic "next free IMSI" prefilled in Create / Edit dialogs. The
 * last 3 digits come from the UE id's numeric suffix so UE-07 maps to
 * `imsi-999010000000007`. Returns `null` when the id does not match the
 * UE-NN or UE-NNNNN pattern, so the UI can keep the field empty rather
 * than seeding an invalid value.
 */
export function nextFreeImsiFor(ueId: string): string | null {
  const match = /^UE-(\d{2,5})$/i.exec(ueId.trim());
  if (!match) return null;
  const index = Number(match[1]);
  if (!Number.isInteger(index) || index < 1 || index > 99999) return null;
  const suffix = index.toString().padStart(3, '0');
  return `imsi-${LAB_IMSI_PREFIX}${suffix}`;
}

/** `true` when the string looks like one of the lab-permitted IMSIs. */
export function isLabFictiveImsi(value: string | null | undefined): boolean {
  if (!value) return false;
  const trimmed = value.trim().replace(/^imsi-/i, '');
  return trimmed.startsWith('99901') && /^\d{15}$/.test(trimmed);
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
