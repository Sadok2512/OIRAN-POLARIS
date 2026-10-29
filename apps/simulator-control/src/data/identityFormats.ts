// 0.7.1 — Format helpers used by the two subscriber-identity forms.
//
// `normalizeImsi` accepts raw digits ("001010000000201") and the
// prefixed shape ("imsi-001010000000201") and returns the canonical
// `imsi-<digits>` form. Returns `null` when the input is not valid.
//
// The UE ID helper covers the backend convention `UE-NN` (01–99) and
// `UE-NNNNN` (00100–10000). The regex is identical to the one Codex
// enforces on `POST /ue-profiles` so an invalid id is caught before
// the operator sees the raw backend error.

export const IMSI_DIGITS_RE = /^\d{5,15}$/;
export const IMSI_PREFIXED_RE = /^imsi-\d{5,15}$/;

export function normalizeImsi(input: string): string | null {
  const trimmed = input.trim();
  if (!trimmed) return null;
  if (IMSI_PREFIXED_RE.test(trimmed)) return trimmed;
  if (IMSI_DIGITS_RE.test(trimmed)) return `imsi-${trimmed}`;
  return null;
}

export function isImsiValid(input: string): boolean {
  return normalizeImsi(input) !== null;
}

/**
 * UE id format published by the backend contract:
 *   * UE-NN           — operator UEs       (01..99)
 *   * UE-NNNNN        — provisioning slots (00100..10000)
 * Any other shape is refused with UE_ID_INVALID.
 */
export const UE_ID_RE = /^UE-(?:\d{2}|\d{5})$/;

export function isUeIdValid(input: string): boolean {
  const trimmed = input.trim();
  if (!UE_ID_RE.test(trimmed)) return false;
  const digits = trimmed.slice(3);
  if (digits.length === 2) {
    const n = Number(digits);
    return Number.isInteger(n) && n >= 1 && n <= 99;
  }
  const n = Number(digits);
  return Number.isInteger(n) && n >= 100 && n <= 10_000;
}

export const UE_ID_HINT = 'Format: UE-NN (01–99) or UE-NNNNN (00100–10000).';
