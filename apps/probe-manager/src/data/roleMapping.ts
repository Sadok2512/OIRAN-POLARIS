// Deterministic mapping from the backend's `capture_point` / `protocol`
// fields to a 3GPP interface role (N2/N3/N4/S1).
//
// Why a helper?
//   The `CaptureInterface` type exposed by the OIRAN backend does NOT carry
//   a `role` field (see packages/ui/src/types.ts). The mockups (docs/ui-mockups)
//   display N2/N3/N4/S1 badges — those must be derived from what the backend
//   actually says. Anything else is rendered as "—" so the UI never invents
//   a plane assignment the backend did not provide.

export type InterfaceRole = 'N2' | 'N3' | 'N4' | 'S1' | 'N6' | null;

/**
 * Prefer the backend-reported `role` field. Fall back to the deterministic
 * `capture_point` / `protocol` mapping below only when the backend did
 * NOT declare a role yet (null / undefined). The UI never invents a role.
 */
export function roleForInterface(input: {
  role?: InterfaceRole;
  capture_point?: string | null;
  protocol?: string | null;
}): InterfaceRole {
  if (input.role != null) return input.role;
  return roleFor(input);
}

/**
 * Return the 3GPP interface role for a `CaptureInterface` or null when
 * neither the capture_point nor the protocol lets us name it honestly.
 *
 * Rules (deterministic, no fallthrough fabrication):
 *   capture_point exact match (case-insensitive): N2 / N3 / N4 / S1 / N6
 *   protocol: NGAP → N2 · GTP-U|GTP → N3 · PFCP → N4 · S1AP → S1
 *   anything else → null (UI shows "—")
 */
export function roleFor(input: {
  capture_point?: string | null;
  protocol?: string | null;
}): InterfaceRole {
  const point = (input.capture_point ?? '').trim().toUpperCase();
  if (point === 'N2' || point === 'N3' || point === 'N4' || point === 'S1' || point === 'N6') {
    return point as InterfaceRole;
  }
  const protocol = (input.protocol ?? '').trim().toUpperCase();
  if (protocol === 'NGAP') return 'N2';
  if (protocol === 'GTP' || protocol === 'GTP-U' || protocol === 'GTPU') return 'N3';
  if (protocol === 'PFCP') return 'N4';
  if (protocol === 'S1AP') return 'S1';
  return null;
}

/**
 * Default BPF filter proposed in the Register-probe dialog. The dialog is
 * read-only (POST /probes does not exist); the filter is suggested so the
 * payload preview is realistic. The exact ports come from 3GPP defaults,
 * not from any live probe.
 */
export function bpfForRole(role: InterfaceRole): string {
  switch (role) {
    case 'N2':
      return 'sctp port 38412';
    case 'N3':
      return 'udp port 2152';
    case 'N4':
      return 'udp port 8805';
    case 'S1':
      return 'sctp port 36412';
    case 'N6':
      return 'ip';
    default:
      return '';
  }
}

/** Tailwind utility picks for the role badge; stay inside Enterprise Precision tokens. */
export function roleBadgeClass(role: InterfaceRole): string {
  switch (role) {
    case 'N2':
      return 'border-primary/50 text-primary';
    case 'N3':
      return 'border-success/50 text-success';
    case 'N4':
      return 'border-warning/50 text-warning';
    case 'S1':
      return 'border-text-secondary/50 text-text-secondary';
    case 'N6':
      return 'border-primary/30 text-primary';
    default:
      return 'text-text-secondary';
  }
}
