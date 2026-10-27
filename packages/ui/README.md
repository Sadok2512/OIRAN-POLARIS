# @oiran-polaris/ui — shared presentation primitives

Reserved for reviewed, reusable presentation primitives shared by frontend
applications. It must not contain application-specific workflows, API
ownership, authentication logic, or domain state.

This package was initialized on `feat/frontend-portal-probe-manager` to
replace the original placeholder. The placeholder guidance is preserved
below. If future work rebases this package, existing exports must be
merged deliberately and never overwritten by a placeholder.

## Contents

| File              | Purpose                                                            |
| ----------------- | ------------------------------------------------------------------ |
| `src/tokens.ts`   | Enterprise Precision colors / spacing / typography (single source) |
| `src/theme.ts`    | React-free Light/Dark/System persistence helpers                   |
| `src/api.ts`      | Fetch wrapper, `ApiError`, session token helpers (no auth logic)   |
| `src/types.ts`    | Typed OIRAN v1 contract mirror (see `OIRAN/OIRAN_V2_2_API_CONTRACT.md`) |

## Scope boundaries

- Pure utilities and type aliases only. No React components that embed
  application-specific state.
- No capture, probe, simulator or correlation domain logic.
- No authentication flow (login forms, token exchange).
- Consumers import via the alias `@shared/*` (also exposed as
  `@oiran-polaris/ui/*`) resolved by each app's `tsconfig.json` and
  `vite.config.ts`.

## Original placeholder guidance

Reserved for reviewed, reusable presentation primitives shared by frontend
applications. It must not contain application-specific workflows, API
ownership, authentication logic, or domain state.

This directory is a placeholder only. Claude Code may initialize the
package on a dedicated `feat/frontend-*` branch. Existing frontend
implementation must be rebased or merged deliberately and must never be
overwritten by this placeholder.
