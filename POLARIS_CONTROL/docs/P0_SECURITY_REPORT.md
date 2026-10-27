# P0 Security Report

- Authentication: named accounts, Argon2id password verification and random server-side sessions.
- Browser session: Secure + HttpOnly + SameSite=Strict cookie; no password or bearer token is stored in browser storage.
- CSRF: random token required for all authenticated mutations.
- Authorization: Viewer is read-only; Operator may validate/Start/Stop only the certified scenario; Administrator additionally manages policy.
- Provisioning: root-only CLI with hidden prompt or standard input; user database mode `0600`.
- Execution: fixed scenario type, fixed UE count, destination, protocol and packet budget; no arbitrary shell API.
- Ownership: Stop targets only the exact controller-owned job and preserves shared Open5GS, gNB and UE processes.
- Safety: existing disk, memory, CPU and lab-health gates remain mandatory and fail closed.
- Audit: login outcome and privileged actions are recorded without passwords, cookies or CSRF tokens.

Sessions are in memory and are intentionally revoked by a controller restart. Account lockout and external identity-provider integration remain future hardening items.
