# POLARIS Control V3 Security Report

## Preserved controls

- Viewer, Operator, and Administrator roles remain server-enforced.
- Passwords remain Argon2id hashes; sessions use HttpOnly cookies and CSRF protection.
- Start requires Operator/Administrator role, enabled policy, fresh certified validation, and current safety gates.
- Stop targets only the exact controller-owned active job.
- Shared Open5GS, gNB, and UE processes are protected from lifecycle actions.
- Traffic destinations remain allowlisted; arbitrary shell execution is absent.
- Disk checks fail closed and block capture-producing writes at 85%.

## Current security posture

The measured root filesystem is above the 85% stop threshold, so the backend returns `STOP_NEW_WRITES` and refuses live Start. The UI and read-only monitoring remain available. No automatic deletion is performed.
