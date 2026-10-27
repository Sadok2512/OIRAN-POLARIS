# OIRAN Live V1 Security Report

- Viewer is read-only; capture validation, start and stop require Operator or Administrator.
- Plain tokens are not stored by the backend. Only server-provisioned SHA-256 fingerprints are compared. The Web client keeps a supplied token in browser `sessionStorage`, never in source code or URLs.
- The manager invokes a fixed executable directly, never a shell, and accepts only three fixed devices and fixed BPF expressions.
- Stop targets exact child PIDs registered by the job. Shared POLARIS captures, Open5GS and UERANSIM are outside the control surface.
- Files are written only below `runtime/live-captures/<capture-id>` with generated identifiers.
- Subscriber payloads and unrestricted raw bytes are not exposed by the event API.

Deployment must run under a dedicated OIRAN service account with narrowly scoped packet-capture capability. Do not grant the Web/API process Docker-socket access or unrestricted sudo. The present deployment gate remains off pending the controlled live approval.
