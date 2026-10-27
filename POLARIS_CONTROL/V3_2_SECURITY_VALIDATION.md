# V3.2 Security Validation

- Production Operator authentication succeeded over HTTPS using the existing server-side account; no credential was logged or committed.
- Viewer/Operator RBAC remains enforced by the API.
- Shared UE ownership protection is enforced server-side.
- Target interfaces and namespaces are resolved through an allowlisted authoritative registry; arbitrary values and shell commands are not accepted.
- The UE provisioning attestation and profiles remain mode 0600; reports contain no IMSI, K, OPc, password, token, or subscriber secret.
- No Open5GS database write occurred.
- No OIRAN, ETV/OTV, firewall, routing, Docker network, or unrelated service change occurred.
- Live actions remain fail-closed because the additional UE authorization flag is disabled and the active CPU gate reports `CPU_CONTENTION_LIMIT`.

