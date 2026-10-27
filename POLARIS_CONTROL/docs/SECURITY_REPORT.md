# Security report

- Loopback-only bind is enforced in the binary.
- Read-only Viewer access is anonymous by explicit operator request.
- Runtime-only Operator and Administrator credentials implement the explicitly requested V2.1 authorization roles.
- Anonymous Viewer requests cannot invoke Start or Stop.
- No credentials are embedded in the frontend bundle.
- No arbitrary path, command, Docker socket, or broad PID matching is exposed.
- UERANSIM profile audit accepts a basename under the fixed POLARIS runtime directory.
- Subscriber identities and authentication keys are not returned.
- Security headers deny framing and MIME sniffing.
- The sample service unit applies write confinement and resource limits.

Remaining limitation: public read-only access exposes sanitized operational metadata. Privileged credentials must only be used over the configured HTTPS endpoint or an SSH tunnel.
