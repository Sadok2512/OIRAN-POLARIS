# POLARIS Control V2.1 Security Report

- Viewer is anonymous and read-only.
- Operator may control certified scenarios only.
- Administrator may manage policy enablement.
- Credentials are generated at deployment, stored in untracked mode-0600 configuration, and held only in browser session storage.
- The public-IP HTTP reverse proxy removes `Authorization`; it therefore remains Viewer-only.
- Privileged Web use is restricted to the existing HTTPS endpoint or an SSH localhost tunnel.
- Audit records never include credentials or subscriber identities.
- The executor uses a fixed `nsenter` command, a fixed container namespace, a fixed destination, and a fixed payload count.
- Stop uses the exact child handle. No process-name matching or shared-service restart exists.
- Disk ≥85%, low memory, excessive load, unhealthy lab services, unavailable profiles, or concurrent jobs block Start.
- Stop does not depend on the Start resource gate.

Operator credentials can be retrieved only by a root administrator on the VPS. They must not be pasted into the public HTTP application.
