# P0 Configurable Counts Security Validation

- GET access remains available to authenticated and public Viewer contexts for read-only inspection.
- POST access requires Operator or Administrator role.
- State-changing requests require a server-issued CSRF token.
- Counts are server-validated against 1..5 UE and 1..2 gNB limits.
- Persistence uses an atomic temporary file, mode 0600, and rename.
- The configuration endpoint has no process-launch side effect.
- Subscriber secrets are neither returned nor logged.
- Missing subscriber provisioning is represented as status metadata only.
- Existing resource safety and exact process-ownership controls remain authoritative for lifecycle endpoints.
