# Repository structure

```text
apps/
  simulator-control/
  probe-manager/
  oiran-analyzer/
  portal/
services/
packages/
  contracts/
infrastructure/
docs/
  architecture/
  contracts/
  development/
.github/workflows/
```

## Placement rules

- `apps/`: independently buildable user-facing applications.
- `services/`: independently deployable backend processes with one clear owner.
- `packages/`: versioned shared contracts and reusable technical libraries.
- `infrastructure/`: reviewed deployment templates and manifests without secrets.
- `docs/`: architecture, contracts, operational boundaries, and contributor guides.
- `.github/workflows/`: targeted automation for components that actually exist.

## Existing top-level snapshots

`OIRAN/` and `POLARIS_CONTROL/` predate this foundation. They are preserved without
movement or modification. Their eventual migration requires a separate reviewed
mission and is explicitly outside this change.
