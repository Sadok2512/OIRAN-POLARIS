# P0 UE Profile Visibility Test Report

Date: 2026-10-26

## Automated validation

| Check | Result |
|---|---|
| Rust workspace tests | PASS — 39/39 |
| API tests | PASS — 16/16 |
| Profile visibility counts | PASS — 1, 3, 5, 10 |
| TypeScript check | PASS |
| Frontend unit tests | PASS — 3/3 |
| Frontend production build | PASS |
| Browser E2E | PASS — 16; SKIPPED — 1 production-credential test |

The skipped browser test requires a provisioned production Operator account. Production deployment and credentials were intentionally outside this mission. Viewer-mode candidate validation covered the requested inventory rendering and all lifecycle state assertions.

## Candidate API evidence

- Configured profiles: 3
- Visible state rows: 3
- Running UE processes: 1
- Registered UEs: 1
- Active PDU Sessions: 1
- UE-02 and UE-03: `VERIFIED / NOT_STARTED / NOT_OBSERVED / INACTIVE`

## Browser evidence

Real Chromium screenshots were captured from the isolated candidate:

- `screenshots/p0_ue_profile_visibility/UE_Manager_candidate_light_1440x900.png`
- `screenshots/p0_ue_profile_visibility/UE_Manager_candidate_dark_1440x900.png`
- `screenshots/p0_ue_profile_visibility/UE_Manager_candidate_light_1920x1080.png`
- `screenshots/p0_ue_profile_visibility/UE_Manager_candidate_dark_1920x1080.png`

Visual inspection confirmed three profile rows and three state rows, no horizontal overflow, consistent themes, and disabled uncertified lifecycle controls.

## Reproducible commands

```bash
cd /root/POLARIS_CONTROL
cargo test --workspace
cd apps/web
npm run typecheck
npm test
npm run build
POLARIS_E2E_BASE_URL=http://127.0.0.1:49155 npm run test:e2e -- --reporter=line
```
