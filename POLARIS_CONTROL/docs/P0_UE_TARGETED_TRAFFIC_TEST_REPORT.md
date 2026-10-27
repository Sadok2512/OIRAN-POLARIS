# P0 UE-Targeted Traffic Test Report

## Offline results

- Rust workspace tests: 71 passed, 0 failed.
- POLARIS Control API tests: 37 passed, 0 failed.
- Frontend unit tests: 5 passed, 0 failed.
- TypeScript validation: passed.
- Frontend production build: passed.
- Rust release workspace build: passed.
- Isolated browser E2E: 1 passed, 0 failed.

## Covered behavior

- Shared UE-01 cannot be submitted as a controller-owned target.
- UE-04 can be selected only with verified ownership, RUNNING process, REGISTERED state, ACTIVE PDU Session, UE IP, approved runtime, exact container handle, TUN, and route.
- Unknown UE and missing-PDU targets are rejected.
- Ambiguous or missing TUN mapping fails closed.
- Route mismatch fails closed.
- Five requested UDP datagrams remain fixed.
- Concurrent duplicate traffic is rejected while an owned job is active.
- Exact Stop preserves UE RUNNING/REGISTERED/PDU ACTIVE state.
- Viewer/RBAC and CSRF controls remain enforced.
- Sustained CPU contention is rejected.
- Existing shared UE-01 bounded-traffic regression remains passing.
- Browser selector excludes the shared UE and sends only the stable UE ID and certified scenario type.

All traffic execution used mock/offline paths. No UDP packet, UE process, or production service was started.
