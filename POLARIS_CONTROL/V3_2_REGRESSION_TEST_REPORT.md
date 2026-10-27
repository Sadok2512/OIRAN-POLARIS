# POLARIS Control V3.2 Regression Test Report

## Automated results

- Rust workspace: 38/38 PASS.
- API tests: 15/15 PASS.
- Frontend unit tests: 3/3 PASS.
- TypeScript: PASS.
- Frontend production build: PASS.
- Browser E2E candidate suite: 15 PASS, 1 production-only test SKIPPED by design.
- Deployed HTTPS Operator smoke test: 1/1 PASS.

## Provisioning validations

- Inventory before: 1.
- Records inserted: 9.
- Inventory after: 10.
- Unique identities / K / OPc: 10 / 10 / 10.
- Compatible subscriber documents: 10/10.
- Idempotent rerun: 0 inserted, 10 verified.
- Matching protected profiles: 10/10.
- Secret scan of tracked source: 0 matches.
- Existing profile preservation: PASS.
- Shared UE/gNB PID preservation: PASS.

Configuration tests cover 1, 2, 5, and 10 desired UEs. Configuration changes create no process handle, and live lifecycle remains locked pending separate approval.
