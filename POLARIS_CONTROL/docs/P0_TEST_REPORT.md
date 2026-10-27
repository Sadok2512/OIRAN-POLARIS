# P0 Test Report

The implementation is validated without launching live simulator traffic.

- Rust workspace: 19/19 PASS (including 6 P0 API/auth tests).
- Frontend component tests: 2/2 PASS.
- Browser/API integration workflows: 7/7 PASS.
- TypeScript check and production build: PASS.

Covered automated cases:

- Anonymous Viewer can read but cannot validate, Start or Stop.
- Invalid credentials are rejected.
- Operator login produces the Operator role.
- Missing or invalid CSRF is rejected.
- Start before certified validation is rejected.
- The exact certified mock scenario can Start and Stop; duplicate Start/Stop is idempotent.
- Uncertified multi-UE scenario remains locked.
- Resource failure blocks Start.
- Operator cannot manage policy; Administrator can.
- Provisioned passwords are hashed and never persisted as plaintext.
- Frontend production build, TypeScript check and component tests pass.

The browser validation signs in and validates only; it does not click Start against the live backend.
