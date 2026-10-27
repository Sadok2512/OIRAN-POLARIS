# POLARIS Control V2.1 Test Report

## Results

- Rust workspace: 23 tests passed.
- Backend authorization/policy/job tests: 10 passed.
- Frontend unit tests: 2 passed.
- Browser/API E2E: 7 passed, including a real HTTPS Operator readiness check that stops before Start.
- TypeScript and React production build: passed.
- Rust release build: passed.
- Browser screenshots: 16 generated across 1440×900 and 1920×1080.

## Validated cases

- Viewer cannot Start or Stop.
- Invalid credentials are rejected.
- Operator can Start/Stop a certified mocked job.
- Duplicate Start is idempotent.
- Uncertified scenario is locked.
- Resource failure blocks Start.
- Existing disk threshold unit tests remain passing.
- UI Start remains disabled until validation and Operator permission are both present.
- Authorized Start UI flow uses a mocked backend response; no live traffic was generated.
- Shared gNB/UE/Open5GS lifecycle is absent from the executor.
