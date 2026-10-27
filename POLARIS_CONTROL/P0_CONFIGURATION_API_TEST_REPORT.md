# P0 Configuration API Test Report

## Results

- Rust workspace: 38/38 PASS.
- API tests: 15/15 PASS.
- Frontend unit tests: 3/3 PASS.
- Browser E2E tests: 15/15 PASS.
- Deployed HTTPS Operator browser smoke: 1/1 PASS.
- TypeScript validation: PASS.
- Production frontend build: PASS.

## Covered cases

- Configuration values 1, 2, and 5 UEs.
- Configuration values 1 and 2 gNBs.
- Persistence after browser refresh.
- Viewer inspection and mutation denial.
- Operator mutation with CSRF enforcement.
- Invalid lower and upper bounds.
- Add UE as configuration-only behavior.
- Missing subscriber provisioning disclosure.
- No process handle created by configuration changes.
- Existing lifecycle and safety regressions.

The browser suite used an isolated candidate service on `127.0.0.1:49155`; no production action endpoint was invoked during pre-deployment testing.

Post-deployment testing used the real HTTPS endpoint. It authenticated as the provisioned Operator, inspected both pages at 1440×900 and 1920×1080 in both themes, and did not invoke any lifecycle action.
