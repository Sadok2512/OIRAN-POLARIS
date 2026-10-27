# V3.1 Multi-UE Test Report

Offline Rust coverage validates:

- Two and five unique compatible UE profiles.
- Secret-format validation without serialization or logging.
- Independent UE lifecycle and serving-gNB metadata.
- Registration and PDU Session state isolation.
- Traffic completion without stopping the UE or releasing its PDU Session.
- Duplicate Start and Stop idempotence.
- Bounded group operations and partial-failure isolation.
- Resource-limit and unknown-profile rejection.
- Viewer denial, Operator/CSRF enforcement and unprovisioned-profile rejection.

Frontend validation covers Viewer-safe disabled states, five-profile presentation, selection and independent counts. Real UE processes were not created; live claims remain limited to the previously certified shared UE.

## Results

- Rust workspace: 34/34 PASS, including 13 API, 8 controller and 4 UERANSIM-adapter tests.
- Frontend unit tests: 3/3 PASS.
- Browser end-to-end tests: 12/12 PASS.
- TypeScript validation: PASS.
- Production frontend build: PASS (215.23 kB JavaScript, 12.01 kB CSS before compression).
- Visual checks: PASS at 1440×900 and 1920×1080 in Light and Dark modes; no horizontal overflow detected.

Screenshots are preserved under `screenshots/v3_1/`; structured browser results are in `tests/V3_1_E2E_RESULTS.json`.

