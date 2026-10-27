# OIRAN P0 Dataset Fix Deployment Instructions

The corrected source and release candidates must be deployed through the existing controlled OIRAN deployment procedure. Do not start a capture during deployment.

1. Verify the fix commit and clean tree.
2. Build the Rust workspace and React application.
3. Record SHA256 hashes of the candidate `oiran-api`, `oiran-capture-helper`, and current installed binaries.
4. Snapshot the OIRAN API/helper unit files and installed binaries.
5. Install the reviewed API and helper artifacts.
6. Restart only `oiran-capture-helper.service` and `oiran-api.service`.
7. Verify service identities, capabilities, IPC, authentication and N2/N3/N4 `ValidateCapture` only.
8. Confirm the recovered-dataset registry is loaded and `recovered-dataset-live-1792964646320-0003` is visible with 20 events and zero sessions.
9. Confirm all original failed jobs remain `FAILED`.

Only after a separate authorization may a bounded live capture be used to certify the corrected end-to-end lifecycle.
