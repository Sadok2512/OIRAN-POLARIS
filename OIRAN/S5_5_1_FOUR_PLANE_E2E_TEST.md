# S5.5.1 four-plane validation E2E

The regression `four_plane_validate_traverses_http_api_and_unix_ipc_without_acquisition` performs:

1. Build the exact four-plane request used by the React frontend.
2. Authenticate an Operator request against `POST /api/v1/captures/validate`.
3. Execute API and live-probe validation, including disk budget and fixed discovery checks.
4. Serialize the closed IPC request over a mode-0660 Unix socket.
5. Authenticate peer credentials in the real Capture Helper request handler.
6. Return `READY` for four allowlisted planes.

The helper uses a validation-only backend whose acquisition initializer panics if invoked. The passing test therefore proves validation never opens AF_PACKET or starts capture. The React test separately asserts that Select All, Apply Configuration and Validate Capture submit `['N2', 'SBI', 'N4', 'N3']`.

Result: PASS.
