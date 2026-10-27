# S5.6 Retry Deployment Report

- Deployment window: 2026-10-26 21:00–21:08 UTC
- Reviewed source: `d7d8ec700b1b1f90222a44ba10f74d24913c5fa4`
- Target: OIRAN production on `127.0.0.1:49152`, public gateway `151.242.147.49:49152`
- Result: corrected API, native Capture Helper and frontend assets deployed.

Only `oiran-capture-helper.service` and `oiran-api.service` were restarted. POLARIS Control, Portal, Infrastructure, Open5GS, UERANSIM, ETV and OTV were not restarted or modified. No capture was started and no simulator traffic was generated.

The deployed API accepted NG-C, SBI, N4 and NG-U both independently and as one four-plane request. Validation used the real production HTTP API, Unix socket and helper, without opening packet-acquisition sockets. Five-plane, duplicate, unknown and unauthenticated requests were rejected.

The production browser suite passed 46/46 tests. The 20 reviewed Light/Dark screenshots at 1440x900 and 1920x1080 are in `S5_6_RETRY_SCREENSHOTS/`.

