# Authenticated OIRAN Candidate E2E

A least-privilege Operator bearer token was injected through `OIRAN_E2E_OPERATOR_TOKEN`. The test fails when the token is unavailable; it is never hardcoded or committed.

The authenticated candidate test validated:

- atomic import and idempotent re-import;
- derived dataset listing and exact session selection;
- Session Explorer and Call Flow navigation;
- `EXACT_TUNNEL_MATCH` with TEID `0xb3b5`;
- strong NGAP/SBI and SBI/PFCP associations;
- PFCP/GTP-U remaining `UNKNOWN`;
- packet 39 provenance and exact-packet navigation;
- Light/Dark screenshots at 1440x900 and 1920x1080.

Result: 1/1 authenticated scenario PASS as part of 47/47 browser tests.
