# OIRAN Dataset Pipeline Fix Deployment Report

Deployment completed at `2026-10-25T22:11:23Z` from reviewed source commit `07333b2f01131ce408b9dc883f13d5752c7f4a00`.

## Outcome

- Installed the reviewed Release API, capture-helper, and recovery CLI atomically under `/opt/oiran/bin`.
- Restarted only `oiran-capture-helper.service` and `oiran-api.service`.
- Both services are active with zero automatic restarts and the expected running executable hashes.
- The helper socket is active at `/run/oiran/capture-helper.sock` with mode `0660` and owner `oiran-capture:oiran-capture`.
- Authenticated validation reached the isolated helper and returned `READY` for N2, N3, and N4.
- No capture was started and no simulator traffic was generated.

## Deployed behavior

The running API now contains parent-directory validation, atomic JSONL and manifest finalization, artifact integrity checks, failed-capture recovery, and persistent recovered-dataset registry loading. The unsafe legacy tcpdump path is absent. The API has no Linux capabilities; the helper retains only `CAP_NET_RAW`.

## Protected systems

POLARIS Core, UERANSIM, POLARIS Control, Portal, Infrastructure, ETV, OTV, PostgreSQL, Docker networks, and historical datasets were not modified or restarted.

