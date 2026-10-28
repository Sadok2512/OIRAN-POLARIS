# POLARIS UE Profile API v1

This contract separates the persistent profile catalog from live simulator capacity.

- Catalog capacity: 0–10,000 profiles.
- Concurrent live capacity: 10 controller-owned UEs, still subject to Operator authorization,
  provisioning attestation, CPU/RAM/disk gates and per-job ownership.
- Creating or importing a profile never starts a UE and never changes Open5GS subscriptions.
- Subscriber identities are represented in API output only by a digest; authentication keys and
  OPc are never returned.

## Profile endpoints

- `GET /api/v1/ue-profiles?page=1&page_size=100&search=&scenario_id=&subscription_status=`
  returns server-side pagination (`page_size` is capped at 500).
- `POST /api/v1/ue-profiles` creates one profile.
- `POST /api/v1/ue-profiles/bulk` accepts only 10, 100, 1,000 or 10,000 generated profiles and
  publishes one durable registry generation. Generated profiles remain
  `PROVISIONING_REQUIRED`.
- `PUT /api/v1/ue-profiles/{ue_id}`, `POST .../{ue_id}/clone`, and
  `DELETE /api/v1/ue-profiles/{ue_id}` preserve the existing stopped-profile rules.
- `GET /api/v1/ue-profiles/export.csv` exports non-secret catalog fields only.

Canonical IDs are `UE-01` through `UE-99`, then zero-padded five-digit IDs through `UE-10000`.
Bulk creation selects unused canonical IDs and rejects capacity overflow or duplicate subscriber
identity digests.

## Execution and scenarios

Existing `/api/v1/ues/start`, `/stop`, group control and traffic endpoints remain bounded to ten
UEs per request and preserve all resource gates. Profile assignment persists `scenario_id` and
`auto_run_scenario`, but profile creation never auto-runs it.

The current scenario engine exposes validation, capability, start, stop, status and history
contracts. Persistent scenario CRUD/versioning and CSV import are deliberately not claimed by
this increment; those contracts require the Scenario Builder schema to be finalized first.

