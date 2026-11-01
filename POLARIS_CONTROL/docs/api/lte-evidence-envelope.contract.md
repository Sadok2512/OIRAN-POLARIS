# POLARIS → OIRAN LTE evidence envelope

API: POLARIS Control 0.28.0  
OIRAN ingestion target: 2.7.1  
Route: `POST /api/v1/lte/runs/:run_id/evidence-envelope`

The route requires an authenticated `operator` or `administrator` session and
a valid CSRF header. It never starts a capture and never reads subscriber
identity material.

## Admission

The referenced run must be `CLEAN`, have outcome `COMPLETED`, have no pending
cleanup, and all five cleanup observations must be true. The request must carry
exactly one independently observed and approved proof for each plane:
`S1_MME`, `S11`, `S1_U`. Raw evidence, 5G planes, duplicate/missing planes,
invalid frame ranges, non-lower-case SHA256, unapproved sanitization and
non-pseudonymous session references fail closed with HTTP 422.

## Request

```json
{
  "bundle_id": "bundle-lte-approved-01",
  "capture_proofs": [{
    "capture_ref": {
      "plane": "S1_MME",
      "source_file_sha256": "<64-lower-hex>",
      "first_frame": 1,
      "last_frame": 10,
      "decoder_version": "0.2.0",
      "event_schema_version": "1.5.0",
      "sanitization_state": "SANITIZED_APPROVED"
    },
    "observed_at": "2026-11-01T09:00:00Z",
    "provenance": "OIRAN_SANITIZED_CAPTURE_MANIFEST",
    "rat": "LTE",
    "session_refs": ["lte-session-pseudonym-01"],
    "source_file": "s1-mme.pcapng",
    "normalized_events_file": "s1-mme.events.jsonl",
    "normalized_events_sha256": "<64-lower-hex>",
    "decoder_name": "decoder-s1ap",
    "endpoint_roles": {"192.0.2.1":"ENB","192.0.2.2":"MME"}
  }]
}
```

A valid request contains three proofs. Paths are relative bundle paths.

## Response

HTTP 200 is the exact OIRAN request body:

```json
{
  "schema_version": "oiran.lte-evidence-ingestion.v1",
  "bundle_id": "bundle-lte-approved-01",
  "evidence": {
    "schema_version": "oiran-polaris.lte-e2e-evidence.v1",
    "run_id": "lte-run-...",
    "profile_id": "LTE-SRSUE-TEST-01",
    "scenario_id": "lte-e2e-certification-v1",
    "started_at": "...Z",
    "ended_at": "...Z",
    "final_state": "COMPLETED",
    "steps": [],
    "capture_refs": [],
    "cleanup": {}
  },
  "capture_bindings": []
}
```

RAT, manifest provenance, observation timestamps and pseudonymous session refs
are stored under the preflight step `measurements`, which OIRAN 2.7.1 accepts;
no unknown top-level field is emitted. The route persists capture refs only
after the complete wrapper validates. It does not set or infer
`POLARIS_LTE_E2E_CERTIFIED`.
