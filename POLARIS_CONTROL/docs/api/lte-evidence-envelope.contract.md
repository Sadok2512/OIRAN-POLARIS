# POLARIS → OIRAN LTE evidence envelope

API: POLARIS Control 0.29.0
OIRAN ingestion target: 2.7.4
Routes:

- `POST /api/v1/lte/runs/:run_id/evidence-finalize` (production finalizer)
- `POST /api/v1/lte/runs/:run_id/evidence-envelope` (existing bundle consumer)

The route requires an authenticated `operator` or `administrator` session and
a valid CSRF header. It never starts a capture and never reads subscriber
identity material.

## Admission

The referenced run must be `CLEAN`, have a terminal outcome (`COMPLETED`,
`FAILED`, or `CANCELLED`), have no pending cleanup, and all five cleanup
observations must be true. A completed run requires exactly one independently
observed approved proof for each of `S1_MME`, `S11`, and `S1_U`. A failed or
cancelled run may publish a non-empty subset containing only observed planes.
Raw evidence, 5G planes, duplicate planes, invalid frame ranges, non-lower-case
SHA256, unapproved sanitization and non-pseudonymous session references fail
closed with HTTP 422.

## Release and staging ownership

An external capture release process may place only captures that are both
available and explicitly authorized after anonymization under
`POLARIS_LTE_EVIDENCE_RELEASE_ROOT` (default
`/var/lib/polaris-control/lte-evidence-releases`). POLARIS never reads the
collector paths directly. The finalizer caller supplies only an opaque
`release_id`:

```json
{"release_id":"release-lte-approved-01"}
```

The private `oiran-lte-capture-release.json` is schema
`polaris.oiran-lte-capture-release.v1` and binds `release_id`, `run_id`,
`profile_id`, `scenario_id`, `rat`, `run_started_at`, `run_ended_at`, terminal
`final_state`, `authorization_state=SANITIZED_APPROVED`, and a non-empty capture
list. Each capture records its interface plus the proof below. The interface
must exactly match the proof plane.

POLARIS confines and re-hashes the approved source PCAP and normalized JSONL,
privacy-scans JSONL, copies both with mode 0600 into a mode 0700 staging
directory, writes the proof manifest, fsyncs it and atomically renames it under
`POLARIS_LTE_EVIDENCE_BUNDLE_ROOT`. A deterministic run/release bundle ID makes
an exact retry idempotent. Changed metadata or files after finalization produce
HTTP 409 and cannot replace the immutable bundle.

The resulting immutable private bundle is stored under
`POLARIS_LTE_EVIDENCE_BUNDLE_ROOT` (default
`/var/lib/polaris-control/lte-evidence-bundles`) containing the sanitized
captures, normalized event streams and `polaris-evidence-proof.json`. POLARIS
re-hashes every referenced file before constructing the request for OIRAN.

The Operator cannot submit hashes, paths, provenance, frame ranges, decoder
versions, endpoint roles or capture references. The only caller-selected value
is the opaque bundle id. Publication is therefore bound to measured files
approved by the capture finalizer, not to operator-supplied metadata.

The manifest is bound to the exact `run_id`, `profile_id` and `scenario_id`.
POLARIS persists the admitted bundle ID with the run. Replaying the same bundle
and references is idempotent; a different bundle or changed references returns
HTTP 409 and cannot replace the original publication.

## HTTP request

```json
{
  "bundle_id": "bundle-lte-approved-01"
}
```

The staged `polaris-evidence-proof.json` uses this private filesystem contract;
it is not accepted in the HTTP body:

```json
{
  "schema_version": "polaris.oiran-observed-capture-proof.v1",
  "run_id": "lte-run-...",
  "profile_id": "LTE-SRSUE-TEST-01",
  "scenario_id": "lte-e2e-certification-v1",
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

A completed manifest contains three proofs; a terminal partial manifest contains
only its observed planes. Paths are safe relative bundle paths;
final files and every parent are confined after canonicalization. Symlinks,
traversal, missing files, hash mismatch and manifests larger than 1 MiB fail
closed.

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
are stored under the preflight step `measurements`, which OIRAN 2.7.4 accepts;
no unknown top-level field is emitted. The route persists capture refs only
after the complete wrapper validates. It does not set or infer
`POLARIS_LTE_E2E_CERTIFIED`.
