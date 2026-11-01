# LTE evidence ingestion contract

Status: `OFFLINE_ONLY`  
OIRAN contract: `oiran.lte-evidence-ingestion.v1`  
ANR1 canonical schema reconciliation: `d22b1c169a` (descends `05485194d857c56c73857100ec064c5e96de29a2`)
Canonical evidence: `oiran-polaris.lte-e2e-evidence.v1`

This contract activates no capture, UE, traffic or deployment. It accepts only
server-staged, already-sanitized evidence. It is not a generic PCAP anonymizer.

## Canonical planes and references

| ANR1 plane | Decoder interface | Stable evidence reference |
|---|---|---|
| `S1_MME` | `S1-MME` | `capture:S1_MME` |
| `S11` | `S11` | `capture:S11` |
| `S1_U` | `S1-U` | `capture:S1_U` |

All three are mandatory and unique. Unsupported planes are rejected. Every
step reference resolves to one binding, and every binding identifies its
canonical capture by zero-based `capture_ref_index`.

## HTTP routes

| Method | Route | Role | CSRF | Result |
|---|---|---|---|---|
| POST | `/api/v1/lte/evidence/import` | Operator+ | required | `201` first import, `200` exact replay |
| GET | `/api/v1/lte/evidence/:run_id` | Viewer+ | no | import summary |
| GET | `/api/v1/lte/evidence/:run_id/sessions?page=1&page_size=50` | Viewer+ | no | page size 1..100 |
| GET | `/api/v1/lte/evidence/:run_id/sessions/:session_id/callflow?limit=100&cursor=` | Viewer+ | no | streaming page, limit 1..256 |
| POST | `/api/v1/lte/evidence/:run_id/exports` | Operator+ | required | immutable pending-review export |

No absolute path is accepted. `bundle_id` selects a directory below the
server inbox. Artifact paths are bundle-relative regular files; symlinks and
traversal are rejected.

## Import request schema

```json
{
  "schema_version": "oiran.lte-evidence-ingestion.v1",
  "bundle_id": "bundle-lte-synthetic-01",
  "evidence": {
    "schema_version": "oiran-polaris.lte-e2e-evidence.v1",
    "run_id": "lte-run-synthetic-0001",
    "profile_id": "LTE-SRSUE-TEST-01",
    "scenario_id": "lte-e2e-certification-v1",
    "started_at": "2026-10-31T12:00:00Z",
    "ended_at": "2026-10-31T12:00:10Z",
    "final_state": "COMPLETED",
    "steps": [{
      "index": 0, "type": "lte_attach", "state": "COMPLETED",
      "started_at": "2026-10-31T12:00:00Z",
      "ended_at": "2026-10-31T12:00:10Z", "reason_code": null,
      "evidence_refs": ["capture:S1_MME", "capture:S11", "capture:S1_U"],
      "measurements": {}
    }],
    "capture_refs": [
      {"plane":"S1_MME","source_file_sha256":"<64-lower-hex>","decoder_version":"0.2.0","event_schema_version":"1.5.0","first_frame":1,"last_frame":10,"sanitization_state":"SANITIZED_APPROVED"},
      {"plane":"S11","source_file_sha256":"<64-lower-hex>","decoder_version":"0.1.0","event_schema_version":"1.5.0","first_frame":1,"last_frame":10,"sanitization_state":"SANITIZED_APPROVED"},
      {"plane":"S1_U","source_file_sha256":"<64-lower-hex>","decoder_version":"0.2.0","event_schema_version":"1.5.0","first_frame":1,"last_frame":10,"sanitization_state":"SANITIZED_APPROVED"}
    ],
    "cleanup": {"srsue_stopped":true,"srsenb_stopped":true,"sidecars_removed":true,"epc_healthy":true,"dumpcaps_preserved":true}
  },
  "capture_bindings": [{
    "evidence_ref": "capture:S1_MME", "capture_ref_index": 0,
    "source_file": "s1-mme.pcapng",
    "normalized_events_file": "s1-mme.events.jsonl",
    "normalized_events_sha256": "<64-lower-hex>",
    "decoder_name": "decoder-s1ap", "decoder_version": "0.2.0",
    "event_schema_version": "1.5.0",
    "endpoint_roles": {"192.0.2.1":"ENB", "192.0.2.2":"MME"}
  }]
}
```

The shortened example shows one binding; a valid request has three.

## POLARIS adapter boundary

The import endpoint accepts either the direct OIRAN request or the complete,
strict POLARIS 0.28.1 envelope with
`schema_version=polaris-oiran.lte-import-envelope.v1`. For the latter, OIRAN
requires the outer run/profile/scenario/time fields and every SHA256-derived
capture ID to match the nested request before opening an artifact. Unknown
outer, provenance, or nested fields are rejected.

The nested evidence uses exact schema
`oiran-polaris.lte-e2e-evidence.v1`. OIRAN does not accept a client-supplied file
path. The operator-controlled staging publication adds only:

- `schema_version=oiran.lte-evidence-ingestion.v1` and a safe `bundle_id`;
- one server-resolved `capture_binding` per canonical `capture_ref`;
- the normalized-event SHA-256, decoder name/version, event schema version and
  endpoint-role map measured from the staged artifacts.

The adapter must not alter the POLARIS `run_id`, scope, steps, cleanup proof or
capture references. `deny_unknown_fields` remains active. Although POLARIS may
model optional S5 planes, this version admits exactly `S1_MME`, `S11` and `S1_U`;
S5 input fails with `LTE_OPTIONAL_PLANE_UNSUPPORTED` until a decoder/correlation
contract is reviewed.

5G N2/N3/N4 evidence does not pass through this LTE route. It is finalized by the
existing CaptureManager pipeline, which verifies source checksums and publishes
its dataset generation atomically. Session Explorer merges those persisted 5G
datasets with admitted LTE datasets without fabricating a missing plane or counter.

## Responses and errors

First import (`201`) and exact replay (`200`) share this shape:

```json
{"data":{"schema_version":"oiran.lte-evidence-ingestion.v1","run_id":"lte-run-synthetic-0001","dataset_id":"dataset-lte-run-synthetic-0001","request_sha256":"<sha256>","manifest_sha256":"<sha256>","event_count":3,"session_count":1,"correlation_edge_count":2,"idempotent":false,"state":"IMPORTED"}}
```

Errors use `{"error":{"code":"CODE","message":"detail"}}`.

- `403 OPERATOR_REQUIRED`, `403 CSRF_REQUIRED`;
- `409 LTE_INGESTION_CONFLICT`, `LTE_EXPORT_CONFLICT`;
- `413 LTE_EVENT_LIMIT_EXCEEDED`, `LTE_EVENT_LINE_TOO_LARGE`;
- `422 LTE_EVIDENCE_SCHEMA_UNSUPPORTED`, `LTE_EVIDENCE_SCOPE_MISMATCH`,
  `LTE_EVIDENCE_NOT_COMPLETED`, `LTE_CLEANUP_NOT_PROVEN`;
- `422 LTE_REQUIRED_PLANE_MISSING`, `LTE_OPTIONAL_PLANE_UNSUPPORTED`,
  `LTE_CAPTURE_PLANE_DUPLICATE`, `LTE_CAPTURE_FRAME_RANGE_INVALID`;
- `422 LTE_EVIDENCE_NOT_APPROVED`, `LTE_EVIDENCE_REF_UNRESOLVED`,
  `LTE_CAPTURE_HASH_MISMATCH`, `LTE_EVENT_HASH_MISMATCH`;
- `422 LTE_EVENT_PROVENANCE_MISMATCH`, `LTE_PACKET_REFERENCE_INVALID`,
  `LTE_EVENT_ID_DUPLICATE`, `LTE_IDENTITY_DISCLOSURE_REJECTED`;
- `422 LTE_SESSION_NOT_RECONSTRUCTED`, `LTE_PAGINATION_INVALID`,
  `LTE_CALLFLOW_PAGE_INVALID`, `LTE_EXPORT_SOURCE_HASH_MISMATCH`,
  `LTE_EXPORT_SOURCE_MANIFEST_INCOMPLETE`,
  `LTE_EXPORT_IDENTITY_SCAN_FAILED`,
  `LTE_EXPORT_TRANSFORMATION_UNSUPPORTED`;
- `500 LTE_ATOMIC_WRITE_FAILED`, `LTE_INGESTION_FINALIZE_FAILED`,
  `LTE_EXPORT_FINALIZE_FAILED`.

## Persistence, memory and export boundary

All derived artifacts are staged, fsynced and renamed once. Same run plus same
request hash is idempotent; a different request conflicts. Failed staging is
removed. Input JSONL is streamed with a 1 MiB line limit, 50,000-event cap and
a 64 MiB conservative retained-allocation budget (8x wire bytes plus 1 KiB
per event). Capture-level decoder and event-schema versions must exactly
match their server binding.
Session pages cap at 100; Call Flow uses the existing streaming reader capped
at 256 events.

Export body is
`{"export_id":"export-lte-opaque-01","transformation":"VERIFIED_COPY"}`.
Any other transformation is rejected with
`LTE_EXPORT_TRANSFORMATION_UNSUPPORTED`. Export copies only
already `SANITIZED_APPROVED` PCAP and derived JSON using 1 MiB buffers while
recomputing output SHA-256. JSON is rescanned for forbidden identity keys and
long digit runs. The manifest records source/output hashes and counts with
`transformation_version=verified-copy-1.0.0`; review state always begins
`SANITIZED_PENDING_REVIEW`.

No payload rewrite or generic anonymization is claimed. OIRAN never promotes
an export to `SANITIZED_APPROVED`.

— ANR3
