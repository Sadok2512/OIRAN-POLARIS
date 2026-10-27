# OIRAN V2.2 API Contract

API version: `2.2.0`. All routes remain under `/api/v1`; existing V2.1 routes are backward compatible.

## Capture context

`GET /api/v1/captures/{capture_id}/context`

Returns the authoritative capture, its exact dataset when registered, session IDs and one resolution:

- `SESSIONS_AVAILABLE`
- `NO_RECONSTRUCTED_SESSIONS`
- `DATASET_UNAVAILABLE`

The endpoint never falls back to another dataset. A recovered dataset may be associated with an immutable `FAILED` capture without changing that capture state.

## Packet provenance filters

`GET /api/v1/packets?capture_id=...&event_id=...&packet_number=...`

Each supplied filter is exact and composable. The response retains capture ID, source reference, packet number, byte offset, timestamp and decoder version. Raw bytes remain unavailable where the normalized event model stores only a payload reference.

## Session context

Session listing supports `dataset_id`. Session and Call Flow responses preserve the canonical S3.3 schema and decoder output. `serving_node` is evidence-derived; when it cannot be established the API reports `NOT AVAILABLE`.

Errors use the existing versioned envelope and controlled HTTP status. No decoder logic is implemented in the frontend.

