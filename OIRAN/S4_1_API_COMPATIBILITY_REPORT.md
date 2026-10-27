# S4.1 API compatibility report

API 1.1 retains every S4 `/api/v1` route and envelope. Existing session IDs, event IDs, exports and the certified Call Flow schema are unchanged.

New authenticated read routes:

- `GET /api/v1/datasets`
- `GET /api/v1/datasets/{id}`
- `GET /api/v1/datasets/{id}/sessions`
- `GET /api/v1/ues`
- `GET /api/v1/ues/{id}`
- `GET /api/v1/ues/{id}/sessions`
- `GET /api/v1/sessions/{id}/procedures`

`GET /sessions` adds optional `dataset_id`, `ue_id`, `technology`, `status` and `interface` filters while preserving search, sort, order and pagination. Session summaries add `dataset_id`, `ue_context_id`, `pdu_session_id` and `duration_ns`; these are additive fields.

Bearer authentication, constant-time token comparison, path sanitization and read-only authorization remain enforced. No import, reprocess or mutation endpoint is exposed.
