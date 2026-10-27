# S5.5 API Contract

- Existing `/api/v1/captures`, validation, start, stop, dataset, session and call-flow routes remain compatible.
- Capture requests add optional `capture_group_id` and `scenario_id`.
- Capture jobs add a backward-compatible `planes` array.
- `GET /api/v1/capture-groups` lists synchronized groups.
- `GET /api/v1/capture-groups/{id}` resolves one exact group or returns 404.
- SBI interfaces report protocol `SBI-HTTP2`; no synthetic telemetry is returned.
