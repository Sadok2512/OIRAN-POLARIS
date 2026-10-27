# Capture Group Schema

`CaptureRequest` accepts optional `capture_group_id` and `scenario_id`; absent group IDs are generated from the immutable capture ID. `CaptureJob.planes[]` contains `plane`, `interface`, `capture_job_id`, start/end timestamps, packet/byte/drop/storage counters, decode status, dataset ID, source SHA256 values and an explicit error. `GET /api/v1/capture-groups` and `GET /api/v1/capture-groups/{id}` expose grouped jobs. Partial evidence is retained rather than collapsed into a false group-wide success.
