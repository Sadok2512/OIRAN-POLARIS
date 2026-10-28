# Scenario Definitions API contract

API version: `0.12.1`. Base path: `/api/v1`. The catalog schema is `1` and is stored by
atomic private write in `/var/lib/polaris-control/scenario-definitions.json`.

## Routes

| Method | Path | Result |
|---|---|---|
| `GET` | `/scenario-definitions` | Complete definition list, total and catalog schema version. |
| `POST` | `/scenario-definitions` | Creates version `1`; Operator/Administrator plus CSRF required. |
| `GET` | `/scenario-definitions/:id` | One definition. |
| `PUT` | `/scenario-definitions/:id` | Replaces the definition and increments `version`; ID is immutable. |
| `DELETE` | `/scenario-definitions/:id` | Deletes one definition. |
| `POST` | `/scenario-definitions/:id/clone` | Creates `target_id` at version `1`. |
| `POST` | `/scenarios/start` | Accepts `scenario_definition_id` and `ue_ids`; Live requires both Live execution mode and `POLARIS_DEFINITION_LIVE_ENABLED=true`. |
| `GET` | `/scenarios/:job_id/steps` | Ordered resolved step states and parameters. |
| `POST` | `/scenarios/stop` | Requests graceful cancellation; stops only UEs started by that definition job. |

Allowed V1 step types are `ue_start`, `ue_stop`, `pdu_establish`, `pdu_release`,
`udp_traffic`, and `wait`. Any other value returns HTTP `422` with
`SCENARIO_STEP_TYPE_UNSUPPORTED`.

`loop_count` defaults to `1` both on the definition and on each step. For definition count
`N` and step count `M`, the complete ordered scenario is repeated `N` times and that step is
repeated `M` times inside each scenario iteration. The resolved total is capped at `10000`.
Parameters are either `{"fixed": value}` or integer `{"random":{"min":a,"max":b}}`.
Random values are selected by the backend and stored in `resolved_parameters`.

One `POST /scenarios/start` request creates one job containing all selected `ue_ids`, not one
job per UE. The Live definition executor permits one active definition job and preserves
`PENDING`, `RUNNING`, `COMPLETED`, or `FAILED` per-step evidence. The safety switch defaults to
disabled; a missing or non-exact value returns HTTP `423`.

`udp_traffic` reuses the certified five-datagram profile and rejects any other `packet_count`.
`pdu_establish` executes UERANSIM `nr-cli ps-establish IPv4` using the profile's validated DNN and
S-NSSAI, then requires the runtime to become `ACTIVE`. `pdu_release` executes
`nr-cli ps-release-all` and requires `INACTIVE`; it does not stop the UE or write Open5GS.

## Measured examples

Commands below were executed against the isolated mock API on `127.0.0.1:49254`.

```bash
curl -sS -b "$COOKIE_JAR" -H "x-csrf-token: $CSRF" -H 'content-type: application/json' \
  -d '{"id":"scenario-contract","name":"Contract scenario","loop_count":2,"steps":[{"type":"wait","loop_count":2,"parameters":{"duration_ms":{"fixed":5}}}]}' \
  http://127.0.0.1:49254/api/v1/scenario-definitions | jq -cS .
```

```json
{"created_at_epoch_s":1793186621,"id":"scenario-contract","loop_count":2,"name":"Contract scenario","steps":[{"loop_count":2,"parameters":{"duration_ms":{"fixed":5}},"type":"wait"}],"updated_at_epoch_s":1793186621,"version":1}
```

```bash
curl -sS -X PUT -b "$COOKIE_JAR" -H "x-csrf-token: $CSRF" -H 'content-type: application/json' \
  -d '{"id":"scenario-contract","name":"Contract scenario v2","loop_count":2,"steps":[{"type":"wait","loop_count":2,"parameters":{"duration_ms":{"fixed":5}}}]}' \
  http://127.0.0.1:49254/api/v1/scenario-definitions/scenario-contract | jq -cS .
```

```json
{"created_at_epoch_s":1793186621,"id":"scenario-contract","loop_count":2,"name":"Contract scenario v2","steps":[{"loop_count":2,"parameters":{"duration_ms":{"fixed":5}},"type":"wait"}],"updated_at_epoch_s":1793186621,"version":2}
```

```bash
curl -sS -b "$COOKIE_JAR" -H "x-csrf-token: $CSRF" -H 'content-type: application/json' \
  -d '{"scenario_definition_id":"scenario-contract","ue_ids":["UE-11"]}' \
  http://127.0.0.1:49254/api/v1/scenarios/start | jq -cS .
```

```json
{"ended_at_epoch_s":1793186621,"job_id":"scenario-contract-1a98345aaa93","scenario_definition_id":"scenario-contract","scenario_definition_version":2,"scenario_id":"scenario-contract","started_at_epoch_s":1793186621,"state":"COMPLETED","steps":[{"ended_at":1793186621,"error":null,"index":0,"resolved_parameters":{"duration_ms":5},"scenario_loop":{"count":2,"iteration":1},"started_at":1793186621,"state":"COMPLETED","step_loop":{"count":2,"iteration":1},"type":"wait"},{"ended_at":1793186621,"error":null,"index":0,"resolved_parameters":{"duration_ms":5},"scenario_loop":{"count":2,"iteration":1},"started_at":1793186621,"state":"COMPLETED","step_loop":{"count":2,"iteration":2},"type":"wait"},{"ended_at":1793186621,"error":null,"index":0,"resolved_parameters":{"duration_ms":5},"scenario_loop":{"count":2,"iteration":2},"started_at":1793186621,"state":"COMPLETED","step_loop":{"count":2,"iteration":1},"type":"wait"},{"ended_at":1793186621,"error":null,"index":0,"resolved_parameters":{"duration_ms":5},"scenario_loop":{"count":2,"iteration":2},"started_at":1793186621,"state":"COMPLETED","step_loop":{"count":2,"iteration":2},"type":"wait"}],"terminal_result":"OFFLINE_MOCK_COMPLETED","traffic_state":"NOT_EXECUTED_OFFLINE","ue_ids":["UE-11"]}
```

```bash
curl -sS http://127.0.0.1:49254/api/v1/scenarios/scenario-contract-1a98345aaa93/steps | jq -cS .
```

```json
{"job_id":"scenario-contract-1a98345aaa93","scenario_definition_id":"scenario-contract","steps":[{"ended_at":1793186621,"error":null,"index":0,"resolved_parameters":{"duration_ms":5},"scenario_loop":{"count":2,"iteration":1},"started_at":1793186621,"state":"COMPLETED","step_loop":{"count":2,"iteration":1},"type":"wait"},{"ended_at":1793186621,"error":null,"index":0,"resolved_parameters":{"duration_ms":5},"scenario_loop":{"count":2,"iteration":1},"started_at":1793186621,"state":"COMPLETED","step_loop":{"count":2,"iteration":2},"type":"wait"},{"ended_at":1793186621,"error":null,"index":0,"resolved_parameters":{"duration_ms":5},"scenario_loop":{"count":2,"iteration":2},"started_at":1793186621,"state":"COMPLETED","step_loop":{"count":2,"iteration":1},"type":"wait"},{"ended_at":1793186621,"error":null,"index":0,"resolved_parameters":{"duration_ms":5},"scenario_loop":{"count":2,"iteration":2},"started_at":1793186621,"state":"COMPLETED","step_loop":{"count":2,"iteration":2},"type":"wait"}]}
```

```bash
curl -sS -o error.json -w 'HTTP %{http_code}\n' -b "$COOKIE_JAR" \
  -H "x-csrf-token: $CSRF" -H 'content-type: application/json' \
  -d '{"id":"bad-step","name":"Bad","steps":[{"type":"rrc_idle","parameters":{}}]}' \
  http://127.0.0.1:49254/api/v1/scenario-definitions
```

```text
HTTP 422
{"error":"SCENARIO_STEP_TYPE_UNSUPPORTED"}
```

## Error contract

| HTTP | Codes |
|---|---|
| `403` | `OPERATOR_PERMISSION_REQUIRED`, `CSRF_TOKEN_REQUIRED` |
| `404` | `SCENARIO_DEFINITION_NOT_FOUND`, `SCENARIO_JOB_NOT_FOUND` |
| `409` | `SCENARIO_DEFINITION_ALREADY_EXISTS` |
| `422` | Invalid ID/name, immutable ID, step count/type, loop count, resolved-step cap, parameter/range, duplicate/invalid UE selection or unowned UE. Exact code is returned in `error`. |
| `423` | `SCENARIO_DEFINITION_LIVE_EXECUTION_NOT_AUTHORIZED` unless explicitly enabled in Live mode. |
