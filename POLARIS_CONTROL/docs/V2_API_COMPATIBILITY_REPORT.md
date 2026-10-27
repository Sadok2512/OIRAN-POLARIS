# POLARIS Control V2 API Compatibility

Existing `/api/v1` routes remain available. V2 adds read-only capability and runtime detail without changing the scenario validation payload.

| Route | Purpose | State |
|---|---|---|
| `GET /api/v1/capabilities` | Technologies, services, limits, profiles, approval state | Expanded, backward compatible |
| `GET /api/v1/ues` | Profile and active UE inventory | Added |
| `GET /api/v1/traffic/status` | Actual controller traffic state | Added |
| `GET /api/v1/scenarios/running` | Controller-owned active scenarios | Added |
| `POST /api/v1/scenarios/validate` | Bounded schema validation | Preserved |
| `POST /api/v1/scenarios/start` | Lifecycle execution | Locked |
| `POST /api/v1/scenarios/stop` | Exact owned-job stop | Locked |
| `GET /api/v1/system/health` | Disk, memory, load, uptime, limits | Expanded |

API version is `0.2.0`; platform version is `2.0.0-dev`.
