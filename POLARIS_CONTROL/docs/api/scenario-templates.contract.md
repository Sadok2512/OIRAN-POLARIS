# POLARIS default scenario templates API v1

Contract: `polaris.scenario-template-catalog.v1`  
Owner: ANR1  
Status: backend contract; no live authorization

## Routes

| Method | Route | Access | Purpose |
|---|---|---|---|
| `GET` | `/api/v1/scenario-templates` | Viewer | Immutable system catalogue and defaults |
| `GET` | `/api/v1/scenario-templates/:template_id` | Viewer | One immutable descriptor |
| `POST` | `/api/v1/scenario-definitions/:template_id/clone` | Operator + CSRF | Durable mutable user copy |
| `GET` | `/api/v1/scenario-definitions` | Viewer | Existing definitions, additively enriched with catalogue metadata |
| `POST` | `/api/v1/scenarios/start` | Operator + CSRF + runtime gates | Existing execution route |

The existing Scenario Definition CRUD, estimate, import/export and job-step
routes remain compatible. System IDs keep the reserved `tpl-` prefix. A system
definition is `catalog_scope=SYSTEM`, `mutable=false`, `cloneable=true`; a
clone is `catalog_scope=USER`, `mutable=true`, version 1 and records
`source_definition_id`. Cloning never updates the original.

## Response envelopes

`GET /api/v1/scenario-templates` returns this exact envelope. `items` contains
the descriptors defined below; it is not a list of mutable definitions.

```json
{
  "schema_version": "polaris.scenario-template-catalog.v1",
  "items": [],
  "total": 13,
  "defaults": {
    "ue_count": 1,
    "execution": "ONCE",
    "transport": "UDP",
    "rate_bps": 1000000,
    "duration_seconds": 60,
    "tcp_authorized": false
  },
  "multi_ue_templates": false
}
```

`GET /api/v1/scenario-templates/:template_id` returns one descriptor directly,
without an envelope. An unknown ID returns HTTP 404 with
`{"error":"SCENARIO_DEFINITION_NOT_FOUND"}`.

Clone request:

```json
{"target_id":"my-5g-registration"}
```

The `target_id` must be a valid, unused user-definition ID and must not start
with `tpl-`. A successful clone returns HTTP 201 and the complete enriched
definition:

```json
{
  "id": "my-5g-registration",
  "name": "5G SA Registration",
  "version": 1,
  "loop_count": 1,
  "steps": [{"type":"ue_start","loop_count":1,"parameters":{}}],
  "created_at_epoch_s": 0,
  "updated_at_epoch_s": 0,
  "rat": "5G_SA",
  "simulator": "UERANSIM",
  "description": "5G SA Registration",
  "source_definition_id": "tpl-5g-registration",
  "catalog_scope": "USER",
  "mutable": true,
  "cloneable": true,
  "backend_support": "SUPPORTED"
}
```

The two epoch values above are placeholders for server-generated values, not
literal response requirements. Descriptor `version` is a SemVer string for an
immutable catalogue item. Definition `version` is an integer revision starting
at 1 and incremented on each successful update.

## Descriptor

```json
{
  "template_id": "tpl-5g-registration",
  "version": "1.0.0",
  "rat": "5G_SA",
  "simulator": "UERANSIM",
  "description": "5G SA Registration",
  "steps": [{"type":"ue_start","loop_count":1,"parameters":{}}],
  "parameters": {
    "ue_count": 1,
    "execution": "ONCE",
    "transport": "UDP",
    "rate_bps": 1000000,
    "duration_seconds": 60,
    "tcp_authorized": false,
    "multi_ue": false
  },
  "required_capabilities": ["ueransim_lifecycle","registration_observation"],
  "backend_support": "SUPPORTED",
  "certification_required": false,
  "read_only": true
}
```

`rat` is exactly `LTE` or `5G_SA`; its simulator is respectively `srsRAN` or
`UERANSIM`. `backend_support` is exactly:

- `SUPPORTED`: the backend implements every step; execution still requires
  ownership, RBAC, CSRF, resource policy and the applicable live grant;
- `BACKEND_REQUIRED`: the requested semantics are not implemented and Start
  returns `422 SCENARIO_BACKEND_REQUIRED` without side effects;
- `CERTIFICATION_REQUIRED`: the backend exists but the RAT procedure is not
  live-certified; existing certification/Grant V2 gates return HTTP 423.

The catalogue never treats UI visibility as execution permission.

`steps` use the existing `polaris.scenario-definition.v2` schema. A parameter
is either `{"fixed": <JSON scalar>}` (number, string or boolean) or
`{"random":{"min":<integer>,"max":<integer>}}`. The descriptor-level
`parameters` object is display/default metadata only. It MUST NOT be merged
into steps by a client; the server-side clone is the authoritative conversion
from descriptor to mutable definition. Clients must preserve string-valued
fixed parameters and support `transfer_verify` before exposing an editor for
definitions that contain it.

## System catalogue

| Template | RAT / simulator | Status |
|---|---|---|
| `tpl-lte-attach` | LTE / srsRAN | `CERTIFICATION_REQUIRED` |
| `tpl-lte-detach` | LTE / srsRAN | `CERTIFICATION_REQUIRED` |
| `tpl-lte-data-ul` | LTE / srsRAN | `BACKEND_REQUIRED` |
| `tpl-lte-data-dl` | LTE / srsRAN | `BACKEND_REQUIRED` |
| `tpl-lte-attach-data` | LTE / srsRAN | `BACKEND_REQUIRED` |
| `tpl-lte-full-session` | LTE / srsRAN | `BACKEND_REQUIRED` |
| `tpl-5g-registration` | 5G SA / UERANSIM | `SUPPORTED` |
| `tpl-5g-deregistration` | 5G SA / UERANSIM | `SUPPORTED` |
| `tpl-5g-pdu-session` | 5G SA / UERANSIM | `SUPPORTED` |
| `tpl-5g-data-ul` | 5G SA / UERANSIM | `BACKEND_REQUIRED` |
| `tpl-5g-data-dl` | 5G SA / UERANSIM | `BACKEND_REQUIRED` |
| `tpl-5g-registration-pdu-data` | 5G SA / UERANSIM | `BACKEND_REQUIRED` |
| `tpl-5g-full-session` | 5G SA / UERANSIM | `BACKEND_REQUIRED` |

The data templates encode UDP, 1,000,000 bit/s and 60 seconds. The current
traffic steps execute a different TCP/byte contract, so the server refuses
these templates instead of silently changing their meaning. TCP is accepted
only when `tcp_authorized=true` is explicit. No multi-UE system template is
advertised: LTE is one-UE certified scope and the new UDP profile is pending.

## Validation and preservation

The server rejects RAT/simulator mismatch, unknown step types, invalid order,
empty definitions, loop counts outside 1..10,000, more than 10,000 resolved
steps, traffic over 200 MiB, UDP rate outside 1..100,000,000 bit/s, duration
outside 1..300 seconds, and implicit TCP. Existing user definitions deserialize
with absent provenance and survive the idempotent system-template migration
byte-for-byte.

Mutation routes retain the existing Operator/Administrator, CSRF and audit
requirements. Start additionally retains UE ownership, resource gates,
live-grant snapshot/anti-replay and LTE certification/Grant V2 enforcement.
No subscriber identity or authentication material appears in this contract.

`GET /api/v1/scenario-definitions` and the single-definition response always
include `rat`, `simulator`, `description`, `catalog_scope`, `mutable`,
`cloneable` and `backend_support`. `source_definition_id` is present for a
clone and absent for an original user definition or a system definition.
Existing definitions missing RAT metadata migrate read-compatibly to
`5G_SA`/`UERANSIM`; their steps and identity remain unchanged. On PUT,
`rat`, `simulator` and `description` are optional. When omitted the server
preserves their existing values, as well as `source_definition_id`; this keeps
old frontend payloads from changing provenance or RAT.

— **ANR1**
