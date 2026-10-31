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

— **ANR1**
