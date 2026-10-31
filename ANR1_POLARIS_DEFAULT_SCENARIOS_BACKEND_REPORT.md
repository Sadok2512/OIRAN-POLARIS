# ANR1 — POLARIS default scenarios backend V1

Date: 2026-10-31

Base: `87daa3445e3058352d21efeba21d05fefe3029d4`

Branch: `anr1/polaris-default-scenarios-backend-v1`
API version: `0.24.0` (minor: additive catalogue and definition metadata)

## Result

The backend now exposes an immutable, versioned catalogue of 13 professional
templates: six LTE/srsRAN and seven 5G-SA/UERANSIM. The catalogue uses the
requested defaults (one UE, ONCE, UDP 1 Mbit/s, 60 seconds), does not advertise
multi-UE execution, and never converts UDP requests into TCP silently.

Status distribution:

- `SUPPORTED`: three existing 5G lifecycle/session templates;
- `CERTIFICATION_REQUIRED`: LTE Attach and LTE Detach;
- `BACKEND_REQUIRED`: eight LTE/5G UDP rate-and-duration templates whose exact
  execution semantics do not yet exist.

System templates are read-only and cloneable. Clone creates a persistent user
definition with `source_definition_id`, copied RAT/simulator metadata and an
independent integer revision. PUT from an older client preserves RAT,
simulator, description and provenance when those fields are omitted.

## API contract

Published contract: `POLARIS_CONTROL/docs/api/scenario-templates.contract.md`

Contract review SHA: `ff748ef`
ANR3 verdict: `READY_CONTRACT` (no remaining contract blocker).

Added routes:

- `GET /api/v1/scenario-templates`
- `GET /api/v1/scenario-templates/:template_id`

Existing clone route is retained and made durable:

- `POST /api/v1/scenario-definitions/:template_id/clone`

Existing definition responses are additively enriched with RAT, simulator,
description, scope, mutability, cloneability, provenance and backend support.

## Validation and security

Server-side validation rejects RAT/simulator mismatch, altered system-step
order, invalid/unknown steps, implicit TCP, out-of-range duration/rate/bytes,
excess loop depth/count and more than 10,000 resolved steps. Start remains
subject to RBAC, CSRF, ownership, resource policy, Grant V2 and RAT
certification. `BACKEND_REQUIRED` fails closed with HTTP 422 and no side
effect. Existing user scenarios survive migration unchanged.

No subscriber identity or credential was added to source, fixtures or API
examples. No UI component was modified.

## Manual test evidence

Commands executed from `POLARIS_CONTROL`:

```text
cargo check -p polaris-control-api
PASS

cargo test -p polaris-control-api scenario_definitions::tests -- --nocapture
13 passed; 0 failed; 0 ignored

cargo test -p polaris-control-api professional_template_catalog_is_versioned_cloneable_and_fail_closed -- --nocapture
1 passed; 0 failed

cargo test -p polaris-control-api
228 passed; 0 failed; 3 ignored
```

The three ignored tests are pre-existing manual large-profile/MongoDB tests;
none belongs to this catalogue change. Formatting and patch checks passed for
the touched Rust modules.

## Safety evidence

```text
df -h /
/dev/sda1 387G 180G 207G 47%

awk '/MemAvailable/ {print}' /proc/meminfo
MemAvailable: 4676008 kB

pgrep -a dumpcap | wc -l
12
```

No live execution, deployment, service restart, UE action or capture change
was performed.

## Verdict

`READY` for backend review and ANR3 frontend integration. Runtime certification
of LTE and the UDP rate/duration executor remain explicitly gated; this report
does not claim `REAL_PASS`.

— **ANR1**
