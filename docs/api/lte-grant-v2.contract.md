# POLARIS LTE Grant V2 API contract

Version: `polaris.live-grant.v2`  
Profile: `LTE-SRSUE-TEST-01`  
Scenario: `lte-e2e-certification-v1`

This contract is additive. Existing UERANSIM V1 grants keep their current
shape, but can never authorize LTE. Mixed V1/V2 request bodies return
`422 LIVE_GRANT_SCHEMA_AMBIGUOUS`.

## Routes

| Method | Route | Role | CSRF | Purpose |
|---|---|---|---|---|
| GET | `/api/v1/lte/profiles/LTE-SRSUE-TEST-01` | Viewer+ | no | Sanitized persistent profile and current configuration hash |
| PATCH | `/api/v1/lte/profiles/LTE-SRSUE-TEST-01` | Administrator | yes | Enable/disable the profile; body `{ "enabled": boolean }` |
| POST | `/api/v1/live/grant` | Operator+ | yes | Issue V1 or exact V2 grant; V2 requires `Idempotency-Key` |
| GET | `/api/v1/live/grant` | Viewer+ | no | V1 `grants` plus sanitized V2 `lte_grants` |
| DELETE | `/api/v1/live/grant/:grant_id` | Operator+ | yes | Durable revocation |
| POST | `/api/v1/lte/runs` | Operator+ | yes | Atomically consume V2 grant; requires `Idempotency-Key` and `X-Polaris-Grant-Nonce` |
| GET | `/api/v1/lte/runs/:run_id` | Viewer+ | no | Sanitized run/evidence state |
| POST | `/api/v1/lte/runs/:run_id/stop` | Operator+ | yes | Idempotent cleanup, valid after expiry/revocation |

The V2 request/response schemas and bounds are those in
`/root/LTE_GRANT_CONTRACT.md`. Nonces are hashed before persistence and never
returned. Grant/run idempotency keys are also stored only as SHA-256 hashes.
The persistent stores are atomically replaced with mode `0600`.

## Runtime ownership

Only Compose project `oiran-lab`, file
`/root/POLARIS/compose/docker-compose.oiran-lab.yml`, services `srsenb` and
`srsue`, and the pinned image digest from the LTE profile are targetable.
Labels and image are checked before every operation. Commands are fixed argv
under `/usr/bin/timeout 30s`; no HTTP value becomes a command argument.

Direct `POST /api/v1/lte/components/start` is retained only as a compatibility
surface and returns `423 LTE_GRANT_V2_REQUIRED` in live mode. Stop remains
grant-independent to prevent stranded processes.

## Evidence handoff to ANR1 and ANR3

Run responses identify `evidence_schema = polaris.lte-evidence.v1`. Evidence
must use ANR1's canonical schema and must not include subscriber identities.
Before ANR3 ingestion, every `evidence_ref` must resolve to an approved
`capture_ref` containing SHA-256, first/last frame and
`sanitization_state = SANITIZED_APPROVED`. Correlation is based on scoped
S1AP identifiers, EBI, F-TEID/TEID and endpoint roles; timestamp proximity
alone is not a correlation key.

## Current offline limitation

Grant persistence, subject binding, runtime allowlisting, startup of the eNB
phase and cleanup are implemented. The complete asynchronous state machine
(S1 readiness, attach, bounded ping/UDP sidecars and evidence publication) is
not implemented by this change. Consequently the profile defaults disabled,
both deployment/certification flags default false, and live certification
remains blocked.

— ANR2
