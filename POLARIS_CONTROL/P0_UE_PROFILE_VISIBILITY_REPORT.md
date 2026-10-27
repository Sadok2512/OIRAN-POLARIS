# P0 UE Profile Visibility Implementation Report

Date: 2026-10-26  
Branch: `feat/p0-configured-profile-visibility`  
Candidate version: Platform/Web 3.2.1, API 0.8.1

## Root cause

`GET /api/v1/ues` returned all configured profiles in `configured_profiles`, but its `items` collection contained only an observed shared UE or non-stopped controller jobs. Both the Console and the UE Manager rendered `items`, so configured profiles without a process were absent.

## Correction

The API now produces one `items` row for each configured profile and joins an observed shared process or persisted controller job by stable `internal_ue_id`. Profile existence, subscriber provisioning, process state, Registration state, PDU Session state, and traffic state remain independent.

For the current three-profile configuration:

| Profile | Provisioning | Process | Registration | PDU Session |
|---|---|---|---|---|
| UE-01 | VERIFIED | RUNNING | REGISTERED | ACTIVE |
| UE-02 | VERIFIED | NOT_STARTED | NOT_OBSERVED | INACTIVE |
| UE-03 | VERIFIED | NOT_STARTED | NOT_OBSERVED | INACTIVE |

UE-02 and UE-03 are not labeled `NOT PROVISIONED`: the backend verifies their subscriber profiles. When provisioning cannot be verified, the API emits `PROVISIONING_UNKNOWN` and offers a read-only provisioning review action. It never writes Open5GS.

All Start actions remain controlled by the existing authorization and live-certification policy. Configuration and page refresh do not start any process.

## UI integration

- The configured-profile table lists only profiles selected by persistent configuration.
- The state table displays the same configured inventory with independent runtime dimensions.
- The Console consumes the same authoritative `items` collection.
- Applying configuration already reloads both configuration and UE inventory endpoints.
- Light and Dark themes and the compact table layout are preserved.

## Deployment status

The correction was validated on an isolated candidate at `127.0.0.1:49155`. It was not installed into or restarted on the production service because this mission explicitly withheld deployment authorization.

No UE or gNB process was started. No Open5GS subscriber was created or modified. POLARIS, OIRAN, ETV, and OTV were not changed.
