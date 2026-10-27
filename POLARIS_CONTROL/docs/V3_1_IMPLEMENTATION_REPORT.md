# POLARIS Control V3.1 Implementation Report

## Result

V3.1 introduces an offline-validated multi-UE control boundary without enabling unapproved simulator execution. The Rust controller represents five distinct UE profiles, maintains independent process, Registration, PDU Session and traffic state, and supports idempotent single/group operations with exact ownership.

The API advertises five configurable profiles and two-node architecture capacity while retaining the certified limits of one shared UE and one shared gNB. Start requests fail closed with the relevant provisioning or LIVE approval state. Stop operates only on exact controller registry entries and never targets shared UERANSIM or Open5GS processes.

The UE Manager displays planned/configured, running, registered and PDU-active counts separately. It provides Add UE, Start UE, Stop UE, Start Selected and Stop Selected controls; disabled actions expose their precise certification or provisioning reason.

## Architecture

- `ueransim-adapter 0.2.0`: sanitized profile specification, uniqueness/PLMN checks and in-memory secret-dependent YAML rendering.
- `simulator-controller 0.2.0`: five-UE registry, lifecycle isolation and fail-closed restart recovery.
- `polaris-control-api 0.7.0`: authenticated single/group UE contracts and truthful capability limits.
- `polaris-control-web 3.1.0`: multi-UE inventory and selection workflow.

No subscriber database, POLARIS configuration, shared process, OIRAN source or ETV/OTV resource was changed.

Controller-owned UE records are atomically persisted to the configurable `POLARIS_UE_JOB_STATE_PATH` (default `/var/lib/polaris-control/ue-jobs.json`, mode `0600`). After a controller restart, a previously active record is marked `FAILED/UNKNOWN` until exact process ownership can be reconciled; it is never assumed to still be running.

