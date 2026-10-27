# POLARIS P0 Configurable Inventory Counts

## Outcome

The Console now exposes persistent numeric selectors for the desired gNB and UE inventory. The controls use backend-reported limits, are read-only for Viewers, and are writable by authenticated Operators and Administrators.

Changing the desired inventory does not start, stop, provision, or otherwise alter any simulator process. Live lifecycle certification remains one shared gNB and one shared UE.

## Implemented behavior

- UE profiles: selectable from 1 through 5.
- gNB profiles: selectable from 1 through 2.
- `Apply Configuration` persists the desired inventory through the authenticated Rust API.
- The Console reports configured, running, registered, and PDU-active counts separately.
- UE Manager provides an `Add UE` configuration-only action.
- Profiles beyond UE-01 are marked `PROVISIONING_REQUIRED`.
- gNB-02 remains `NOT_DEPLOYED` and `NOT_VALIDATED`.
- Existing lifecycle, disk, CPU, RAM, authorization, and process-ownership gates are unchanged.

## API contract

### `GET /api/v1/configuration`

Returns the desired counts, configurable limits, live-certified limits, missing subscriber count, persistence metadata, and `execution_started: false`.

### `POST /api/v1/configuration`

Requires an authenticated Operator or Administrator and a valid CSRF token.

```json
{
  "ue_count": 5,
  "gnb_count": 2
}
```

The request validates bounds, updates the configuration-only controller state, writes an atomic mode-0600 registry file, and creates an audit event. It never invokes a simulator executable.

## Safety

No Open5GS subscriber was created or modified. No UE or gNB process was started. POLARIS, OIRAN, ETV, and OTV were not modified.
