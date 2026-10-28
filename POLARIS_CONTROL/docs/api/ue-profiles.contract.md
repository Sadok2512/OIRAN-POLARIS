# UE Profiles API contract

API version: `0.10.0`. Base path: `/api/v1`. Mutations require an authenticated
Operator or Administrator session and its CSRF header. Reads never expose SUPI, K or OPc.

## Routes

| Method | Path | Result |
|---|---|---|
| `GET` | `/ue-profiles?page=1&page_size=100&search=&scenario_id=&subscription_status=` | Paginated sanitized profiles. `page >= 1`; `page_size` is clamped to `1..500`. Status filter accepts `VERIFIED` or `PROVISIONING_REQUIRED`. |
| `POST` | `/ue-profiles` | Creates one stopped local profile and restricted UERANSIM YAML. Does **not** provision Open5GS. |
| `PUT` | `/ue-profiles/:ue_id` | Replaces public fields on a stopped profile. The ID is immutable. All three secret fields may be `null` together to preserve existing material. |
| `DELETE` | `/ue-profiles/:ue_id` | Deletes a stopped POLARIS-owned local profile and YAML. Does **not** delete an Open5GS subscription. |
| `POST` | `/ue-profiles/:ue_id/clone` | Creates a stopped profile with a new UE ID, generated local SUPI/K/OPc and `PROVISIONING_REQUIRED`. |
| `POST` | `/ue-profiles/bulk` | Creates exactly `10`, `100`, `1000` or `10000` local profiles; total registry capacity is `10000`; starts zero UEs. |
| `GET` | `/ue-profiles/export.csv` | Sanitized CSV export. |
| `POST` | `/ue-profiles/:ue_id/validate-provisioning` | Read/attest existing provisioning; returns `open5gs_changed:false`. |

There is no CSV import route in this version.

## Shapes and protection

Create/replace input fields are `ue_id`, `name`, `supi`, `authentication_key`, `opc`,
`plmn_mcc`, `plmn_mnc`, `dnn`, `sst`, `sd`, `serving_gnb`, `scenario_id`, and
`auto_run_scenario`. `supi`, `authentication_key`, and `opc` are write-only.

Every JSON read represents them only as:

```json
{"authentication_material":"PROTECTED","subscriber_identity":"PROTECTED"}
```

The CSV columns, in order, are:

```text
ue_id,name,mcc,mnc,dnn,sst,sd,serving_gnb,scenario_id,subscription_status
```

## Measured examples

The following commands were executed against an isolated `0.10.0` API on
`127.0.0.1:49254`; `$COOKIE_JAR` and `$CSRF` were populated by `/auth/login` and are not
printed.

```bash
curl -sS -b "$COOKIE_JAR" -H "x-csrf-token: $CSRF" -H 'content-type: application/json' \
  -d '{"ue_id":"UE-11","name":"Contract UE 11","supi":"imsi-001010000000011","authentication_key":"11111111111111111111111111111111","opc":"22222222222222222222222222222222","plmn_mcc":"001","plmn_mnc":"01","dnn":"internet","sst":1,"sd":"010203","serving_gnb":"GNB-01","scenario_id":null,"auto_run_scenario":false}' \
  http://127.0.0.1:49254/api/v1/ue-profiles | jq -cS .
```

```json
{"authentication_material":"PROTECTED","auto_run_scenario":false,"dnn":"internet","name":"Contract UE 11","pdu_session":{"dnn":"internet","type":"IPv4"},"plmn":{"mcc":"001","mnc":"01"},"profile":"ue-11.yaml","revision":1,"scenario_id":null,"serving_gnb":"GNB-01","snssai":{"sd":"010203","sst":1},"subscriber_identity":"PROTECTED","subscription_status":"PROVISIONING_REQUIRED","ue_id":"UE-11","updated_at_epoch_s":1793186621}
```

```bash
curl -sS 'http://127.0.0.1:49254/api/v1/ue-profiles?page=1&page_size=1&search=UE-11' | jq -cS .
```

```json
{"items":[{"authentication_material":"PROTECTED","auto_run_scenario":false,"dnn":"internet","name":"Contract UE 11","pdu_session":{"dnn":"internet","type":"IPv4"},"plmn":{"mcc":"001","mnc":"01"},"profile":"ue-11.yaml","revision":1,"scenario_id":null,"serving_gnb":"GNB-01","snssai":{"sd":"010203","sst":1},"subscriber_identity":"PROTECTED","subscription_status":"PROVISIONING_REQUIRED","ue_id":"UE-11","updated_at_epoch_s":1793186621}],"max":10000,"page":1,"page_size":1,"pages":1,"secrets_exposed":false,"total":1}
```

```bash
curl -sS -X PUT -b "$COOKIE_JAR" -H "x-csrf-token: $CSRF" -H 'content-type: application/json' \
  -d '{"ue_id":"UE-11","name":"Contract UE 11 updated","supi":null,"authentication_key":null,"opc":null,"plmn_mcc":"001","plmn_mnc":"01","dnn":"internet","sst":1,"sd":"010203","serving_gnb":"GNB-01","scenario_id":"scenario-contract","auto_run_scenario":false}' \
  http://127.0.0.1:49254/api/v1/ue-profiles/UE-11 | jq -cS .
```

```json
{"authentication_material":"PROTECTED","auto_run_scenario":false,"dnn":"internet","name":"Contract UE 11 updated","pdu_session":{"dnn":"internet","type":"IPv4"},"plmn":{"mcc":"001","mnc":"01"},"profile":"ue-11.yaml","revision":2,"scenario_id":"scenario-contract","serving_gnb":"GNB-01","snssai":{"sd":"010203","sst":1},"subscriber_identity":"PROTECTED","subscription_status":"PROVISIONING_REQUIRED","ue_id":"UE-11","updated_at_epoch_s":1793186621}
```

```bash
curl -sS -b "$COOKIE_JAR" -H "x-csrf-token: $CSRF" -H 'content-type: application/json' \
  -d '{"target_ue_id":"UE-12"}' http://127.0.0.1:49254/api/v1/ue-profiles/UE-11/clone | jq -cS .
```

```json
{"authentication_material":"PROTECTED","auto_run_scenario":false,"dnn":"internet","name":"Contract UE 11 updated CLONE","pdu_session":{"dnn":"internet","type":"IPv4"},"plmn":{"mcc":"001","mnc":"01"},"profile":"ue-12.yaml","revision":1,"scenario_id":"scenario-contract","serving_gnb":"GNB-01","snssai":{"sd":"010203","sst":1},"subscriber_identity":"PROTECTED","subscription_status":"PROVISIONING_REQUIRED","ue_id":"UE-12","updated_at_epoch_s":1793186621}
```

```bash
curl -sS -X DELETE -b "$COOKIE_JAR" -H "x-csrf-token: $CSRF" \
  http://127.0.0.1:49254/api/v1/ue-profiles/UE-12 | jq -cS .
```

```json
{"deleted":"UE-12","profile_secret_deleted":true}
```

```bash
curl -sS http://127.0.0.1:49254/api/v1/ue-profiles/export.csv | head -n 3
```

```text
ue_id,name,mcc,mnc,dnn,sst,sd,serving_gnb,scenario_id,subscription_status
"UE-01","UE-PSEUDONYM-01","001","01","internet","1","010203","GNB-01","","PROVISIONING_REQUIRED"
"UE-11","Contract UE 11 updated","001","01","internet","1","010203","GNB-01","scenario-contract","PROVISIONING_REQUIRED"
```

## Error contract

| HTTP | Codes |
|---|---|
| `403` | `OPERATOR_PERMISSION_REQUIRED`, `CSRF_TOKEN_REQUIRED` |
| `404` | `UNKNOWN_UE_PROFILE` |
| `409` | `UE_PROFILE_ALREADY_EXISTS`, `DUPLICATE_SUBSCRIBER_IDENTITY` |
| `423` | `UE_PROFILE_ACTIVE`, `SHARED_UE_PROTECTED` |
| `422` | Invalid/partial secrets, invalid immutable ID, invalid fields, invalid bulk count, capacity or persistence/validation failure. The exact backend code is returned in `{"error":"..."}`. |

## Current integration boundaries

- `POST` and `DELETE` modify only the POLARIS registry/YAML/controller state: Open5GS is not changed.
- `serving_gnb` is persisted and returned, but currently no profile field feeds `gnbSearchList`;
  the UERANSIM renderer emits the fixed address `10.77.0.20`.
