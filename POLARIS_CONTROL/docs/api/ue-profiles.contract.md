# UE Profiles API contract

API version: `0.11.0`. Base path: `/api/v1`. Mutations require an authenticated
Operator or Administrator session and its CSRF header. Reads never expose SUPI, K or OPc.

## Routes

| Method | Path | Result |
|---|---|---|
| `GET` | `/ue-profiles?page=1&page_size=100&search=&scenario_id=&subscription_status=` | Paginated sanitized profiles. `page >= 1`; `page_size` is clamped to `1..500`. Status filter accepts `VERIFIED` or `PROVISIONING_REQUIRED`. |
| `GET` | `/ue-profiles/:id` | Sanitized profile detail, observed PDU state, IMS availability, scenario assignment, and last-job UL/DL bytes. |
| `POST` | `/ue-profiles` | Creates one stopped local profile and restricted UERANSIM YAML. Does **not** provision Open5GS. |
| `PUT` | `/ue-profiles/:ue_id` | Replaces public fields on a stopped profile. The ID is immutable. All three secret fields may be `null` together to preserve existing material. |
| `DELETE` | `/ue-profiles/:ue_id` | Deletes a stopped POLARIS-owned local profile and YAML. Does **not** delete an Open5GS subscription. |
| `POST` | `/ue-profiles/:ue_id/clone` | Creates a stopped profile with a new UE ID, generated local SUPI/K/OPc and `PROVISIONING_REQUIRED`. |
| `POST` | `/ue-profiles/bulk` | Creates exactly `10`, `100`, `1000` or `10000` local profiles; total registry capacity is `10000`; starts zero UEs. |
| `GET` | `/ue-profiles/export.csv` | Sanitized CSV export. |
| `GET` | `/ue-profiles/provisioning-slots` | Subscribers already provisioned in Open5GS (from the private V3.2 plan): slot id and bound UE only, never secrets. `503` with `PROVISIONING_SLOTS_UNAVAILABLE` / `SUBSCRIBER_PLAN_UNSAFE` / `SUBSCRIBER_PLAN_INVALID` when the plan cannot be used. |
| `GET` | `/gnbs` | gNB registry a profile may name as `serving_gnb`: `{items:[{gnb_id,link_ip}], total, source}`; `source` is `LAB_DEFAULT` or `CONFIGURED_REGISTRY`. |
| `POST` | `/ue-profiles/:ue_id/validate-provisioning` | Read/attest existing provisioning; returns `open5gs_changed:false`. |

CSV import reuses `POST /ue-profiles/bulk` with `Content-Type: text/csv`; the JSON bulk-create
contract remains available on the same route.

## Shapes and protection

Create/replace input fields are `ue_id`, `name`, `supi`, `authentication_key`, `opc`,
`plmn_mcc`, `plmn_mnc`, `dnn`, `sst`, `sd`, `serving_gnb`, `scenario_id`, and
`auto_run_scenario`. `supi`, `authentication_key`, and `opc` are write-only.

API 0.15.0 additionally accepts this protected subscriber-binding request on `POST /ue-profiles`:

```json
{"ue_id":"UE-11","gnb_id":"GNB-01","note":"Lab profile","imsi":"<15 digits; write-only>"}
```

The server resolves the POLARIS-owned Open5GS subscriber and fills PLMN, S-NSSAI, preferred DNN,
AMBR/provisioning evidence, K, and OPc server-side. An unknown or non-POLARIS identity returns
`422 SUBSCRIBER_NOT_PROVISIONED`. Responses retain `subscriber_identity: PROTECTED` and
`authentication_material: PROTECTED`.

For CSV import, `POST /ue-profiles/bulk` also accepts `Content-Type: text/csv` with exact columns:

```text
ue_id,gnb_id,note,imsi
```

At most 100,000 input rows are parsed and individually reported. The persistent profile registry
still enforces its independently certified 10,000-profile capacity; excess rows return
`UE_PROFILE_CAPACITY_REACHED` rather than being silently dropped.

On creation, `provisioning_slot` (for example `"UE-02"`) may replace the three secret fields:
the backend then reads SUPI/K/OPc from the protected server-side plan. Sending a slot together
with any secret field is rejected (`PROVISIONING_SLOT_EXCLUDES_SECRETS`). A slot binds to at most
one profile (`409 DUPLICATE_SUBSCRIBER_IDENTITY`). Open5GS is not written.

`serving_gnb` must name an entry of `GET /gnbs`; it is rendered as the UE's `gnbSearchList`.
An unknown value is rejected with `422 UNKNOWN_SERVING_GNB`.

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

## Measured examples — 0.11.0 additions

Executed against an isolated `0.11.0` API in mock mode on `127.0.0.1:49299`, with a two-line
test plan (`UE-01`, `UE-02`) of synthetic test vectors. Session cookie and CSRF not printed.

```
curl -sS -b "$COOKIE_JAR" http://127.0.0.1:49299/api/v1/gnbs | jq -cS .
{"items":[{"gnb_id":"GNB-01","link_ip":"10.77.0.20"}],"source":"LAB_DEFAULT","total":1}

curl -sS -b "$COOKIE_JAR" http://127.0.0.1:49299/api/v1/ue-profiles/provisioning-slots | jq -cS .
{"available":2,"items":[{"bound_ue_id":null,"slot_id":"UE-01"},{"bound_ue_id":null,"slot_id":"UE-02"}],"secrets_exposed":false,"total":2}

curl -sS -b "$COOKIE_JAR" -H "x-csrf-token: $CSRF" -H 'content-type: application/json' \
  -d '{"ue_id":"UE-11","name":"Slot UE 11","supi":null,"authentication_key":null,"opc":null,"provisioning_slot":"UE-02","plmn_mcc":"001","plmn_mnc":"01","dnn":"internet","sst":1,"sd":"010203","serving_gnb":"GNB-01","scenario_id":null,"auto_run_scenario":false}' \
  http://127.0.0.1:49299/api/v1/ue-profiles | jq -cS .
{"authentication_material":"PROTECTED","auto_run_scenario":false,"dnn":"internet","name":"Slot UE 11","pdu_session":{"dnn":"internet","type":"IPv4"},"plmn":{"mcc":"001","mnc":"01"},"profile":"ue-11.yaml","revision":1,"scenario_id":null,"serving_gnb":"GNB-01","snssai":{"sd":"010203","sst":1},"subscriber_identity":"PROTECTED","subscription_status":"PROVISIONING_REQUIRED","ue_id":"UE-11","updated_at_epoch_s":1793189644}

# after binding
{"available":1,"items":[{"bound_ue_id":null,"slot_id":"UE-01"},{"bound_ue_id":"UE-11","slot_id":"UE-02"}],"secrets_exposed":false,"total":2}

# serving_gnb "GNB-99"
HTTP 422 {"error":"UNKNOWN_SERVING_GNB"}

# slot UE-02 again for UE-12
HTTP 409 {"error":"DUPLICATE_SUBSCRIBER_IDENTITY"}
```

A slot-bound profile still reports `PROVISIONING_REQUIRED` until `validate-provisioning`
succeeds against a regenerated provisioning attestation (`polaris-provisioning-attest`).

## Error contract

| HTTP | Codes |
|---|---|
| `403` | `OPERATOR_PERMISSION_REQUIRED`, `CSRF_TOKEN_REQUIRED` |
| `404` | `UNKNOWN_UE_PROFILE` |
| `422` (0.11.0) | `UNKNOWN_SERVING_GNB`, `UNKNOWN_PROVISIONING_SLOT`, `PROVISIONING_SLOT_EXCLUDES_SECRETS`, `PROVISIONING_SLOTS_UNAVAILABLE` |
| `409` | `UE_PROFILE_ALREADY_EXISTS`, `DUPLICATE_SUBSCRIBER_IDENTITY` |
| `423` | `UE_PROFILE_ACTIVE`, `SHARED_UE_PROTECTED` |
| `422` | Invalid/partial secrets, invalid immutable ID, invalid fields, invalid bulk count, capacity or persistence/validation failure. The exact backend code is returned in `{"error":"..."}`. |

## Current integration boundaries

- `POST` and `DELETE` modify only the POLARIS registry/YAML/controller state: Open5GS is not changed.
- Since 0.11.0, `serving_gnb` feeds `gnbSearchList` through the gNB registry; `GNB-01` output is
  byte-identical to 0.10.0.
