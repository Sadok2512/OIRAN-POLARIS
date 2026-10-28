# POLARIS subscriber provisioning API — 0.15.0

All mutation routes require an authenticated Operator session and a valid CSRF header. IMSI, K,
and OPc are write-only: response schemas use `PROTECTED`, audit records contain only the generated
slot, and errors never echo request values.

## Routes

| Method | Route | Contract |
|---|---|---|
| `GET` | `/api/v1/subscribers` | Sanitized POLARIS-owned Open5GS subscribers only. |
| `POST` | `/api/v1/subscribers` | Validates, runs `mongodump`, then inserts one POLARIS-owned record. |
| `POST` | `/api/v1/subscribers/bulk` | CSV, at most 100,000 data rows, processed in batches of 5,000. Each write batch has its own dump. |
| `GET` | `/api/v1/gnbs` | Configured gNB registry. |
| `GET` | `/api/v1/owners` | Owners present in the current UE registry. |
| `GET` | `/api/v1/plmns` | PLMNs present on POLARIS-owned Open5GS subscribers. |
| `GET` | `/api/v1/dnns` | DNNs present on POLARIS-owned Open5GS subscribers. |

Single-create request shape:

```json
{
  "imsi": "<15 decimal digits; write-only>",
  "k": "<32 hexadecimal characters; write-only>",
  "opc": "<32 hexadecimal characters; write-only>",
  "sst": 1,
  "sd": "010203",
  "dnns": ["internet", "ims"],
  "ambr": {"uplink": 1000000000, "downlink": 1000000000}
}
```

Created response shape:

```json
{
  "slot": "SUB-<12 hex>",
  "state": "PROVISIONED",
  "subscriber_identity": "PROTECTED",
  "authentication_material": "PROTECTED",
  "open5gs_changed": true
}
```

Bulk CSV columns, in exact order:

```text
imsi,k,opc,sst,sd,dnns,ambr_uplink,ambr_downlink
```

Multiple DNNs use `|`, for example `internet|ims`. Allowed DNNs are `internet` and `ims`.
The response is `{ok, errors, results[], secrets_exposed:false}`; each result contains only row,
status, slot, and error. `413` is returned above 100,000 data rows. Existing non-POLARIS records
return `409 SUBSCRIBER_NOT_POLARIS_OWNED` and are never changed.

Before every MongoDB write batch, the API executes `mongodump` for the `open5gs.subscribers`
collection and stores a mode-0600 archive below the protected backup root. A failed dump prevents
the write.
