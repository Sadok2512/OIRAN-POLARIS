# Open5GS Subscriber Readiness

## Observed

The read-only query used `open5gs.subscribers` in the laboratory MongoDB. It returned exactly **1** subscriber. No subscriber identity or authentication value is included here.

| Attribute | Sanitized result |
|---|---|
| Provisioned profiles | 1 |
| Required profiles | 5 |
| Missing profiles | 4 |
| PLMN compatibility | `001/01`, matches AMF/gNB/UE |
| DNN compatibility | `internet`, matches SMF/UPF/UE |
| S-NSSAI compatibility | SST 1, SD `010203`, matches AMF/NSSF/gNB/UE |
| Existing authentication consistency | Identity, K, OPc and AMF comparisons all matched; only booleans and lengths were emitted |
| Authentication field format | K and OPc are each 32 hexadecimal characters |

## Required before approval

An authorized Open5GS administrator must provision four additional synthetic subscribers with unique identities and unique authentication material, while retaining PLMN `001/01`, DNN `internet`, and S-NSSAI `1/010203`. Five matching UE configuration files must then be stored outside Git with restrictive permissions. This audit did not create or change records.

Readiness: `BLOCKED_PROVISIONING`.

