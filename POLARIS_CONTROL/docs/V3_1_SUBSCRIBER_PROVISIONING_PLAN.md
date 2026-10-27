# V3.1 Subscriber Provisioning Plan

Current evidence shows one compatible synthetic subscriber. Four additional subscribers are required for five simultaneous UEs.

An authorized Open5GS administrator must create four new synthetic records idempotently. Each record must use a unique subscriber identity, K and OPc; PLMN `001/01`; DNN `internet`; and S-NSSAI SST `1`, SD `010203`. Existing records must be compared by identity and left unchanged.

Secrets must be generated through an approved cryptographic source, supplied to the provisioning tool through protected input, stored outside Git with mode `0600`, and never returned by API, audit log or UI. Reports may retain only pseudonym, verification booleans and configuration fingerprints.

After provisioning, the administrator must verify subscriber count, field lengths, PLMN/DNN/S-NSSAI compatibility and one-to-one mapping to `UE-01` through `UE-05`. Rollback removes only the four newly created, transaction-recorded synthetic records after explicit approval. This mission did not run this procedure.

