# V3.2 UERANSIM Profile Validation

- Profile location: `/var/lib/polaris-control/ue-profiles`
- Directory mode: 0700.
- Profile modes: 0600.
- Profiles present: 10 (`ue-01.yaml` through `ue-10.yaml`).
- One-to-one database/profile matches: 10/10.
- Duplicate identities: 0.
- Duplicate authentication keys: 0.
- Duplicate OPc values: 0.
- PLMN compatibility: 10/10.
- DNN compatibility: 10/10.
- S-NSSAI compatibility: 10/10.
- AMF compatibility: 10/10.
- gNB search target compatibility: 10/10.

The UE-01 generated profile is byte-identical to the pre-existing shared UERANSIM profile. Profiles UE-02 through UE-10 were generated but not executed. Profile files and the provisioning plan remain outside Git and are accessible only to root.
