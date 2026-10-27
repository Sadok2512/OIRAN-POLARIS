# UE Profile Assignment Plan

| UE pseudonym | Target gNB | Search endpoint | Profile state | Proposed management endpoint |
|---|---|---|---|---|
| UE-01 | gNB-01 | `10.77.0.20` | Existing, provisioned | Existing `.21` |
| UE-02 | gNB-01 | `10.77.0.20` | Missing | Proposed `.23` |
| UE-03 | gNB-01 | `10.77.0.20` | Missing | Proposed `.24` |
| UE-04 | gNB-02 | `10.77.0.22` | Missing | Proposed `.25` |
| UE-05 | gNB-02 | `10.77.0.22` | Missing | Proposed `.26` |

All proposed endpoints are currently unallocated in the inspected `/24`; they must be revalidated before deployment. Each UE requires a unique synthetic subscription, separate secret file, and independent container/network namespace. Reusing `uesimtun0` is safe only across separate namespaces; multiple UEs in one namespace would conflict.

Common compatible settings: PLMN `001/01`, DNN `internet`, S-NSSAI `1/010203`, one IPv4 PDU session.

`gnbSearchList` constrains the radio simulation endpoint but is not proof of attachment. Verify actual placement with: gNB-specific RRC logs, NGAP association/source endpoint, Global RAN Node ID/NCI, per-UE RAN/AMF UE NGAP IDs, and OIRAN packet provenance. Never correlate by time alone.

Ready profiles: `1/5`. Missing profiles: `4/5`.

