# POLARIS Runtime Inventory — Read Only

Observed on 2026-10-26 through the existing read-only POLARIS Control API:

| Item | Observed |
|---|---:|
| Configured UE profiles | 3 |
| Running UE processes | 3 |
| Registered UEs | 3 |
| Active PDU sessions | 3 |
| Running gNBs | 1 |

UE-01, UE-02 and UE-03 were each reported RUNNING, REGISTERED and PDU ACTIVE on GNB-01. Their traffic state was IDLE. This runtime inventory does not prove that corresponding N2/N3/N4 establishment packets exist in an OIRAN dataset, and it was not used to fabricate sessions.

No subscriber identity, authentication credential or secret was read into this report. No POLARIS process, subscriber, configuration or service was changed.
