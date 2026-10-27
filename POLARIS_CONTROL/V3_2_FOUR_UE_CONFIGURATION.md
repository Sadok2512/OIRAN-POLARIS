# Four-UE Configuration Validation

The reviewed plan was applied as configuration only. To prevent reconciliation from starting UE-04, `POLARIS_ADDITIONAL_UE_LIVE_ENABLED=false` is active in the POLARIS Control configuration. Existing exact Stop behavior remains available for owned jobs.

| Metric | Actual |
|---|---:|
| Configured UE profiles | 4 |
| Running UE processes | 3 |
| Registered UEs | 3 |
| Active PDU Sessions | 3 |
| Configured/running gNB profiles | 1 / 1 |

UE-04 was verified in the root-only provisioning attestation without writing to Open5GS. Its state is `VERIFIED / CONFIGURED / NOT_STARTED / NOT_OBSERVED / INACTIVE / IDLE`. No UE-04 process, PDU Session, or traffic job exists.

The three protected UE process IDs and shared gNB PID remained unchanged across deployment: UE-01 `2833882`, UE-02 `1575608`, UE-03 `1576016`, gNB-01 `2773390`.

