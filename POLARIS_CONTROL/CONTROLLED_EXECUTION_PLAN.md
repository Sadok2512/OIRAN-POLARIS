# Controlled Execution Plan

Execution is not authorized. The current controller cannot create UE/gNB processes and must be extended/tested before these phases.

## Universal preflight

Require: operator authorization for the exact phase; subscriber/config review; filesystem below 80% for 15 minutes; reserved capture budget; Open5GS healthy without restart; no conflicting controller job; CPU PSI not sustained; at least 8 GiB RAM available; exact job registry and PID/container ownership. Stop on 85% disk, OOM, service degradation, capture failure, timeout, or identity ambiguity.

| Phase | Owned additions | Budget / timeout | Expected evidence | Acceptance |
|---|---|---|---|---|
| B: 1 gNB + 2 UE | Two new UE containers attached to shared gNB-01; shared core/gNB untouched | 1.5 vCPU, 1 GiB; 5 min plus 10 min capture | 2 registrations, 2 PDU sessions, PFCP and bounded GTP-U | Two distinct UE contexts/tunnels; zero contamination |
| C: 1 gNB + 5 UE | Five scenario-owned UE containers, staggered; gNB-01 shared | 3.75 vCPU, 2.5 GiB; 8 min plus 10 min capture | 5 registrations/PDU sessions and per-UE bounded traffic | Five independent sessions on gNB-01 |
| D: 2 gNB + 5 UE | Scenario-owned gNB-02 plus five UE containers; gNB-01/core shared | 4.5 vCPU, 3 GiB; 10 min plus 10 min capture | Two NG Setup associations; 3+2 UE distribution; N2/N4/N3 | Correct gNB placement and five independent call flows |

For each phase: validate first, reserve resources, start captures, start only scenario-owned containers in staggered order, wait for observed registration/PDU states, send exactly five small UDP datagrams per UE to the approved laboratory endpoint, finalize captures, then stop owned UEs and gNB-02 by recorded IDs. Preserve shared gNB-01, UE-01 and Open5GS. Stop is idempotent; never use name-wide process killing.

Rollback means graceful stop of only registry-owned PIDs/containers, capture finalization, resource release and immutable result manifest. No deletion is part of rollback.

Progression requires Phase B pass before C, and C pass before D. Any failure returns to review; it does not authorize retries with broader scope.

