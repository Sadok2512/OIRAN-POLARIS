# POLARIS Control V3.2 Deployment Report

The reviewed UE-targeted traffic release was deployed successfully to `https://polaris.etv-sadok.duckdns.org/` from source commit `7845580d527feb0cf4e3bac0d506a7b8a84b0d75`.

Only `polaris-control.service` was transitioned. OIRAN, Open5GS, UERANSIM processes, POLARIS Portal, ETV and OTV were not restarted. The original three UEs and one gNB retained their process identities and remain running. The desired configuration now contains four UE profiles; UE-04 remains stopped with no PDU Session or traffic job.

Fresh validation passed: Rust 71/71, API 37/37, frontend 5/5, candidate E2E 1/1, and deployed production E2E 1/1. HTTPS health, existing Operator login, both themes, UE inventory, selector restrictions, disk thresholds and CPU fail-closed behavior were verified.

The deployment is certified. UE-04 lifecycle and traffic are not certified and were not exercised.
