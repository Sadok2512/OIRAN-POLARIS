# P0 UE-Targeted Traffic Generator Report

## Outcome

The bounded UDP traffic contract now supports an explicitly selected controller-owned UERANSIM UE. The compatibility path for the protected shared UE-01 remains separate; there is no implicit UE-01 fallback when the controller-owned scenario type is requested.

The browser sends only a stable internal UE ID. The API resolves that ID through the controller registry and independently verifies controller ownership, current process state, Registration, active PDU Session, exact approved container identity, network-namespace PID, `uesimtunN` interface, UE source address, and route to the fixed laboratory destination. Browser-provided interface names, namespaces, destinations, and commands are not accepted.

## UE-04 readiness

- The sanitized authoritative inventory records UE-PSEUDONYM-04 as database-present, profile-present, PLMN-compatible, DNN-compatible, S-NSSAI-compatible, and structurally valid.
- The protected profile `/var/lib/polaris-control/ue-profiles/ue-04.yaml` exists with root ownership and mode `0600`.
- Production desired configuration remains three UE profiles. The four-profile plan in `config/ue-targeted-traffic-four-profile-plan.json` is explicitly non-applied.
- UE-04 was not started and no Open5GS record was changed during this mission.

## Lifecycle behavior

Traffic state is recorded against the selected UE. Completing or stopping a traffic job updates only traffic state. It does not stop the UE process, release its PDU Session, restart the shared gNB, or alter Open5GS.

Stop continues to require the exact controller-owned traffic job ID. Duplicate starts remain idempotent for the same ID and conflicting concurrent jobs are rejected.

## Production boundary

This change was implemented and validated in the isolated worktree only. No production artifact was installed, no service was restarted, and no network packet was generated.
