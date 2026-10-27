# gNB Configuration Audit

## Existing gNB-01

| Field | Observed |
|---|---|
| PLMN / TAC | `001/01`, TAC 200 |
| NCI / ID length | `0x000000010` / 32 bits |
| Link IP | `10.77.0.20` on `oiran-lab-mgmt` |
| NGAP IP | `10.77.21.20` on `oiran-lab-n2` |
| GTP-U IP | `10.77.22.20` on `oiran-lab-n3` |
| AMF | `10.77.21.11:38412` |
| Slice | SST 1, SD `010203` |
| Runtime sockets | UDP/4997 on link IP, UDP/2152 on GTP IP; SCTP association to AMF confirmed |

## Proposed gNB-02 (not created)

The following is a deterministic allocation from the same Docker IPAM pools after checking current endpoint occupancy:

| Field | Proposed value | Rationale |
|---|---|---|
| NCI | `0x000000020` | With 32-bit gNB ID length, derives a gNB identity distinct from gNB-01 |
| ID length | 32 | Matches the validated gNB |
| PLMN / TAC / slice | `001/01`, 200, `1/010203` | Matches deployed core |
| Link IP | `10.77.0.22` | Unallocated in inspected `10.77.0.0/24`; `.20/.21/.30` are occupied |
| NGAP IP | `10.77.21.21` | Unallocated in inspected `10.77.21.0/24` |
| GTP-U IP | `10.77.22.21` | Unallocated in inspected `10.77.22.0/24` |
| AMF | `10.77.21.11:38412` | Existing healthy AMF |

These are proposed reservations, not assignments. Recheck Docker occupancy immediately before approved deployment.

Run gNB-02 in its own container/network namespace attached to the existing management, N2 and N3 networks. This isolates UDP/4997 and UDP/2152, so loopback aliases are unnecessary. Running both gNBs in the host namespace would create binding risk and is not approved.

Observed conflicts: none for the proposed identities/endpoints. Deployment remains blocked by controller capability, subscriber provisioning and disk safety.

