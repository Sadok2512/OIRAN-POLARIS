# S5.4 laboratory readiness

Audit timestamp: 2026-10-26 19:11–19:30 UTC. All observations were read-only.

## Runtime inventory

| Area | Observed state | Evidence |
|---|---|---|
| Open5GS | Version 2.8.0; NRF, AMF, SMF, UPF, AUSF, UDM, UDR, PCF, NSSF and BSF containers running and Docker-health `healthy` | OCI labels and container health |
| UERANSIM | Version 3.3.0; one shared gNB and three UE processes running | OCI labels, process/container inventory |
| gNB | `oiran-lab-ueransim-gnb-1`, healthy; N2 `10.77.21.20`, N3 `10.77.22.20` | Docker network inventory |
| UE state | UE-01, UE-02 and UE-03 logs show Registration success and PDU Session 1 active | Sanitized UERANSIM logs and controller registry |
| Subscriber provisioning | Ten restricted UE profiles exist; the controller attestation covers the three configured profiles | File modes 0600, directory mode 0700; V3.2 manifest |
| POLARIS Control | API active on localhost port 49153; configured for three UEs and one gNB | Service/process and controller configuration |
| OIRAN API | Healthy on localhost port 49152; deployed API is pre-S5.3 (`event-schema 1.2.0`, correlation 0.2.0) | `/api/v1/health` and `/api/v1/version` |
| Capture Helper | Active as `oiran-capture`, Unix socket mode 0660; only N2/N3/N4 are allowlisted | systemd unit, socket and source audit |
| Existing laboratory capture | A pre-existing hourly capture container is active independently of this mission | Container/process inventory |

No subscriber secret, IMSI/SUPI, authentication key or operator token was exported.

## Important operational distinctions

- Three profiles are configured and three UE processes are currently registered; this does not expand the published live-certification limit automatically.
- Traffic jobs are independent from UE and PDU Session lifecycles. A pre-existing OIRAN timer currently sends bounded background traffic for UE-01 through UE-03 every 30 seconds.
- The existing capture container is not an OIRAN Capture Helper job and is not synchronized to an OIRAN scenario ID.
- The production OIRAN API has not been upgraded to the S5.3 SBI decoder. S5.3 was used only from its reviewed offline worktree.

## Readiness conclusion

The laboratory topology and packets needed for an E2E test are observable. Live approval is premature until a reviewed SBI capture path is added to the OIRAN helper or the separate laboratory capture service is formally incorporated into the scenario contract, and the S5.3 decoder is made available through an authorized offline-processing or deployment path.
