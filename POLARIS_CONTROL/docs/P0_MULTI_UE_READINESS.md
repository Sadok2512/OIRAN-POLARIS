# Multi-UE Readiness Audit

## Observed capability

- UERANSIM: `v3.3.0`, immutable image digest `sha256:b10346e5...`.
- `nr-ue` exposes `--num-of-UE`, `--imsi`, and `--tempo`; one process can therefore request multiple sequential subscriber identities and stagger their starts.
- UERANSIM's CLI does not advertise a numeric maximum. The installed controller's safe/certified maximum remains exactly `1`; any higher number is `UNKNOWN` until staged measurement.
- One gNB can serve multiple UE contexts at protocol level, subject to subscriber provisioning and measured resource/capture capacity.
- Current deployment contains exactly one root-readable synthetic UE profile and one running UE container.
- The UE and gNB containers are each limited to `0.75` CPU and `512 MiB` RAM. Observed idle usage was approximately 0.2% CPU and 6 MiB/4 MiB RAM respectively; this does not certify multi-UE load.
- Host: 10 vCPU and approximately 12.2 GiB available RAM during the audit.

## Gaps

- No allowlisted set of five independently provisioned subscriber profiles exists.
- Unique SUPI, key material, IMEI and database subscriber records require a separately approved provisioning workflow.
- Independent process ownership, TUN naming, IP allocation and cleanup have not been validated for multiple `nr-ue` processes.
- Multi-UE N2/N3/N4 capture correlation has not been certified.
- Root filesystem usage was observed at `85.04%` (`STOP_NEW_WRITES`, zero budget) and later at `84.95%` (`WARNING`, only about 151 MiB writable budget). This threshold fluctuation does not provide safe headroom for capture-producing multi-UE testing, which remains blocked.

## Classification

`NEW_UE_CREATION = LOCKED`

`MULTI_UE_READINESS = CAPABILITY_PRESENT_BUT_NOT_PROVISIONED_OR_CERTIFIED`

No arbitrary UE count is exposed in the Web UI.
