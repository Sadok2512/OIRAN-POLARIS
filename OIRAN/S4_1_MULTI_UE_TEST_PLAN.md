# Controlled POLARIS multi-UE test plan — approval required

Status: **NOT EXECUTED**. The existing authorized capture inventory does not contain a certified real multi-UE/multi-PDU scenario.

## Proposed scenario

1. Allocate five synthetic UERANSIM UE profiles with unique test-only SUPIs and the existing isolated PLMN/DNN.
2. Confirm Open5GS subscriber fixtures and two DNN/PDU profiles for UE 1 without touching production PostgreSQL or ETV/OTV.
3. Start simultaneous N2/N4/N3 captures at the already validated namespaces, using new scenario-specific output files.
4. Register UE 1–3 concurrently, then UE 4–5 sequentially.
5. Establish one PDU session per UE and, if the selected UERANSIM release demonstrably supports it, a second PDU session for UE 1.
6. Generate five bounded ICMP requests per active tunnel to an authorized lab endpoint.
7. Produce one incomplete procedure by using an isolated negative test profile, not by disrupting an active UE.
8. Release supported sessions, stop only scenario-owned UE processes and captures, checksum outputs, and restore the prior simulator set.

## Resource envelope

- Duration: 5–10 minutes.
- CPU: expected below two vCPU sustained; abort on service pressure.
- RAM: below 1 GiB incremental.
- Disk: below 250 MiB with bounded captures/logs.
- Network: laboratory private networks only; no public endpoint.

## Approval and rollback

Approval must name the five synthetic profiles, authorized endpoint, capture file names and whether a second PDU session is supported. Rollback stops only newly approved UE/scenario processes, retains captures for evidence, and restores the exact pre-test POLARIS configuration. No Open5GS/UERANSIM restart, Docker network edit, firewall edit or route edit is implicit in this plan.
