# S5.4 OIRAN-E2E-001 test plan

No step in this plan was executed during S5.4.

## Scope

- Scenario: `OIRAN-E2E-001`
- One existing shared gNB; never restart or stop it.
- One provisioned, stopped synthetic profile, initially UE-04, after controller authorization and attestation revalidation.
- One Registration and one PDU Session establishment.
- Five 64-byte UDP datagrams, one per second, to approved lab endpoint `10.46.0.1:49001`.
- Optional release only for the exact controller-owned UE-04 session; otherwise explicitly stop that UE after evidence finalization.

UE-01 through UE-03 are already registered and unsuitable for proving a fresh Registration. They must not be released or stopped.

## Approval prerequisites

1. Approve one controller-owned UE-04 lifecycle and verify that live-certification policy permits it.
2. Approve the four-plane capture implementation/deployment, including SBI.
3. Approve temporary suspension of the existing bounded background-traffic timer, or explicitly accept and filter that traffic by independently proven UE IP/TEID.
4. Recheck Open5GS, gNB, existing UEs, ETV/OTV, disk, CPU and RAM immediately before execution.
5. Confirm no other OIRAN capture job is active.

## Execution outline

1. Generate a unique scenario ID and immutable capture IDs for N2, SBI, N4 and N3.
2. Validate all four capture points and reserve at most 256 MiB total plus a 32 MiB safety reserve for a five-minute window.
3. Arm all workers and require explicit `READY`; start them and require `CAPTURING` before UE action.
4. Start only the attested UE-04 runtime through POLARIS Control.
5. Wait at most 60 seconds for process start, 60 seconds for Registration and 60 seconds for one active PDU Session. Abort without affecting other UEs on timeout.
6. Send exactly five UDP datagrams. The expected downlink is ICMP Port Unreachable from the controlled endpoint; it is transport evidence, not an application UDP reply.
7. Optionally request session release only when explicitly approved and supported for the owned UE.
8. Stop UE-04 by exact controller ownership ID. Never use process-name matching.
9. Gracefully finalize all owned capture files and manifests.
10. Verify PCAP/PCAPNG structure, SHA256, packet counts, timestamps and TShark parity before decoding.

## Abort conditions

Abort on any unavailable capture point, missing ownership proof, disk at or above 85%, failed measurement, memory pressure, sustained resource degradation, unhealthy shared NF/gNB, capture drop/error, missing UE attestation or unexpected identity reuse. Preserve partial evidence without calling the session complete.

## Acceptance

A successful test requires one isolated UE context, one PDU Session, Create/Update SM Context, PFCP establishment/modification, five uplink GTP-U packets, independently explainable downlink packets, packet provenance and no cross-UE merge. Each cross-interface edge must satisfy `S5_4_CORRELATION_EVIDENCE.md`.
