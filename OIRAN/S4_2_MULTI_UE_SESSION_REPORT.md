# S4.2 multi-UE session report

Real five-UE session count: **NOT_RUN**.

The prepared scenario uses five synthetic UE pseudonyms, staggered registration followed by a concurrent phase, one PDU session each, and an optional second session only after UERANSIM capability is demonstrated. Each expected session will require distinct scoped NGAP context, PDU identity, PFCP lifecycle, tunnel endpoints/TEID and packet provenance.

S4.1 synthetic validation already proves five contexts, six PDU sessions, identifier reuse isolation and an incomplete procedure without claiming captured evidence. Live certification additionally requires the approved run, independent TShark parity and per-UE N2/N4/N3 evidence.

Blocker: approval is required to create or enable five test subscribers/profiles and launch scenario-owned UE processes. Existing UE/Open5GS containers will not be restarted automatically.
