# S5.2 Multi-UE Isolation

The multi-IMSI fixture reconstructs six UE context lifecycles (five active/observed contexts plus one released lifecycle) and five PDU sessions. All five PDU Session IDs are scoped to their UE context.

NAS children inherit the exact NGAP context through parent-event identity. They cannot create or merge a UE context using timestamp proximity. A dedicated regression places a NAS child temporally beside an unrelated UE and verifies association with only its parent UE.

Result: no cross-UE contamination observed. Identifier reuse after release and repeated-import determinism remain covered by existing regression tests.
