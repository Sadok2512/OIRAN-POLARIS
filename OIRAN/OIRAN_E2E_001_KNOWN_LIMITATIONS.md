# OIRAN-E2E-001 Known Limitations

1. UE-04 is provisioned and has a compatible protected profile, but current controller configuration stops at UE-03.
2. The current certified traffic scenario is bound to the shared UE-01 container namespace and cannot truthfully validate UE-04 user-plane traffic.
3. Additional UE lifecycle has implementation support but is not live-certified; this test would be its first explicit certification phase.
4. Current CPU contention from OTV is unsafe for a controlled live run.
5. NAS may be ciphered and must remain unresolved without an authorized security context.
6. No E2E correlation, Call Flow, TShark parity or dataset registration result exists until a separately approved capture executes.

