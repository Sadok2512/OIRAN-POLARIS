# Release Consolidation V1.1 — Maintenance Plan

This plan is prepared only. It is not deployment authorization.

1. Recheck disk (<90%), CPU/RAM, production binary hashes, controller-owned jobs, and the exact external `dumpcap` process set.
2. Record the current continuous-import job, copy its entire directory atomically, and verify packet/event/session counts, unique event IDs, call-flow references, and a complete tree SHA256.
3. Finalize only `continuous-lab-import`; do not signal or restart any external `dumpcap` process. Confirm their PIDs, file descriptors, and output sizes still progress.
4. Back up both applications, registries, configuration, frontend assets, units, and manifests; verify hashes and rollback readability.
5. Install the reviewed POLARIS candidate first and restart only POLARIS Control. Verify its running SHA256, authentication, 20/20 browser suite, four-profile inventory, and decision history.
6. Install the reviewed OIRAN candidate and restart only OIRAN API. Restart the helper only if its reviewed hash/compatibility requires it. Run non-acquiring four-plane validation and 47/47 authenticated browser tests.
7. Resume `continuous-lab-import` from the validated checkpoint. Require event-set superset semantics, five retained sessions, zero duplicate event IDs, zero missing call-flow references, and monotonic packet/event accounting.
8. Recheck the external capture PID set and demonstrate output-file progress. If lossless resume cannot be proved, preserve all data, roll back the affected application only, and leave live actions disabled.
