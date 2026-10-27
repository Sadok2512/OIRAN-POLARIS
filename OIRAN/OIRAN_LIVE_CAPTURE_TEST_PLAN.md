# OIRAN-LIVE-CAPTURE-001 — Controlled Test Plan

Status: **NOT EXECUTED — explicit operator approval required**.

1. Verify POLARIS, POLARIS Control and ETV/OTV health without restarting them.
2. Verify disk is below 85%, inode headroom is available, and no OIRAN capture job is active.
3. Provision a short-lived Operator token fingerprint and enable the capture execution deployment flag.
4. Validate a 60-second, 256 MiB total `POLARIS-5G-SA` job on available N2/N3/N4 bridges.
5. Start capture through the authenticated OIRAN API.
6. Through the separately authorized POLARIS Control workflow, send exactly five UDP datagrams from the existing UE to the approved laboratory endpoint.
7. Stop or allow the bounded capture to complete. Do not stop the shared UE, gNB or core.
8. Verify non-zero N3 GTP-U packets; record N2/N4 only if traffic is actually observed. Validate PCAP structure, timestamps, SHA-256, decoding, provenance, dataset registration and UI visibility.
9. Compare decoded headers with TShark if available. Do not expect new Registration or PDU Session establishment for an already-active UE.
10. Disable execution, revoke the temporary Operator credential, confirm no owned helper remains, and report certification separately for capture, decoding and session reconstruction.

Abort on disk stop state, helper failure, service degradation, unexpected traffic destination, missing ownership evidence, or any POLARIS/ETV/OTV health regression.
