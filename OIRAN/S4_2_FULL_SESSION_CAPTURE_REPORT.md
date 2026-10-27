# S4.2 full session capture report

## Status

Preparation and disk-safety implementation are complete. The requested five-UE live scenario is **not executed** because it requires new synthetic subscriber/profile material and additional UERANSIM processes. The mission explicitly requires approval before those POLARIS actions.

The current real dataset remains the S3.3/S4 certified single-session dataset: two observable NGAP UE contexts, one PDU session, two PFCP lifecycles, two directional GTP-U tunnels, 14 NGAP messages, 30 PFCP messages and 10 GTP-U packets. It is not relabeled as five-UE evidence.

S4.1 is available at commit `84b2c41` and supplies generalized multi-session discovery. S4.2 adds permanent disk policy enforcement and read-only API/UI visibility. Capture controls remain disabled until a separately approved, ownership-safe capture controller exists.
