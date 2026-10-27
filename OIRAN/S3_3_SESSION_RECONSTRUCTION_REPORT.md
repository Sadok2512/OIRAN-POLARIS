# S3.3 session reconstruction report

## Result

`session-engine` 0.1.0 reconstructed one active 5G SA context, pseudonymized as `UE-A`, from the certified 54-event dataset. The resulting session ID is `5g-UE-A-pdu-1`.

| State | Reconstructed value |
|---|---|
| RAN UE NGAP ID | 4 |
| AMF UE NGAP ID | 4 |
| PDU Session ID | 1 |
| UE/PDU state | ACTIVE_WITH_USER_PLANE |
| SMF F-SEID | `0x00000000000001a8` |
| UPF F-SEID | `0x000000000000035e` |
| PFCP state | ESTABLISHED |
| Uplink tunnel | TEID `0x000096a8`, UPF endpoint `10.77.22.13`, 5 packets |
| Downlink tunnel | TEID `0x00000003`, gNB endpoint `10.77.22.20`, 5 packets |

## Association method

The UE anchor is the observed PDU Session Resource Setup context. NGAP events must share its RAN or AMF UE ID. PFCP establishment/modification is joined by sequence and F-SEID continuity. GTP-U requires a PFCP-observed TEID plus a matching tunnel endpoint; TEID alone is insufficient.

The engine classified 26 session events. Twenty-eight records remain background: 24 PFCP heartbeats, two prior PFCP deletion messages, and two NGAP release messages for UE context ID 3. Nothing was dropped: 54 source = 26 session + 28 background + 0 unmatched. Duplicate IDs: 0.

Ordering is deterministic on exact timestamp, packet number, interface and event ID. Original timestamps were preserved; no clock correction was applied.

## Reproduction

```bash
cargo build --workspace --release
./target/release/oiran-callflow \
  --dataset datasets/OIRAN_5G_PDU_SESSION_DATA_V1 \
  --json OIRAN_5G_E2E_CALLFLOW.json \
  --html OIRAN_5G_E2E_CALLFLOW.html
```
