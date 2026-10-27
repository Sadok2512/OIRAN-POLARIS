# S5.4 offline validation

## Input

Read-only completed PCAPNG files from 2026-10-26 12:12 UTC were used because they cover two actual UE registrations and PDU Session establishments. Originals were not copied, truncated or modified.

| Plane | SHA256 | Packets/messages |
|---|---|---:|
| N2 | `d5a70d67ee2b712e3cd9633eecfa9074ba0bfc5f95ecc96f60233366136039d4` | 1,417 packets; 41 NGAP PDUs |
| N4 | `6927aedadaee4e235b672073b6dacc29bd0015a1e42a55e90c7a920c346e1251` | 1,316 PFCP messages |
| SBI | `2b3cfb526a4a5726dedbfc328def407dac6be11ae99bb9d605ea473675220afe` | 9,142 packets; 8,986 HTTP/2 frames |
| N3 | PCAPNG header only | 0 packets |

## Independent parity

TShark 4.2.2 reported 41 NGAP PDUs, 1,316 PFCP messages and 8,986 HTTP/2 frames. The reviewed S5.3 offline decoder produced the same counts, plus 25 TCP connections, 2,977 HTTP/2 streams and 772 SBI transactions. Six priority operations were decoded: two CreateSMContext, two N1N2MessageTransfer and two UpdateSMContext.

## Reconstruction

The combined event replay produced three observed UE contexts, two PDU sessions and two PFCP sessions. The two PDU sessions reference distinct UE-context IDs. It produced zero GTP-U tunnels because the aligned N3 file is empty. No user-plane event or E2E completion was fabricated.

The window independently demonstrates:

- UE/PDU identifier scoping across two concurrent registrations.
- Direct AMF/SMF HTTP/2 visibility with relevant connection setup.
- Two distinct PFCP establishment/modification sequences.
- Correct partial-session and missing-N3 reporting.

It does not prove the final SBI-to-PFCP association or PFCP-to-GTP-U bridge. S5.3's conservative rejection of a PDU Session ID-only match remains correct.

Reference S5.3 corpus SHA256 verification also remains `PASS` for all 13 files.

Targeted offline regressions for `transport-tcp`, `decoder-sbi` and `correlation-engine` passed 17/17 tests using the reviewed S5.3 code.
