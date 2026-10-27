# S3.1 SCTP parsing and reassembly report

## Implementation

transport-sctp 0.1.0 parses the common header and all chunks in each packet. For DATA it records verification tag, TSN, stream ID, SSN, PPID and B/E/U flags. Association identity uses the canonical endpoint/port pair plus a generation counter advanced by INIT. Direction remains part of fragment and duplicate keys.

Complete B+E messages are emitted immediately. Fragmented messages are emitted only after contiguous TSNs reach E. Retransmitted TSNs are detected and ignored. INIT discards incomplete state with an explicit restart diagnostic. End-of-capture reports every remaining assembly as incomplete. SCTP I-DATA type 64 is explicitly UNSUPPORTED and is never handed to NGAP as a complete DATA message.

## Validation

- Real finalized N2: 14 NGAP messages from 13 TShark-classified NGAP packets. Packet 13 carried two DATA chunks and produced two independently provenanced events.
- Open5GS reference: 23 NGAP messages.
- Real inputs: zero duplicate, malformed, I-DATA or incomplete-message diagnostic.
- Unit fixtures: single DATA, two chunks, multiple streams, B/E fragmentation, retransmission, tail without beginning, unfinished beginning, and I-DATA.

The total real NGAP handoff was 37 complete PPID 60 messages. No incomplete message was passed to decoder-ngap.

## Limitations

CRC32c verification is not implemented. AUTH/ASCONF semantics are not interpreted. Traditional unordered fragmented DATA supports one active association/generation/direction/stream/SSN/PPID assembly; I-DATA interleaving is unsupported. No fragmented DATA appeared in the selected real captures, so real-world fragmentation behavior is unit-validated rather than capture-validated.
