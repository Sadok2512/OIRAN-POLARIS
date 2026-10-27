# S5.3 TelcoLadder comparison

Only the previously audited TelcoLadder 0.1.0 Apache-2.0 research output was used. No newer or PolyForm Noncommercial code was downloaded, copied or integrated.

The retained baseline identifies SBI-containing streams and groups registration/PDU-session procedures, but reports undecoded headers for relevant captured streams and does not expose a stable field-level HTTP/2 transaction contract comparable to OIRAN's normalized events. Exact HTTP/2/SBI field parity is therefore `NOT_COMPARABLE`.

At the session level both tools retain the five independent PDU sessions in the multi-IMSI corpus. OIRAN additionally records native frame/stream provenance and refuses to bridge SBI to PFCP without explicit evidence. TelcoLadder is treated as a secondary research comparator, not an oracle.
