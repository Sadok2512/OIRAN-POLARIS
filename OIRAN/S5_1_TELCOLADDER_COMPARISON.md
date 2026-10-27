# S5.1 TelcoLadder 0.1.0 comparison

Only the previously audited Apache-2.0 TelcoLadder 0.1.0 environment was used. No later PolyForm source was downloaded or copied into OIRAN production code.

TelcoLadder reports 1,441 decoded multi-layer messages across the seven fixtures. OIRAN emits 239 top-level NGAP/PFCP/GTP-U events, all independently aligned with TShark. Total message counts are `NOT_COMPARABLE` because TelcoLadder expands nested NAS, SBI HTTP/2 and derived layers.

PDU-session counts align exactly across the seven fixtures: eight in TelcoLadder and eight in OIRAN. This count agreement does not prove every cross-interface edge; OIRAN PDU correlation status remains `UNKNOWN` where no shared N2/N4 identifier exists.
