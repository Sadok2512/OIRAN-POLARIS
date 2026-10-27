# TShark Independent Parity

Reference: TShark 4.2.2.

N2 packet 39 at `1793054681.578522000`: AMF UE NGAP ID 8, RAN UE NGAP ID 8, PDU Session ID 1, endpoint `10.77.22.13`, TEID `0x0000b3b5`.

N4 packet 30 at `1793054681.575873000`: header/F-SEIDs `0xdb8` and `0x6e9`; Created-PDR F-TEIDs include `10.77.22.13 / 0x0000b3b5`. OIRAN normalizes this to `10.77.22.13 / 0xb3b5`, preserving packet references 39 and 30.

Result: exact parity for the tunnel tuple and packet provenance. SBI/PFCP identity remains STRONG, not exact.
