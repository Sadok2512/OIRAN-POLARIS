# S5.2 5GSM Decoder Report

Native dispatch covers PDU Session Establishment, Authentication, Modification, Release and Status message identities. The parser exposes PDU Session ID, PTI, causes, selected session type/SSC mode, DNN, S-NSSAI, PDU address and bounded raw evidence for QoS/AMBR fields where full semantic decoding is not implemented.

Deterministic tests validate a plain UL NAS Transport containing a 5GSM PDU Session Establishment Request and DNN `internet`. The unchanged corpus yielded zero OIRAN-decoded 5GSM child events because every NGAP-carried instance is inside a ciphered security envelope. OIRAN did not treat clear-looking bytes from a laboratory null-cipher trace as authorized plaintext.

Result: implementation validated; corpus message certification remains partial pending an authorized security context or an independently captured plain 5GSM fixture.
