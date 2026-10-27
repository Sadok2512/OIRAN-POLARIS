# S3.2.2 certified multi-interface dataset

The dataset is [OIRAN_5G_PDU_SESSION_DATA_V1](/root/OIRAN_VPROBE/datasets/OIRAN_5G_PDU_SESSION_DATA_V1). It contains 38 N2 packets / 14 NGAP messages, 30 N4 packets / 30 PFCP messages, and 10 N3 packets / 10 GTP-U events.

The control-plane capture begins with Registration and includes PDU Session establishment. User-plane capture occurs later in the same continuously active session. Coherence is STRONG rather than EXACT at whole-session level because the capture windows are not contiguous; exact TEID/endpoint matches and unchanged session owners bridge the gap.

The dataset is suitable for S3.3 functional development and Call Flow ground truth. It is not a performance or full NGAP parity fixture.
