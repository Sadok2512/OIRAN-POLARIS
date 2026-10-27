# NGAP to SBI Association

The derived replay observes NGAP AMF/RAN UE IDs `8/8`, PDU Session ID `1`, SBI `CreateSMContext`, and `N1N2MessageTransfer`. A unique capture-scoped PDU Session ID bridge produces `STRONG_CONTEXT_ASSOCIATION` between N2 packet 39 and the CreateSMContext transaction beginning at SBI packet 336.

No verified NGAP UE-ID to SBI subscriber-identity bridge exists, so the relationship remains STRONG and raw subscriber identities are neither exposed nor used as display labels.
