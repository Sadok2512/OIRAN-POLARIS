# SBI to PFCP Association

The replay preserves SBI SM Context reference `6` and PFCP SEIDs `0xdb8` and `0x6e9`. A unique CreateSMContext and PFCP Session Establishment in the same capture group share the observed DNN `internet` and SMF procedure context, producing `STRONG_CONTEXT_ASSOCIATION`.

The edge does not assert that SM Context reference `6` maps directly to either SEID. Those identifiers remain separate evidence with an explicit limitation.
