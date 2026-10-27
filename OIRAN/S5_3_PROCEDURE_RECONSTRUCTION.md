# S5.3 procedure reconstruction

The procedure engine can represent Create/Update/Release SM Context, PFCP establishment/modification/deletion, and NGAP resource setup/release using real start/end events, duration, result, evidence and missing-stage fields.

The corpus contains six CreateSMContext, six UpdateSMContext, two ReleaseSMContext and six N1N2MessageTransfer HTTP transactions. These transactions are real and ordered, but are not upgraded to complete cross-interface procedures because the SBI-to-PFCP identity bridge is absent. The five PDU sessions established by existing UE-scoped NGAP/PFCP evidence remain independent and partial at the new E2E layer.

No success is inferred from a request alone or from HTTP 2xx alone. `PROCEDURE_RECONSTRUCTION = PARTIAL_EVIDENCE`.
