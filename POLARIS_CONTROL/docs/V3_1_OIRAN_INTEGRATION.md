# V3.1 OIRAN Integration Contract

Schema 1.1 carries scenario ID, pseudonymized UE ID, serving gNB, capture ID/interface, dataset ID, session ID and start/end timestamps. POLARIS Control supplies orchestration metadata only.

OIRAN remains responsible for decoding, session reconstruction and correlation from captured evidence. POLARIS Control never injects normalized events, decoded fields, correlation edges or Call Flows. Missing identifiers remain absent rather than inferred.

The contract is stored in `config/integration-contract-v1.json`; its additional fields are backward-compatible and contain no subscriber secrets.
