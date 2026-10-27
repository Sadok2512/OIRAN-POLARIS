# OIRAN V2.3 API and UI Integration

## API 2.3

`GET /api/v1/datasets` now exposes a stable normalized shape for historical, captured-live and recovered datasets. `GET /api/v1/sessions` accepts `dataset_id` and `dataset_kind` together with existing UE, technology, interface, status, pagination and sorting parameters.

Exact missing or zero-session datasets return no sessions. They never fall back to the primary historical flow.

## Session Explorer

The dataset selector provides All, Historical, Live, Recovered and individual dataset choices. URL state retains dataset, capture, probe, technology and session context. A zero-session dataset offers packet and decoded-event inspection while clearly stating that no session was reconstructed.

Call Flow navigation includes the selected dataset ID and opens only the selected stable session. The frontend contains no decoder or correlation logic.

## POLARIS metadata contract

Future integration may carry scenario ID, UE pseudonym, gNB ID, capture ID, dataset ID, session ID and start/end timestamps. Such metadata can assist discovery only; protocol identifiers and packet provenance remain mandatory evidence.
