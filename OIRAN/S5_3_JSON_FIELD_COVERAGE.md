# S5.3 JSON field coverage

The decoder respects JSON or multipart content types and extracts observed PDU Session ID, DNN, S-NSSAI, access type, serving network, cause, SM Context reference, N1/N2 container references and tunnel information when structurally present.

Missing values remain absent. Multipart binary containers are referenced but are not mislabeled as decoded NAS or NGAP. Authorization headers are discarded, subscriber references are pseudonymized, and request URIs are sanitized before normalized events are exported. Raw sensitive identifiers remain outside public SBI events.

The parity run compared 766 stable HTTP/SBI fields: 766 exact, zero mismatched and 26 unresolved. The unresolved count is separate and arises from missing prior HPACK state, not invented JSON defaults.
