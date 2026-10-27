# S5.3 Call Flow integration

The existing Call Flow model now accepts SBI request and response events, SBI procedure groups, HTTP method/URI/status fields and dynamic source/destination network functions. Observed SCP hops remain visible as network hops; OIRAN does not invent a logical AMF-to-SMF arrow when only an SCP leg was observed.

SBI events retain HTTP/2 stream evidence and all contributing packet references, enabling the existing Message Inspector and provenance navigation. NGAP, PFCP and GTP-U mappings are unchanged.

Schema integration is complete and regression tested. The corpus Call Flow remains partially correlated because the N2/SBI/N4 bridge is not independently proven.
