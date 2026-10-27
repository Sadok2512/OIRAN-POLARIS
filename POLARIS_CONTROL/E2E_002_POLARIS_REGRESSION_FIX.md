# POLARIS V3.2 Regression Correction

The CPU-evidence candidate retained the backend V3.2 contracts but did not expose all certified controls in the current React tree. The integration restores:

- **Apply Configuration** with the existing `/configuration` endpoint.
- **Add UE** as configuration-only capacity increment.
- **Start Selected / Stop Selected** through the existing `/ues/group/{action}` contract.
- One selectable row per configured UE profile.
- Viewer read-only behavior and Operator-only configuration/lifecycle controls.
- Shared-UE and server-side process ownership protections.

No control is enabled by a screenshot-derived assumption. Runtime authorization and backend safety remain authoritative.
