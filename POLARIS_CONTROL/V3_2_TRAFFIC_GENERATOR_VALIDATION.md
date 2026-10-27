# UE-Targeted Traffic Generator Validation

The deployed Traffic Generator exposes a required Target UE selector backed by the authoritative API inventory.

- Selectable targets: verified, controller-owned, running UEs with active PDU Sessions (currently UE-02 and UE-03).
- Shared UE-01 is excluded and visibly protected.
- Stopped UE-04 is excluded from selectable targets.
- Non-executing API validation for UE-02 returned HTTP 200 and `bounded-controller-ue-udp-v1`.
- UE-04 validation failed closed with HTTP 423 `UE_NOT_RUNNING`.
- An invalid/shared target failed closed with `SHARED_UE_TRAFFIC_TARGET_FORBIDDEN`.
- Namespace and TUN names are never accepted from the browser; they are resolved from the verified backend mapping.
- Traffic jobs use exact controller ownership. Completion does not stop the UE.

No Start Traffic endpoint was called and no UDP packet was generated.

