# Known limitations

- Live execution is certified only for the bounded existing-UE UDP scenario.
- LTE controls are unavailable until LTE Attach is validated.
- V2.1 implementation did not execute another live scenario; POLARIS-LIVE-001 remains the live evidence.
- Public-IP HTTP is Viewer-only; Operator control requires HTTPS or an SSH tunnel.
- New UE creation, multi-UE execution, gNB lifecycle, LTE, ICMP and TCP remain locked.
- The UI reports no fabricated rates, registrations, sessions, or history.

# V3.1 multi-UE boundary

- Five UE profiles are modeled and offline-tested, but only the existing shared UE is live-certified.
- Ten synthetic Open5GS subscribers are provisioned, but only the pre-existing shared UE is live-certified. UE-02 through UE-10 remain execution-locked pending controlled registration certification.
- New UE process launch requires LIVE-002 approval; two and five UE execution require LIVE-003 and LIVE-004 respectively.
- GNB-02 is a non-deployed architecture plan. Multi-gNB execution requires LIVE-005.
- The controller does not claim RRC state when it cannot be observed independently.
