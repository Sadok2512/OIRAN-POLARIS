# V3.1 Controlled Live Certification Plans

Every phase requires a separate written authorization, fresh resource safety receipt and exact process ownership ledger.

## LIVE-002 — one new UE

Provision one new synthetic subscriber; render one protected UE profile; start one controller-owned `nr-ue`; verify Registration and PDU Session; send five approved UDP datagrams; verify the UE remains active; stop the exact UE; confirm no orphan. Timeout: 120 seconds. Abort on health degradation, duplicate identity or resource gate failure.

## LIVE-003 — two UEs

Use two independently provisioned profiles on GNB-01 with two-second stagger. Verify distinct processes, Registration contexts, UE IPs and PDU Sessions. Run independent bounded traffic and stop each independently. Abort on cross-UE state contamination.

## LIVE-004 — five UEs

Start five provisioned profiles sequentially, then repeat with bounded stagger after success. Capture N2/N3/N4 within disk quota. OIRAN must independently discover five contexts and sessions; timestamps alone are insufficient correlation evidence.

## LIVE-005 — two gNB / five UE

Requires separately reviewed gNB-02 identity, endpoints and isolated namespace. Validate gNB-02 alone before distributing UE assignments 3+2. Handover is out of scope.

Rollback always stops only scenario-owned UE/gNB processes, finalizes owned captures, releases reservations and preserves shared Open5GS, GNB-01 and the shared UE.

