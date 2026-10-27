# V3.1 API Validation

## Verified production behavior

- `/health` and `/version`: PASS.
- HTTPS page and API reachability: PASS; certificate verification result `0`.
- Operator login using the existing protected credential: HTTP 200. No credential or session token was written to this report.
- UE inventory: five planned profiles, one configured/verified profile, four provisioning-required profiles.
- Runtime inventory: one shared UE running, registered and PDU-active; it remains non-controller-owned and protected.
- Node inventory: GNB-01 healthy/protected; GNB-02 not deployed and locked; LTE remains uncertified.
- Scenario registry: zero active jobs and six preserved historical records.
- Existing bounded traffic result: five packets completed and preserved; no new traffic was generated.
- Viewer mutation denial and Operator/CSRF contracts: PASS in API and E2E tests.
- Disk policy: `NORMAL`, writes allowed at 49.02% usage; no safety bypass.

No Start endpoint for a UE, gNB or traffic job was invoked against production.

