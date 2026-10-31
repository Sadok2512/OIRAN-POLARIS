# Simulator Control — UI screenshots

These images are rendered against a **mocked POLARIS API**, not a live
backend. The Playwright script that produces them is at
[`scripts/capture-network-screenshots.py`](../../scripts/capture-network-screenshots.py):

- It stubs every `/polaris-api/v1/*` call with fixtures baked into the
  script (auth, capabilities, lab, nodes, ues, ue-profiles/provisioning-slots,
  scenarios/*, traffic/status, system/health).
- No real Open5GS, UERANSIM, gNB, UE, scenario or job is involved.
- Values rendered on the page (gNB endpoints, container health,
  provisioning slots) are illustrative — they come from the fixture, not
  from a deployment.

The screenshots are kept in-tree only to document the UI target of the
Network section (LOT 2 / 2.1). They should not be read as proof of
backend health. Reproduce them locally with:

```bash
cd apps/simulator-control
npm run dev          # terminal 1 — vite on 127.0.0.1:4330/simulator/
python3 scripts/capture-network-screenshots.py   # terminal 2
```

| File | Page | Theme |
|---|---|---|
| `network-topology-{light,dark}.png` | `/network/topology` — Core → gNB → UE composed from /lab + /nodes + /ues; link labels say `configured` / `down` / `unknown` (never "UP") | both |
| `network-core-{light,dark}.png` | `/network/core` · functions tab — AMF HEALTHY, other NFs "not exposed"; header badge "AMF container: running, healthy" with source `/lab.observed.open5gs = oiran-lab-amf-1` | both |
| `network-gnbs-{light,dark}.png` | `/network/gnbs` — GNB-01 real card, GNB-02 locked `LIVE_005_APPROVAL_REQUIRED`, ENB-01 under "LTE profile (not certified)" with `LTE_ATTACH_NOT_CERTIFIED` | both |
| `subscribers-tab.png` | `/core-open5gs` · Subscribers tab — slot rows with PROTECTED identity, bound UE id or Free badge, Edit action, Generate button in aside | light |
| `subscriber-edit-dialog.png` | SST / SD / DNN dropdowns, AMBR number inputs, opt-in "Rotate authentication material" with write-only K/OPc inputs placeholder `PROTECTED — write-only` | light |
| `subscriber-generate-dialog.png` | count (1-1000), SST/SD/DNN dropdowns pre-filled from lab defaults (SST=1, SD=010203, DNN=internet), AMBR 1 Mbps defaults, result list showing a slot with PROTECTED identity | light |

## 0.8.0 — Subscribers surface

The `e2e/subscribers.spec.ts` suite (ran with `npx playwright test` after
`npm install && npx playwright install chromium`) renders the three
captures above. Every mocked response in the spec uses the literal
`"PROTECTED"` for `subscriber_identity` / `authentication_material`; no
real IMSI, K or OPc appears in artefacts, logs or assertion material.
