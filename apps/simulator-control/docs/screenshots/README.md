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
