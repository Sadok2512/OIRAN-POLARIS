# Probe Manager — UI screenshots

These images are rendered against a **mocked OIRAN API**, not a live
backend. The Playwright script that produces them is at
[`scripts/capture-screenshots.py`](../../scripts/capture-screenshots.py):

- It stubs every `/api/v1/*` call with fixtures baked into the script
  (probes, interfaces, captures, metrics, storage safety, auth).
- No real `tcpdump`, `dumpcap`, probe or capture pipeline is involved.
- Values rendered on the page (packet counts, growth, disk usage, probe
  IDs) are illustrative — they come from the fixture, not from a
  deployment.

The screenshots are kept in-tree only to document the UI target. They
should not be read as proof of backend health. Reproduce them locally
with:

```bash
cd apps/probe-manager
npm run dev          # terminal 1 — vite on 127.0.0.1:4310
python3 scripts/capture-screenshots.py     # terminal 2
```

| File | Page | Theme |
|---|---|---|
| `probes-{light,dark}.png` | `/probes` with interface chips + inspector | both |
| `register-probe-{light,dark}.png` | Register probe dialog (locked, with JSON payload preview) | both |
| `live-captures-{light,dark}.png` | `/live-captures` (growth stats, disk gauge, locked actions) | both |
| `capture-library-{light,dark}.png` | `/capture-library` (locked Download, server-paginated table) | both |
