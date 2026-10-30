# Probe Manager — LIVE screenshots

These images are rendered against the **production OIRAN backend** at
`https://151.242.147.49:8020`. Zero fixtures, zero mock data: every value
is what the backend actually returned at capture time.

Reproducing the images requires network reach to the lab host. The
Playwright script that produces them is at
[`scripts/capture-screenshots-live.py`](../../scripts/capture-screenshots-live.py):

- Starts a local Vite dev server on `127.0.0.1:4310`.
- Playwright intercepts every `/api/v1/*` call and forwards it to
  `https://151.242.147.49:8020/api/v1/*` via `urllib.request`
  (certificate verification disabled — operator-known lab CA).
- No JSON is injected on the way back; the backend's own payload is
  rendered.

Reproduce with:
```bash
cd apps/probe-manager
npm run dev          # terminal 1 — vite 127.0.0.1:4310
python3 scripts/capture-screenshots-live.py   # terminal 2
```

| File | Page | Theme |
|---|---|---|
| `overview-{light,dark}.png` | `/overview` with real metrics / probe fleet | both |
| `probes-{light,dark}.png` | `/probes` — real `oiran-vprobe-local-01` card + interfaces | both |
| `interfaces-{light,dark}.png` | `/interfaces` with the Docker-bridge discovery of the live host | both |
| `live-captures-{light,dark}.png` | `/live-captures` showing the running capture jobs | both |
| `capture-library-{light,dark}.png` | `/capture-library` — real backlog + locked Download column | both |

Sibling folder `../screenshots/` keeps the mocked-fixture renders used
for mockup alignment; `../screenshots-live/` is the honest-build witness.
