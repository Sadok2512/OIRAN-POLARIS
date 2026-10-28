# OIRAN Analyzer — LIVE screenshots

Rendered against the **production backend** at
`https://151.242.147.49:8020`. Zero fixtures: every value is what the
backend returned at capture time. Reproduce with
[`scripts/capture-screenshots-live.py`](../../scripts/capture-screenshots-live.py).

| File | Page | Theme |
|---|---|---|
| `overview-{light,dark}.png` | `/overview` real metrics strip | both |
| `sessions-{light,dark}.png` | `/investigation/sessions` session table from live `/sessions` | both |
| `packets-{light,dark}.png` | `/analysis/packets` with the backend's packet list | both |
| `correlation-{light,dark}.png` | `/investigation/correlation` with real edges | both |
