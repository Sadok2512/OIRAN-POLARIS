# PR #2 — Merge & Secure Frontend Preview readiness

Date: 2026-10-27
Branch: `feat/frontend-portal-probe-manager`
HEAD: `2c455300e4e62c53274f0cc6121e4ef66d539d66`

> **No action was taken on main, on the running Cloudflare tunnel, on
> the OIRAN or POLARIS backend, or on any process serving live
> captures.** This file documents the exact steps required for the
> operator to deploy the preview and merge the PR. Nothing was merged,
> nothing was exposed.

## Phase 1 — Git / PR state

| Check                                           | Result |
| ----------------------------------------------- | ------ |
| Local branch HEAD = `EXPECTED_COMMIT`           | PASS — `2c455300e4e62c53274f0cc6121e4ef66d539d66` |
| Remote HEAD = local HEAD                        | PASS   |
| `origin/main` is ancestor of PR HEAD            | PASS (fast-forward mergeable) |
| Commits ahead of main                           | 4      |
| Commits behind main                             | 0      |
| Files touched: scope                            | `apps/portal/**`, `apps/probe-manager/**`, `packages/ui/**`, `e2e/**`, `docs/frontend/**`, `.gitignore` |
| Backend files touched (`OIRAN/`, `POLARIS_CONTROL/`, `services/`, `infrastructure/`) | **None** |
| CI workflows blocking the merge                 | None — `.github/workflows/README.md` states "no executable workflow is defined yet" |

Verified via:

```
git fetch origin --prune
git rev-parse origin/feat/frontend-portal-probe-manager
git merge-base --is-ancestor origin/main origin/feat/frontend-portal-probe-manager
git diff origin/main...origin/feat/frontend-portal-probe-manager --name-only | grep -E "^OIRAN/|^POLARIS_CONTROL/|infrastructure/|services/"   # → empty
```

**Merge readiness: READY (fast-forward).** `MERGE_EXECUTED = FALSE` — awaiting operator approval.

## Phase 2 — Preview infrastructure audit

### Existing reusable infrastructure (preferred)

| Component           | Status                                                                          |
| ------------------- | ------------------------------------------------------------------------------- |
| `cloudflared.service` | Active (running since 2026-10-17). Config at `/etc/cloudflared/config.yml`. Already fronts `api.qoebit.net` (8000), `kpi.qoebit.net` (8001), `georef-api.qoebit.net` (8010). HTTPS terminated at Cloudflare. |
| Node 20.20.2        | Available for a tiny static server                                              |
| Python 3            | Available as fallback (`python3 -m http.server`)                                |
| `nginx`, `caddy`, `traefik`, `haproxy` | Not installed. Not needed — the Cloudflare tunnel already terminates HTTPS. |

### Occupied local ports

`22, 53, 300, 3000, 3300, 5000, 5174, 5432, 5433, 6379, 8000, 8002, 8010, 15432, 18020, 18030, 18040, 20241, 20242` — the two new preview services pick unused ports **8020** and **8021** (same decade as the existing `api/kpi/georef` services for consistency).

### Build artifacts verified

| Path                                | Result                                              |
| ----------------------------------- | --------------------------------------------------- |
| `apps/portal/dist/index.html`       | Exists (195 kB JS gzip 62 kB, 12 kB CSS gzip 3 kB)  |
| `apps/probe-manager/dist/index.html`| Exists (505 kB JS gzip 155 kB, 31 kB CSS gzip 6 kB) |

Both bundles were produced by `vite build` from the HEAD commit — no `vite` dev server is involved in the preview.

## Phase 2 — Preview deployment plan (NOT executed)

### Target topology

```
                                 ┌───────────────────────────────────────────┐
                                 │              Cloudflare edge             │
                                 │  (TLS termination · Access policy)       │
                                 └───────────────────────────────────────────┘
                                               │          │
                     portal-preview.qoebit.net │          │ probe-preview.qoebit.net
                                               ▼          ▼
                                        existing cloudflared tunnel (service)
                                               │          │
                                               ▼          ▼
                                 http://127.0.0.1:8020   http://127.0.0.1:8021
                                 (static dist from       (static dist from
                                 apps/portal/dist)       apps/probe-manager/dist)
```

- **HTTPS**: terminated at Cloudflare. The origin stays plain HTTP on `127.0.0.1:8020/8021` and is **never** exposed on `0.0.0.0`.
- **Authentication**: Cloudflare Access policy on both hostnames (email allowlist or GitHub OAuth). No origin-side secrets required.
- **No new public backend port**. `/api/v1/*` continues to be served by the existing OIRAN API on 127.0.0.1 (not exposed through the tunnel).

### Step 1 — Cloudflare DNS records (operator action)

Create two CNAMEs pointing to the existing tunnel CNAME target
(`0cd3caf1-9424-4c99-be09-58d83b052015.cfargotunnel.com`):

| Hostname                           | Type  | Target                                                                 |
| ---------------------------------- | ----- | ---------------------------------------------------------------------- |
| `portal-preview.qoebit.net`        | CNAME | `0cd3caf1-9424-4c99-be09-58d83b052015.cfargotunnel.com` (Proxied)      |
| `probe-preview.qoebit.net`         | CNAME | `0cd3caf1-9424-4c99-be09-58d83b052015.cfargotunnel.com` (Proxied)      |

### Step 2 — Append to `/etc/cloudflared/config.yml`

```yaml
ingress:
  # existing rules — preserve order
  - hostname: api.qoebit.net
    service: http://localhost:8000
  - hostname: kpi.qoebit.net
    service: http://localhost:8001
  - hostname: georef-api.qoebit.net
    service: http://localhost:8010

  # new preview rules — MUST sit above the http_status:404 catch-all
  - hostname: portal-preview.qoebit.net
    service: http://localhost:8020
  - hostname: probe-preview.qoebit.net
    service: http://localhost:8021

  - service: http_status:404
```

Reload:

```bash
sudo cloudflared service reload   # or: sudo systemctl reload cloudflared.service
```

### Step 3 — Cloudflare Access policy (operator action)

For each of the two hostnames, create a Cloudflare Access application
with an authentication policy:

- **Policy type**: Allow
- **Identity provider**: operator's choice (email OTP / GitHub / Google Workspace)
- **Session duration**: 1 hour
- **CORS**: not required (no cross-site requests to the preview)

Document the resulting URLs in the final report.

### Step 4 — Serve the dist/ artifacts on 127.0.0.1

Each app ships a hardened static server from Node's standard library.
It binds to loopback only, sends security headers, and refuses any
method other than `GET` or `HEAD`.

```bash
# Terminal 1 (Portal)
cd /home/devmat/OIRAN-POLARIS/apps/portal
PORT=8020 node ../../scripts/serve-static.mjs dist

# Terminal 2 (Probe Manager)
cd /home/devmat/OIRAN-POLARIS/apps/probe-manager
PORT=8021 node ../../scripts/serve-static.mjs dist
```

A systemd user unit per app is recommended for durability (template at
the end of this document). Do **not** start the servers automatically
from this agent — see `PREVIEW_DEPLOYED = FALSE`.

## Phase 3 — Post-deploy validation checklist

Run these from any workstation with Cloudflare Access authentication:

1. `curl -I https://portal-preview.qoebit.net/` returns `200` after
   Access challenge.
2. `curl -I https://probe-preview.qoebit.net/#/overview` returns `200`.
3. Portal shows the three application cards + health dots. The
   Simulator and OIRAN Analyzer cards show the real backend status
   (healthy / degraded / auth-required) — no fake telemetry.
4. Probe Manager routes resolve: `/#/overview`, `/#/topology`,
   `/#/probes`, `/#/interfaces`, `/#/live-captures`,
   `/#/capture-library`, `/#/settings`.
5. Topology renders the 5G SA scaffold (`INFERRED`) plus any
   backend-reported probes/interfaces (`DISCOVERED`). No edge is
   `CONFIGURED` without a backend-verified mapping (per PR #2 Section 2).
6. Toggle Theme switch — Light/Dark persist across refresh.
7. Resize the viewport to 1920/1440/1280/1024 — no horizontal overflow.
8. Confirm `/#/live-captures` honors `/auth/me.capture_control` — the
   Stop button stays disabled under the viewer role. No request to
   `/captures/:id/stop` is sent from this UI during the review.
9. `sudo systemctl status cloudflared.service` still `active (running)`;
   no restart happened.
10. `curl http://127.0.0.1:8000/api/v1/health` (OIRAN backend) still
    returns the previous `status: healthy` body — the preview does not
    change the OIRAN API process.
11. No OIRAN capture job state transitions during steps 1–10
    (`capture_job.state`, `active_capture_must_finalize`): `CAPTURES_INTERRUPTED = FALSE`.

## Live host observations (snapshot at `date -u`)

- `cloudflared.service` has been running since `2026-10-17 21:58:12 UTC`
  (1 week 2 days). It will **not** restart to add the two preview
  ingresses — only the config reload path is used.
- Local ports 8000 (`api.qoebit.net`), 8001 (`kpi.qoebit.net`), 8010
  (`georef-api.qoebit.net`) are responding to loopback requests
  (various HTTP codes). The tunnel is intact.
- **No OIRAN API process is currently serving `/api/v1/*` on this host.
  No live capture is in progress.** The frontends render honest
  `Not available` states until an OIRAN API is reachable at the base
  configured by the preview build (`VITE_API_BASE`). `CAPTURES_INTERRUPTED
  = FALSE` is therefore trivially satisfied.
- Ports **8020** and **8021** are free (see `ss -tlnp` snapshot in the
  audit above).

## Known limitations / blockers

- The agent cannot edit `/etc/cloudflared/config.yml` (root-owned,
  requires `sudo`). The operator must apply Step 2.
- Cloudflare DNS and Access policies are operator-side actions.
- No automated CI job gates the merge — reviewers must manually
  re-verify `tsc`, `vite build`, `vitest`, and `playwright` on the HEAD
  commit if that is desired before `MERGE_EXECUTED = TRUE`.

## Appendix — hardened static server (NEW FILE, not run)

The server at `scripts/serve-static.mjs` is a 60-line Node script with:

- `127.0.0.1`-only bind (never `0.0.0.0`)
- `GET`/`HEAD` only
- Path traversal prevention
- SPA fallback to `index.html` for client-side routing
- Security headers: `X-Content-Type-Options`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`,
  `Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://rsms.me; font-src https://rsms.me; connect-src 'self' https://api.qoebit.net`

See the file itself for the implementation.

## Appendix — systemd user unit template (not installed)

```ini
# ~/.config/systemd/user/oiran-portal-preview.service
[Unit]
Description=OIRAN Portal preview (static dist)
After=network.target

[Service]
Environment=PORT=8020
WorkingDirectory=%h/OIRAN-POLARIS/apps/portal
ExecStart=/usr/bin/node %h/OIRAN-POLARIS/scripts/serve-static.mjs dist
Restart=on-failure
Restart Sec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
```

Replace `oiran-portal-preview` with `oiran-probe-manager-preview` and
port `8021` for the second unit.
