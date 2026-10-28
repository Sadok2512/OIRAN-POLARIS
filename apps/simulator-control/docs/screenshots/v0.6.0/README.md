# 0.6.0 — captures (mocked API)

These screenshots document the provisioning layer added in `0.6.0`
(polaris-provisioning branch, UI flag `polarisProvisioning`). They are
rendered against a **mocked POLARIS API** — no live backend is
involved. The mocks live in `apps/simulator-control/e2e/captures.spec.ts`
and intercept every `/polaris-api/v1/*` request via `page.route`.

The Playwright suite ships two projects — `chromium-light` and
`chromium-dark` — so every page has a light-theme and a dark-theme
capture.

## Reproduce

```bash
cd apps/simulator-control
npm run dev                           # terminal 1 — vite on 127.0.0.1:4330/simulator/
npx playwright test                   # terminal 2
# Captures land in docs/screenshots/v0.6.0/*.{chromium-light,chromium-dark}.png
```

## Files

| File | Page | Theme |
|---|---|---|
| `templates.chromium-{light,dark}.png` | `/scenarios` — Templates tab, Clone + Download JSON actions, API-provided duration estimate | both |
| `ue-manager.chromium-{light,dark}.png` | `/ues` — list under `polarisProvisioning` ON, Import CSV (backend) and Add UE buttons wired to the new dialogs | both |
| `provisioning.chromium-{light,dark}.png` | `/provisioning` — subscriber directory, Import CSV button, IMSI always PROTECTED | both |
| `ue-detail.chromium-{light,dark}.png` | `/ues/UE-01` — the eight structured blocks (Identity, Provisioning, Network profile, Registration, PDU sessions, IMS, Scenario, Traffic) | both |

Values in these captures are illustrative and come from the mock
fixtures. They are not proof of backend readiness; the real
`/subscribers`, `/owners`, `/plmns`, `/dnns`, `/ue-profiles/import` and
`/provisioning/import` routes land with Codex's `feat/polaris-provisioning`.
