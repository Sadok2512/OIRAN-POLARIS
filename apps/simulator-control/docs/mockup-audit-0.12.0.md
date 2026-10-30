# Mockup audit — simulator-control 0.12.0

**Base**: `b0adf3b` (simulator-control 0.11.1 shipped)
**Mockup reference**: `origin/docs/ui-mockups @ 48dea75` — `docs/ui-mockups/polaris-control.html` + `docs/ui-mockups/README.md`
**Date**: 2026-10-29

Objective: rebuild simulator-control 0.12.0 so each screen matches the mockup faithfully (layout, components, labels, light/dark), while keeping every function already shipped (grant, Start/Stop/Run, Activity, Create subscriber, IMSI for operator, scenarios) and replacing mockup sample data with real API data. Items the mockup shows but the API cannot support are rendered as "verrouillé / backend pending" per the mockup README.

Format of each table below:
- **Mockup**: what the mockup renders
- **Actuel**: what `b0adf3b` renders today (`apps/simulator-control/src/...`)
- **Écart**: delta to resolve for 0.12.0

---

## 0. Shell (sidebar + topbar + theme)

Current: `apps/simulator-control/src/layout/AppShell.tsx`, `SidebarNavigation.tsx`.

| Zone | Mockup | Actuel | Écart |
|---|---|---|---|
| Logo | Antenna icon in blue 32×32 square + bold "POLARIS" + "5G lab control" sub-caption | Letter "P" in a square + "POLARIS" + "Simulator Control" | **Change logo to the antenna glyph; replace sub-caption with "5G lab control"** |
| Sidebar sections | 3 sections — **Network / Simulation / Review** — in that order | 5 sections — **OPERATIONS / NETWORK / SIMULATION / REVIEW / PLATFORM** | **Collapse to the 3 mockup sections**: move Console into Network; Traffic Generator → not in nav (next lot #47) → hide behind flag; Provisioning + Settings → relocate to Review or hide (no mockup entry) |
| Sidebar items | 8 fixed items: `console / topology / core / gnbs / ues / scenarios / monitor / history` | 11 items (adds Traffic Generator, Provisioning, Settings) | **Reduce to the mockup 8** (keep Provisioning + Settings reachable from a secondary chrome, not the primary nav; Traffic Generator stays hidden pending #47) |
| Section labels casing | Capitalised: `Network`, `Simulation`, `Review` | Uppercase: `OPERATIONS`, `NETWORK`, … | **Use capitalised casing, mockup spacing (`uppercase tracking-wider text-xs`)** |
| Sidebar footer | Static note: "Probes and captures are managed in the OIRAN Probe Manager." | Absent | **Add footer note at the bottom of the sidebar, same wording** |
| Topbar | **Live** core-health dot + `PLMN 001/01 · TAC 200` + `Live UEs 2 / 10` + `Example data` chip + theme toggle (Dark ↔ Light) | Branding `Enterprise Precision · POLARIS Simulator Control v{x}` + auth badge + theme radiogroup (Light/Dark/System) | **Rework topbar**: show live lab state (core health, PLMN/TAC, live/cap UEs). Drop `Example data` chip (we show real data). Keep theme toggle but 2-state (Light/Dark); auth badge stays but minimised |
| Topbar version chip | None | Shows `v{x.x.x}` | **Move version into Settings or footer** |
| Theme tokens | CSS custom props (`--c-surface`, `--c-primary`, …) resolved for light + `@media (prefers-color-scheme: dark)` + `[data-theme="dark"]` override | Already uses `packages/ui` Enterprise Precision tokens | ** Keep tokens; verify dark theme pairs with mockup values (surface #152238, primary #5B93F7, …)** |
| Pulse animation on live dot | `.live-dot` keyframes (1.6 s pulse) | No pulsing dot in shell today | **Add `live-dot` utility class in app CSS** |

---

## 1. Console (`/console`)

Current: `apps/simulator-control/src/pages/Console.tsx`.

| Bloc | Mockup | Actuel | Écart |
|---|---|---|---|
| Eyebrow / title | `Network` · `Console` · desc "One view of the simulated network: core, radio and the UEs running on it." | `Operations` · title + desc differs | **Change eyebrow to `Network`, use mockup wording for title + desc** |
| Stat grid | 4 tiles (`Core functions 10 / 10`, `gNodeBs 1 active`, `UEs registered 2`, `PDU sessions 2`) | 8 infra tiles (Configured UEs, Registered UEs, Scenario mode, Scenario library, CPU, Memory, Active scenario, Traffic state) | **Reduce to the 4 mockup tiles**; derive from `/lab` + `/nodes` + `/ues`. Preserve the richer metrics but surface them lower on the page (or Settings) |
| "Readiness before starting a UE" card | 5-row checklist (gNB active / PLMN / TAC / S-NSSAI / Subscriber provisioned) with PASS/WARN pills | **Absent** | **Add Readiness card**; compute from `/lab`+`/gnbs`+`/ues`+`/subscribers` |
| "Recent activity" card | 4 last events, mono UE id + mute description | Shows "Certified scenario profiles" (unrelated content) | **Replace with Recent activity**; back it with existing `/activity` SSE stream, show 4 last events |

---

## 2. Topology (`/network/topology`)

Current: `apps/simulator-control/src/pages/Topology.tsx`.

| Bloc | Mockup | Actuel | Écart |
|---|---|---|---|
| Eyebrow / title / desc | `Network` · `Topology` · "Core, radio and UEs as they are wired now. Links show the live state of each interface." | OK with minor wording drift | **Align wording to mockup** |
| Header actions | 2 pills: `N2 / N3 up` (live) + `No mobility (UERANSIM)` | Different chip set | **Switch to the 2 mockup pills** |
| Core block | Rounded card, title "5G Core · Open5GS 2.8.0", sub `PLMN … · S-NSSAI 1/010203 · DNN internet`, 5-col grid of NF pills (10 NFs) each with a green dot | 2–5 col responsive grid of same NFs with same tone | **Pin to 5-col grid at `md`+ to match mockup; render identical header line** |
| Lines (N2 · NGAP / N3 · GTP-U) | Two vertical connectors per gNB with centred label; `UP` → `bg-ok` + `text-ok` pill, otherwise `bg-line` + mute pill | OK structure but adds S1 variant | **Keep S1 variant conditional on LTE; default to N2+N3 only when 5G gNB** |
| gNB node card | Antenna icon, `GNB-01`, sub `link <ip> · TAC <tac>`, pill `ACTIVE` with live dot (or `PLANNED` dashed with brand pill); `multi-gNB locked · LIVE-005` for GNB-02 | Close, but uses different ownership badge | **Switch state pill to mockup wording (`ACTIVE` / `PLANNED`); surface `multi-gNB locked · LIVE-005` on non-certified gNBs** |
| UE mini-cards | Phone icon, mono `UE-ID`, pills `REGISTERED` + `PDU` (when active) | Adds `PROTECTED` footer | **Remove PROTECTED footer (mockup drops it since identity never shown); keep the dotted path to UE Activity page via `onClick` on card** |
| Footer note | "Each UE searches only for its serving gNB (gnbSearchList). UERANSIM has no handover, so a UE stays on its gNB." | Not shown | **Add footer note** |

---

## 3. Core · Open5GS (`/network/core`)

Current: `apps/simulator-control/src/pages/CoreOpen5gs.tsx`.

| Bloc | Mockup | Actuel | Écart |
|---|---|---|---|
| Eyebrow / title / desc | `Network` · `Core · Open5GS` · "Open5GS 2.8.0 running the lab 5G core. Observe first; subscriber changes need a confirmation and a database backup; configuration edits come last." | Close enough but mentions Enterprise Precision wording | **Align copy to mockup verbatim** |
| Tabs | 3 tabs: `Network functions` / `Configuration` / `Subscribers` | 3 tabs, same labels | ✓ ok |
| Functions table columns | **Function / State / Address / Detail / Actions** | Function / State / Detail / Actions (Address removed) | **Restore `Address` column**; use `/lab` info to feed it when available, else `—` |
| Functions row — identity | mono NF name + role sub-caption | OK | ✓ |
| Functions row — state | `ok` pill with live dot | OK | ✓ |
| Functions row — detail | role-specific sub-caption (NGAP SCTP 38412 · 1 gNB connected, etc.) | Dumped from `observed.open5gs` container info | **Prefer the mockup descriptor; fall back to container info only when no NF detail available** |
| Functions row — action | `Restart` locked | OK | ✓ |
| Config tab — left card | "Identity and slicing" — PLMN / AMF NGAP / TAI list / S-NSSAI / DNN / AMF field | "Capabilities" with `/capabilities` endpoint | **Switch to mockup card: hard-wire the 6 fields; use `/lab` or `/capabilities` for values** |
| Config tab — right card | "Consistency checks" — 4 rows (PLMN / TAC / GNB-02 plan / UE profile slice) | OK | ✓ |
| Config tab — footer | Locked `Edit configuration` button | OK | ✓ |
| Subscribers tab — left table | Columns Slot / Identity (PROTECTED) / Profile / S-NSSAI · DNN; "Identity" column shows `<key icon> PROTECTED` monochrome | Current columns differ | **Rebuild table with mockup columns**; **IMSI for operator** (per Message B) → show full IMSI mono only when role=operator & #48 API shipped; otherwise `PROTECTED` icon |
| Subscribers tab — right card | "Provision a subscriber" with intro paragraph, 3-step `<ol>` and locked `Provision UE-13` button; small print "SUPI, K and OPc are generated server-side and never displayed." | "Generate…" dialog (already shipped) | **Keep Generate dialog but match mockup wording and layout (title / 3-step list / footer); IMSI pour operator in a separate role-gated section when API is ready** |

---

## 4. gNodeBs (`/network/gnbs`)

Current: `apps/simulator-control/src/pages/Gnbs.tsx`.

| Bloc | Mockup | Actuel | Écart |
|---|---|---|---|
| Eyebrow / title / desc | `Network` · `gNodeBs` · "UERANSIM gNodeBs connected to the core. A UE profile names its serving gNB; the controller writes it into the UE's gnbSearchList." | Different wording | **Align wording** |
| Header action | `Add gNodeB` locked (V1.1) | OK | ✓ |
| Card grid | 2-col at `lg`, 1-col below | ✓ | ✓ |
| Card header | `GNB-XX` + sub `UERANSIM 3.3.0 · NCI 0x… / 32 bits` + state pill (ACTIVE live, PLANNED brand dashed) + certification pill (`Live certified` / `Not certified`) | Uses process-state wording, differs on certification | **Switch to mockup wording and badges**; map `running`→`ACTIVE`, `NOT_DEPLOYED`→`PLANNED` |
| dl grid | 6 fields (PLMN · TAC / Link IP / NGAP IP / GTP-U IP / NG Setup / UEs attached) | Different field set | **Replace with the 6 mockup fields**; feed from `/gnbs` + `/nodes` |
| Footer actions | ACTIVE → locked `Stop gNB`; PLANNED → locked `Deploy and start` + explanatory sub-caption | Different wording | **Align wording and locked reasons** |

---

## 5. UE Manager (`/ues`)

Current: `apps/simulator-control/src/pages/UeManager.tsx`.

| Bloc | Mockup | Actuel | Écart |
|---|---|---|---|
| Eyebrow / title / desc | `Simulation` · `UE Manager` · "UE profiles bound to a serving gNB and, ideally, to a provisioned subscriber slot. Identity is write-only." | `Operations` · `UE Profile Manager` · different desc | **Align eyebrow/title/desc** |
| Header actions | 2 buttons: `Add UE` primary + `Export CSV` secondary | Live grant + Add UE + Bulk create + Import CSV + Export CSV | **Keep the mockup 2 buttons visible at all times**; **expose the live-grant action in a dedicated topbar / page-sticky slot** (so it is preserved as per Message B §3). Bulk / Import go into a kebab or sticky bar when selection > 0 |
| Columns | 7 cols: UE / Serving gNB / Subscriber / Registration / PDU · IP / Scenario / Actions | 8 cols: ☐ / UE ID / IMSI / Owner / Serving gNB / État / Scenario / Actions | **Target the mockup 7-col structure**; keep selection via hover + checkbox-on-row; **merge Registration + PDU · IP cells back out of État**; IMSI shown ONLY as a sub-caption `slot UE-XX` (mockup) unless role=operator (then mono IMSI in the Subscriber cell, feature-gated on #48) |
| Owner column | Not present | New in 0.11.x | **Fold Owner into UE row sub-caption (`<name> · owner <email>` or `—`)** |
| État column (0.10.4) | Not present (mockup splits Registration vs PDU) | Present | **Replace by 2 columns (`Registration` / `PDU · IP`)**; keep enriched text ("↑ x Mbit/s ↓ y Mbit/s · TCP/UDP") inside the `PDU · IP` cell for #50 |
| Actions cell | Shared → locked `Protected`; Registered → outlined `Stop`; Non-provisioned → locked `Start`; Provisioned → primary `Start` | Richer menu (Run / Stop / Live grant / dot delete etc.) | **Follow mockup first-row CTA**; place `Run` + `Stop` behind a kebab reachable from the row; **expose live-grant intent at page level** |
| Pagination | None (small list) | 25/50/100/250 selector + prev/next | **Hide pagination until > 50 rows**; keep selector in overflow |
| Bulk bar | None | Shown when selection > 0 | **Hide behind kebab in mockup chrome; keep behaviour** |

---

## 6. Scenarios (`/scenarios`)

Current: `apps/simulator-control/src/pages/ScenariosLibrary.tsx` + `ScenarioBuilder.tsx`.

| Bloc | Mockup | Actuel | Écart |
|---|---|---|---|
| Eyebrow / title / desc | `Simulation` · `Scenarios` · "Saved on the controller with versions. Six V1 step types; numeric parameters can be fixed or random." | `Workflows` · different desc | **Align copy** |
| Header action | `New scenario` primary | `Import JSON` + `Create scenario` | **Primary CTA = `New scenario`; keep Import JSON behind a kebab** |
| Layout | 2-col: left scenario sidebar (card w/ list buttons) + right detail card | Full-width table with search, templates tab, columns (steps / loop / assigned / updated / actions) | **Replace table with 2-col sidebar + detail**; keep template-vs-mine as a filter chip row inside the sidebar card |
| Sidebar list item | `<name>` bold + `v<ver> · <n> steps · ×<loop>` mono mute | Table row with 7 columns | **Collapse to list-button items** |
| Detail card | h2 scenario name + `v<ver>` mute + loop pill; ordered list of steps `<n> · <type_mono> · <desc>` | Edit/Duplicate/Delete + rows | **Rebuild detail card**; keep edit/duplicate/delete in a header kebab |

---

## 7. Execution monitor (`/scenarios/monitor`)

Current: `apps/simulator-control/src/pages/ExecutionMonitor.tsx`.

| Bloc | Mockup | Actuel | Écart |
|---|---|---|---|
| Eyebrow / title / desc | `Simulation` · `Execution monitor` · "Step states come from the controller, never from the browser." | `Workflows` · different | **Align copy** |
| Status card | 1 card: left side scenario name + mono UE/job/loop sub; right side RUNNING live pill + outlined bad `Stop job` button | Dense dl with ~13 fields | **Compact header card**; move the 13 metrics into a second card below ("Runtime detail") |
| Steps list | Rounded border rows: `<n> · <type_mono> · <state_pill> · <desc_mute>` | Backend-flag conditional block | **Always render steps list with mockup layout** when a job is in flight; derive state from backend when `scenarioBackend` flag ON, otherwise from local projection |

---

## 8. History (`/history`)

Current: `apps/simulator-control/src/pages/History.tsx`.

| Bloc | Mockup | Actuel | Écart |
|---|---|---|---|
| Eyebrow / title | `Review` · `History` | `Review` · `Scenario history` | **Rename title to `History`** |
| Table columns | 5: Job / Scenario / UE / Loops / Result | 7: Scenario / Target UE / Started / Duration / Packets / Terminal result / State | **Collapse to the 5 mockup columns**; expose Started/Duration/Packets via row expand or details drawer |
| Result pill | COMPLETED (ok) / FAILED (bad) / STOPPED (mute) | Separate State + Terminal result columns | **Single `Result` pill with mockup tone mapping** |

---

## 9. Backend reality & "backend pending" (per mockup README)

Items the mockup renders that have no API support → render **locked** with reason string:

| Target | Status | How we lock it |
|---|---|---|
| NF restart | locked | Already locked ✓ |
| Core config edit | locked | Already locked ✓ |
| Live subscriber list (full) | locked | We DO have `/subscribers` for POLARIS-owned slots → show those; add a note "Open5GS-owned records never shown" |
| GNB-02 deploy | locked (LIVE-005) | Already locked ✓ |
| ENB-01 | locked (LTE_ATTACH_NOT_CERTIFIED) | Already locked ✓ |
| `GET /lab` for Core NF state | **real** route ✓ | Use it |
| `GET /nodes` + `GET /gnbs` | **real** route ✓ | Use them |
| Topology compose | **client-side** composition of `/lab`+`/nodes`+`/ues` | Done ✓ |

Rule from README reconciled with Message B §3 ("IMSI pour l'operator"):
- Default: identity is PROTECTED (icon + mono `PROTECTED`).
- When role=operator AND backend `/subscribers` (or `/ues`) returns real IMSI (API 0.19.7 #48), show mono IMSI in Core · Subscribers (Identity column) and in UE Manager (Subscriber cell sub-caption).
- All other secrets (K, OPc, IMEI, TMSI, GUTI, RNTI) stay PROTECTED.

---

## 10. Preserved functions (checklist for the redesign)

| Function | Where it lives today | Where it lives in 0.12.0 redesign |
|---|---|---|
| Grant / Autoriser le live | UE Manager header button + dialog (0.11.1) | Topbar slot (sticky), visible on UE Manager + Execution monitor |
| Start / Stop / Run (UE) | UE Manager action cell | UE Manager action cell (mockup single CTA + row kebab) |
| Activity (SSE per-UE) | `/ues/:ueId/activity` | Keep route; link from UE row AND Topology UE card |
| Create / Edit / Delete subscriber | Core · Subscribers "Generate…" dialog | Right-hand card on Core · Subscribers tab (mockup) + role-gated |
| IMSI for operator | Not shown today (always PROTECTED) | Operator-only reveal in Core · Subscribers Identity cell and UE Manager Subscriber sub-caption (API 0.19.7 #48 driven) |
| Scenarios create/edit/run | `/scenarios`, `/scenarios/new`, `/scenarios/:id/edit`, `/scenarios/monitor` | Keep routes; detail card primary CTA = `Run` |

---

## 11. Reproduction plan

1. **Shell**: rework `AppShell` + `SidebarNavigation` to match mockup (logo, 3 sections, 8 items, footer note, topbar health/PLMN/live/Light-Dark). Add `.live-dot` CSS keyframes.
2. **Primitives**: lift the mockup's `Pill` / `Locked` / `Btn` / `Card` / `PageHeader` / `Stat` into `apps/simulator-control/src/components/mockup/*.tsx` using packages/ui tokens; mockup CSS vars already correspond to Enterprise Precision tones.
3. **Pages**: rebuild each page in order: Console → Topology → Core → gNodeBs → UE Manager → Scenarios → Execution monitor → History.
4. **Data wiring**: replace mockup sample constants (`CORE`, `GNBS`, `UES`, `SCENARIOS`) with live `useQuery` hooks against existing routes (`/lab`, `/nodes`, `/gnbs`, `/ues`, `/subscribers`, `/scenarios`, `/scenarios/status`, `/activity`, `/history`).
5. **Integrate remaining front items into the new design**:
   - #49 Grant countdown — already shipped; verify placement in new topbar
   - #50 État enriched — collapse back into mockup's `Registration` + `PDU · IP` cells; show PDU detail (`↑ x Mbit/s ↓ y Mbit/s · TCP/UDP`)
   - #51 UE detail page — verify route still works from Topology UE card + UE Manager row
   - #45 Subscribers AMBR<10Mbit or no-SD orange warn — pill in Identity column secondary line
   - #44 Provisioning retry + real HTTP code — error toast with status code; retry button
   - Owner column — move into UE row sub-caption, not a column
6. **API 0.19.7** (#48 IMSI operator exposure, #50 `/activity` protocole) — separate commit on `feat/polaris-0.19.7-imsi-expose` from `28da715`.
7. **Captures**: Playwright projects at 1280/1440/1920 × light/dark; a dedicated run per page producing side-by-side composites in `apps/simulator-control/docs/screenshots/0.12.0/<page>/mockup+impl.{light,dark}.png`.
8. **Anti-overlap**: existing test suite re-run at 1280/1440/1920.

— BC3
