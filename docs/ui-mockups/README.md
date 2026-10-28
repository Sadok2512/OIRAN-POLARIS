# UI mockups — POLARIS Control & Probe Manager

Reference mockups (React 18 + Tailwind, single HTML file, **example data only**).
Open them directly in a browser. They are a visual/UX target, **not** code to copy:
the implementation goes into the real apps with the existing `packages/ui` tokens
("Enterprise Precision") and the real API fields.

| File | Target app | Screens |
|---|---|---|
| `portal.html` | `apps/portal` (:8020/portal/) | 3 bricks: POLARIS Control, Probe Manager, OIRAN Analyzer — same layout as today, new names/taglines/scope chips |
| `probe-manager.html` | `apps/probe-manager` | Overview, Probes (multi-interface + inspector), Register probe dialog, Interfaces, Live captures, Capture library, Preferences |
| `oiran-analyzer.html` | `OIRAN/apps/web` (served at /analyzer/) | Overview, Sessions, Call flow (ladder + IE inspector), Correlation, Packets, Datasets, Exports — Probe Manager page leaves the Analyzer |
| `polaris-control.html` | `apps/simulator-control` | Console, Topology, Core · Open5GS (functions / config / subscribers), gNodeBs, UE Manager, Scenarios, Execution monitor, History |

## Architecture rule
- **POLARIS** controls Open5GS core, gNBs/eNB, network topology, UEs and scenarios.
- **Probe Manager** manages probes only (vProbe + physical), each probe with N interfaces (role N2/N3/N4/S1/N6).
  The Topology page leaves Probe Manager.

## Backend reality (audit 2026-10-28) — what the UI may show as real
| Block | Real route | Not available → locked / "backend pending" |
|---|---|---|
| Core NF state | `GET /lab` (container status) | NF restart, config edit, live subscriber list |
| gNB/eNB | `GET /nodes`, `GET /gnbs` | start/stop, create GNB-02 (LIVE-005), ENB-01 = `LTE_ATTACH_NOT_CERTIFIED` |
| Topology | compose `/lab` + `/nodes` + `/ues` client-side | single topology route |
| Probes | `GET /probes`, `/probes/:id`, `/probes/:id/interfaces`, `/interfaces` | `POST /probes` (register), physical type, interface role field |
| Analyzer | `/sessions`, `/sessions/:id/callflow`, `/events/:id`, `/datasets`, `/packets` (OIRAN API, `{data,meta}`) | PCAP slice / frame download (`/captures/:id/download` = 404) |
| Captures | `GET /captures*` | Stop stays locked; `/captures/:id/download` = 404 |

Never display subscriber identity (IMSI, IMEI, TMSI, GUTI, RNTI, K, OPc): secrets are write-only (`PROTECTED`).
