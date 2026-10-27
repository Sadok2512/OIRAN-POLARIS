# Capture Helper Service Report

| Property | Verified value |
|---|---|
| Service | `oiran-capture-helper.service` |
| Binary | `/opt/oiran/bin/oiran-capture-helper` |
| SHA256 | `35486254cda1755f9e2af18e049fa5c110e742cfcb029d5ec7673a946f8712bf` |
| Service user/group | `oiran-capture` / `oiran-capture` (995/987) |
| State | active, enabled |
| Started | 2026-10-25 21:19:47 UTC |
| Capabilities | `CAP_NET_RAW` only (`CapEff=0x2000`) |
| NoNewPrivileges | enabled |
| Address families | `AF_UNIX`, `AF_PACKET` only |
| Public listener | none |
| Docker socket | unavailable |
| systemd exposure | 4.2, OK |

`CAP_NET_ADMIN`, `CAP_SETUID`, and `CAP_SETGID` are not granted. The helper is restricted to the fixed N2/N3/N4 interface enum and the dedicated capture directory `/var/lib/oiran/captures`.
