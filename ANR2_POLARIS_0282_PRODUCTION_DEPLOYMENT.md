# ANR2 — POLARIS 0.28.2 Production Deployment

Date UTC: 2026-11-01

DEPLOYMENT = PASS

ACTIVE_VERSION = 0.28.2

RUNNING_SHA256 = `c7b2687c6f2f374609c4b8455b0583f1a1211b810cab1d3018c7ff039bb2a2f3`

SOURCE_SHA = `d22b24ffc0b4fea792310084dbc7b5020aafbbff`

BACKUP = PASS — `/root/release-gate-backups/20261101T134642Z-polaris-0282-prep/polaris-0281-current.tar`, SHA256 `fa09dcd14e1d94daa69b517f3d6f9e73025c9cf8177dcf4870c3326203beeed5`; extracted rollback binary verified as 0.28.1 hash `3294fc65dbb7b5b28a734dc0d92e621c99fd0d9501b3e837ed7fdc05d8d7d450`.

HEALTH = PASS — local and public `/api/v1/version` and `/health` returned HTTP 200 with 0.28.2/ok. Public endpoint verified at `https://polaris.etv-sadok.duckdns.org`.

SECURITY = PASS — anonymous viewer has no start/admin permission and no CSRF token; unauthenticated Grant creation returned HTTP 403. The only stored LTE Grant V2 is the previous certification record in `REVOKED` state; active grant count is zero. `certified=false`, ownership false, S1/Attach/session UNKNOWN and traffic disallowed.

FUNCTIONAL_READS = PASS — 13 templates (6 LTE, 7 5G SA), zero traffic sessions, no DEMO/mock/fixture marker in audited operational responses.

OIRAN = UNCHANGED — API 2.7.3, PID 1685704, running hash `bbb7ca640794d17654540c4b80f23c17cd5afb0cacb401337e96fae4e23c0845`.

DUMPCAP = PASS — all 12 baseline PIDs unchanged: `1803146,1803148,1803159,1803167,1803196,1803202,1803241,1803293,1803305,1803312,1803318,1803320`.

RESOURCES = PASS — RAM used 7,375,511,552 B; available 13,595,070,464 B; disk 64%.

ROLLBACK = NOT REQUIRED; exact 0.28.1 rollback remains prepared and verified.

No grant, LTE process, traffic, UI, OIRAN or capture component was created, started, deployed or modified.

— ANR2
