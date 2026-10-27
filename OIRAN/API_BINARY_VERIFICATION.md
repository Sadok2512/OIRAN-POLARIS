# API Binary Verification

| Item | Value |
|---|---|
| Previous mapped binary SHA256 | `feacf022ece0ccfd2ede7da1ebd3873be3f041db5b711a97b81e5e7cf0624722` |
| Deployed binary | `/opt/oiran/bin/oiran-api` |
| Deployed/running SHA256 | `ad560d2bd3aa7d790f11efc12c91f231603b99e5bd28236c5a1326c147c7e9c3` |
| Unit fragment | `/etc/systemd/system/oiran-api.service` |
| Started | 2026-10-25 21:20:25 UTC |
| API version | 2.1.0 |
| Health | healthy |

The API has empty permitted, effective, ambient, and bounding capability sets. It uses the helper socket configured by `OIRAN_CAPTURE_HELPER_SOCKET`; the authenticated API validation completed through that adapter. Source inspection finds no `Command` or subprocess invocation in `live-probe`, `capture-helper`, or the API. The legacy `tcpdump` execution path is absent and there is no running `tcpdump` process.
