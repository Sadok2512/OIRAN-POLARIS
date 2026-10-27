# OIRAN Running Binary Verification

| Component | Running path | SHA256 | Identity | State |
|---|---|---|---|---|
| API | `/opt/oiran/bin/oiran-api` | `9d8c296e6eca8a9aedd28a6ca7ec15ab3ca86e4fabc08b1ae987460d790bcc17` | `root` with empty capability sets | active |
| Capture Helper | `/opt/oiran/bin/oiran-capture-helper` | `83bec7371c9a32885c79a14ac015acb4c83b80f3d86dcbb1d11b5fd9537d5b96` | `oiran-capture` with `CAP_NET_RAW` only | active |
| Recovery CLI | `/opt/oiran/bin/oiran-recover` | `94f00480ed90af81d6379363dc0808844e5bcac3b27a689488643903fa875649` | offline tool, not a service | installed |

The hashes of `/proc/<pid>/exe` match the installed candidate hashes. No deleted or stale executable is mapped. API version is `2.1.0`; Platform Core is `2.1.0-dev`.

Systemd `ExecStart` remains fixed to the paths above. The API has `NoNewPrivileges=yes`, an empty capability bounding set, and communicates with the helper over Unix IPC. No `tcpdump` process exists and no Rust capture component contains a subprocess invocation for tcpdump.

