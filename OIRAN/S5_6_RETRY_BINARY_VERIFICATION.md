# S5.6 Retry Binary Verification

| Component | PID | Executable | Running SHA256 | Result |
|---|---:|---|---|---|
| OIRAN API | 3897041 | `/opt/oiran/bin/oiran-api` | `1d928d0175d9cc4a40e76e600920d0dbe4630b476ce3531bf2badc6b8a7fd191` | exact Release artifact |
| Capture Helper | 3891823 | `/opt/oiran/bin/oiran-capture-helper` | `b26963459cad9810cdda6ae31ff2ab446b842835cd5db14375746f206b6c5850` | exact Release artifact |

Verification used `/proc/PID/exe`, not only installed-file hashes. The API reports version `2.3.0`; the source release is `2.3.0-dev` from the reviewed commit. Both services are active and use the same source release.

The API has an empty capability bounding/ambient/effective set. The helper runs as UID 995/GID 987 with only `CAP_NET_RAW`. Neither service has child packet-capture subprocesses. The legacy tcpdump execution adapter is absent and disabled.

