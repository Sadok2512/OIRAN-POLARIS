# S5.6 Retry Security Report

- Unix socket: `/run/oiran/capture-helper.sock`, mode `0660`, owner `oiran-capture:oiran-capture`.
- API joins only the `oiran-capture` supplementary group and has no Linux capabilities.
- Helper is unprivileged and retains only `CAP_NET_RAW`; `CAP_SETUID`, `CAP_SETGID`, Docker socket access and public TCP control are absent.
- API address families: Unix, IPv4 and IPv6. Helper address families: Unix and packet sockets only.
- Interface names and capture filters are fixed by the allowlist.
- Viewer validation was denied with HTTP 403.
- A random, short-lived validation credential was used only for deployment validation because production stores only its hash. The original `/etc/oiran/operator.env` was restored byte-for-byte and verified by SHA256.
- API/helper process trees contain no tcpdump/dumpcap child process. Existing independent laboratory `dumpcap` workers were not touched.
- No capture or simulator process was started.

