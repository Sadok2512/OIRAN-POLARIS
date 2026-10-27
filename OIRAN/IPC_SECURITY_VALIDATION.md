# IPC Security Validation

- Socket: `/run/oiran/capture-helper.sock`
- Owner: `oiran-capture:oiran-capture`
- Socket mode: `0660`
- Runtime directory mode: `0750`
- Server identity checked by the API: UID 995
- Allowed client credentials: UID 0, GID 0 (the hardened OIRAN API service)
- API supplementary socket-access group: `oiran-capture`

An authorized round trip returned protocol version 1.0 and state `READY` for a validation-only N2/N3/N4 request. A connection attempt as `nobody` was rejected with `EACCES`. An API request for `eth0` was rejected as `INTERFACE_eth0_NOT_ALLOWLISTED`.

The IPC schema does not accept output paths, shell commands, or arbitrary BPF expressions. No public TCP listener is created by the helper.
