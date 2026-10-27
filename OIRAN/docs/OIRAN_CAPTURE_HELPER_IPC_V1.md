# OIRAN Capture Helper IPC v1

## Transport and authentication

The API connects to `/run/oiran/capture-helper.sock`. The socket is Unix-only, mode `0660`, and has no TCP listener. The server authenticates every connection with Linux `SO_PEERCRED`; both the configured primary UID and, when configured, primary GID must match. The client independently verifies the helper UID returned by `SO_PEERCRED`.

Messages are one bounded JSON request and one bounded JSON response per connection. Each side accepts at most 64 KiB. Protocol version is `1.0`.

## Allowlisted commands

- `VALIDATE_CAPTURE`
- `START_CAPTURE`
- `STOP_CAPTURE`
- `GET_CAPTURE_STATUS`
- `GET_CAPTURE_METRICS`

The request schema accepts only a capture ID, interface enum, duration, global byte budget, and rotation count. It contains no shell command, executable, output path, raw interface name, or BPF expression.

Interfaces are enums mapped internally:

| ID | Linux device |
|---|---|
| N2 | `br-oiran-n2` |
| N3 | `br-oiran-n3` |
| N4 | `br-oiran-n4` |

Capture IDs are limited to 128 ASCII alphanumeric, hyphen, or underscore characters. A peer may stop only a job created by the same authenticated UID.

## State model

`CREATED → VALIDATING → READY → STARTING → CAPTURING → STOPPING → COMPLETED | COMPLETED_EMPTY | FAILED`

`CAPTURING` is emitted only after every selected AF_PACKET socket and bounded PCAP writer has initialized. An initialization failure remains `FAILED`; it is never reported as an empty success.

Errors contain a stable category, sanitized detail, optional exit code, and optional Unix termination signal. Native capture does not launch a subprocess. The signal fields remain in the contract for adapters and forensic compatibility.
