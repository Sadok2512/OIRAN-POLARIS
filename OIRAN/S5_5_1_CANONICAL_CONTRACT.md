# S5.5.1 canonical capture contract

`MAX_CAPTURE_PLANES = 4`.

| Logical plane | Wire identifier | Fixed Linux capture point | Fixed scope |
|---|---|---|---|
| NG-C | `N2` | `br-oiran-n2` | SCTP port 38412 |
| SBI | `SBI` | `br-oiran-sbi` | TCP port 7777 |
| N4 | `N4` | `br-oiran-n4` | UDP port 8805 |
| NG-U | `N3` | `br-oiran-n3` | UDP port 2152 |

The browser sends logical wire identifiers only. It cannot submit Linux device names, namespaces, output paths, shell commands or custom filters. The API resolves the logical values against its fixed discovery registry. IPC converts them to the closed `InterfaceId` enum. The helper independently maps that enum to fixed devices and packet filters.

One through four unique allowlisted planes are valid when available. Empty, duplicate, unknown, unavailable or more-than-four selections fail closed. Logical count is distinct from device identity; the mapping remains explicit even if future deployments place multiple planes on one approved device.
