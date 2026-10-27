# S5.6 Retry Four-Plane Validation

Production validation results:

| Request | Result | Evidence |
|---|---|---|
| NG-C (`N2`) | PASS | READY, interface available |
| SBI | PASS | READY, interface available |
| N4 | PASS | READY, interface available |
| NG-U (`N3`) | PASS | READY, interface available |
| NG-C + SBI + N4 + NG-U | PASS | READY, four logical planes accepted |
| Five entries | REJECTED | `INVALID_INTERFACE_COUNT` plus duplicate evidence |
| Duplicate plane | REJECTED | `DUPLICATE_INTERFACE` |
| Unknown plane | REJECTED | `INTERFACE_X5_NOT_ALLOWLISTED` |
| Unauthenticated request | REJECTED | HTTP 403 |

Resolved production capture points:

- NG-C: `br-oiran-n2`, SCTP/38412.
- SBI: `br-oiran-sbi`, TCP/7777.
- N4: `br-oiran-n4`, UDP/8805.
- NG-U: `br-oiran-n3`, UDP/2152.

The reviewed profile requests a bounded 256 MiB total capture budget. The disk policy additionally bounds every rotated file at 256 MiB, permits at most eight files, and reports a 2 GiB absolute policy ceiling. The validated request reserved 32 MiB of between-poll safety headroom. No `StartCapture` request was made and the capture registry remained at zero active jobs.

