# S5.5.1 API and helper parity

Both Rust validation boundaries consume `capture_helper::MAX_CAPTURE_PLANES`.

| Case | API | Helper |
|---|---|---|
| 1 plane | accepted | accepted |
| 2 planes | accepted | accepted |
| 3 planes | accepted | accepted |
| 4 planes | accepted | accepted |
| 5 entries | `INVALID_INTERFACE_COUNT` | `INVALID_INTERFACES` |
| Duplicate | `DUPLICATE_INTERFACE` | `INVALID_INTERFACES` |
| Unknown | `INTERFACE_*_NOT_ALLOWLISTED` | rejected by closed IPC enum/schema |
| Unavailable | `INTERFACE_*_UNAVAILABLE` | `INTERFACE_UNAVAILABLE` |
| Unauthorized HTTP caller | `OPERATOR_REQUIRED` | IPC peer credentials independently enforced |

Production helper discovery remains rooted at the fixed `/sys/class/net`. Tests inject a temporary directory populated only with the four approved device names. The injection is constructor-only and not exposed through HTTP or environment configuration.
