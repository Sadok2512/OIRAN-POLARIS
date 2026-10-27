# S5.5.1 validator root cause

Baseline `ab5e3e34dfbf27416940d3e9f986f5d432bbbac8` introduced a four-plane default profile but retained two earlier cardinality checks:

- `live-probe` rejected more than three logical interfaces.
- `capture-helper` independently rejected more than three interface enum values.

The S5.5 test verified four-plane serialization and UI visibility, not execution of `ValidateCapture`. The API authorization test expected an invalid result because execution was deliberately gated and asserted only that one gate was present. This allowed the contradictory interface-count blocker to remain unnoticed.

The correction defines one exported Rust constant in the security boundary crate and consumes it in both validators. Tests now execute the four-plane contract rather than inspecting it structurally.
