# V3.2.1 CPU PSI Validation

Fresh post-deployment observations on 2026-10-26 UTC showed:

- PSI `some avg10`: 3.87% during the independent five-second sample; later 5.01%.
- PSI `full avg10`: 0.00%.
- API-reported PSI source: `/proc/pressure/cpu`.
- Telemetry age in the final evidence sample: 656 ms.

The UI truthfully showed transient `WARNING` states when the API cgroup throttling interval crossed the configured warning/block boundary and returned to `READY` only after recovery samples. A single PSI or utilization spike did not become a sustained block.

If PSI is absent or malformed, the policy reports invalid mandatory telemetry and fails closed rather than assuming zero pressure.
