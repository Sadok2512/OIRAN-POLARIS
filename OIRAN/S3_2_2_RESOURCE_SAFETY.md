# S3.2.2 resource and production safety

Pre-test: 10 vCPU, approximately 16 GiB RAM available, 90 GiB disk available, no swap, no OOM evidence, CPU 84–94% idle during the observation, zero meaningful steal, and no new restart during the gate. ETV/OTV and required POLARIS components were running; health-check-enabled components were healthy.

The capture container already had two externally caused restarts before the scenario and remained stable throughout this mission. The test generated ten N3 packets total and no benchmark load. Post-test service state and restart counters were checked again.

No ETV/OTV command was issued. No database, volume, Docker network, route, firewall, package, configuration, or service lifecycle was modified.

## External lifecycle observation

At 22:23:33–22:23:44 UTC, roughly one minute after the bounded traffic ended, `otv-app-1` and `otv-worker-1` were replaced by an external Docker Compose action. The new app carries `com.docker.compose.replace=app-1`, has restart count zero, and became healthy. This mission issued no command against OTV and cannot attribute that independent replacement to the ten-packet lab flow. It is disclosed rather than hidden; no OTV degradation was observed after replacement.
