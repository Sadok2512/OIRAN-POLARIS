# S2.1 resource safety report

## Decision

`RESOURCE_SAFETY_GATE = FAIL`  
`BENCHMARK_STATUS = DEFERRED_RESOURCE_SAFETY`

The prerequisite 15-minute stable window was not demonstrated. Existing diagnostic evidence records OTV lifecycle transitions during the earlier S2 interval and an external restart of `oiran-lab-capture-1` at 21:11:42 UTC. OTV also exhibited major CPU bursts during the diagnostic. Historical sampling cannot prove a clean 15-minute period for this execution. Per policy, no A/B/C throughput run was launched.

## Implemented gate thresholds

- minimum uninterrupted observation: 900 seconds;
- Docker container identity set unchanged; protected workloads present and healthy;
- no OOM-killed state and no running OIRAN benchmark;
- CPU PSI `some avg10 < 2%` and memory PSI `full avg10 = 0`;
- steal below 1% per sample;
- available RAM at least 8 GiB;
- no root-cgroup throttling increment;
- no ETV/OTV container sample at or above 200% CPU;
- five-minute receipt validity after a pass.

The observer is `/root/OIRAN_VPROBE/scripts/s2_1_safety_gate.sh`. It performs read-only host/container inspection and writes only a small receipt in this workspace. No service, cgroup, affinity, kernel parameter, network, ETV/OTV resource, or POLARIS resource was changed.

## Resume conditions

Obtain owner confirmation that lifecycle activity is expected/stable, achieve a fresh passing receipt, begin with one worker and bounded 250 ms runs, then two workers. Continuously reject runs on service degradation, lifecycle change, OOM, pressure, steal, throttling, affinity failure, or accounting mismatch.
