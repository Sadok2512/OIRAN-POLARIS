# POLARIS Control V3.2.1 CPU Safety Implementation

Date: 2026-10-26 UTC  
Branch: `feat/v3-2-1-cpu-safety`  
Deployed source commit: `0314b8a20dd10e64e1b802e1c00aadfb1ff98147`

The former gate compared host `load1` with `std::thread::available_parallelism()`. Under the service's `CPUQuota=100%`, Rust reported one available CPU although the host has ten logical CPUs. Consequently, a normal host load above 1 produced `CPU_CONTENTION_LIMIT`.

V3.2.1 replaces that gate with a modular sampler and evaluator:

- `HostCpuSampler`: successive `/proc/stat` deltas with user, system, idle, iowait and steal accounting.
- `CpuPressureSampler`: `/proc/pressure/cpu`, including PSI averages and stall deltas.
- `CgroupCapacityReader`: cgroup v2 plus v1 fallback, parent quota and effective cpuset evaluation.
- `CpuThrottlingMonitor`: interval deltas for `nr_periods`, `nr_throttled` and throttled time.
- `ScenarioResourceBudget`: bounded traffic, UE lifecycle and four-plane capture envelopes.
- `CpuSafetyEvaluator`: freshness, consecutive samples, hysteresis and precise decision states.

The old load average remains visible as informational data only. It no longer authorizes or blocks execution. The API exposes evidence under `/api/v1/system/health.cpu_safety`; the Web System Health view displays the same authoritative state and reason.

No CPU quota or affinity was changed. No UE, traffic generator or capture was started.
