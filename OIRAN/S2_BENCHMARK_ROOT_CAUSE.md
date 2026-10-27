# S2 benchmark root-cause assessment

## Conclusion

The best-supported primary cause of poor scaling beyond two workers is **E. BENCHMARK_PRODUCER_BOTTLENECK**. The producer performs serial frame allocation/fill, integrity fingerprinting, provenance construction and dispatch; one worker plus producer already consumes about 1.88 cores, and adding workers produces little additional CPU consumption or throughput.

The shared VPS was not isolated. Current measurements confirm that ETV/OTV can consume multiple cores and all unrestricted workloads overlap the benchmark CPU set. This is a credible variance source and makes absolute throughput less reliable, but historical data does not confirm sustained external CPU saturation during S2. A later POLARIS capture-container restart also makes the live diagnostic window unsuitable as a quiet benchmark window.

## Classification

| Class | Evidence | Affected workload | Time correlation | Impact | Confidence |
|---|---|---|---|---|---|
| A. EXTERNAL_CPU_CONTENTION | Current OTV cgroup averaged 754% in one burst window; ETV test DB 87%; all use CPU 0–9 | `otv-worker-1`, `etv-test-db-1` | Current only; OTV deployment activity overlapped S2 but historical CPU by container unavailable | Can add jitter/preemption | MEDIUM for current contention; LOW for causal S2 attribution |
| B. CPU_QUOTA_OR_THROTTLING | Benchmark session `cpu.max=max`, `nr_throttled=0`; taskset only | Rust benchmark | Direct configuration | Not causal | HIGH confidence rejected |
| C. HYPERVISOR_STEAL_TIME | 0.31% in historical S2 aggregate; 0.14% current five-second average | Whole VM | Historical and current | Negligible relative to scaling gap | HIGH confidence rejected |
| D. CPU_AFFINITY_CONFLICT | Workers fixed to CPU 0…N−1; producer allowed on 0–4; external processes also 0–9 | Producer/workers and shared workloads | Configuration existed during S2 | Possible migrations/preemption; not measured per run | MEDIUM |
| E. BENCHMARK_PRODUCER_BOTTLENECK | 1 worker already 187.66% CPU/2.999539 Gbit/s; 2 workers 197.52%/3.175694; 3–4 regress | Benchmark producer | Direct S2 measurements | Primary scaling ceiling | HIGH |
| F. QUEUE_OR_DISPATCHER BOTTLENECK | Larger batches improve rate; seven small-frame one-worker cases reached queue bound and dropped explicitly; best profile queue depth low/no drops | Producer-to-worker channels | Direct S2 measurements | Secondary/profile-specific; dispatcher not isolated | MEDIUM |
| G. INSUFFICIENT EVIDENCE | No historical PID CPU or thread migration at 100 ms resolution | External-cause attribution | Missing | Prevents definitive PID blame | HIGH |

## Root-cause ranking

1. **Confirmed primary:** serial producer/generator ceiling.
2. **Confirmed design risk:** producer has no dedicated CPU and may overlap pinned workers.
3. **Confirmed current environmental risk:** unrestricted ETV/OTV workloads can occupy the same CPUs.
4. **Not supported:** benchmark CPU quota or cgroup throttling.
5. **Not supported:** hypervisor steal as a material cause.
6. **Unknown:** exact contribution of external processes to individual S2 measurements.

## Benchmark reliability

- Correctness/integrity comparisons: HIGH; 17/17 tests and no silent loss.
- Relative before/after optimization at the same method: MEDIUM-HIGH; repeatable gains, but shared-host variance exists.
- Absolute scaling/line-rate capacity: MEDIUM-LOW; short 100 ms points, nonexclusive CPUs and no per-run scheduler telemetry.
- 25/100 Gbit/s certification: NOT ESTABLISHED.

S2.1 should not resume while OTV workload and lifecycle are unstable. No recommendation requires stopping ETV/OTV; an owner-approved quiet window or separate benchmark host is preferred.

