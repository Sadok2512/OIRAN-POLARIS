# S2.1 CPU affinity report

## Implementation

Affinity accepts `auto`, `explicit`, or `disabled`. The runtime obtains the calling process's effective mask with `sched_getaffinity`; it never assumes host CPUs 0–9 are usable. Automatic mode requires one distinct producer CPU plus one CPU per worker. Explicit IDs are rejected if duplicated, outside the effective cpuset, or inconsistent with worker count.

Mode C pins only its own producer thread through a restoring guard and assigns distinct worker CPUs. Mode B has no producer in the timed path and pins each independent worker. Effective masks are captured from inside worker threads and included in output. Mode A uses the selected producer CPU. No unrelated PID or global scheduler setting is touched.

## Validation

Unit tests validated an artificial non-contiguous allowed mask `[3,5,7,9]`, automatic selection, explicit selection, duplicate rejection, outside-mask rejection, and worker-count matching. Runtime affinity was not exercised in a performance run because the safety gate failed.

Recommended initial topology after a quiet gate: automatically select one producer plus two workers. Four workers require five distinct allowed CPUs and remain within the approved maximum.
