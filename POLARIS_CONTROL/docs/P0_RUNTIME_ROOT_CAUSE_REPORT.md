# P0 Scenario Runtime Root-Cause Report

## Investigated job

`POLARIS-WEB-1792941865027` is `COMPLETED`.

- Start: `2026-10-25T15:24:25Z` (`1792941865`).
- End inferred from the persisted one-second duration: `2026-10-25T15:24:26Z`.
- Owned process exit code: `0`.
- Requested UDP writes: `5`.
- Successful writes: `5`, established from the fixed five-iteration command and successful process exit. This is process-write accounting, not packet-capture proof.
- Owned process remaining: none.
- Shared UE: registered; PDU Session: active; these are preconditions and were not controller-owned.

## Root cause

The backend correctly moved the short-lived child from `RUNNING` into persistent history as `COMPLETED`. The Dashboard polled only `/scenarios/running`. The child finished between two-second polls, so that endpoint immediately returned an empty list and React rendered its empty fallback as `NOT RUNNING`. The Start response was stale evidence and was not the problem.

The traffic endpoint compounded the issue by returning `IDLE` and hardcoded zero counters whenever no child was active, even though it exposed a completed `last_result`.

## Correction

- `GET /api/v1/scenarios/status` returns `active_job` and `latest_terminal_job` from one locked registry snapshot.
- The Dashboard polls that authoritative snapshot every second.
- Terminal jobs remain visible with scenario ID, technology, simulator, UE/PDU counts, traffic state, start/end time, duration and terminal result.
- Process PID, requested datagrams and successful write accounting are persisted.
- A failed child is `FAILED`; an authorized exact-job stop is `STOPPED`; a successful child is `COMPLETED`.
- Stop after completion returns the original terminal state idempotently instead of falsely changing it to `STOPPED`.
- Duplicate job IDs return the original active or terminal job and never start another process.
- Controller restart recovery marks an interrupted active record `FAILED` with `CONTROLLER_RESTART_RECOVERY`.

No new scenario was executed during this fix.
