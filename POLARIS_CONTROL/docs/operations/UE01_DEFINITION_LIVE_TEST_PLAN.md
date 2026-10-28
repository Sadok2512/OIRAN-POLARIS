# One-UE definition Live test plan

This plan is not an execution authorization. Target: one verified controller-owned slot
`UE-01 → GNB-01`, with one `wait` step followed by the existing bounded five-datagram UDP step.

## Preconditions

1. Confirm the deployed source/artifact hashes and explicit Operator approval for this test.
2. Confirm `UE-01` is `POLARIS_CONTROLLER`, uniquely owned, already running, registered, PDU
   `ACTIVE`, bound to `GNB-01`, and has a verified traffic target. If not, stop; this plan does not
   transfer ownership or start a UE.
3. Regenerate and verify the provisioning attestation after any slot binding. No Open5GS write.
4. Confirm no active scenario job, `MAX_LIVE_UES` headroom, CPU safety READY, RAM safety, and disk
   below 90% (`df -P /root`).
5. Enable `POLARIS_DEFINITION_LIVE_ENABLED=true` only in a separately approved POLARIS maintenance
   window. Keep every other safety and Operator/CSRF gate enabled.

## Definition and bounded execution

Create a versioned definition with `loop_count: 1` and exactly:

```json
{
  "id": "ue01-wait-udp-v1",
  "name": "UE-01 wait plus bounded UDP",
  "loop_count": 1,
  "steps": [
    {"type":"wait","loop_count":1,"parameters":{"duration_ms":{"fixed":1000}}},
    {"type":"udp_traffic","loop_count":1,"parameters":{"packet_count":{"fixed":5}}}
  ]
}
```

Validate via the non-executing APIs, then submit one start with `ue_ids:["UE-01"]`. Poll
`/scenarios/:job_id/steps`; require observed transitions from `PENDING` to `RUNNING` to
`COMPLETED`, exact terminal evidence, and no unrelated UE state change. The UDP command is the
existing send-only five-datagram profile; received packets remain unclaimed unless independently
observed.

## Stop and cleanup

If a step fails, resources cross a hard gate, or the Operator requests stop, call the existing
scenario stop route once. It must cancel the job and stop only UEs that this job itself started;
because this plan targets an already-running UE, it must not stop UE-01. Disable the definition
Live flag after evidence collection. Preserve job history and audit records.
