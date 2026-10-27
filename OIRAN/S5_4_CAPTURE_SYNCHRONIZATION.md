# S5.4 capture synchronization

## Common manifest

All four workers must share `scenario_id = OIRAN-E2E-001` and record capture ID, probe ID, host bridge, monotonic start/ready/stop times, UTC packet timestamps, first/last packet, packet/byte/drop counts, file rotation index, SHA256 and decoder version.

Docker containers use the host kernel clock. This implies a common clock source, but the plan must still record each worker's ready timestamp and observed offset; it must not assume a numeric zero offset without measurement.

## Barrier sequence

1. `ValidateCapture` independently for N2, SBI, N4 and N3.
2. Reserve the global write budget atomically.
3. Create all job records in `READY` without packet acquisition.
4. Start all workers and wait for every worker to report successful packet-source initialization.
5. Record a common barrier timestamp. If any worker is not `CAPTURING`, stop/finalize only the scenario-owned workers and do not start the UE.
6. Launch the separately approved UE scenario and record its controller job ID.
7. Record Registration, PDU activation and traffic boundaries in the common manifest.
8. Finalize workers in N3, N4, SBI, N2 order after the final expected response and a bounded two-second drain.
9. Atomically finalize manifests, then calculate SHA256 without changing originals.

## Rotation and HPACK

Use a five-minute duration, 64 MiB per interface and one file per interface for this low-volume test. If SBI must span existing rotations, feed preceding files into one ordered offline TCP/HPACK state without editing them. Capture truncation, gaps and mid-connection starts remain explicit partial evidence.

## Collision controls

The native helper allows one active capture job. Existing continuous laboratory captures have separate ownership and filenames. The test must not overwrite, stop or repurpose them. Current 30-second background UE traffic is a confounder and requires an explicit pre-test decision as described in the test plan.
