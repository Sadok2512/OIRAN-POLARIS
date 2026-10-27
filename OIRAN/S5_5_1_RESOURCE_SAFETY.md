# S5.5.1 resource safety

The four-plane request retains one global `max_bytes` reservation. For each job, the helper computes:

`segments = logical_planes × rotation_files`

and divides the global budget across those bounded segments. The default 256 MiB job with four planes and four rotations therefore allows at most 16 MiB per file and 64 MiB per plane, never 256 MiB per plane.

The Capture Guard authorizes every write against the same global reservation. Existing maximum duration, file count, file size, concurrent-job, inode and disk thresholds remain unchanged. Tests verify aggregate writer capacity does not exceed the requested job budget, oversized jobs fail disk safety, partial-plane initialization fails closed, and no automatic deletion occurs.

Offline validation snapshot: filesystem 63% used with 155,305,828,352 bytes available and 3% inode use; 15,628,136,448 bytes RAM available. No live write reservation was created.
