# OIRAN Live V1 Disk Safety

The existing 75/80/85/90 policy is enforced at validation and once per second during a job. Measurement failure blocks capture. At 85% the manager gracefully finalizes OIRAN-owned helpers; at 90% no new writes are accepted. Read-only analysis stays available.

The request byte limit is a global job budget. It is divided across selected interfaces and rotation segments, preventing three-interface capture from multiplying the reserved allowance. V1 allows one concurrent job, up to 15 minutes, up to eight files, and the policy maximum of 2 GiB. The UI default is 60 seconds and 256 MiB total.

There is no cleanup or deletion operation. Certified datasets, POLARIS files, ETV/OTV data and unknown-owner resources are never removed.
