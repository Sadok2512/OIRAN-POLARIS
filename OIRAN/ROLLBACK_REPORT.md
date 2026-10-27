# Rollback Report

Rollback was prepared but not executed because all critical deployment checks passed.

Snapshot directory: `/root/OIRAN_VPROBE/deployment/rollback/20261025T211500Z` (mode `0700`, excluded from Git).

It contains the previous mapped API binary, transient service definition, prior privilege drop-in, and the protected operator environment. The legacy capture path must never be re-enabled. If rollback becomes necessary, restore historical analysis availability with capture execution disabled; do not restore the unsafe `tcpdump` privilege configuration.

The installed persistent unit files and artifact hashes are recorded in `DEPLOYMENT_MANIFEST.json` for deterministic review.
