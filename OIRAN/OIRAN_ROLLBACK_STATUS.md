# OIRAN Dataset Fix Rollback Status

Rollback was prepared but not required.

Protected backup directory:

`/var/backups/oiran/dataset-fix-07333b2-20261025T220800Z`

It contains the previous API/helper binaries, both systemd unit files, and protected environment files. Directory mode is `0700`; environment backups are mode `0600`.

Previous binary hashes:

- API: `ad560d2bd3aa7d790f11efc12c91f231603b99e5bd28236c5a1326c147c7e9c3`
- Helper: `35486254cda1755f9e2af18e049fa5c110e742cfcb029d5ec7673a946f8712bf`

If rollback becomes necessary, restore only the reviewed OIRAN API/helper artifacts and units, keep capture execution disabled during verification, restart only the two OIRAN services, and verify historical read-only analysis. The unsafe legacy tcpdump backend must not be reactivated.

