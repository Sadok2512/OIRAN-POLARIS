# POLARIS 0.29.8 LTE runtime overlay

This overlay applies only to `srsenb` and `srsue`. It preserves the existing
`SYS_NICE` capability on the UE, adds it to the eNB, removes the two CPU quota
keys, and grants bounded real-time priority plus unlimited locked memory. It
does not alter Open5GS, capture services, networks, or persistent data.

The release gate renders the base compose file plus this exact override and
pins the canonical JSON SHA-256 in `srsran_controller.rs`.

The matching runtime log configuration is:

- `filename=/var/log/oiran/srsue.log` or `srsenb.log`;
- `file_max_size=4999` KiB;
- `all_hex_limit=64`;
- PHY library disabled, PHY warning, RRC/NAS/PDCP/RLC debug, MAC info.

The deployment procedure must back up the base compose file and both runtime
configuration files before installing the override or changing log settings.
No percentage-based disk gate is part of this release. Before a write, the
operator still verifies available bytes and inodes; ENOSPC is fail-closed.
