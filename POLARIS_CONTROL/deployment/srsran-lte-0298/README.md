# POLARIS 0.29.8 LTE runtime overlay

This overlay applies only to `srsenb` and `srsue`. It preserves the existing
`SYS_NICE` capability on the UE, adds it to the eNB, removes the two CPU quota
keys, and grants bounded real-time priority plus unlimited locked memory. It
does not alter Open5GS, capture services, networks, or persistent data.

The release gate renders the base compose file plus this exact override and
pins the canonical JSON SHA-256 in `srsran_controller.rs`.

The matching runtime log configuration is:

- `filename=stdout`, so the API's `docker logs` gates and terminal evidence
  collection observe the same stream;
- `all_hex_limit=64`;
- PHY library disabled, PHY warning, RRC/NAS/PDCP/RLC debug, MAC info.

The deployment procedure must back up the base compose file and both runtime
configuration files before installing the override or changing log settings.
The safety guard enforces the 98% ceiling, the 8 GiB free-space reserve and
the inode/ENOSPC protections restored in POLARIS 0.29.9.
