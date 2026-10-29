# Prepared continuous-import resumption

This change is prepared only; it is not installed by the 0.17 deployment
script. The current maintenance override sorts after
`continuous-import.conf` and disables the importer. In an authorized OIRAN
maintenance window, install the accompanying file as:

```bash
install -m 0644 OIRAN/deployment/oiran-api-continuous-import-resume.conf \
  /etc/systemd/system/oiran-api.service.d/zzz-continuous-import-resume.conf
systemctl daemon-reload
systemctl restart oiran-api.service
```

Expected effect: the importer opens its persisted checkpoint/ledger, resumes
at the first uncommitted source record, and leaves OIRAN-native capture
disabled. The source is the API's exact allowlisted collector volume,
`/var/lib/docker/volumes/oiran_lab_pcap/_data`. External `dumpcap` processes
are independent and are not signalled.
Before executing, the checkpoint generation, source identities, offsets and
event/session stable IDs must be snapshotted and verified according to the
V1.1 lossless-recovery procedure.

Rollback is to remove only
`zzz-continuous-import-resume.conf`, reload systemd and restart only
`oiran-api.service`. The earlier maintenance override then makes the effective
import setting `0`; no checkpoint or registry is rolled back.
