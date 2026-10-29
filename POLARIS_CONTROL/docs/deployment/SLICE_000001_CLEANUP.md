# Prepared cleanup for POLARIS-owned slice 1/000001

This is a prepared operator procedure. It was not executed while creating this
release. It deliberately matches only records carrying the POLARIS ownership
marker and the exact S-NSSAI.

## Backup and preview

```bash
cleanup_stamp=$(date -u +%Y%m%dT%H%M%SZ)
cleanup_dir=/var/backups/polaris-control/subscriber-cleanup-$cleanup_stamp
install -d -m 0700 "$cleanup_dir"
docker exec oiran-lab-mongodb-1 mongodump \
  --db open5gs --collection subscribers --archive \
  >"$cleanup_dir/open5gs-subscribers.archive"
sha256sum "$cleanup_dir/open5gs-subscribers.archive" \
  >"$cleanup_dir/SHA256SUMS"
docker exec oiran-lab-mongodb-1 mongosh --quiet open5gs --eval '
const q={"polaris.owned":true,slice:{$elemMatch:{sst:1,sd:"000001"}}};
printjson(db.subscribers.find(q,{_id:0,"polaris.slot":1}).toArray()
  .map(d=>({slot:d.polaris.slot,owner:"POLARIS"})));'
```

## Authorized deletion command (not run by this release)

```bash
docker exec oiran-lab-mongodb-1 mongosh --quiet open5gs --eval '
const q={"polaris.owned":true,slice:{$elemMatch:{sst:1,sd:"000001"}}};
const before=db.subscribers.countDocuments(q);
if (before !== 2) throw new Error(`EXPECTED_TWO_POLARIS_RECORDS_FOUND_${before}`);
printjson(db.subscribers.deleteMany(q));'
```

Re-run the preview query and require an empty result. A rollback must first
stop further subscriber writes, validate `SHA256SUMS`, and restore the saved
collection in a controlled maintenance window; it must never overwrite newer
records blindly.
