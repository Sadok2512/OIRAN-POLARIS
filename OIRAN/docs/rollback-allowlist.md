# Rollback allowlist and shard inventory

Set `OIRAN_ROLLBACK_ALLOWLIST` to the absolute path of the JSON declaration used by both the Analyzer and the purge check. Update the declaration with each pose, selecting the rollback targets of the last three versions by verified content. Deploy the declaration as an immutable file and select it when restarting the service. Each entry has a unique name, the exact manifest pathname and the complete set of shard basenames declared by that manifest.

```json
[
  {
    "name": "verified-rollback-target",
    "manifest": "/var/lib/oiran/deployment-backups/example/dataset_manifest.json",
    "shards": ["shard-retained-example.jsonl"]
  }
]
```

Read the authorized manifest to populate the declaration before pose. For example, the basename set is `jq '[.event_shards[].path | split("/") | last] | unique'` for a sharded manifest. A missing or invalid configuration leaves inventory unavailable. An explicit empty list declares that there are no rollback targets. The purge check must consume the same immutable declaration, and still apply its separate conservation and exclusion checks.

## Health fields

`event_shard_orphans.unreferenced` counts regular shards in the pinned physical population absent from both the served manifest and the authorized shard declarations. Backups outside the list are outside rollback policy. A shard referenced only by such a backup counts as unreferenced. Ordinary retention archives carry event lines and do not nominate live shard files as rollback targets.

`event_shard_orphans.rollback_held` reports the shards held by authorized rollback targets. If any authorized manifest cannot be read, its `status` is `unavailable` and its counts are null, with the failing path and reason. The configured declarations still protect their shards from the unreferenced count. If a readable manifest has invalid JSON, invalid structure or a reference set that differs from its declaration, both totals are unavailable and the error identifies the manifest and the cause. Both fields use the same pinned `commit_seq`.
