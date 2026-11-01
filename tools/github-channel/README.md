# ChatGPT ↔ Codex GitHub Issue channel

This dispatcher treats GitHub Issue comments as an authenticated transport, not
as execution authority. It never invokes a shell or executes the `PAYLOAD`.
Every mission is stored for manual review and explicitly states that GitHub
cannot authorize production, live traffic, grants, captures or deployment.

## Protocol

Inbound comments must be authored by an exact allowlisted GitHub login:

```text
CODEX_MISSION_V1
MISSION_ID = 01234567-89ab-4def-8123-456789abcdef
MESSAGE = ECHO
PAYLOAD = hello
```

`MESSAGE` is `ECHO` or `MISSION`. Mission IDs are canonical UUIDs. `ECHO`
returns ECHO. `MISSION` persists a 0600 inbox document and returns ACK with
`MANUAL_REVIEW_REQUIRED`. A second active mission is rejected. Exact replay is
ignored; changed replay fails closed.

The dispatcher also accepts the channel's fenced transport form with an
allowlisted `MIS-...` identifier and exactly these fields: `MISSION_ID`,
`BASE_SHA`, `OBJECTIVE`, `SCOPE`, `ACCEPTANCE_CRITERIA` and
`SAFETY_CONSTRAINTS`. It is always treated as a mission requiring manual
review, never as executable input.

DONE is a separate manual command after independently authorized work:

```bash
python3 codex_github_dispatcher.py --config config.json done \
  --mission-id 01234567-89ab-4def-8123-456789abcdef \
  --result PASS --report /path/to/sanitized-report.md
```

The report is size-bounded and screened for common GitHub tokens, bearer
headers and private keys before posting.

## Local dry run

Use a disposable absolute state directory override, which is accepted only in
dry-run mode:

```bash
python3 codex_github_dispatcher.py --config config.example.json \
  --state-directory /tmp/codex-channel-dry-run poll --once \
  --fixture test-fixture.json --dry-run
```

Run the same command twice to verify persistent idempotent replay. Run a second
process while the first owns `dispatcher.lock` to verify exclusive locking.

## systemd

The provided unit is a hardened `oneshot`. It has no `[Install]` section and no
timer, so it is neither installed nor enabled by this repository. Deployment
requires copying the script/config, provisioning a systemd credential named
`github_token`, running `systemd-analyze verify`, and separate approval to run
even one real poll. Permanent polling requires an additional explicit approval.
