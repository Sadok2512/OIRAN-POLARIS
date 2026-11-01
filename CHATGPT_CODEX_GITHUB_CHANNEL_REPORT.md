# ChatGPT ↔ Codex GitHub channel setup

Date: 2026-11-01 UTC

Repository: `Sadok2512/OIRAN-POLARIS`

Channel: <https://github.com/Sadok2512/OIRAN-POLARIS/issues/10>

Branch: `feat/codex-github-channel-setup-v1`

Base: `b5213e060fddeccef995ac96638cd2820b503181` (`origin/main`)

## Required report

```text
GITHUB_AUTH = PASS — gh 2.45.0 authenticated as Sadok2512 under root@OIRAN with repository write/admin permission.
HANDSHAKE = POSTED — comment 6564899743 was written and read back through the GitHub API.
DISPATCHER = PASS SINGLE-SHOT — secure Python 3 transport accepted the real fenced ChatGPT ECHO; mission content was persisted for manual review and never executed.
DRY_RUN = PASS — ECHO/ACK/DONE, unauthorized author rejection, active-mission exclusion and structured reports verified locally before the live channel test.
ANTI_REPLAY = PASS — canonical UUID, unique comment ID, persistent SQLite ledger, body SHA256 and exclusive flock verified.
SYSTEMD = PASS PREPARED — hardened oneshot unit passes systemd-analyze; not installed, not enabled, no timer/persistent polling.
CHANNEL_READY = YES
BLOCKERS = NONE
```

The real GitHub round-trip completed with mission
`MIS-20261101-2235-codex-echo`: ACK comment `6564923731`, DONE comment
`6564925975`, then an exact replay produced no new comment.

## GitHub access evidence

The GitHub CLI was initially absent. Package `gh` 2.45.0 was installed from the
Ubuntu repository without restarting application services. No token value was
read or printed.

```bash
gh auth status
```

```text
Logged in to github.com account Sadok2512
Active account: true
Git operations protocol: https
Token value: not recorded
```

Authenticated GitHub API evidence:

```text
repository = Sadok2512/OIRAN-POLARIS
permissions.admin = true
permissions.push = true
issue = 10 OPEN
```

The following handshake was posted as comment `6564899743` and read back by
ID:

```text
CODEX = CONNECTED
HOST = OIRAN
CHANNEL = ISSUE_10
READY_FOR_MISSIONS = YES
```

## Dispatcher security model

Files:

- `tools/github-channel/codex_github_dispatcher.py`
- `tools/github-channel/config.example.json`
- `tools/github-channel/README.md`
- `infrastructure/systemd/codex-github-dispatcher.service`

Controls implemented:

1. Exact allowlist of GitHub `author.login`; default: `Sadok2512`.
2. Canonical UUID or allowlisted `MIS-...` `MISSION_ID`, unique comment ID and
   SHA256-bound persistent replay ledger.
3. Non-blocking exclusive `flock`; only one dispatcher instance can operate.
4. Only one mission may remain ACK/active; another receives `REJECTED_BUSY`.
5. Mission payload is bounded and written to a mode 0600 inbox inside a mode
   0700 state directory.
6. No `shell=True`, `os.system`, command interpreter, plugin or evaluator.
   Mission payload is never passed to a process.
7. Every ACK/DONE declares `AUTHORITY=NONE` and
   `PRODUCTION_AUTHORIZATION=NOT_GRANTED_BY_GITHUB`.
8. DONE is a separate manual action; reports are size bounded and screened for
   common GitHub tokens, bearer headers and private keys.
9. GitHub CLI failures expose only stable local error codes, never stderr that
   could contain credential material.
10. Token files can be supplied through a systemd credential and are injected
    only into the child `gh` environment.

Inbound format:

```text
CODEX_MISSION_V1
MISSION_ID = <canonical UUID>
MESSAGE = ECHO|MISSION
PAYLOAD = <bounded single-line payload>
```

No GitHub comment can authorize deployment, grants, traffic, captures, live
LTE/5G work or production mutation. Such actions always require the normal
explicit authorization path outside this transport.

## DRY_RUN evidence

Commands:

```bash
python3 -m py_compile tools/github-channel/codex_github_dispatcher.py

python3 tools/github-channel/codex_github_dispatcher.py \
  --config tools/github-channel/config.example.json \
  --state-directory /tmp/codex-channel-test/state \
  poll --once --fixture tools/github-channel/test-fixture.json --dry-run

python3 tools/github-channel/codex_github_dispatcher.py \
  --config tools/github-channel/config.example.json \
  --state-directory /tmp/codex-channel-test/state \
  done --mission-id 33333333-3333-4333-8333-333333333333 \
  --result PASS --report tools/github-channel/test-report.md --dry-run
```

Observed results:

```text
ECHO = OK
ACK = RECEIVED / MANUAL_REVIEW_REQUIRED
DONE = PASS with report SHA256
unauthorized-user = IGNORED_UNAUTHORIZED_AUTHOR
second concurrent mission = REJECTED_BUSY
exact replay = IGNORED_IDEMPOTENT_REPLAY
changed replay = fail closed by mission/comment digest binding
state directory mode = 0700
inbox document mode = 0600
ledger final states = ECHO and DONE
```

Exclusive-lock test:

```text
second dispatcher = DISPATCHER_ALREADY_ACTIVE
exit code = 2
```

## Real GitHub ECHO round-trip

```text
MISSION_ID = MIS-20261101-2235-codex-echo
mission comment = 6564903456
validated author = Sadok2512
dispatcher mode = poll --once
ACK comment = 6564923731
DONE comment = 6564925975
DONE status = PASS
exact replay outcome = IGNORED_IDEMPOTENT_REPLAY
comments before replay = 5
comments after replay = 5
comment IDs unchanged = YES
```

The initial single-shot exposed a compatibility defect with Ubuntu `gh` 2.45,
which lacks `gh api --slurp`. It failed before claiming the mission or posting
an ACK. Pagination was replaced with explicit bounded REST pages, tested
offline, then the real single-shot succeeded.

## systemd state

```bash
systemd-analyze verify infrastructure/systemd/codex-github-dispatcher.service
systemctl is-enabled codex-github-dispatcher.service
```

```text
verify = PASS (exit 0)
installed state = not-found
enabled state = not enabled
timer = none
```

The unit is a hardened `oneshot`, uses `DynamicUser`, `StateDirectory=`, a
systemd credential for the GitHub token, read-only system/home protection and
has no `[Install]` section. It cannot become a permanent poller merely by
enabling it. No file was installed under `/etc` or `/usr/local`, and systemd was
not reloaded.

## Safety verification

```text
production deployment = none
Open5GS/POLARIS/OIRAN changes = none
grant or LTE/5G traffic = none
capture changes = none
dumpcap count = 12
disk = 81% (<85% stop threshold)
subscriber identity exposure = none
```

## Operating state

The channel is ready for manually triggered `poll --once` operations. The
systemd unit remains uninstalled and there is no timer or background
dispatcher. Any future mission still requires independent scope and safety
review; GitHub comments remain transport only and grant no production
authority.

— ANR3
