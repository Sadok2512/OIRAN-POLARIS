# ChatGPT ↔ Codex GitHub channel setup

Date: 2026-11-01 UTC

Repository: `Sadok2512/OIRAN-POLARIS`

Channel: <https://github.com/Sadok2512/OIRAN-POLARIS/issues/10>

Branch: `feat/codex-github-channel-setup-v1`

Base: `b5213e060fddeccef995ac96638cd2820b503181` (`origin/main`)

## Required report

```text
GITHUB_AUTH = BLOCKED — gh 2.45.0 installed, but `gh auth status` reports no authenticated GitHub host; GH_TOKEN/GITHUB_TOKEN and hosts.yml are absent.
HANDSHAKE = NOT_POSTED — Issue #10 is publicly readable, but authenticated write access cannot be tested or used without credentials.
DISPATCHER = PASS OFFLINE — secure Python 3 transport prepared; mission content is persisted for manual review and never executed.
DRY_RUN = PASS — ECHO/ACK/DONE, unauthorized author rejection, active-mission exclusion and structured reports verified locally.
ANTI_REPLAY = PASS — canonical UUID, unique comment ID, persistent SQLite ledger, body SHA256 and exclusive flock verified.
SYSTEMD = PASS PREPARED — hardened oneshot unit passes systemd-analyze; not installed, not enabled, no timer/persistent polling.
CHANNEL_READY = NO
BLOCKERS = Authenticate gh with an account permitted to comment on Issue #10, then publish the handshake and complete a real GitHub ECHO round-trip.
```

No `READY` claim is made because the required real GitHub round-trip has not
occurred.

## GitHub access evidence

The GitHub CLI was initially absent. Package `gh` 2.45.0 was installed from the
Ubuntu repository without restarting application services. No token value was
read or printed.

```bash
gh auth status
```

```text
You are not logged into any GitHub hosts.
```

Credential-presence checks, without reading values:

```text
GH_TOKEN = absent
GITHUB_TOKEN = absent
/root/.config/gh/hosts.yml = absent
```

Git SSH access is functional for repository fetch/push, but SSH repository
authentication does not provide GitHub Issues API authorization.

Public, read-only GitHub API evidence:

```json
{
  "author": "Sadok2512",
  "comments": 0,
  "number": 10,
  "state": "open",
  "title": "[COORDINATION] ChatGPT ↔ Codex (serveur OIRAN) — missions et rapports"
}
```

Authenticated read/write access remains unverified. The requested handshake
was deliberately not fabricated:

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
2. Canonical UUID `MISSION_ID`, unique comment ID and SHA256-bound persistent
   replay ledger.
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

## Required next action

An administrator must authenticate `gh` using a dedicated least-privilege
GitHub account/token allowed to read and comment on Issue #10. After
`gh auth status` succeeds, the next validation must:

1. verify authenticated Issue #10 read access;
2. publish the exact handshake;
3. post an authorized ECHO mission with a fresh UUID;
4. execute one manual `poll --once`;
5. observe the ECHO response on GitHub;
6. leave permanent polling disabled.

Only then may `CHANNEL_READY=YES` be reported.

— ANR3
