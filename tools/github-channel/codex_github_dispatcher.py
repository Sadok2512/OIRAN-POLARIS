#!/usr/bin/env python3
"""Safe GitHub Issue transport for manually reviewed Codex missions.

This program never executes mission content. It validates, persists and
acknowledges messages; a human/agent must perform any resulting work through
the normal authorization path.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time
from typing import Any, Iterator
import uuid


PROTOCOL = "CODEX_CHANNEL_V1"
MISSION_HEADER = "CODEX_MISSION_V1"
MAX_COMMENT_BYTES = 64 * 1024
SAFE_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SAFE_LOGIN = re.compile(r"^[A-Za-z0-9-]{1,39}$")
SAFE_CHANNEL_MISSION_ID = re.compile(r"^MIS-[A-Za-z0-9][A-Za-z0-9.-]{7,119}$")
SECRET_PATTERNS = (
    re.compile(r"github_pat_[A-Za-z0-9_]+"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)authorization\s*:\s*bearer\s+\S+"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


class DispatchError(RuntimeError):
    pass


def load_config(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > 64 * 1024:
        raise DispatchError("CONFIG_TOO_LARGE")
    data = json.loads(raw)
    required = {"repository", "issue", "authorized_authors", "state_directory"}
    if set(data) != required:
        raise DispatchError("CONFIG_FIELDS_INVALID")
    if not isinstance(data["repository"], str) or not SAFE_REPO.fullmatch(data["repository"]):
        raise DispatchError("CONFIG_REPOSITORY_INVALID")
    if not isinstance(data["issue"], int) or data["issue"] <= 0:
        raise DispatchError("CONFIG_ISSUE_INVALID")
    authors = data["authorized_authors"]
    if not isinstance(authors, list) or not authors:
        raise DispatchError("CONFIG_AUTHORS_INVALID")
    if any(not isinstance(author, str) or not SAFE_LOGIN.fullmatch(author) for author in authors):
        raise DispatchError("CONFIG_AUTHORS_INVALID")
    if not isinstance(data["state_directory"], str) or not data["state_directory"].startswith("/"):
        raise DispatchError("CONFIG_STATE_DIRECTORY_INVALID")
    data["authorized_authors"] = {author.casefold() for author in authors}
    data["state_directory"] = Path(data["state_directory"])
    return data


def gh_environment() -> dict[str, str]:
    env = os.environ.copy()
    credential = env.get("CODEX_GITHUB_TOKEN_FILE")
    if "GH_TOKEN" not in env and credential:
        token_path = Path(credential)
        token = token_path.read_text(encoding="utf-8").strip()
        if not token:
            raise DispatchError("GITHUB_CREDENTIAL_EMPTY")
        env["GH_TOKEN"] = token
    return env


def run_gh(arguments: list[str], *, input_text: str | None = None) -> str:
    try:
        result = subprocess.run(
            ["gh", *arguments],
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
            env=gh_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DispatchError("GITHUB_CLI_UNAVAILABLE") from error
    if result.returncode != 0:
        raise DispatchError("GITHUB_API_FAILED")
    return result.stdout


def require_gh_auth() -> None:
    run_gh(["auth", "status", "--hostname", "github.com"])


@contextlib.contextmanager
def exclusive_state(state_directory: Path) -> Iterator[tuple[sqlite3.Connection, Path]]:
    state_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(state_directory, 0o700)
    lock_path = state_directory / "dispatcher.lock"
    lock_file = lock_path.open("a+", encoding="utf-8")
    os.chmod(lock_path, 0o600)
    database: sqlite3.Connection | None = None
    try:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise DispatchError("DISPATCHER_ALREADY_ACTIVE") from error
        database_path = state_directory / "anti-replay.sqlite3"
        database = sqlite3.connect(database_path)
        os.chmod(database_path, 0o600)
        database.execute("PRAGMA journal_mode=WAL")
        database.execute("PRAGMA synchronous=FULL")
        database.execute(
            """
            CREATE TABLE IF NOT EXISTS missions (
                mission_id TEXT PRIMARY KEY,
                comment_id INTEGER UNIQUE NOT NULL,
                author TEXT NOT NULL,
                message_type TEXT NOT NULL,
                body_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                received_epoch INTEGER NOT NULL,
                completed_epoch INTEGER
            )
            """
        )
        database.commit()
        yield database, state_directory
    finally:
        with contextlib.suppress(Exception):
            if database is not None:
                database.close()
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        lock_file.close()


def canonical_mission_id(value: str) -> str:
    try:
        parsed_uuid = uuid.UUID(value)
    except ValueError:
        if SAFE_CHANNEL_MISSION_ID.fullmatch(value):
            return value
        raise DispatchError("MISSION_ID_INVALID") from None
    if str(parsed_uuid) != value.lower():
        raise DispatchError("MISSION_ID_NOT_CANONICAL")
    return str(parsed_uuid)


def parse_fenced_mission(lines: list[str]) -> dict[str, str] | None:
    if not lines or lines[0].strip() != "```chatgpt→codex":
        return None
    try:
        closing_fence = next(
            index for index, line in enumerate(lines[1:], start=1) if line.strip() == "```"
        )
    except StopIteration:
        raise DispatchError("MISSION_FENCE_INVALID")
    allowed = {
        "MISSION_ID",
        "BASE_SHA",
        "OBJECTIVE",
        "SCOPE",
        "ACCEPTANCE_CRITERIA",
        "SAFETY_CONSTRAINTS",
    }
    fields: dict[str, str] = {}
    for line in lines[1:closing_fence]:
        if not line.strip():
            continue
        if ":" not in line:
            raise DispatchError("MISSION_FORMAT_INVALID")
        key, value = (part.strip() for part in line.split(":", 1))
        if key not in allowed or key in fields or not value:
            raise DispatchError("MISSION_FIELDS_INVALID")
        fields[key] = value
    if set(fields) != allowed:
        raise DispatchError("MISSION_FIELDS_INVALID")
    mission_id = canonical_mission_id(fields["MISSION_ID"])
    payload_fields = dict(fields)
    trailing_note = "\n".join(lines[closing_fence + 1 :]).strip()
    if trailing_note:
        payload_fields["TRAILING_NOTE"] = trailing_note
    payload = json.dumps(
        payload_fields, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return {"MISSION_ID": mission_id, "MESSAGE": "MISSION", "PAYLOAD": payload}


def parse_mission(body: str) -> dict[str, str] | None:
    if len(body.encode("utf-8")) > MAX_COMMENT_BYTES:
        raise DispatchError("COMMENT_TOO_LARGE")
    lines = body.splitlines()
    fenced = parse_fenced_mission(lines)
    if fenced is not None:
        return fenced
    if not lines or lines[0].strip() != MISSION_HEADER:
        return None
    fields: dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        if "=" not in line:
            raise DispatchError("MISSION_FORMAT_INVALID")
        key, value = (part.strip() for part in line.split("=", 1))
        if key not in {"MISSION_ID", "MESSAGE", "PAYLOAD"} or key in fields:
            raise DispatchError("MISSION_FIELDS_INVALID")
        fields[key] = value
    if set(fields) != {"MISSION_ID", "MESSAGE", "PAYLOAD"}:
        raise DispatchError("MISSION_FIELDS_INVALID")
    fields["MISSION_ID"] = canonical_mission_id(fields["MISSION_ID"])
    if fields["MESSAGE"] not in {"ECHO", "MISSION"}:
        raise DispatchError("MISSION_MESSAGE_INVALID")
    if not fields["PAYLOAD"] or len(fields["PAYLOAD"].encode("utf-8")) > 32 * 1024:
        raise DispatchError("MISSION_PAYLOAD_INVALID")
    return fields


def structured_response(mission_id: str, message: str, status: str, **extra: str) -> str:
    lines = [
        PROTOCOL,
        f"MISSION_ID = {mission_id}",
        f"MESSAGE = {message}",
        f"STATUS = {status}",
        "HOST = OIRAN",
        "AUTHORITY = NONE",
        "PRODUCTION_AUTHORIZATION = NOT_GRANTED_BY_GITHUB",
    ]
    lines.extend(f"{key} = {value}" for key, value in sorted(extra.items()))
    return "\n".join(lines)


def post_comment(config: dict[str, Any], body: str, dry_run: bool) -> None:
    assert_safe_outbound(body)
    if dry_run:
        print(json.dumps({"dry_run_post": body}, sort_keys=True))
        return
    endpoint = f"repos/{config['repository']}/issues/{config['issue']}/comments"
    run_gh(["api", "--method", "POST", endpoint, "-f", f"body={body}"])


def assert_safe_outbound(body: str) -> None:
    if len(body.encode("utf-8")) > MAX_COMMENT_BYTES:
        raise DispatchError("OUTBOUND_TOO_LARGE")
    if any(pattern.search(body) for pattern in SECRET_PATTERNS):
        raise DispatchError("OUTBOUND_SECRET_REJECTED")


def fetch_comments(config: dict[str, Any]) -> list[dict[str, Any]]:
    endpoint = f"repos/{config['repository']}/issues/{config['issue']}/comments"
    comments: list[dict[str, Any]] = []
    for page_number in range(1, 101):
        page = json.loads(
            run_gh(["api", f"{endpoint}?per_page=100&page={page_number}"])
        )
        if not isinstance(page, list):
            raise DispatchError("GITHUB_RESPONSE_INVALID")
        comments.extend(page)
        if len(page) < 100:
            return comments
    raise DispatchError("GITHUB_PAGINATION_LIMIT")


def store_inbox(state_directory: Path, mission: dict[str, str], comment: dict[str, Any]) -> None:
    inbox = state_directory / "inbox"
    inbox.mkdir(mode=0o700, exist_ok=True)
    destination = inbox / f"{mission['MISSION_ID']}.json"
    document = {
        "schema": "codex.github-mission.v1",
        "mission_id": mission["MISSION_ID"],
        "message": mission["MESSAGE"],
        "payload": mission["PAYLOAD"],
        "comment_id": comment["id"],
        "author": comment["user"]["login"],
        "received_epoch": int(time.time()),
        "execution": "MANUAL_REVIEW_REQUIRED",
        "github_comment_authorizes_production": False,
    }
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(document, output, sort_keys=True, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def claim_comment(
    database: sqlite3.Connection,
    state_directory: Path,
    config: dict[str, Any],
    comment: dict[str, Any],
    dry_run: bool,
) -> str:
    if not isinstance(comment, dict) or not isinstance(comment.get("id"), int):
        raise DispatchError("GITHUB_COMMENT_INVALID")
    user = comment.get("user")
    author = user.get("login") if isinstance(user, dict) else None
    if not isinstance(author, str) or author.casefold() not in config["authorized_authors"]:
        return "IGNORED_UNAUTHORIZED_AUTHOR"
    body = comment.get("body")
    if not isinstance(body, str):
        raise DispatchError("GITHUB_COMMENT_INVALID")
    mission = parse_mission(body)
    if mission is None:
        return "IGNORED_NON_PROTOCOL"

    mission_id = mission["MISSION_ID"]
    body_sha256 = hashlib.sha256(body.encode("utf-8")).hexdigest()
    database.execute("BEGIN IMMEDIATE")
    replay = database.execute(
        "SELECT body_sha256 FROM missions WHERE mission_id = ? OR comment_id = ?",
        (mission_id, comment["id"]),
    ).fetchone()
    if replay:
        database.rollback()
        if replay[0] != body_sha256:
            raise DispatchError("MISSION_REPLAY_CONFLICT")
        return "IGNORED_IDEMPOTENT_REPLAY"
    if mission["MESSAGE"] == "MISSION":
        active = database.execute(
            "SELECT mission_id FROM missions WHERE message_type = 'MISSION' AND status = 'ACK'"
        ).fetchone()
        if active:
            database.execute(
                "INSERT INTO missions VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
                (
                    mission_id,
                    comment["id"],
                    author,
                    mission["MESSAGE"],
                    body_sha256,
                    "REJECTED_BUSY",
                    int(time.time()),
                ),
            )
            database.commit()
            post_comment(
                config,
                structured_response(mission_id, "ACK", "REJECTED_BUSY", ACTIVE_MISSION=active[0]),
                dry_run,
            )
            return "REJECTED_BUSY"
    status = "ECHO" if mission["MESSAGE"] == "ECHO" else "ACK"
    database.execute(
        "INSERT INTO missions VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
        (
            mission_id,
            comment["id"],
            author,
            mission["MESSAGE"],
            body_sha256,
            status,
            int(time.time()),
        ),
    )
    if mission["MESSAGE"] == "MISSION":
        store_inbox(state_directory, mission, comment)
    database.commit()
    response = (
        structured_response(
            mission_id,
            "ECHO",
            "OK",
            PAYLOAD_SHA256=hashlib.sha256(mission["PAYLOAD"].encode()).hexdigest(),
        )
        if mission["MESSAGE"] == "ECHO"
        else structured_response(mission_id, "ACK", "RECEIVED", EXECUTION="MANUAL_REVIEW_REQUIRED")
    )
    post_comment(config, response, dry_run)
    return status


def poll(config: dict[str, Any], fixture: Path | None, dry_run: bool) -> list[str]:
    if fixture:
        comments = json.loads(fixture.read_text(encoding="utf-8"))
    else:
        require_gh_auth()
        comments = fetch_comments(config)
    if not isinstance(comments, list):
        raise DispatchError("FIXTURE_INVALID")
    outcomes: list[str] = []
    with exclusive_state(config["state_directory"]) as (database, state_directory):
        for comment in sorted(comments, key=lambda item: item.get("id", 0)):
            outcomes.append(claim_comment(database, state_directory, config, comment, dry_run))
    return outcomes


def report_done(
    config: dict[str, Any], mission_id: str, report_path: Path, result: str, dry_run: bool
) -> None:
    canonical_id = canonical_mission_id(mission_id)
    if result not in {"PASS", "FAIL", "BLOCKED"}:
        raise DispatchError("DONE_ARGUMENT_INVALID")
    report = report_path.read_text(encoding="utf-8")
    assert_safe_outbound(report)
    digest = hashlib.sha256(report.encode("utf-8")).hexdigest()
    with exclusive_state(config["state_directory"]) as (database, _state_directory):
        row = database.execute(
            "SELECT status FROM missions WHERE mission_id = ? AND message_type = 'MISSION'",
            (canonical_id,),
        ).fetchone()
        if not row:
            raise DispatchError("MISSION_UNKNOWN")
        if row[0] == "DONE":
            raise DispatchError("MISSION_ALREADY_DONE")
        body = structured_response(
            canonical_id,
            "DONE",
            result,
            REPORT_SHA256=digest,
        ) + f"\nREPORT_BEGIN\n{report}\nREPORT_END"
        post_comment(config, body, dry_run)
        database.execute(
            "UPDATE missions SET status = 'DONE', completed_epoch = ? WHERE mission_id = ?",
            (int(time.time()), canonical_id),
        )
        database.commit()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--state-directory", type=Path)
    subcommands = parser.add_subparsers(dest="command", required=True)
    poll_parser = subcommands.add_parser("poll")
    poll_parser.add_argument("--once", action="store_true", required=True)
    poll_parser.add_argument("--fixture", type=Path)
    poll_parser.add_argument("--dry-run", action="store_true")
    done_parser = subcommands.add_parser("done")
    done_parser.add_argument("--mission-id", required=True)
    done_parser.add_argument("--report", required=True, type=Path)
    done_parser.add_argument("--result", required=True)
    done_parser.add_argument("--dry-run", action="store_true")
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    try:
        config = load_config(arguments.config)
        if arguments.state_directory is not None:
            if not arguments.state_directory.is_absolute():
                raise DispatchError("STATE_DIRECTORY_NOT_ABSOLUTE")
            if not arguments.dry_run:
                raise DispatchError("STATE_OVERRIDE_REQUIRES_DRY_RUN")
            config["state_directory"] = arguments.state_directory
        if arguments.command == "poll":
            outcomes = poll(config, arguments.fixture, arguments.dry_run)
            print(json.dumps({"outcomes": outcomes}, sort_keys=True))
        else:
            report_done(
                config,
                arguments.mission_id,
                arguments.report,
                arguments.result,
                arguments.dry_run,
            )
            print(json.dumps({"status": "DONE_RECORDED"}, sort_keys=True))
        return 0
    except (DispatchError, json.JSONDecodeError, OSError, sqlite3.Error, ValueError) as error:
        print(json.dumps({"error": str(error)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
