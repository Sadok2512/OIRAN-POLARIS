#!/usr/bin/env python3
"""Create one reusable local Operator session without printing secrets."""

import getpass
import http.client
import json
import os
from pathlib import Path

HOST = os.environ.get("POLARIS_AUTH_HOST", "127.0.0.1")
PORT = int(os.environ.get("POLARIS_AUTH_PORT", "49153"))
AUTH_DIR = Path("/root/ANR3_RELEASE_ARTIFACTS/operator-auth/.auth")
SESSION = AUTH_DIR / "session.json"


def request(method, path, body=None, headers=None):
    connection = http.client.HTTPConnection(HOST, PORT, timeout=10)
    payload = None if body is None else json.dumps(body, separators=(",", ":"))
    merged = {"Host": f"{HOST}:{PORT}"}
    if payload is not None:
        merged["Content-Type"] = "application/json"
    if headers:
        merged.update(headers)
    connection.request(method, path, body=payload, headers=merged)
    response = connection.getresponse()
    raw = response.read()
    parsed = json.loads(raw) if raw else {}
    received = {}
    for name, value in response.getheaders():
        received.setdefault(name.lower(), []).append(value)
    result = response.status, received, parsed
    connection.close()
    return result


def main():
    os.umask(0o077)
    password = getpass.getpass("POLARIS Operator password: ")
    try:
        status, headers, body = request(
            "POST", "/api/v1/auth/login", {"username": "operator", "password": password}
        )
    finally:
        password = ""
    if status != 200 or body.get("authenticated") is not True or body.get("role") != "operator":
        raise SystemExit(f"AUTH_VALIDATION=FAIL HTTP={status}")
    cookies = headers.get("set-cookie", [])
    session_cookie = next((value for value in cookies if value.startswith("polaris_session=")), "")
    cookie_pair = session_cookie.split(";", 1)[0]
    csrf = body.get("csrf_token", "")
    if not cookie_pair or len(csrf) < 32:
        raise SystemExit("AUTH_VALIDATION=FAIL SESSION_MATERIAL_MISSING")
    attributes = {item.strip().lower() for item in session_cookie.split(";")[1:] if item.strip()}
    required = {"path=/", "httponly", "secure", "samesite=strict", "max-age=28800"}
    if not required.issubset(attributes):
        raise SystemExit("AUTH_VALIDATION=FAIL COOKIE_POLICY_MISMATCH")
    status, _, me = request("GET", "/api/v1/auth/me", headers={"Cookie": cookie_pair})
    if status != 200 or me.get("authenticated") is not True or me.get("role") != "operator":
        raise SystemExit("AUTH_VALIDATION=FAIL SESSION_CHECK_FAILED")
    AUTH_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    SESSION.write_text(json.dumps({
        "cookie": cookie_pair,
        "csrf": csrf,
        "role": "operator",
        "expires_at_epoch_s": body.get("expires_at_epoch_s"),
    }, separators=(",", ":")) + "\n", encoding="utf-8")
    SESSION.chmod(0o600)
    print(f"HTTP_STATUS={status}")
    print("AUTH_VALIDATION=PASS")
    print("ROLE=operator")
    print(f"SESSION_STORAGE={AUTH_DIR}")


if __name__ == "__main__":
    main()
