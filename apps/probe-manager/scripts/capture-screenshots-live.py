#!/usr/bin/env python3
"""Capture Probe Manager screenshots against the LIVE OIRAN backend.

Opposite of `capture-screenshots.py` (which mocks). This script talks to
the production host at https://151.242.147.49:8020, forwards /api/v1/*
through Playwright's own request router (TLS verification disabled —
operator-known lab certificate), and does NOT inject any fixture.

Usage:
    npm run dev &                  # terminal 1 — vite 127.0.0.1:4310
    python3 scripts/capture-screenshots-live.py
"""

import ssl
import time
from pathlib import Path
from playwright.sync_api import Page, sync_playwright

BASE = "http://127.0.0.1:4310"
API_UPSTREAM = "https://151.242.147.49:8020"
OUT_DIR = Path(__file__).resolve().parent.parent / "docs" / "screenshots-live"
OUT_DIR.mkdir(parents=True, exist_ok=True)

ssl._create_default_https_context = ssl._create_unverified_context  # lab CA


def shoot(page: Page, path: str, filename: str, theme: str, wait_for=None):
    page.goto(f"{BASE}/#{path}", wait_until="domcontentloaded")
    if wait_for:
        page.wait_for_selector(wait_for, timeout=10_000)
    page.wait_for_timeout(600)
    target = OUT_DIR / f"{filename}-{theme}.png"
    page.screenshot(path=str(target), full_page=True)
    print(f"  -> {target}")


def main():
    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True,
            args=["--ignore-certificate-errors"],
        )
        for theme in ("light", "dark"):
            print(f"== Theme: {theme} ==")
            context = browser.new_context(
                viewport={"width": 1440, "height": 900},
                device_scale_factor=2,
                ignore_https_errors=True,
            )
            context.add_init_script(
                f"try {{ localStorage.setItem('telecom.theme', '{theme}'); "
                f"document.documentElement.setAttribute('data-theme', '{theme}'); }} catch(e){{}}"
            )

            # Playwright refuses `continue_` across protocols. We fulfil
            # the request ourselves with urllib against the HTTPS upstream.
            import urllib.request

            def handle(route):
                req = route.request
                upstream = req.url.replace(BASE, API_UPSTREAM)
                r = urllib.request.Request(upstream, method=req.method)
                for k, v in req.headers.items():
                    if k.lower() in ("host", "connection"):
                        continue
                    r.add_header(k, v)
                body = req.post_data_buffer or None
                try:
                    with urllib.request.urlopen(
                        r, data=body, context=ssl._create_unverified_context()
                    ) as resp:
                        route.fulfill(
                            status=resp.status,
                            headers={h.lower(): v for h, v in resp.getheaders()},
                            body=resp.read(),
                        )
                except urllib.error.HTTPError as e:
                    route.fulfill(
                        status=e.code,
                        headers={h.lower(): v for h, v in e.headers.items()},
                        body=e.read(),
                    )
                except Exception as e:
                    route.fulfill(status=502, body=str(e))

            context.route("**/api/v1/**", handle)
            page = context.new_page()
            page.on("pageerror", lambda err: print(f"  [pageerror] {err}"))

            shoot(page, "/overview", "overview", theme)
            shoot(page, "/probes", "probes", theme)
            shoot(page, "/interfaces", "interfaces", theme)
            shoot(page, "/live-captures", "live-captures", theme)
            shoot(page, "/capture-library", "capture-library", theme)
            context.close()
        browser.close()
    print(f"\nSaved live screenshots under {OUT_DIR}")


if __name__ == "__main__":
    main()
