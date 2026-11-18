"""Render the dashboard with synthetic demo data and save screenshots to docs/images/.

    python tools/screenshots.py [--chrome /usr/bin/google-chrome]

Starts the real app (same templates, CSP and auth) on a loopback port with
``DemoReader``, logs in through the real login form, and captures each page with
headless Chrome via Playwright.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import time
from pathlib import Path

import uvicorn

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tools")]

from demo_reader import VULNS, DemoReader  # noqa: E402

from cyberintel.web.app import create_app  # noqa: E402
from cyberintel.web.auth import (  # noqa: E402
    MIN_SCRYPT_N,
    AuthConfig,
    PasswordHash,
    SessionSigner,
    hash_password,
)

PASSWORD = "demo-password-for-screenshots"  # noqa: S105 - local, throwaway demo instance
SOURCES = [
    {"name": n, "kind": k, "tier": "primary"}
    for n, k in [
        ("cisa-kev", "kev"), ("first-epss", "epss"), ("nvd-cve-api", "nvd"),
        ("cve-org-records", "cve5"), ("research-blog", "feed"), ("vendor-psirt", "feed"),
        ("national-cert", "feed"), ("security-news", "feed"),
    ]
]  # fmt: skip
PAGES = [
    ("overview", "/"),
    ("vulnerabilities", "/vulns"),
    ("vulnerability", f"/vulns/{VULNS[0]['cve_id']}"),
    ("stories", "/stories"),
    ("story-ai", "/stories/example-gateway-preauth-rce"),
    ("sources", "/sources"),
]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--chrome", default="/usr/bin/google-chrome")
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "images")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    auth = AuthConfig(
        PasswordHash.parse(hash_password(PASSWORD, n=MIN_SCRYPT_N)), SessionSigner(bytes(32))
    )
    app = create_app(DemoReader(), auth, sources=SOURCES, secure_cookies=False, ai_enabled=True)
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)

    from playwright.sync_api import sync_playwright

    base = f"http://localhost:{port}"
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=args.chrome)
        page = browser.new_page(viewport={"width": 1400, "height": 600}, device_scale_factor=1)
        page.goto(base + "/login")
        page.screenshot(path=str(args.out / "login.png"))
        page.fill("input[name=password]", PASSWORD)
        page.click("button[type=submit]")
        page.wait_for_url(base + "/")
        for name, path in PAGES:
            page.goto(base + path)
            page.screenshot(path=str(args.out / f"{name}.png"), full_page=True)
            print("saved", name)
        browser.close()
    server.should_exit = True
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
