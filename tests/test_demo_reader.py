"""The screenshot/demo dataset must keep rendering every page (and stay escaped)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("starlette")
pytest.importorskip("jinja2")
from asgi import request
from test_web import structural_problems

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from demo_reader import STORIES, VULNS, DemoReader

from cyberintel.web.app import create_app
from cyberintel.web.auth import (
    MIN_SCRYPT_N,
    AuthConfig,
    PasswordHash,
    SessionSigner,
    hash_password,
)


@pytest.fixture(scope="module")
def app_cookie() -> tuple[Any, dict[str, str]]:
    auth = AuthConfig(
        PasswordHash.parse(hash_password("x" * 12, n=MIN_SCRYPT_N)), SessionSigner(bytes(32))
    )
    app = create_app(DemoReader(), auth, ai_enabled=True)
    return app, {"cookie": f"__Host-cit_session={auth.signer.issue()}"}


@pytest.mark.parametrize(
    "path",
    ["/", "/vulns", "/vulns?kev=1", "/stories", "/news", "/sources"]
    + [f"/vulns/{v['cve_id']}" for v in VULNS]
    + [f"/stories/{s[0]}" for s in STORIES],
)
def test_every_demo_page_renders(app_cookie: tuple[Any, dict[str, str]], path: str) -> None:
    app, cookie = app_cookie
    r = request(app, "GET", path, headers=cookie)
    assert r.status == 200, (path, r.text[:300])
    assert structural_problems(r.text) == []


def test_demo_data_is_obviously_synthetic() -> None:
    # high, unused CVE range and reserved example domains only
    assert all(v["cve_id"].startswith("CVE-2026-9") for v in VULNS)
    ai = DemoReader().story_ai(1)
    assert ai is not None
    assert all(".example/" in u for u in ai["output"]["cited_urls"])


def test_related_items_match_the_cve(app_cookie: tuple[Any, dict[str, str]]) -> None:
    app, cookie = app_cookie
    acme = next(v for v in VULNS if v["title"].startswith("Acme"))
    html = request(app, "GET", f"/vulns/{acme['cve_id']}", headers=cookie).text
    assert "Acme VPN" in html and "Example Gateway exploit chain" not in html
