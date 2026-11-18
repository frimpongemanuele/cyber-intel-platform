"""End-to-end: real PostgreSQL + psycopg reader + the web app (CI).

Seeds the database through the production Store from fixtures, then renders every page.
Also proves the reader's session is read-only at the database level.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("starlette")
pytest.importorskip("jinja2")
from asgi import request
from pgharness import _psql, enabled

psycopg = pytest.importorskip("psycopg")

from cyberintel.collectors.cve5 import parse_cve5  # noqa: E402
from cyberintel.collectors.kev import parse_kev  # noqa: E402
from cyberintel.collectors.nvd import parse_nvd_page  # noqa: E402
from cyberintel.eval.archive import link_stories, load_archive  # noqa: E402
from cyberintel.parsing.feeds import parse_feed  # noqa: E402
from cyberintel.store import migrate  # noqa: E402
from cyberintel.store.repo import Store  # noqa: E402
from cyberintel.web.app import create_app  # noqa: E402
from cyberintel.web.auth import (  # noqa: E402
    MIN_SCRYPT_N,
    AuthConfig,
    PasswordHash,
    SessionSigner,
    hash_password,
)
from cyberintel.web.reader import DbReader, psycopg_connector  # noqa: E402

FIX = Path(__file__).parent / "fixtures"
T1 = datetime(2026, 11, 18, 6, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def dbname() -> Iterator[str]:
    if not enabled():
        pytest.skip("set CIT_TEST_PG=1 and PGHOST/PGUSER to run database tests")
    name = f"cit_web_{uuid.uuid4().hex[:12]}"
    _psql("postgres", f"CREATE DATABASE {name};")
    with psycopg.connect(dbname=name, autocommit=True) as conn:
        migrate.apply(conn)
        store = Store(conn)
        store.store_kev(parse_kev((FIX / "kev" / "kev_sample.json").read_bytes()), T1)
        store.store_cve5([parse_cve5((FIX / "cve5" / "published.json").read_bytes())], T1)
        store.store_nvd_page(parse_nvd_page((FIX / "nvd" / "page.json").read_bytes()), T1)
        store.store_documents("unit42", parse_feed((FIX / "feeds" / "rss_ok.xml").read_bytes()), T1)
        store.import_archive_stories(link_stories(load_archive(FIX / "archive").developments))
    try:
        yield name
    finally:
        _psql("postgres", f"DROP DATABASE IF EXISTS {name} WITH (FORCE);")


@pytest.fixture(scope="module")
def app_and_cookie(dbname: str) -> tuple[Any, str]:
    auth = AuthConfig(
        PasswordHash.parse(hash_password("pw-for-tests", n=MIN_SCRYPT_N)),
        SessionSigner(bytes(range(32))),
    )
    app = create_app(
        DbReader(psycopg_connector(f"dbname={dbname}")),
        auth,
        sources=[{"name": "unit42", "kind": "feed", "tier": "primary"}],
    )
    return app, f"__Host-cit_session={auth.signer.issue()}"


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/vulns",
        "/vulns?sort=cvss&kev=1",
        "/vulns?q=openssh",
        "/vulns/CVE-2026-123158",
        "/vulns/CVE-2026-102895",
        "/stories",
        "/stories?rollups=1",
        "/stories/2026-11-01-acme-vpn-authbypass",
        "/news",
        "/news?source=unit42&q=fail",
        "/sources",
    ],
)
def test_every_page_renders_from_real_data(app_and_cookie: tuple[Any, str], path: str) -> None:
    app, cookie = app_and_cookie
    r = request(app, "GET", path, headers={"cookie": cookie})
    assert r.status == 200, (path, r.text[:500])


def test_real_data_shows_provenance_and_priority(app_and_cookie: tuple[Any, str]) -> None:
    app, cookie = app_and_cookie
    html = request(app, "GET", "/vulns/CVE-2026-102895", headers={"cookie": cookie}).text
    assert "CNA (vendor)" in html and "GitHub_M" in html  # who issued the score
    assert "SSVC: active" in html
    listing = request(app, "GET", "/vulns", headers={"cookie": cookie}).text
    assert listing.index("CVE-2026-123158") < listing.index("CVE-2009-0001")  # KEV ranks first


def test_reader_session_cannot_write(dbname: str) -> None:
    connect = psycopg_connector(f"dbname={dbname}")
    with connect() as conn, pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
        conn.execute("INSERT INTO source_state (source_name) VALUES ('evil-write')")
