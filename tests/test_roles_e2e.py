"""Every service's real code path works under its least-privilege role (CI, psycopg).

The grants test proves what each role *cannot* do. This one proves the grants are
sufficient: the production Store (as cit_ingest), the dashboard reader (as cit_web) and
the AI runner (as cit_ai) all run end to end. A missing grant fails here, before a
deployment does.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("starlette")
pytest.importorskip("jinja2")
from aihelpers import good_output
from asgi import request
from pgharness import _psql, enabled

psycopg = pytest.importorskip("psycopg")

from cyberintel.ai.__main__ import PgAIRepo  # noqa: E402
from cyberintel.ai.prompt import Prompt  # noqa: E402
from cyberintel.ai.providers import Completion  # noqa: E402
from cyberintel.ai.runner import run  # noqa: E402
from cyberintel.collectors.cve5 import parse_cve5  # noqa: E402
from cyberintel.collectors.epss import parse_epss  # noqa: E402
from cyberintel.collectors.kev import parse_kev  # noqa: E402
from cyberintel.collectors.nvd import parse_nvd_page  # noqa: E402
from cyberintel.eval.archive import link_stories, load_archive  # noqa: E402
from cyberintel.net.types import Validators  # noqa: E402
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
from cyberintel.web.reader import DbReader  # noqa: E402

FIX = Path(__file__).parent / "fixtures"
T1 = datetime(2026, 11, 18, 6, 0, tzinfo=UTC)
ROLES = ("cit_ingest", "cit_web", "cit_ai")


@pytest.fixture(scope="module")
def dbname() -> Iterator[str]:
    if not enabled():
        pytest.skip("set CIT_TEST_PG=1 and PGHOST/PGUSER to run database tests")
    for role in ROLES:
        _psql(
            "postgres",
            f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}')"
            f" THEN CREATE ROLE {role} NOLOGIN; END IF; END $$;",
        )
    name = f"cit_roles_{uuid.uuid4().hex[:12]}"
    _psql("postgres", f"CREATE DATABASE {name};")
    with psycopg.connect(dbname=name, autocommit=True) as conn:
        migrate.apply(conn)
        migrate.apply_grants(conn)
    try:
        yield name
    finally:
        _psql("postgres", f"DROP DATABASE IF EXISTS {name} WITH (FORCE);")


def as_role(dbname: str, role: str, **kw: Any) -> Any:
    # libpq "options" sets the role for the whole session before any statement runs
    return psycopg.connect(dbname=dbname, options=f"-c role={role}", **kw)


class OkProvider:
    name, model, enabled = "scripted", "m", True

    def complete(self, prompt: Prompt) -> Completion:
        evidence = prompt.user.split(f"\n{prompt.boundary}\n")[1].splitlines()
        url = json.loads(evidence[0])["url"]
        out = good_output(cited_urls=[url], summary="Role test summary.", key_points=[])
        return Completion(json.dumps(out), 10, 10)


def test_ingest_ai_and_web_work_under_their_roles(dbname: str) -> None:
    # --- ingest (cit_ingest): every Store write path
    with as_role(dbname, "cit_ingest", autocommit=True) as conn:
        assert conn.execute("SELECT current_user").fetchone()[0] == "cit_ingest"
        store = Store(conn)
        store.store_kev(parse_kev((FIX / "kev" / "kev_sample.json").read_bytes()), T1)
        epss_lines = (FIX / "epss" / "epss_sample.csv").read_text().splitlines()
        store.store_epss(parse_epss(epss_lines), T1)
        store.store_cve5([parse_cve5((FIX / "cve5" / "published.json").read_bytes())], T1)
        store.store_nvd_page(parse_nvd_page((FIX / "nvd" / "page.json").read_bytes()), T1)
        store.store_documents("unit42", parse_feed((FIX / "feeds" / "rss_ok.xml").read_bytes()), T1)
        stories = link_stories(load_archive(FIX / "archive").developments)
        store.import_archive_stories(stories)
        store.import_archive_stories(stories)  # re-import exercises the delete path
        store.record_success("unit42", Validators(etag='"x"'), T1)
        store.record_failure("unit42", "boom", T1)
        store.cve5_queue(10)
        store.state("unit42")
        # evidence for an archive story, so the AI runner has something to analyse
        conn.execute(
            "INSERT INTO documents (source_name, canonical_url, url, title, excerpt, cves)"
            " VALUES ('unit42', 'https://r.example/p', 'https://r.example/p', 'Write-up',"
            " 'Details.', ARRAY['CVE-2026-10001'])"
        )

    # --- AI (cit_ai): runner writes analyses and usage
    with as_role(dbname, "cit_ai", autocommit=True) as conn:
        report = run(
            PgAIRepo(conn, {"unit42": "primary"}),
            OkProvider(),
            now=T1,
            since_days=3650,
            limit=50,
        )
        assert report.analysed >= 1 and report.errors == 0, report

    # --- web (cit_web): every page renders, including the AI panel
    from psycopg.rows import dict_row

    def connect() -> Any:
        return psycopg.connect(
            dbname=dbname,
            row_factory=dict_row,
            options="-c default_transaction_read_only=on -c role=cit_web",
        )

    auth = AuthConfig(
        PasswordHash.parse(hash_password("pw-for-tests", n=MIN_SCRYPT_N)),
        SessionSigner(bytes(range(32))),
    )
    app = create_app(
        DbReader(connect),
        auth,
        sources=[{"name": "unit42", "kind": "feed", "tier": "primary"}],
        ai_enabled=True,
    )
    cookie = {"cookie": f"__Host-cit_session={auth.signer.issue()}"}
    for path in ("/", "/vulns", "/vulns/CVE-2026-123158", "/stories", "/news", "/sources"):
        r = request(app, "GET", path, headers=cookie)
        assert r.status == 200, (path, r.text[:300])
    with as_role(dbname, "cit_web") as conn:
        slugs = [
            r[0]
            for r in conn.execute(
                "SELECT d.slug FROM developments d JOIN ai_analyses a ON a.development_id = d.id"
                " WHERE a.validated"
            ).fetchall()
        ]
    assert slugs, "AI runner produced no validated analysis to render"
    html = request(app, "GET", f"/stories/{slugs[0]}", headers=cookie).text
    assert "Role test summary." in html
