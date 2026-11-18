"""Repository + migration runner through psycopg against a real PostgreSQL (CI).

Requires psycopg and CIT_TEST_PG=1 with libpq environment variables.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pgharness import _psql, enabled

psycopg = pytest.importorskip("psycopg")

from cyberintel.collectors.cve5 import parse_cve5  # noqa: E402
from cyberintel.collectors.epss import parse_epss  # noqa: E402
from cyberintel.collectors.kev import KevCatalog, KevEntry, parse_kev  # noqa: E402
from cyberintel.collectors.nvd import parse_nvd_page  # noqa: E402
from cyberintel.net.types import Validators  # noqa: E402
from cyberintel.parsing.feeds import parse_feed  # noqa: E402
from cyberintel.store import migrate, repo  # noqa: E402
from cyberintel.store.repo import Store  # noqa: E402

FIX = Path(__file__).parent / "fixtures"
T1 = datetime(2026, 11, 18, 6, 0, tzinfo=UTC)
ALL_VERSIONS = [m.version for m in migrate.discover()]
T2 = datetime(2026, 11, 19, 6, 0, tzinfo=UTC)


@pytest.fixture
def empty_db() -> Iterator[str]:
    if not enabled():
        pytest.skip("set CIT_TEST_PG=1 and PGHOST/PGUSER to run database tests")
    name = f"cit_db_{uuid.uuid4().hex[:12]}"
    _psql("postgres", f"CREATE DATABASE {name};")
    try:
        yield name
    finally:
        _psql("postgres", f"DROP DATABASE IF EXISTS {name} WITH (FORCE);")


@pytest.fixture
def conn(empty_db: str) -> Iterator[psycopg.Connection]:
    with psycopg.connect(dbname=empty_db, autocommit=True) as c:
        migrate.apply(c)
        yield c


@pytest.fixture
def store(conn: psycopg.Connection) -> Store:
    return Store(conn)


def table_count(conn: psycopg.Connection, table: str, where: str = "true") -> int:
    return int(conn.execute(f"SELECT count(*) FROM {table} WHERE {where}".encode()).fetchone()[0])


# --------------------------------------------------------------------------- migrations


def test_migrations_apply_idempotently_and_roll_back(empty_db: str) -> None:
    with psycopg.connect(dbname=empty_db, autocommit=True) as c:
        assert migrate.apply(c) == ALL_VERSIONS
        assert migrate.apply(c) == []
        assert table_count(c, "pg_tables", "schemaname = 'public'") == 14  # + schema_migrations
        assert migrate.rollback(c, 0) == ALL_VERSIONS[::-1]  # newest first
        assert table_count(c, "pg_tables", "schemaname = 'public'") == 1
        assert migrate.apply(c) == ALL_VERSIONS


def test_tampered_checksum_stops_migrations(empty_db: str) -> None:
    with psycopg.connect(dbname=empty_db, autocommit=True) as c:
        migrate.apply(c)
        c.execute("UPDATE schema_migrations SET checksum = repeat('0', 64)")
        with pytest.raises(migrate.MigrationError, match="modified after being applied"):
            migrate.apply(c)


def test_concurrent_deployers_apply_each_migration_once(empty_db: str) -> None:
    results: list[list[int]] = []
    errors: list[BaseException] = []

    def run() -> None:
        try:
            with psycopg.connect(dbname=empty_db, autocommit=True) as c:
                results.append(migrate.apply(c))
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert sorted(v for r in results for v in r) == ALL_VERSIONS  # each applied exactly once


# --------------------------------------------------------------------------- repository


def test_kev_with_rejected_rows_never_marks_removals(store: Store) -> None:
    res = store.store_kev(parse_kev((FIX / "kev" / "kev_sample.json").read_bytes()), T1)
    assert res.upserted == 3 and res.removal_check_skipped and res.removed == ()


def test_kev_clean_catalog_marks_removal(store: Store, conn: psycopg.Connection) -> None:
    base = parse_kev((FIX / "kev" / "kev_sample.json").read_bytes()).entries[0]

    def catalog(n: int) -> KevCatalog:
        entries = tuple(
            KevEntry(**{**base.model_dump(), "cve_id": f"CVE-2026-{20000 + i}"}) for i in range(n)
        )
        return KevCatalog(
            catalog_version="v", date_released=None, declared_count=n, entries=entries, rejected=()
        )

    store.store_kev(catalog(20), T1)
    res = store.store_kev(catalog(19), T2)
    assert res.removed == ("CVE-2026-20019",) and not res.removal_check_skipped
    assert table_count(conn, "kev_entries") == 20


def test_epss_chunks_within_one_transaction(
    store: Store, conn: psycopg.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(repo, "EPSS_CHUNK", 2)
    snap = parse_epss((FIX / "epss" / "epss_sample.csv").read_text().splitlines())
    assert store.store_epss(snap, T1) == 3
    assert table_count(conn, "epss_scores") == 3


def test_cve5_then_nvd_headline_and_ownership(store: Store, conn: psycopg.Connection) -> None:
    rec = parse_cve5((FIX / "cve5" / "published.json").read_bytes())
    assert store.store_cve5([rec], T1) == ["CVE-2026-102895"]
    assert store.store_cve5([rec], T2) == ["CVE-2026-102895"]  # same version: idempotent
    assert table_count(conn, "cvss_scores") == 2
    written = store.store_nvd_page(parse_nvd_page((FIX / "nvd" / "page.json").read_bytes()), T2)
    assert set(written) == {"CVE-2026-123158", "CVE-2026-130001", "CVE-2009-0001"}
    row = conn.execute(
        "SELECT headline_score::text, headline_origin FROM vulnerabilities "
        "WHERE cve_id = 'CVE-2026-123158'"
    ).fetchone()
    assert row == ("8.1", "nvd")


def test_documents_counts(store: Store) -> None:
    feed = parse_feed((FIX / "feeds" / "rss_ok.xml").read_bytes())
    assert store.store_documents("src-a", feed, T1) == (2, 0)
    assert store.store_documents("src-a", feed, T2) == (0, 2)


def test_source_state_and_fetch_runs(store: Store, conn: psycopg.Connection) -> None:
    assert store.validators("cisa-kev") is None
    store.record_failure("cisa-kev", "boom", T1)
    store.record_failure("cisa-kev", "boom", T1)
    assert store.consecutive_failures("cisa-kev") == 2
    store.record_success("cisa-kev", Validators(etag='"e"', last_modified="L"), T2)
    assert store.validators("cisa-kev") == Validators(etag='"e"', last_modified="L")
    assert store.consecutive_failures("cisa-kev") == 0
    store.record_fetch_run(
        source_name="cisa-kev",
        started_at=T1,
        finished_at=T2,
        outcome="ok",
        http_status=200,
        bytes=10,
        peer_address="2606:4700::1",
        records_ok=3,
        records_rejected=0,
        error=None,
    )
    assert table_count(conn, "fetch_runs") == 1


def test_injection_payload_round_trips_as_data(store: Store, conn: psycopg.Connection) -> None:
    store.record_failure("cisa-kev", "'); DROP TABLE source_state; --", T1)
    assert table_count(conn, "source_state") == 1


def test_archive_import_builds_stories_and_is_rebuildable(
    store: Store, conn: psycopg.Connection
) -> None:
    from cyberintel.eval.archive import link_stories, load_archive

    stories = link_stories(load_archive(FIX / "archive").developments)
    assert store.import_archive_stories(stories) == len(stories)
    assert table_count(conn, "developments") == len(stories)
    assert table_count(conn, "development_sightings") == 11  # every archive entry
    acme = conn.execute(
        "SELECT first_seen::text, last_seen::text FROM developments "
        "WHERE slug = '2026-11-01-acme-vpn-authbypass'"
    ).fetchone()
    assert acme == ("2026-11-01", "2026-11-02")
    # carry-over touches 3 developments but only 2 distinct stories (WidgetDB x2 + Zebra)
    assert table_count(conn, "development_links", "kind = 'rollup_of'") == 2
    assert table_count(conn, "developments", "is_rollup") >= 1
    # Re-import: rebuilt, not duplicated.
    store.import_archive_stories(stories)
    assert table_count(conn, "developments") == len(stories)
    assert table_count(conn, "development_sightings") == 11
