"""Least-privilege grants (store/grants.sql) against a real PostgreSQL.

Each service role gets exactly what its code path needs. The matrix is checked with
PostgreSQL's own privilege functions, then a few writes are attempted for real under
``SET ROLE`` to show the denial in practice.
"""

from __future__ import annotations

import pytest
from pgharness import PgDB, PsqlError, _psql

from cyberintel.store.migrate import BOOTSTRAP, GRANTS_SQL

ROLES = ("cit_ingest", "cit_web", "cit_ai")
FACTS = (
    "source_state", "fetch_runs", "vulnerabilities", "cvss_scores", "affected_products",
    "vulnerability_references", "kev_entries", "epss_scores", "documents", "developments",
    "development_sightings", "development_vulnerabilities", "development_links",
)  # fmt: skip


@pytest.fixture
def granted(pg: PgDB) -> PgDB:
    for role in ROLES:  # cluster-wide; created once, reused across test databases
        _psql(
            "postgres",
            f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}')"
            f" THEN CREATE ROLE {role} NOLOGIN; END IF; END $$;",
        )
    pg.run(BOOTSTRAP)  # the harness applies migration files directly; add the runner's table
    pg.run(GRANTS_SQL.read_text())
    return pg


def priv(pg: PgDB, role: str, table: str, what: str) -> bool:
    return pg.scalar(f"SELECT has_table_privilege('{role}', '{table}', '{what}')") == "t"


def test_ingest_writes_facts_but_never_ai(granted: PgDB) -> None:
    for t in FACTS:
        assert priv(granted, "cit_ingest", t, "INSERT") and priv(
            granted, "cit_ingest", t, "UPDATE"
        ), t
    for t in ("ai_analyses", "ai_usage", "schema_migrations"):
        for what in ("SELECT", "INSERT", "UPDATE", "DELETE"):
            assert not priv(granted, "cit_ingest", t, what), (t, what)
    deletable = {t for t in FACTS if priv(granted, "cit_ingest", t, "DELETE")}
    assert deletable == {
        "cvss_scores",
        "affected_products",
        "vulnerability_references",
        "developments",
    }
    assert not any(priv(granted, "cit_ingest", t, "TRUNCATE") for t in FACTS)


def test_web_is_read_only_and_cannot_see_raw_model_output(granted: PgDB) -> None:
    for t in (*FACTS, "vulnerability_overview"):
        assert priv(granted, "cit_web", t, "SELECT"), t
        for what in ("INSERT", "UPDATE", "DELETE", "TRUNCATE"):
            assert not priv(granted, "cit_web", t, what), (t, what)
    col = "SELECT has_column_privilege('cit_web', 'ai_analyses', '{c}', 'SELECT')"
    assert granted.scalar(col.format(c="output")) == "t"
    for hidden in ("raw_output", "rejected_reasons", "input_tokens"):
        assert granted.scalar(col.format(c=hidden)) == "f", hidden
    assert not priv(granted, "cit_web", "ai_usage", "SELECT")


def test_ai_reads_facts_and_writes_only_ai_tables(granted: PgDB) -> None:
    for t in FACTS:
        for what in ("INSERT", "UPDATE", "DELETE"):
            assert not priv(granted, "cit_ai", t, what), (t, what)
    assert priv(granted, "cit_ai", "vulnerability_overview", "SELECT")
    assert priv(granted, "cit_ai", "ai_analyses", "INSERT")
    assert not priv(granted, "cit_ai", "ai_analyses", "UPDATE")  # analyses are append-only
    assert not priv(granted, "cit_ai", "ai_analyses", "DELETE")
    assert priv(granted, "cit_ai", "ai_usage", "UPDATE")


@pytest.mark.parametrize(
    ("role", "statement"),
    [
        ("cit_web", "INSERT INTO source_state (source_name) VALUES ('evil')"),
        ("cit_web", "SELECT raw_output FROM ai_analyses"),
        ("cit_ai", "UPDATE kev_entries SET ransomware_known = false"),
        ("cit_ai", "DELETE FROM ai_analyses"),
        (
            "cit_ingest",
            "INSERT INTO ai_usage (day, provider, model) VALUES (current_date, 'p', 'm')",
        ),
        ("cit_ingest", "DELETE FROM kev_entries"),
        ("cit_ingest", "CREATE TABLE planted (x int)"),
        ("cit_ingest", "DROP TABLE kev_entries"),
    ],
)
def test_denied_in_practice(granted: PgDB, role: str, statement: str) -> None:
    with pytest.raises(PsqlError, match=r"permission denied|must be owner"):
        granted.run(f"SET ROLE {role}; {statement}")


def test_allowed_write_works_including_identity_column(granted: PgDB) -> None:
    granted.run(
        "INSERT INTO developments (slug, title, first_seen, last_seen, status, confidence)"
        " VALUES ('s', 't', '2026-11-10', '2026-11-10', 'CONFIRMED', 'HIGH')"
    )
    granted.run(
        "SET ROLE cit_ai; INSERT INTO ai_analyses (development_id, provider, model,"
        " prompt_version, prompt_sha256, input_hash, document_ids, cve_ids, validated,"
        " rejected_reasons) SELECT id, 'p', 'm', 'v1', repeat('a', 64), repeat('b', 64),"
        " '{}', '{}', false, '{r}' FROM developments"
    )
    assert (
        granted.scalar("SET ROLE cit_web; SELECT count(*) FROM ai_analyses WHERE validated") == "0"
    )


def test_reapplying_revokes_drifted_privileges(granted: PgDB) -> None:
    granted.run("GRANT DELETE ON kev_entries TO cit_web")
    assert priv(granted, "cit_web", "kev_entries", "DELETE")
    granted.run(GRANTS_SQL.read_text())
    assert not priv(granted, "cit_web", "kev_entries", "DELETE")
