"""Production SQL (store/sql.py) against a real PostgreSQL, via the psql harness.

Run: CIT_TEST_PG=1 PGHOST=... PGUSER=... pytest tests/test_store_sql.py
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from pgharness import PgDB, PsqlError

from cyberintel.collectors.cve5 import parse_cve5
from cyberintel.collectors.cvss import headline
from cyberintel.collectors.epss import parse_epss
from cyberintel.collectors.kev import parse_kev
from cyberintel.collectors.nvd import parse_nvd_page
from cyberintel.parsing.feeds import parse_feed
from cyberintel.store import rows, sql

FIX = Path(__file__).parent / "fixtures"
T1 = datetime(2026, 11, 18, 6, 0, tzinfo=UTC)
T2 = datetime(2026, 11, 19, 6, 0, tzinfo=UTC)


def count(pg: PgDB, table: str, where: str = "true") -> int:
    return int(pg.scalar(f"SELECT count(*) FROM {table} WHERE {where}"))


# --------------------------------------------------------------------------- constraints


@pytest.mark.parametrize(
    ("statement", "fragment"),
    [
        (
            "INSERT INTO epss_scores (cve_id, epss, percentile) VALUES ('CVE-26-1', 0.1, 0.1)",
            "cve_id",
        ),
        (
            "INSERT INTO epss_scores (cve_id, epss, percentile) VALUES ('CVE-2026-1234', 1.5, 0.1)",
            "check constraint",
        ),
        (
            "INSERT INTO vulnerabilities (cve_id, headline_score) VALUES ('CVE-2026-1234', 9.8)",
            "check constraint",
        ),  # score without version/origin
        (
            "INSERT INTO vulnerabilities (cve_id, ssvc_exploitation) "
            "VALUES ('CVE-2026-1234', 'maybe')",
            "check constraint",
        ),
        (
            "INSERT INTO documents (source_name, canonical_url, url, title, excerpt) "
            "VALUES ('src-a', 'javascript:alert(1)', 'https://a.example/', 't', 'e')",
            "http_url",
        ),
        (
            "INSERT INTO documents (source_name, canonical_url, url, title, excerpt) "
            "VALUES ('src-a', 'https://a.example/', 'https://a.example/', 't', repeat('x', 601))",
            "check constraint",
        ),
        ("INSERT INTO source_state (source_name) VALUES ('Bad Name!')", "source_name"),
        (
            "INSERT INTO developments (slug, title, first_seen, last_seen, status, confidence) "
            "VALUES ('x', 't', '2026-11-02', '2026-11-01', 'CONFIRMED', 'HIGH')",
            "check constraint",
        ),
    ],
)
def test_database_refuses_malformed_facts(pg: PgDB, statement: str, fragment: str) -> None:
    with pytest.raises(PsqlError, match=fragment):
        pg.run(statement)


def test_sql_injection_payload_is_stored_as_data(pg: PgDB) -> None:
    payload = "'); DROP TABLE kev_entries; --"
    row = rows.kev_rows(parse_kev((FIX / "kev" / "kev_sample.json").read_bytes()))[0]
    row["vendor"] = payload
    pg.run(sql.UPSERT_KEV, rows=rows.to_json([row]), catalog_version="t", seen_at=T1)
    assert pg.scalar("SELECT vendor FROM kev_entries") == payload
    assert count(pg, "kev_entries") == 1  # table intact


# --------------------------------------------------------------------------- KEV


def kev_json(n: int) -> str:
    base = rows.kev_rows(parse_kev((FIX / "kev" / "kev_sample.json").read_bytes()))[0]
    return rows.to_json([{**base, "cve_id": f"CVE-2026-{10000 + i}"} for i in range(n)])


def test_kev_upsert_is_idempotent_and_tracks_sightings(pg: PgDB) -> None:
    cat = parse_kev((FIX / "kev" / "kev_sample.json").read_bytes())
    data = rows.to_json(rows.kev_rows(cat))
    pg.run(sql.UPSERT_KEV, rows=data, catalog_version=cat.catalog_version, seen_at=T1)
    pg.run(sql.UPSERT_KEV, rows=data, catalog_version=cat.catalog_version, seen_at=T2)
    assert count(pg, "kev_entries") == 3
    first, last = pg.run(
        "SELECT first_seen_at = %(t1)s::timestamptz, "
        "last_seen_at = %(t2)s::timestamptz FROM kev_entries LIMIT 1",
        t1=T1,
        t2=T2,
    )[0]
    assert (first, last) == ("t", "t")
    assert pg.scalar("SELECT cwes::text FROM kev_entries WHERE cve_id='CVE-2026-102895'") == (
        "{CWE-287,CWE-290}"
    )


def test_kev_removal_is_recorded_not_deleted(pg: PgDB) -> None:
    pg.run(sql.UPSERT_KEV, rows=kev_json(20), catalog_version="v1", seen_at=T1)
    present = json.dumps([f"CVE-2026-{10000 + i}" for i in range(19)])  # one dropped
    removed = pg.run(sql.MARK_KEV_REMOVED, present=present, seen_at=T2)
    assert removed == [["CVE-2026-10019"]]
    assert count(pg, "kev_entries") == 20  # history kept
    assert count(pg, "kev_entries", "removed_at IS NOT NULL") == 1
    pg.run(sql.UPSERT_KEV, rows=kev_json(20), catalog_version="v2", seen_at=T2)  # re-added
    assert count(pg, "kev_entries", "removed_at IS NOT NULL") == 0


def test_truncated_kev_catalog_cannot_mass_remove(pg: PgDB) -> None:
    pg.run(sql.UPSERT_KEV, rows=kev_json(20), catalog_version="v1", seen_at=T1)
    present = json.dumps([f"CVE-2026-{10000 + i}" for i in range(10)])  # half missing
    assert pg.run(sql.MARK_KEV_REMOVED, present=present, seen_at=T2) == []
    assert count(pg, "kev_entries", "removed_at IS NOT NULL") == 0
    assert pg.run(sql.MARK_KEV_REMOVED, present="[]", seen_at=T2) == []  # empty feed


# --------------------------------------------------------------------------- EPSS


def test_epss_upsert_skips_stale_snapshots_and_unchanged_rows(pg: PgDB) -> None:
    snap = parse_epss((FIX / "epss" / "epss_sample.csv").read_text().splitlines())
    data = rows.to_json(rows.epss_rows(snap))
    pg.run(
        sql.UPSERT_EPSS, rows=data, score_date=date(2026, 11, 17), model_version="v1", seen_at=T1
    )
    assert count(pg, "epss_scores") == 3
    # Same values again, later: not rewritten (updated_at unchanged).
    pg.run(
        sql.UPSERT_EPSS, rows=data, score_date=date(2026, 11, 17), model_version="v1", seen_at=T2
    )
    assert count(pg, "epss_scores", f"updated_at = '{T1.isoformat()}'") == 3
    # An older snapshot with different values must not overwrite newer data.
    stale = rows.to_json([{"cve_id": "CVE-2026-123158", "epss": 0.00001, "percentile": 0.1}])
    pg.run(
        sql.UPSERT_EPSS, rows=stale, score_date=date(2026, 11, 1), model_version="v1", seen_at=T2
    )
    assert pg.scalar("SELECT epss FROM epss_scores WHERE cve_id='CVE-2026-123158'") == "0.94321"


# --------------------------------------------------------------------------- CVE.org + NVD


def store_cve5(pg: PgDB, fixture: str, seen_at: datetime = T1) -> list[list[str]]:
    rec = parse_cve5((FIX / "cve5" / fixture).read_bytes())
    vulns, scores, products, refs = rows.cve5_rows([rec])
    written = pg.run(sql.UPSERT_CVE5, rows=rows.to_json(vulns), seen_at=seen_at)
    ids = [r[0] for r in written]
    if ids:
        pg.run(sql.DELETE_SCORES, collected_from="cve5", cve_ids=ids)
        pg.run(sql.INSERT_SCORES, rows=rows.to_json(scores), collected_from="cve5", seen_at=seen_at)
        pg.run(sql.DELETE_PRODUCTS, cve_ids=ids)
        pg.run(sql.INSERT_PRODUCTS, rows=rows.to_json(products))
        pg.run(sql.DELETE_REFERENCES, cve_ids=ids)
        pg.run(sql.INSERT_REFERENCES, rows=rows.to_json(refs))
        pg.run(sql.RECOMPUTE_HEADLINE, cve_ids=ids)
        pg.run(sql.CLEAR_HEADLINE_WITHOUT_SCORES, cve_ids=ids)
    return written


def test_cve5_record_with_scores_products_ssvc_and_headline(pg: PgDB) -> None:
    assert store_cve5(pg, "published.json") == [["CVE-2026-102895"]]
    v = pg.run(
        "SELECT record_state, assigner, ssvc_exploitation, adp_kev_date, cwes::text, "
        "headline_score, headline_version, headline_origin FROM vulnerabilities"
    )[0]
    assert v == [
        "PUBLISHED",
        "GitHub_M",
        "active",
        "2026-11-09",
        "{CWE-287,CWE-290}",
        "9.8",
        "3.1",
        "cna",
    ]
    assert count(pg, "cvss_scores") == 2
    assert pg.run("SELECT vendor_norm, product_norm FROM affected_products") == [
        ["gpustack", "gpustack"]
    ]
    assert count(pg, "vulnerability_references") == 1


def test_cve5_older_record_never_overwrites_newer(pg: PgDB) -> None:
    store_cve5(pg, "published.json")
    doc = json.loads((FIX / "cve5" / "published.json").read_text())
    doc["cveMetadata"]["dateUpdated"] = "2026-01-01T00:00:00Z"  # older revision
    doc["containers"]["cna"]["title"] = "STALE"
    rec = parse_cve5(json.dumps(doc).encode())
    vulns, *_ = rows.cve5_rows([rec])
    assert pg.run(sql.UPSERT_CVE5, rows=rows.to_json(vulns), seen_at=T2) == []
    assert pg.scalar("SELECT title FROM vulnerabilities") != "STALE"


def test_rejected_record_clears_headline(pg: PgDB) -> None:
    store_cve5(pg, "rejected.json")
    assert pg.run("SELECT record_state, headline_score FROM vulnerabilities") == [["REJECTED", ""]]


def test_nvd_fills_only_its_columns_and_unions_cwes(pg: PgDB) -> None:
    store_cve5(pg, "published.json")  # CVE.org owns description/title
    nvd = parse_nvd_page((FIX / "nvd" / "page.json").read_bytes())
    vulns, scores = rows.nvd_rows(nvd.cves)
    written = pg.run(sql.UPSERT_NVD, rows=rows.to_json(vulns), seen_at=T2)
    assert len(written) == 3
    ids = [w[0] for w in written]
    pg.run(sql.DELETE_SCORES, collected_from="nvd", cve_ids=ids)
    pg.run(sql.INSERT_SCORES, rows=rows.to_json(scores), collected_from="nvd", seen_at=T2)
    pg.run(sql.RECOMPUTE_HEADLINE, cve_ids=ids)
    ssh = pg.run(
        "SELECT nvd_status, nvd_has_cpe, headline_score, headline_origin "
        "FROM vulnerabilities WHERE cve_id='CVE-2026-123158'"
    )[0]
    assert ssh == ["Analyzed", "t", "8.1", "nvd"]
    deferred = pg.run(
        "SELECT nvd_status, headline_origin FROM vulnerabilities WHERE cve_id='CVE-2026-130001'"
    )[0]
    assert deferred == ["Deferred", "cna"]
    # Stale NVD page ignored:
    old = [{**vulns[0], "nvd_last_modified": "2020-01-01T00:00:00+00:00", "nvd_status": "X"}]
    assert pg.run(sql.UPSERT_NVD, rows=rows.to_json(old), seen_at=T2) == []


def test_sql_headline_matches_python_policy(pg: PgDB) -> None:
    nvd = parse_nvd_page((FIX / "nvd" / "page.json").read_bytes())
    vulns, scores = rows.nvd_rows(nvd.cves)
    pg.run(sql.UPSERT_NVD, rows=rows.to_json(vulns), seen_at=T1)
    ids = [c.cve_id for c in nvd.cves]
    pg.run(sql.INSERT_SCORES, rows=rows.to_json(scores), collected_from="nvd", seen_at=T1)
    pg.run(sql.RECOMPUTE_HEADLINE, cve_ids=ids)
    db = {
        r[0]: (r[1], r[2], r[3])
        for r in pg.run(
            "SELECT cve_id, headline_version, headline_origin, headline_score FROM vulnerabilities"
        )
    }
    for c in nvd.cves:
        h = headline(c.scores)
        assert h is not None
        assert db[c.cve_id] == (h.version, h.origin, f"{h.base_score:.1f}"), c.cve_id


@pytest.mark.parametrize(
    "text", ["N-able", "N-central", "Ivanti Connect Secure", "  Apache  Log4j2 ", "株式会社X", "--"]
)
def test_entity_norm_parity_python_vs_sql(pg: PgDB, text: str) -> None:
    db = pg.scalar("SELECT lower(regexp_replace(%(t)s, '[^A-Za-z0-9]', '', 'g'))", t=text)
    assert db == rows.norm(text)


# --------------------------------------------------------------------------- documents


def test_documents_dedupe_and_idempotency(pg: PgDB) -> None:
    feed = parse_feed((FIX / "feeds" / "rss_ok.xml").read_bytes())
    docs = rows.document_rows(feed)
    first = pg.run(sql.UPSERT_DOCUMENTS, rows=rows.to_json(docs), source_name="src-a", seen_at=T1)
    assert first == [["t"], ["t"]]  # 2 linkable items (the javascript: one was dropped)
    again = pg.run(sql.UPSERT_DOCUMENTS, rows=rows.to_json(docs), source_name="src-a", seen_at=T2)
    assert again == [["f"], ["f"]]  # updated, not duplicated
    assert count(pg, "documents") == 2
    assert pg.scalar("SELECT cves::text FROM documents WHERE title LIKE 'Auth bypass%%'") == (
        "{CVE-2026-123158}"
    )
    assert "utm_source" not in pg.scalar("SELECT string_agg(canonical_url, ' ') FROM documents")


def test_database_refuses_duplicate_url_within_one_batch(pg: PgDB) -> None:
    # Why rows.document_rows() de-duplicates: Postgres refuses this outright.
    row = rows.document_rows(parse_feed((FIX / "feeds" / "rss_ok.xml").read_bytes()))[0]
    with pytest.raises(PsqlError, match="cannot affect row a second time"):
        pg.run(sql.UPSERT_DOCUMENTS, rows=rows.to_json([row, row]), source_name="src-a", seen_at=T1)


# --------------------------------------------------------------------------- bookkeeping


def test_source_state_success_failure_cycle(pg: PgDB) -> None:
    pg.run(sql.RECORD_FAILURE, source_name="cisa-kev", at=T1, error="timeout")
    pg.run(sql.RECORD_FAILURE, source_name="cisa-kev", at=T1, error="x" * 900)
    assert pg.run(sql.GET_SOURCE_STATE, source_name="cisa-kev")[0][2] == "2"
    assert len(pg.scalar("SELECT last_error FROM source_state")) == 500  # truncated
    pg.run(sql.RECORD_SUCCESS, source_name="cisa-kev", etag='"e1"', last_modified=None, at=T2)
    etag, last_mod, failures, *_ = pg.run(sql.GET_SOURCE_STATE, source_name="cisa-kev")[0]
    assert (etag, last_mod, failures) == ('"e1"', "", "0")
    pg.run(sql.RECORD_SUCCESS, source_name="cisa-kev", etag=None, last_modified=None, at=T2)
    assert pg.run(sql.GET_SOURCE_STATE, source_name="cisa-kev")[0][0] == '"e1"'  # kept


def test_fetch_run_audit_row(pg: PgDB) -> None:
    pg.run(
        sql.INSERT_FETCH_RUN,
        source_name="cisa-kev",
        started_at=T1,
        finished_at=T2,
        outcome="ok",
        http_status=200,
        bytes=1234,
        peer_address="104.84.0.10",
        records_ok=3,
        records_rejected=4,
        error=None,
    )
    pg.run(
        sql.INSERT_FETCH_RUN,
        source_name="cisa-kev",
        started_at=T1,
        finished_at=T1,
        outcome="error",
        http_status=None,
        bytes=None,
        peer_address=None,
        records_ok=None,
        records_rejected=None,
        error="blocked",
    )
    assert count(pg, "fetch_runs") == 2
    with pytest.raises(PsqlError, match="check constraint"):
        pg.run(
            sql.INSERT_FETCH_RUN,
            source_name="cisa-kev",
            started_at=T1,
            finished_at=T1,
            outcome="maybe",
            http_status=None,
            bytes=None,
            peer_address=None,
            records_ok=None,
            records_rejected=None,
            error=None,
        )


# --------------------------------------------------------------------------- developments


def test_development_upsert_merges_dates_and_sightings(pg: PgDB) -> None:
    def upsert(first: str, last: str) -> str:
        return pg.scalar(
            sql.UPSERT_DEVELOPMENT,
            slug="sshole",
            title="SSHole",
            first_seen=first,
            last_seen=last,
            status="CONFIRMED",
            confidence="HIGH",
            is_rollup=False,
        )

    dev = upsert("2026-11-12", "2026-11-12")
    assert upsert("2026-11-10", "2026-11-11") == dev  # same row
    assert pg.run("SELECT first_seen, last_seen FROM developments") == [
        ["2026-11-10", "2026-11-12"]
    ]
    sightings = [
        {"external_id": "2026-11-10-example-auth-bypass", "day": "2026-11-10", "urgency": 5},
        {"external_id": "2026-11-12-example-followup", "day": "2026-11-12", "urgency": 4},
    ]
    pg.run(sql.INSERT_SIGHTINGS, development_id=dev, origin="archive", rows=rows.to_json(sightings))
    pg.run(sql.INSERT_SIGHTINGS, development_id=dev, origin="archive", rows=rows.to_json(sightings))
    assert count(pg, "development_sightings") == 2
    pg.run(sql.INSERT_DEVELOPMENT_CVES, development_id=dev, cves='["CVE-2026-123158"]')
    assert count(pg, "development_vulnerabilities") == 1
    with pytest.raises(PsqlError, match="check constraint"):
        pg.run(
            sql.INSERT_DEVELOPMENT_LINK,
            a_slug="sshole",
            b_slug="sshole",
            kind="related",
            method="cve",
        )


def test_nvd_never_overwrites_cve_org_record_fields(pg: PgDB) -> None:
    # Same CVE from both sources: CVE.org owns the record text; NVD may only fill gaps.
    store_cve5(pg, "published.json")
    before = pg.scalar("SELECT description FROM vulnerabilities")
    nvd_row = {
        "cve_id": "CVE-2026-102895",
        "description": "NVD's paraphrase that must not replace the CNA's text",
        "published_at": "2020-01-01T00:00:00+00:00",
        "cwes": ["CWE-306"],
        "nvd_status": "Analyzed",
        "nvd_last_modified": "2026-11-12T00:00:00+00:00",
        "nvd_has_cpe": True,
    }
    assert pg.run(sql.UPSERT_NVD, rows=rows.to_json([nvd_row]), seen_at=T2) == [["CVE-2026-102895"]]
    desc, published, cwes, status = pg.run(
        "SELECT description, published_at = '2026-11-04T22:17:00Z'::timestamptz, cwes::text, "
        "nvd_status FROM vulnerabilities"
    )[0]
    assert desc == before  # CNA text kept
    assert published == "t"  # CNA date kept
    assert cwes == "{CWE-287,CWE-290,CWE-306}"  # union of both sources
    assert status == "Analyzed"  # NVD's own column updated


def test_cve5_queue_prioritises_known_cves_missing_records(pg: PgDB) -> None:
    pg.run(sql.UPSERT_KEV, rows=kev_json(3), catalog_version="v", seen_at=T1)
    feed = parse_feed((FIX / "feeds" / "rss_ok.xml").read_bytes())
    pg.run(
        sql.UPSERT_DOCUMENTS,
        rows=rows.to_json(rows.document_rows(feed)),
        source_name="src-a",
        seen_at=T2,
    )
    queue = [r[0] for r in pg.run(sql.CVE5_QUEUE, limit=10)]
    assert set(queue) == {"CVE-2026-10000", "CVE-2026-10001", "CVE-2026-10002", "CVE-2026-123158"}
    assert queue[0] == "CVE-2026-123158"  # seen most recently (article on T2)
    store_cve5(pg, "published.json")  # unrelated CVE: queue unchanged
    pg.run(
        sql.UPSERT_CVE5,
        rows=rows.to_json([{"cve_id": "CVE-2026-10000", "record_state": "PUBLISHED", "cwes": []}]),
        seen_at=T2,
    )
    assert "CVE-2026-10000" not in [r[0] for r in pg.run(sql.CVE5_QUEUE, limit=10)]
    assert len(pg.run(sql.CVE5_QUEUE, limit=2)) == 2
