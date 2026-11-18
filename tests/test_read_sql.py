"""Dashboard read model (migration 0002 + store/read_sql.py) on real PostgreSQL via psql."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from pgharness import PgDB

from cyberintel.collectors.cve5 import parse_cve5
from cyberintel.collectors.kev import parse_kev
from cyberintel.parsing.feeds import parse_feed
from cyberintel.store import read_sql as q
from cyberintel.store import rows, sql

FIX = Path(__file__).parent / "fixtures"
T1 = datetime(2026, 11, 18, 6, 0, tzinfo=UTC)
TODAY = date.today()


def kev(
    pg: PgDB,
    cve: str,
    *,
    added: date,
    ransomware: bool = False,
    vendor: str = "Acme",
    product: str = "Widget",
) -> None:
    base = rows.kev_rows(parse_kev((FIX / "kev" / "kev_sample.json").read_bytes()))[0]
    row = {
        **base,
        "cve_id": cve,
        "date_added": added,
        "ransomware_known": ransomware,
        "vendor": vendor,
        "product": product,
        "name": f"{vendor} {product} bug",
    }
    pg.run(sql.UPSERT_KEV, rows=rows.to_json([row]), catalog_version="v", seen_at=T1)


def vuln(
    pg: PgDB,
    cve: str,
    *,
    score: float | None = None,
    ssvc: str | None = None,
    state: str = "PUBLISHED",
    title: str | None = None,
) -> None:
    pg.run(
        sql.UPSERT_CVE5,
        rows=rows.to_json(
            [
                {
                    "cve_id": cve,
                    "record_state": state,
                    "title": title or cve,
                    "cwes": [],
                    "ssvc_exploitation": ssvc,
                }
            ]
        ),
        seen_at=T1,
    )
    if score is not None:
        pg.run(
            sql.INSERT_SCORES,
            rows=rows.to_json(
                [
                    {
                        "cve_id": cve,
                        "version": "3.1",
                        "origin": "cna",
                        "provider": "p",
                        "base_score": score,
                    }
                ]
            ),
            collected_from="cve5",
            seen_at=T1,
        )
        pg.run(sql.RECOMPUTE_HEADLINE, cve_ids=[cve])


def epss(pg: PgDB, cve: str, pct: float) -> None:
    pg.run(
        sql.UPSERT_EPSS,
        rows=rows.to_json([{"cve_id": cve, "epss": pct / 2, "percentile": pct}]),
        score_date=TODAY,
        model_version="v",
        seen_at=T1,
    )


def overview(pg: PgDB, cve: str) -> dict[str, str]:
    cols = [
        "priority",
        "p_exploitation",
        "p_epss",
        "p_severity",
        "p_ransomware",
        "p_recency",
        "in_kev",
    ]
    row = pg.run(
        f"SELECT {', '.join(cols)} FROM vulnerability_overview WHERE cve_id = %(c)s", c=cve
    )
    assert row, f"{cve} missing from overview"
    return dict(zip(cols, row[0], strict=True))


def list_ids(pg: PgDB, sort: str = "priority", **f: object) -> list[str]:
    params = {
        "kev_only": False,
        "exploited_only": False,
        "min_priority": 0,
        "pattern": None,
        "limit": 50,
        "offset": 0,
        **f,
    }
    return [r[0] for r in pg.run(q.LIST_VULNS[sort], **params)]


# --------------------------------------------------------------------------- priority


def test_priority_components_are_explainable(pg: PgDB) -> None:
    # Max case: KEV (40) + recent (10) + ransomware (10) + EPSS p=1.0 (20) + CVSS 10 (20)
    vuln(pg, "CVE-2026-1001", score=10.0)
    kev(pg, "CVE-2026-1001", added=TODAY - timedelta(days=2), ransomware=True)
    epss(pg, "CVE-2026-1001", 1.0)
    assert overview(pg, "CVE-2026-1001") == {
        "priority": "100.0",
        "p_exploitation": "40",
        "p_epss": "20.0",
        "p_severity": "20.0",
        "p_ransomware": "10",
        "p_recency": "10",
        "in_kev": "t",
    }


def test_priority_ssvc_active_without_kev(pg: PgDB) -> None:
    vuln(pg, "CVE-2026-1002", score=7.5, ssvc="active")
    epss(pg, "CVE-2026-1002", 0.5)
    o = overview(pg, "CVE-2026-1002")
    assert (o["p_exploitation"], o["p_epss"], o["p_severity"], o["priority"]) == (
        "30",
        "10.0",
        "15.0",
        "55.0",
    )
    assert (o["p_ransomware"], o["p_recency"], o["in_kev"]) == ("0", "0", "f")


def test_priority_old_kev_and_poc_and_plain(pg: PgDB) -> None:
    kev(pg, "CVE-2026-1003", added=TODAY - timedelta(days=60))  # KEV only, old, no record
    vuln(pg, "CVE-2026-1004", ssvc="poc")
    vuln(pg, "CVE-2026-1005", score=9.8)
    assert overview(pg, "CVE-2026-1003")["priority"] == "40.0"
    assert overview(pg, "CVE-2026-1004")["priority"] == "10.0"
    assert overview(pg, "CVE-2026-1005")["priority"] == "19.6"


def test_rejected_records_hidden_unless_in_kev(pg: PgDB) -> None:
    vuln(pg, "CVE-2026-1006", state="REJECTED")
    vuln(pg, "CVE-2026-1007", state="REJECTED")
    kev(pg, "CVE-2026-1007", added=TODAY)
    ids = list_ids(pg)
    assert "CVE-2026-1006" not in ids and "CVE-2026-1007" in ids


def test_removed_kev_entry_loses_kev_points(pg: PgDB) -> None:
    kev(pg, "CVE-2026-1008", added=TODAY)
    pg.run("UPDATE kev_entries SET removed_at = now()")
    assert overview(pg, "CVE-2026-1008")["in_kev"] == "f"


# --------------------------------------------------------------------------- listing


@pytest.fixture
def seeded(pg: PgDB) -> PgDB:
    vuln(pg, "CVE-2026-99999", score=5.0, title="Older numbering")
    vuln(pg, "CVE-2026-100000", score=5.0, title="Newer numbering")
    vuln(pg, "CVE-2026-2001", score=9.0, ssvc="active", title="Exploited thing")
    kev(
        pg, "CVE-2026-2002", added=TODAY - timedelta(days=1), vendor="Fortinet", product="FortiGate"
    )
    vuln(pg, "CVE-2026-2003", score=4.0, title="100% literal_match")
    return pg


def test_sort_by_priority_then_cve_numerically(seeded: PgDB) -> None:
    ids = list_ids(seeded)
    assert ids[:2] == ["CVE-2026-2002", "CVE-2026-2001"]  # KEV 50, then SSVC-active 48
    assert ids.index("CVE-2026-100000") < ids.index("CVE-2026-99999")  # numeric, not text


def test_every_allowlisted_sort_runs(seeded: PgDB) -> None:
    for key in q.VULN_SORTS:
        assert len(list_ids(seeded, key)) == 5, key
    assert list_ids(seeded, "cvss")[0] == "CVE-2026-2001"
    assert list_ids(seeded, "newest_kev")[0] == "CVE-2026-2002"


def test_filters(seeded: PgDB) -> None:
    assert list_ids(seeded, kev_only=True) == ["CVE-2026-2002"]
    assert set(list_ids(seeded, exploited_only=True)) == {"CVE-2026-2002", "CVE-2026-2001"}
    assert set(list_ids(seeded, min_priority=45)) == {"CVE-2026-2002", "CVE-2026-2001"}
    assert list_ids(seeded, pattern=q.like_pattern("fortigate")) == ["CVE-2026-2002"]
    assert list_ids(seeded, pattern=q.like_pattern("cve-2026-2001")) == ["CVE-2026-2001"]


def test_search_wildcards_are_literal(seeded: PgDB) -> None:
    # "%" and "_" typed by the user must not act as wildcards.
    assert list_ids(seeded, pattern=q.like_pattern("%")) == ["CVE-2026-2003"]
    assert list_ids(seeded, pattern=q.like_pattern("l_teral")) == []
    assert list_ids(seeded, pattern=q.like_pattern("literal_match")) == ["CVE-2026-2003"]
    assert list_ids(seeded, pattern=q.like_pattern("\\")) == []


def test_search_injection_payload_is_just_text(seeded: PgDB) -> None:
    assert list_ids(seeded, pattern=q.like_pattern("' OR 1=1 --")) == []
    assert int(seeded.scalar("SELECT count(*) FROM vulnerabilities")) == 4


def test_pagination_and_count(seeded: PgDB) -> None:
    page1 = list_ids(seeded, limit=2, offset=0)
    page2 = list_ids(seeded, limit=2, offset=2)
    assert len(page1) == 2 and len(page2) == 2 and not set(page1) & set(page2)
    assert (
        seeded.scalar(
            q.COUNT_VULNS, kev_only=False, exploited_only=False, min_priority=0, pattern=None
        )
        == "5"
    )


# --------------------------------------------------------------------------- detail


def test_vulnerability_detail_queries(pg: PgDB) -> None:
    rec = parse_cve5((FIX / "cve5" / "published.json").read_bytes())
    vulns, scores, products, refs = rows.cve5_rows([rec])
    pg.run(sql.UPSERT_CVE5, rows=rows.to_json(vulns), seen_at=T1)
    pg.run(sql.INSERT_SCORES, rows=rows.to_json(scores), collected_from="cve5", seen_at=T1)
    pg.run(sql.INSERT_PRODUCTS, rows=rows.to_json(products))
    pg.run(sql.INSERT_REFERENCES, rows=rows.to_json(refs))
    pg.run(sql.RECOMPUTE_HEADLINE, cve_ids=[rec.cve_id])
    feed = parse_feed(
        b"<rss><channel><title>t</title><item><title>GPUStack CVE-2026-102895"
        b"</title><link>https://n.example/a</link></item></channel></rss>"
    )
    pg.run(
        sql.UPSERT_DOCUMENTS,
        rows=rows.to_json(rows.document_rows(feed)),
        source_name="src-a",
        seen_at=T1,
    )
    c = {"cve_id": "CVE-2026-102895"}
    assert pg.run(q.GET_VULN, **c)[0][0] == "CVE-2026-102895"
    assert pg.run(q.GET_VULN_RECORD, **c)[0][6] == "active"
    assert [r[1] for r in pg.run(q.LIST_SCORES, **c)] == ["3.1", "4.0"]  # policy order
    assert pg.run(q.LIST_PRODUCTS, **c) == [["gpustack", "gpustack"]]
    assert len(pg.run(q.LIST_REFERENCES, **c)) == 1
    assert pg.run(q.LIST_DOCUMENTS_FOR_CVE, **c)[0][2].startswith("GPUStack")
    assert pg.run(q.GET_VULN, cve_id="CVE-2026-0000") == []


def test_summary_and_source_health(pg: PgDB) -> None:
    kev(pg, "CVE-2026-3001", added=TODAY)
    kev(pg, "CVE-2026-3002", added=TODAY - timedelta(days=30))
    vuln(pg, "CVE-2026-3003", ssvc="active")
    pg.run(sql.RECORD_FAILURE, source_name="first-epss", at=T1, error="boom")
    pg.run(
        sql.INSERT_FETCH_RUN,
        source_name="first-epss",
        started_at=T1,
        finished_at=T1,
        outcome="error",
        http_status=503,
        bytes=None,
        peer_address=None,
        records_ok=None,
        records_rejected=None,
        error="boom",
    )
    kev_active, kev_new, ssvc_active, _, _, failing, _ = pg.run(q.SUMMARY)[0]
    assert (kev_active, kev_new, ssvc_active, failing) == ("2", "1", "1", "1")
    health = pg.run(q.LIST_SOURCE_HEALTH)
    assert health[0][0] == "first-epss" and health[0][5] == "error" and health[0][9] == "503"


def test_developments_list_and_detail(pg: PgDB) -> None:
    dev = pg.scalar(
        sql.UPSERT_DEVELOPMENT,
        slug="2026-11-10-example",
        title="Example story",
        first_seen="2026-11-10",
        last_seen="2026-11-12",
        status="CONFIRMED",
        confidence="HIGH",
        is_rollup=False,
    )
    roll = pg.scalar(
        sql.UPSERT_DEVELOPMENT,
        slug="2026-11-11-rollup",
        title="Roll-up",
        first_seen="2026-11-11",
        last_seen="2026-11-11",
        status="CONFIRMED",
        confidence="HIGH",
        is_rollup=True,
    )
    pg.run(
        sql.INSERT_SIGHTINGS,
        development_id=dev,
        origin="archive",
        rows=rows.to_json(
            [
                {"external_id": "a", "day": "2026-11-10", "urgency": 3},
                {"external_id": "b", "day": "2026-11-12", "urgency": 5},
            ]
        ),
    )
    pg.run(sql.INSERT_DEVELOPMENT_CVES, development_id=dev, cves='["CVE-2026-4001"]')
    pg.run(
        sql.INSERT_DEVELOPMENT_LINK,
        a_slug="2026-11-11-rollup",
        b_slug="2026-11-10-example",
        kind="rollup_of",
        method="cve",
    )
    base = {"pattern": None, "limit": 50, "offset": 0}
    listed = pg.run(q.LIST_DEVELOPMENTS, include_rollups=False, **base)
    assert [(r[0], r[7], r[8], r[9]) for r in listed] == [("2026-11-10-example", "2", "5", "1")]
    assert len(pg.run(q.LIST_DEVELOPMENTS, include_rollups=True, **base)) == 2
    assert pg.scalar(q.COUNT_DEVELOPMENTS, include_rollups=True, pattern=None) == "2"
    assert [r[2] for r in pg.run(q.LIST_SIGHTINGS, development_id=dev)] == [
        "2026-11-10",
        "2026-11-12",
    ]
    assert pg.run(q.LIST_DEVELOPMENT_CVES, development_id=dev)[0][0] == "CVE-2026-4001"
    links = pg.run(q.LIST_DEVELOPMENT_LINKS, development_id=dev)
    assert links == [["in", "rollup_of", "cve", "2026-11-11-rollup", "Roll-up"]]
    assert pg.run(q.LIST_DEVELOPMENT_LINKS, development_id=roll)[0][0] == "out"


def test_documents_listing(pg: PgDB) -> None:
    feed = parse_feed((FIX / "feeds" / "rss_ok.xml").read_bytes())
    pg.run(
        sql.UPSERT_DOCUMENTS,
        rows=rows.to_json(rows.document_rows(feed)),
        source_name="src-a",
        seen_at=T1,
    )
    base = {"limit": 50, "offset": 0}
    assert len(pg.run(q.LIST_DOCUMENTS, source=None, pattern=None, **base)) == 2
    assert pg.run(q.LIST_DOCUMENTS, source="other", pattern=None, **base) == []
    hit = pg.run(q.LIST_DOCUMENTS, source=None, pattern=q.like_pattern("fail-open"), **base)
    assert len(hit) == 1 and hit[0][2].startswith("Auth bypass")
    assert pg.scalar(q.COUNT_DOCUMENTS, source="src-a", pattern=None) == "2"


def test_like_pattern_escaping() -> None:
    assert q.like_pattern("50%_off\\") == "%50\\%\\_off\\\\%"
