"""Pure row mappers (no database)."""

import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from cyberintel.collectors.cve5 import parse_cve5
from cyberintel.collectors.cvss import CvssScore
from cyberintel.collectors.kev import parse_kev
from cyberintel.parsing.feeds import Feed, FeedItem, parse_feed
from cyberintel.store import rows

FIX = Path(__file__).parent / "fixtures"


def test_kev_rows_shape() -> None:
    r = rows.kev_rows(parse_kev((FIX / "kev" / "kev_sample.json").read_bytes()))
    assert [x["cve_id"] for x in r] == ["CVE-2026-123158", "CVE-2026-102895", "CVE-2026-116779"]
    assert r[0]["date_added"] == date(2026, 11, 9) and r[2]["due_date"] is None


def test_to_json_handles_dates_and_unicode() -> None:
    out = rows.to_json(
        [{"d": date(2026, 11, 9), "t": datetime(2026, 1, 1, tzinfo=UTC), "s": "café"}]
    )
    assert json.loads(out) == [{"d": "2026-11-09", "t": "2026-01-01T00:00:00+00:00", "s": "café"}]
    with pytest.raises(TypeError):
        rows.to_json([{"x": object()}])


def test_cve5_rows_split_into_tables() -> None:
    rec = parse_cve5((FIX / "cve5" / "published.json").read_bytes())
    vulns, scores, products, refs = rows.cve5_rows([rec])
    assert vulns[0]["ssvc_exploitation"] == "active"
    assert {(s["version"], s["origin"]) for s in scores} == {("3.1", "cna"), ("4.0", "cna")}
    assert products == [{"cve_id": "CVE-2026-102895", "vendor": "gpustack", "product": "gpustack"}]
    assert len(refs) == 1


def test_unknown_ssvc_values_become_null_not_batch_failures() -> None:
    doc = json.loads((FIX / "cve5" / "published.json").read_text())
    doc["containers"]["adp"][0]["metrics"][0]["other"]["content"]["options"] = [
        {"Exploitation": "widespread"}  # hypothetical future vocabulary
    ]
    vulns, *_ = rows.cve5_rows([parse_cve5(json.dumps(doc).encode())])
    assert vulns[0]["ssvc_exploitation"] is None


def test_duplicate_scores_are_collapsed() -> None:
    s = CvssScore(version="3.1", base_score=9.8, origin="cna", provider="p")
    assert len(rows._score_rows("CVE-2026-1234", [s, s])) == 1


def test_document_rows_dedupe_by_canonical_url_and_skip_linkless() -> None:
    item = FeedItem(
        title="SSHole CVE-2026-123158",
        url="https://a.example/x?utm_source=rss",
        guid=None,
        published=None,
        excerpt="also cve-2026-102895",
    )
    dupe = item.model_copy(update={"url": "https://A.example/x/#top"})
    linkless = item.model_copy(update={"url": None})
    feed = Feed(kind="rss", title="f", items=(item, dupe, linkless), truncated=False)
    (row,) = rows.document_rows(feed)
    assert row["canonical_url"] == "https://a.example/x"
    assert row["url"] == "https://a.example/x?utm_source=rss"  # original kept for citation
    assert row["cves"] == ["CVE-2026-102895", "CVE-2026-123158"]


def test_document_rows_on_fixture() -> None:
    docs = rows.document_rows(parse_feed((FIX / "feeds" / "rss_ok.xml").read_bytes()))
    assert len(docs) == 2


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("N-able", "nable"),
        ("N-central", "ncentral"),
        ("Apache Log4j2", "apachelog4j2"),
        ("--", ""),
        ("株式会社X", "x"),
    ],
)
def test_norm(text: str, expected: str) -> None:
    assert rows.norm(text) == expected
