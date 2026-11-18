"""Collector jobs, tested with a fake Fetcher (no HTTP library, no network)."""

from __future__ import annotations

import gzip
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from cyberintel.collectors.run import (
    CollectError,
    collect_cve5,
    collect_epss,
    collect_feed,
    collect_kev,
    iter_nvd_modified,
)
from cyberintel.net.types import FetchResult, Validators
from cyberintel.sources import Source

FIX = Path(__file__).parent / "fixtures"
T0 = datetime(2026, 11, 17, tzinfo=UTC)


def src(kind: str, url: str, **kw: object) -> Source:
    return Source(name=f"test-{kind}", kind=kind, url=url, trust_tier="primary", **kw)  # type: ignore[arg-type]


@dataclass
class FakeFetcher:
    """Answers from a list of bodies (or a callable) and records every call."""

    bodies: list[bytes] = field(default_factory=list)
    not_modified: bool = False
    calls: list[dict[str, object]] = field(default_factory=list)

    def get(
        self,
        url: str,
        *,
        validators: Validators | None = None,
        headers: Mapping[str, str] | None = None,
        max_bytes: int | None = None,
        min_interval: float | None = None,
    ) -> FetchResult:
        self.calls.append(
            {"url": url, "validators": validators, "headers": headers, "interval": min_interval}
        )
        body = b"" if self.not_modified else self.bodies.pop(0)
        return FetchResult(
            url=url,
            final_url=url,
            status=304 if self.not_modified else 200,
            body=body,
            not_modified=self.not_modified,
            validators=Validators(etag='"new"'),
            content_type=None,
            fetched_at=T0,
            peer_address="203.0.113.7",
        )


KEV = src("kev", "https://www.cisa.gov/kev.json", min_interval_seconds=10)
EPSS = src("epss", "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz")
FEED = src("feed", "https://research.example.org/rss")
CVE5 = src("cve5", "https://cveawg.mitre.org/api/cve/")
NVD = src("nvd", "https://services.nvd.nist.gov/rest/json/cves/2.0", min_interval_seconds=6.5)


def test_kev_job_parses_and_passes_validators() -> None:
    f = FakeFetcher([(FIX / "kev" / "kev_sample.json").read_bytes()])
    out = collect_kev(f, KEV, Validators(etag='"old"'))
    assert out.data is not None and len(out.data.entries) == 3
    assert out.fetched.validators.etag == '"new"'  # to persist for next run
    assert f.calls[0]["validators"] == Validators(etag='"old"')
    assert f.calls[0]["interval"] == 10


def test_not_modified_yields_no_data() -> None:
    f = FakeFetcher(not_modified=True)
    assert collect_kev(f, KEV).data is None
    assert collect_feed(f, FEED).data is None
    assert collect_epss(f, EPSS).data is None


def test_epss_job_decompresses_then_parses() -> None:
    raw = (FIX / "epss" / "epss_sample.csv").read_bytes()
    out = collect_epss(FakeFetcher([gzip.compress(raw)]), EPSS)
    assert out.data is not None and len(out.data.scores) == 3


def test_feed_job() -> None:
    out = collect_feed(FakeFetcher([(FIX / "feeds" / "rss_ok.xml").read_bytes()]), FEED)
    assert out.data is not None and len(out.data.items) == 3


def test_kind_mismatch_is_refused() -> None:
    with pytest.raises(CollectError, match="expected 'kev'"):
        collect_kev(FakeFetcher(), FEED)


# --------------------------------------------------------------------- CVE.org


def test_cve5_job_builds_url_from_validated_id() -> None:
    f = FakeFetcher([(FIX / "cve5" / "published.json").read_bytes()])
    rec = collect_cve5(f, CVE5, " cve-2026-102895 ")
    assert rec.cve_id == "CVE-2026-102895"
    assert f.calls[0]["url"] == "https://cveawg.mitre.org/api/cve/CVE-2026-102895"


@pytest.mark.parametrize(
    "bad_id",
    [
        "../../admin",
        "CVE-2026-1234/../../x",
        "CVE-2026-1234?x=1",
        "CVE-2026-1234#frag",
        "CVE-2026-1234%2F..",
        "CVE-2026-12",
        "",
    ],
)
def test_cve5_job_refuses_untrusted_ids_before_any_request(bad_id: str) -> None:
    f = FakeFetcher()
    with pytest.raises(CollectError, match="invalid CVE ID"):
        collect_cve5(f, CVE5, bad_id)
    assert f.calls == []


def test_cve5_job_rejects_mismatched_record() -> None:
    f = FakeFetcher([(FIX / "cve5" / "published.json").read_bytes()])
    with pytest.raises(CollectError, match="server returned"):
        collect_cve5(f, CVE5, "CVE-2026-999999")


# --------------------------------------------------------------------- NVD paging


def nvd_page(start: int, per_page: int, total: int, n: int) -> bytes:
    vulns = [
        {
            "cve": {
                "id": f"CVE-2026-{100000 + start + i}",
                "sourceIdentifier": "cna@example.org",
                "published": "2026-11-17T00:00:00.000",
                "lastModified": "2026-11-17T01:00:00.000",
                "vulnStatus": "Deferred",
                "descriptions": [{"lang": "en", "value": "x"}],
            }
        }
        for i in range(n)
    ]
    return json.dumps(
        {
            "startIndex": start,
            "resultsPerPage": per_page,
            "totalResults": total,
            "vulnerabilities": vulns,
        }
    ).encode()


def test_nvd_pages_until_total_and_formats_query() -> None:
    f = FakeFetcher([nvd_page(0, 2, 5, 2), nvd_page(2, 2, 5, 2), nvd_page(4, 2, 5, 1)])
    pages = list(iter_nvd_modified(f, NVD, T0, T0 + timedelta(days=1), page_size=2))
    assert sum(len(p.cves) for p in pages) == 5
    starts = [parse_qs(urlsplit(str(c["url"])).query)["startIndex"][0] for c in f.calls]
    assert starts == ["0", "2", "4"]
    q = parse_qs(urlsplit(str(f.calls[0]["url"])).query)
    assert q["lastModStartDate"] == ["2026-11-17T00:00:00.000+00:00"]
    assert q["resultsPerPage"] == ["2"]
    assert all(c["interval"] == 6.5 and c["headers"] is None for c in f.calls)


def test_nvd_api_key_goes_in_header_and_speeds_up_pacing() -> None:
    f = FakeFetcher([nvd_page(0, 10, 1, 1)])
    list(iter_nvd_modified(f, NVD, T0, T0 + timedelta(hours=1), api_key="k3y"))
    assert f.calls[0]["headers"] == {"apiKey": "k3y"}
    assert "k3y" not in str(f.calls[0]["url"])  # never in the URL (logs, proxies)
    assert f.calls[0]["interval"] == pytest.approx(0.7)


def test_nvd_inconsistent_paging_is_an_error_not_a_loop() -> None:
    f = FakeFetcher([nvd_page(0, 2, 5, 2), nvd_page(0, 2, 5, 2)])  # server repeats page 0
    with pytest.raises(CollectError, match="startIndex 0, expected 2"):
        list(iter_nvd_modified(f, NVD, T0, T0 + timedelta(days=1), page_size=2))


def test_nvd_max_pages_guard() -> None:
    f = FakeFetcher([nvd_page(i * 1, 1, 10_000, 1) for i in range(3)])
    with pytest.raises(CollectError, match="stopped after 3 pages"):
        list(iter_nvd_modified(f, NVD, T0, T0 + timedelta(days=1), page_size=1, max_pages=3))


@pytest.mark.parametrize(
    ("start", "end", "match"),
    [
        (T0, T0, "before"),
        (T0, T0 + timedelta(days=121), "120 days"),
        (T0.replace(tzinfo=None), T0.replace(tzinfo=None) + timedelta(days=1), "timezone"),
    ],
)
def test_nvd_window_validation(start: datetime, end: datetime, match: str) -> None:
    f = FakeFetcher([nvd_page(0, 1, 1, 1)])
    with pytest.raises(CollectError, match=match):
        list(iter_nvd_modified(f, NVD, start, end))
