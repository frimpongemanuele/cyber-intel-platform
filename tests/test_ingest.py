"""Ingest runner with a fake fetcher and an in-memory store (no network, no database)."""

from __future__ import annotations

import gzip
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from cyberintel.collectors.cve5 import Cve5Record
from cyberintel.collectors.epss import EpssSnapshot
from cyberintel.collectors.kev import KevCatalog
from cyberintel.collectors.nvd import NvdPage
from cyberintel.ingest import is_due, nvd_window, run_once, run_source
from cyberintel.net.types import FetchHTTPError, FetchResult, Validators
from cyberintel.parsing.feeds import Feed
from cyberintel.sources import Registry, Source

FIX = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 11, 18, 7, 0, tzinfo=UTC)


def src(name: str, kind: str, url: str, **kw: Any) -> Source:
    return Source(name=name, kind=kind, url=url, trust_tier="primary", **kw)  # type: ignore[arg-type]


KEV = src("cisa-kev", "kev", "https://www.cisa.gov/kev.json", poll_minutes=60)
FEED = src("research-feed", "feed", "https://research.example.org/rss")
EPSS = src("first-epss", "epss", "https://epss.example.org/current.csv.gz")
NVD = src("nvd-cve-api", "nvd", "https://services.nvd.nist.gov/rest/json/cves/2.0")
CVE5 = src("cve-org-records", "cve5", "https://cveawg.mitre.org/api/cve/")


@dataclass
class State:
    validators: Validators | None = None
    consecutive_failures: int = 0
    last_success_at: datetime | None = None
    last_attempt_at: datetime | None = None


@dataclass
class MemStore:
    states: dict[str, State] = field(default_factory=dict)
    runs: list[dict[str, Any]] = field(default_factory=list)
    stored: dict[str, Any] = field(default_factory=dict)
    queue: list[str] = field(default_factory=list)

    def state(self, source_name: str) -> State:
        return self.states.setdefault(source_name, State())

    def store_kev(self, catalog: KevCatalog, seen_at: datetime) -> None:
        self.stored["kev"] = catalog

    def store_epss(self, snapshot: EpssSnapshot, seen_at: datetime) -> int:
        self.stored["epss"] = snapshot
        return len(snapshot.scores)

    def store_documents(self, source_name: str, feed: Feed, seen_at: datetime) -> tuple[int, int]:
        self.stored[source_name] = feed
        return 2, 0

    def store_nvd_page(self, page: NvdPage, seen_at: datetime) -> list[str]:
        self.stored.setdefault("nvd", []).append(page)
        return [c.cve_id for c in page.cves]

    def store_cve5(self, records: Sequence[Cve5Record], seen_at: datetime) -> list[str]:
        self.stored["cve5"] = list(records)
        return [r.cve_id for r in records]

    def cve5_queue(self, limit: int) -> list[str]:
        return self.queue[:limit]

    def record_success(self, source_name: str, validators: Validators, at: datetime) -> None:
        s = self.state(source_name)
        s.validators, s.consecutive_failures = validators, 0
        s.last_success_at = s.last_attempt_at = at

    def record_failure(self, source_name: str, error: str, at: datetime) -> None:
        s = self.state(source_name)
        s.consecutive_failures += 1
        s.last_attempt_at = at

    def record_fetch_run(self, **fields: Any) -> None:
        self.runs.append(fields)


@dataclass
class Fetch:
    """Fake fetcher: body by URL prefix, or an exception to raise."""

    routes: dict[str, bytes | Exception]
    calls: list[str] = field(default_factory=list)
    not_modified: bool = False

    def get(self, url: str, *, validators: Validators | None = None,
            headers: Mapping[str, str] | None = None, max_bytes: int | None = None,
            min_interval: float | None = None) -> FetchResult:  # fmt: skip
        self.calls.append(url)
        for prefix, body in self.routes.items():
            if url.startswith(prefix):
                if isinstance(body, Exception):
                    raise body
                return FetchResult(url=url, final_url=url, status=304 if self.not_modified else 200,
                                   body=b"" if self.not_modified else body,
                                   not_modified=self.not_modified,
                                   validators=Validators(etag='"v2"'), content_type=None,
                                   fetched_at=NOW, peer_address="203.0.113.9")  # fmt: skip
        raise AssertionError(f"unexpected fetch {url}")


def clock() -> datetime:
    return NOW


# --------------------------------------------------------------------------- outcomes


def test_success_stores_data_and_records_validators_and_audit_row() -> None:
    store = MemStore()
    fetch = Fetch({KEV.url: (FIX / "kev" / "kev_sample.json").read_bytes()})
    report = run_source(KEV, fetch, store, clock=clock)
    assert (report.outcome, report.records_ok, report.records_rejected) == ("ok", 3, 4)
    assert store.state("cisa-kev").validators == Validators(etag='"v2"')
    (run,) = store.runs
    assert run["outcome"] == "ok" and run["http_status"] == 200
    assert run["peer_address"] == "203.0.113.9" and run["error"] is None


def test_not_modified_is_success_without_storing() -> None:
    store = MemStore()
    fetch = Fetch({KEV.url: b""}, not_modified=True)
    assert run_source(KEV, fetch, store, clock=clock).outcome == "not_modified"
    assert "kev" not in store.stored and store.runs[0]["outcome"] == "not_modified"


@pytest.mark.parametrize(
    "error",
    [
        FetchHTTPError("https://www.cisa.gov/kev.json", 503),
        b"{not json",  # KevError
        b"<!DOCTYPE x [<!ENTITY e 'x'>]><rss/>",  # unsafe XML (feed source)
    ],
)
def test_expected_source_failures_are_recorded_not_raised(error: Exception | bytes) -> None:
    store = MemStore()
    source = FEED if isinstance(error, bytes) and error.startswith(b"<!") else KEV
    fetch = Fetch({source.url: error})
    report = run_source(source, fetch, store, clock=clock)
    assert report.outcome == "error"
    assert store.state(source.name).consecutive_failures == 1
    (run,) = store.runs
    assert run["outcome"] == "error" and run["error"]
    if isinstance(error, FetchHTTPError):
        assert run["http_status"] == 503


def test_unexpected_errors_propagate() -> None:
    class Broken(MemStore):
        def store_kev(self, catalog: KevCatalog, seen_at: datetime) -> None:
            raise RuntimeError("database is down")

    fetch = Fetch({KEV.url: (FIX / "kev" / "kev_sample.json").read_bytes()})
    with pytest.raises(RuntimeError, match="database is down"):
        run_source(KEV, fetch, Broken(), clock=clock)


# --------------------------------------------------------------------------- scheduling


def test_poll_interval_and_exponential_backoff() -> None:
    assert is_due(KEV, State(), NOW)  # never attempted
    recent = State(last_attempt_at=NOW - timedelta(minutes=30))
    assert not is_due(KEV, recent, NOW)  # 60-minute poll
    assert is_due(KEV, State(last_attempt_at=NOW - timedelta(minutes=61)), NOW)
    failing = State(consecutive_failures=3, last_attempt_at=NOW - timedelta(hours=7))
    assert not is_due(KEV, failing, NOW)  # 60 min x 2^3 = 8 h
    assert is_due(KEV, State(consecutive_failures=3, last_attempt_at=NOW - timedelta(hours=8)), NOW)
    capped = State(consecutive_failures=50, last_attempt_at=NOW - timedelta(hours=64))
    assert is_due(KEV, capped, NOW)  # backoff capped at x64


def test_skipped_when_not_due_unless_forced() -> None:
    store = MemStore(states={"cisa-kev": State(last_attempt_at=NOW - timedelta(minutes=5))})
    fetch = Fetch({KEV.url: (FIX / "kev" / "kev_sample.json").read_bytes()})
    assert run_source(KEV, fetch, store, clock=clock).outcome == "skipped"
    assert fetch.calls == []
    assert run_source(KEV, fetch, store, clock=clock, force=True).outcome == "ok"


def test_nvd_window_overlaps_last_success_and_is_capped() -> None:
    start, end = nvd_window(State(last_success_at=NOW - timedelta(hours=2)), NOW)
    assert (start, end) == (NOW - timedelta(hours=3), NOW)
    start, _ = nvd_window(State(), NOW)
    assert start == NOW - timedelta(days=1)
    start, _ = nvd_window(State(last_success_at=NOW - timedelta(days=400)), NOW)
    assert NOW - start < timedelta(days=120)  # API limit respected


# --------------------------------------------------------------------------- source kinds


def test_epss_feed_nvd_and_cve5_jobs() -> None:
    store = MemStore(queue=["CVE-2026-102895"])
    fetch = Fetch({
        EPSS.url: gzip.compress((FIX / "epss" / "epss_sample.csv").read_bytes()),
        FEED.url: (FIX / "feeds" / "rss_ok.xml").read_bytes(),
        NVD.url: b'{"startIndex":0,"resultsPerPage":10,"totalResults":0,"vulnerabilities":[]}',
        CVE5.url: (FIX / "cve5" / "published.json").read_bytes(),
    })  # fmt: skip
    reports = {r.source: r for r in run_once(
        Registry(sources=(KEV.model_copy(update={"enabled": False}), EPSS, FEED, NVD, CVE5)),
        fetch, store, clock=clock)}  # fmt: skip
    assert reports["first-epss"].records_ok == 3
    assert reports["research-feed"].records_ok == 2
    assert reports["nvd-cve-api"].outcome == "ok"
    assert reports["cve-org-records"].records_ok == 1
    assert "cisa-kev" not in reports  # disabled
    assert fetch.calls[-1] == "https://cveawg.mitre.org/api/cve/CVE-2026-102895"  # cve5 last


def test_cve5_job_refuses_poisoned_queue_entries() -> None:
    # Queue values come from untrusted article text; a malformed one must fail the job
    # through CollectError (recorded), never become a URL.
    store = MemStore(queue=["../../admin"])
    fetch = Fetch({CVE5.url: b"{}"})
    report = run_source(CVE5, fetch, store, clock=clock)
    assert report.outcome == "error" and "invalid CVE ID" in report.detail
    assert fetch.calls == []


def test_api_key_is_never_in_the_url_or_the_audit_row() -> None:
    store = MemStore()
    fetch = Fetch({NVD.url: b'{"startIndex":0,"resultsPerPage":10,"totalResults":0,'
                               b'"vulnerabilities":[]}'})  # fmt: skip
    run_source(NVD, fetch, store, clock=clock, nvd_api_key="s3cr3t-key")
    assert all("s3cr3t" not in c for c in fetch.calls)
    assert all("s3cr3t" not in str(r) for r in store.runs)
