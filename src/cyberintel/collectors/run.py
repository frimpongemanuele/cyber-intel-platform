"""Collector jobs: fetch (via the ``Fetcher`` protocol) + parse, one function per source kind.

These depend only on ``net.types.Fetcher``, so they are tested with a fake fetcher and
never touch the network in unit tests. Persistence (Phase 7) wraps these: callers store
``Collected.fetched.validators`` and pass them back for the next conditional GET.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import urlencode

from cyberintel.collectors.cve5 import Cve5Record, parse_cve5
from cyberintel.collectors.epss import EpssSnapshot, parse_epss
from cyberintel.collectors.kev import KevCatalog, parse_kev
from cyberintel.collectors.nvd import NvdPage, parse_nvd_page
from cyberintel.net.decompress import gunzip_capped
from cyberintel.net.types import Fetcher, FetchResult, Validators
from cyberintel.normalize import CVE_ID
from cyberintel.parsing.feeds import MAX_FEED_BYTES, Feed, parse_feed
from cyberintel.sources import Source

MAX_EPSS_DECOMPRESSED = 256 * 1024 * 1024
NVD_MAX_WINDOW = timedelta(days=120)  # NVD API limit for lastMod/pub date ranges
NVD_KEYED_INTERVAL = 0.7  # 50 requests / 30 s with a key -> 0.6 s; keep margin


class CollectError(ValueError):
    """The job's own preconditions failed (bad input, inconsistent paging, wrong kind)."""


@dataclass(frozen=True, slots=True)
class Collected[T]:
    source: str
    fetched: FetchResult
    data: T | None  # None when the server answered 304 Not Modified


def _require(source: Source, kind: str) -> None:
    if source.kind != kind:
        raise CollectError(f"source {source.name!r} is kind {source.kind!r}, expected {kind!r}")


def collect_kev(
    fetcher: Fetcher, source: Source, validators: Validators | None = None
) -> Collected[KevCatalog]:
    _require(source, "kev")
    res = fetcher.get(source.url, validators=validators, min_interval=source.min_interval_seconds)
    return Collected(source.name, res, None if res.not_modified else parse_kev(res.body))


def collect_epss(
    fetcher: Fetcher, source: Source, validators: Validators | None = None
) -> Collected[EpssSnapshot]:
    _require(source, "epss")
    res = fetcher.get(
        source.url,
        validators=validators,
        max_bytes=64 * 1024 * 1024,
        min_interval=source.min_interval_seconds,
    )
    if res.not_modified:
        return Collected(source.name, res, None)
    csv_text = gunzip_capped(res.body, MAX_EPSS_DECOMPRESSED).decode("utf-8", errors="replace")
    return Collected(source.name, res, parse_epss(csv_text.splitlines()))


def collect_feed(
    fetcher: Fetcher, source: Source, validators: Validators | None = None
) -> Collected[Feed]:
    _require(source, "feed")
    limit = source.max_bytes or MAX_FEED_BYTES
    res = fetcher.get(
        source.url,
        validators=validators,
        max_bytes=limit,
        min_interval=source.min_interval_seconds,
    )
    if res.not_modified:
        return Collected(source.name, res, None)
    feed = parse_feed(res.body, max_bytes=limit, allow_doctype=source.xml_allow_doctype)
    return Collected(source.name, res, feed)


def collect_cve5(fetcher: Fetcher, source: Source, cve_id: str) -> Cve5Record:
    """Fetch one CVE.org record. ``cve_id`` usually comes from untrusted text, so it is
    validated strictly *before* it becomes part of a URL path (no traversal, no injection)."""
    _require(source, "cve5")
    cve = cve_id.strip().upper()
    if not CVE_ID.match(cve):
        raise CollectError(f"refusing to build a URL from invalid CVE ID {cve_id[:40]!r}")
    res = fetcher.get(source.url.rstrip("/") + "/" + cve, min_interval=source.min_interval_seconds)
    record = parse_cve5(res.body)
    if record.cve_id != cve:
        raise CollectError(f"asked for {cve}, server returned {record.cve_id}")
    return record


def _nvd_time(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise CollectError("NVD date bounds must be timezone-aware")
    return dt.isoformat(timespec="milliseconds")


def iter_nvd_modified(
    fetcher: Fetcher,
    source: Source,
    start: datetime,
    end: datetime,
    *,
    api_key: str | None = None,
    page_size: int = 500,
    max_pages: int = 200,
) -> Iterator[NvdPage]:
    """Yield NVD pages for CVEs modified in ``[start, end]`` (max 120-day window).

    Paging is checked for consistency: a server that repeats or skips a page is an error,
    not an infinite loop.
    """
    _require(source, "nvd")
    if not start < end:
        raise CollectError("start must be before end")
    if end - start > NVD_MAX_WINDOW:
        raise CollectError("NVD date windows are limited to 120 days")
    if not 1 <= page_size <= 2000:
        raise CollectError("page_size must be 1..2000")

    headers = {"apiKey": api_key} if api_key else None
    interval = NVD_KEYED_INTERVAL if api_key else source.min_interval_seconds
    index = 0
    for _ in range(max_pages):
        query = urlencode(
            {
                "lastModStartDate": _nvd_time(start),
                "lastModEndDate": _nvd_time(end),
                "resultsPerPage": page_size,
                "startIndex": index,
            }
        )
        res = fetcher.get(
            f"{source.url}?{query}",
            headers=headers,
            max_bytes=64 * 1024 * 1024,
            min_interval=interval,
        )
        page = parse_nvd_page(res.body)
        if page.start_index != index:
            raise CollectError(f"NVD returned startIndex {page.start_index}, expected {index}")
        yield page
        nxt = page.next_start_index
        if nxt is None:
            return
        index = nxt
    raise CollectError(f"stopped after {max_pages} pages; narrow the date window")
