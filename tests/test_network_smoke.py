"""Live checks against the real sources. Marked ``network``: skipped by default.

Run with ``pytest -m network``. CI runs these weekly, on demand, and on pull requests as
a non-blocking job. They verify what unit tests cannot:

* every configured URL still works and still parses (feeds move; EPSS already moved once);
* the parsers' assumptions about real NVD / CVE.org / KEV / EPSS layouts hold;
* IP pinning with SNI works against real TLS endpoints (every request here is pinned).

A redirect to an unlisted host fails loudly with "redirect blocked", which is the signal
to review the target and add it to that source's ``extra_hosts``.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

pytestmark = pytest.mark.network
httpx = pytest.importorskip("httpx")

from cyberintel.collectors.nvd import parse_nvd_page  # noqa: E402
from cyberintel.collectors.run import (  # noqa: E402
    collect_cve5,
    collect_epss,
    collect_feed,
    collect_kev,
    iter_nvd_modified,
)
from cyberintel.net.fetch import SafeFetcher  # noqa: E402
from cyberintel.net.ratelimit import HostRateLimiter  # noqa: E402
from cyberintel.sources import load_registry  # noqa: E402

REGISTRY = load_registry(Path(__file__).resolve().parents[1] / "config" / "sources.toml")


@pytest.fixture(scope="module")
def fetcher() -> Iterator[SafeFetcher]:
    with SafeFetcher(REGISTRY.allowlist(), rate_limiter=HostRateLimiter(1.0)) as f:
        yield f


def test_kev_live(fetcher: SafeFetcher) -> None:
    out = collect_kev(fetcher, REGISTRY.get("cisa-kev"))
    assert out.data is not None
    assert len(out.data.entries) > 1000
    assert len(out.data.rejected) < 10, out.data.rejected[:5]
    assert out.fetched.peer_address is not None  # the connection was pinned


def test_epss_live(fetcher: SafeFetcher) -> None:
    out = collect_epss(fetcher, REGISTRY.get("first-epss"))
    assert out.data is not None
    assert len(out.data.scores) > 100_000
    assert out.data.model_version is not None
    assert out.data.rejected_rows < 100


def test_nvd_live_single_cve(fetcher: SafeFetcher) -> None:
    nvd = REGISTRY.get("nvd-cve-api")
    res = fetcher.get(f"{nvd.url}?cveId=CVE-2021-44228", min_interval=nvd.min_interval_seconds)
    page = parse_nvd_page(res.body)
    assert page.rejected == ()
    (cve,) = page.cves
    assert cve.cve_id == "CVE-2021-44228"
    assert cve.kev_date_added is not None  # Log4Shell is in KEV
    assert cve.scores and cve.cwes and cve.references


def test_nvd_live_modified_window(fetcher: SafeFetcher) -> None:
    end = datetime.now(UTC)
    first = next(
        iter_nvd_modified(fetcher, REGISTRY.get("nvd-cve-api"), end - timedelta(hours=6), end,
                          page_size=20)
    )  # fmt: skip
    assert first.start_index == 0
    assert len(first.rejected) == 0, first.rejected[:3]


def test_cve5_live(fetcher: SafeFetcher) -> None:
    rec = collect_cve5(fetcher, REGISTRY.get("cve-org-records"), "CVE-2021-44228")
    assert rec.state == "PUBLISHED" and rec.description and rec.affected


@pytest.mark.parametrize("name", [s.name for s in REGISTRY.enabled("feed")])
def test_feed_live(fetcher: SafeFetcher, name: str) -> None:
    out = collect_feed(fetcher, REGISTRY.get(name))
    assert out.data is not None
    assert len(out.data.items) > 0, f"{name}: parsed but empty"
    assert any(i.url for i in out.data.items), f"{name}: no usable item links"
