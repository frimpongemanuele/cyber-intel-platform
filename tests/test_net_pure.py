"""Network-layer pieces that need no HTTP library: rate limiter, bounded gunzip, registry."""

import gzip
import tracemalloc
from pathlib import Path

import pytest

from cyberintel.net.decompress import DecompressionError, gunzip_capped
from cyberintel.net.ratelimit import HostRateLimiter
from cyberintel.sources import Registry, Source, load_registry

ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------- rate limiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0
        self.slept: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, s: float) -> None:
        self.slept.append(s)
        self.now += s


def test_rate_limiter_spaces_requests_per_host() -> None:
    c = FakeClock()
    rl = HostRateLimiter(6.5, clock=c.clock, sleep=c.sleep)
    assert rl.acquire("services.nvd.nist.gov") == 0.0  # first request: no wait
    c.now += 2.0
    assert rl.acquire("services.nvd.nist.gov") == pytest.approx(4.5)  # waits the remainder
    assert rl.acquire("www.cisa.gov") == 0.0  # other hosts are independent
    c.now += 10.0
    assert rl.acquire("services.nvd.nist.gov") == 0.0  # interval already elapsed


def test_rate_limiter_stays_within_nvd_public_limit() -> None:
    # NVD: 5 requests per rolling 30 s without a key. Simulate a burst of 50 requests and
    # check that no 30-second window ever contains more than 5.
    c = FakeClock()
    rl = HostRateLimiter(6.5, clock=c.clock, sleep=c.sleep)
    times = []
    for _ in range(50):
        rl.acquire("nvd")
        times.append(c.now)
    assert max(sum(1 for t in times if start <= t < start + 30) for start in times) <= 5


def test_rate_limiter_per_call_override_and_validation() -> None:
    c = FakeClock()
    rl = HostRateLimiter(10, clock=c.clock, sleep=c.sleep)
    rl.acquire("h")
    assert rl.acquire("h", interval=0.5) == pytest.approx(0.5)
    with pytest.raises(ValueError):
        rl.acquire("h", interval=-1)
    with pytest.raises(ValueError):
        HostRateLimiter(-1)


# --------------------------------------------------------------------- bounded gunzip


def test_gunzip_roundtrip_and_multimember() -> None:
    assert gunzip_capped(gzip.compress(b"hello"), 100) == b"hello"
    two = gzip.compress(b"cve,epss\n") + gzip.compress(b"CVE-2026-1,0.1\n")
    assert gunzip_capped(two, 100) == b"cve,epss\nCVE-2026-1,0.1\n"


def test_gunzip_exact_limit_is_allowed() -> None:
    assert len(gunzip_capped(gzip.compress(b"a" * 1000), 1000)) == 1000
    with pytest.raises(DecompressionError, match="exceeds"):
        gunzip_capped(gzip.compress(b"a" * 1001), 1000)


def test_gunzip_bomb_is_stopped_with_bounded_memory() -> None:
    bomb = gzip.compress(b"\0" * (200 * 1024 * 1024), compresslevel=9)  # 200 MiB of zeros
    assert len(bomb) < 1024 * 1024  # tiny on the wire
    tracemalloc.start()
    with pytest.raises(DecompressionError, match="exceeds"):
        gunzip_capped(bomb, 4 * 1024 * 1024)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert peak < 32 * 1024 * 1024, f"peak {peak} bytes: decompression was not bounded"


@pytest.mark.parametrize(
    "data",
    [b"not gzip at all", gzip.compress(b"x" * 10_000)[:-20], b"\x1f\x8b\x08\x00garbage"],
)
def test_gunzip_corrupt_or_truncated(data: bytes) -> None:
    with pytest.raises(DecompressionError):
        gunzip_capped(data, 1_000_000)


# --------------------------------------------------------------------- source registry


def test_repo_registry_loads_and_builds_allowlist() -> None:
    reg = load_registry(ROOT / "config" / "sources.toml")
    assert reg.get("cisa-kev").kind == "kev"
    assert {s.kind for s in reg.enabled()} >= {"kev", "epss", "nvd", "cve5", "feed"}
    allow = reg.allowlist()
    assert allow.allows("www.cisa.gov")
    assert allow.allows("services.nvd.nist.gov")
    assert not allow.allows("evil.example")
    assert all(s.url.startswith("https://") for s in reg.sources)


@pytest.mark.parametrize(
    "url",
    [
        "http://www.cisa.gov/x",  # plaintext
        "https://user@www.cisa.gov/x",  # userinfo
        "https://www.cisa.gov:8443/x",  # explicit port
        "file:///etc/passwd",
    ],
)
def test_source_rejects_unsafe_urls(url: str) -> None:
    with pytest.raises(ValueError):
        Source(name="x1", kind="feed", url=url, trust_tier="primary")


def test_registry_rejects_duplicates_and_unknown_fields() -> None:
    a = Source(name="dup", kind="feed", url="https://a.example/f", trust_tier="primary")
    with pytest.raises(ValueError, match="duplicate"):
        Registry(sources=(a, a))
    with pytest.raises(ValueError):
        Source(name="x1", kind="feed", url="https://a.example/", trust_tier="primary", oops=1)  # type: ignore[call-arg]


def test_disabled_sources_are_not_allowlisted() -> None:
    reg = Registry(
        sources=(
            Source(name="on", kind="feed", url="https://on.example/f", trust_tier="primary"),
            Source(
                name="off",
                kind="feed",
                url="https://off.example/f",
                trust_tier="primary",
                enabled=False,
                extra_hosts=("redirect.off.example",),
            ),
        )
    )
    allow = reg.allowlist()
    assert allow.allows("on.example")
    assert not allow.allows("off.example") and not allow.allows("redirect.off.example")


def test_doctype_opt_in_only_valid_for_feeds() -> None:
    with pytest.raises(ValueError, match="only to kind"):
        Source(
            name="k1", kind="kev", url="https://a.example/k", trust_tier="primary",
            xml_allow_doctype=True,
        )  # fmt: skip
    reg = load_registry(ROOT / "config" / "sources.toml")
    assert reg.get("msrc-blog").xml_allow_doctype is True
    assert reg.get("elastic-security-labs").max_bytes == 16 * 1024 * 1024
    assert all(not s.xml_allow_doctype for s in reg.sources if s.name != "msrc-blog")
