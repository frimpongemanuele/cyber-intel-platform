"""SafeFetcher tests with httpx.MockTransport (no real network). Run where httpx is installed."""

from __future__ import annotations

import gzip
from collections.abc import Callable, Iterator, Sequence

import pytest

httpx = pytest.importorskip("httpx")

from cyberintel.net.fetch import SafeFetcher  # noqa: E402
from cyberintel.net.ratelimit import HostRateLimiter  # noqa: E402
from cyberintel.net.types import (  # noqa: E402
    FetchError,
    FetchHTTPError,
    FetchRejectedError,
    FetchTooLargeError,
    Validators,
)
from cyberintel.security.url_guard import HostAllowlist  # noqa: E402

ALLOW = HostAllowlist(["www.cisa.gov", "feeds.example.org", "cdn.example.org"])
DNS: dict[str, list[str]] = {
    "www.cisa.gov": ["104.84.0.10", "104.84.0.11"],
    "feeds.example.org": ["93.184.216.34"],
    "cdn.example.org": ["2606:2800:220:1:248:1893:25c8:1946"],
}


def resolver(host: str, port: int) -> Sequence[str]:
    return DNS[host]


Handler = Callable[["httpx.Request"], "httpx.Response"]


def make(handler: Handler, **kw: object) -> tuple[SafeFetcher, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    no_wait = HostRateLimiter(0.0, clock=lambda: 0.0, sleep=lambda s: None)
    fetcher = SafeFetcher(
        ALLOW,
        resolver=resolver,
        rate_limiter=no_wait,
        transport=httpx.MockTransport(record),
        **kw,  # type: ignore[arg-type]
    )
    return fetcher, seen


def test_connects_to_pinned_ip_with_hostname_in_host_and_sni() -> None:
    fetcher, seen = make(lambda r: httpx.Response(200, content=b"{}"))
    res = fetcher.get("https://www.cisa.gov/feeds/kev.json")
    (req,) = seen
    assert req.url.host == "104.84.0.10"  # pinned: DNS is not re-resolved
    assert req.url.path == "/feeds/kev.json"
    assert req.headers["host"] == "www.cisa.gov"
    assert req.extensions["sni_hostname"] == "www.cisa.gov"  # TLS cert checked vs hostname
    assert req.headers["user-agent"].startswith("cyber-intel-platform/")
    assert res.body == b"{}" and res.peer_address == "104.84.0.10"
    assert res.final_url == "https://www.cisa.gov/feeds/kev.json"


def test_ipv6_pinned_address() -> None:
    fetcher, seen = make(lambda r: httpx.Response(200, content=b"ok"))
    fetcher.get("https://cdn.example.org/x")
    assert seen[0].url.host == "2606:2800:220:1:248:1893:25c8:1946"
    assert seen[0].headers["host"] == "cdn.example.org"


def test_falls_back_to_next_validated_address_on_connect_error() -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        if r.url.host == "104.84.0.10":
            raise httpx.ConnectError("refused", request=r)
        return httpx.Response(200, content=b"ok")

    fetcher, seen = make(handler)
    res = fetcher.get("https://www.cisa.gov/x")
    assert [r.url.host for r in seen] == ["104.84.0.10", "104.84.0.11"]
    assert res.peer_address == "104.84.0.11"


def test_all_addresses_failing_raises_fetch_error() -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=r)

    fetcher, _ = make(handler)
    with pytest.raises(FetchError, match="could not connect"):
        fetcher.get("https://www.cisa.gov/x")


def test_rejected_url_makes_no_request() -> None:
    fetcher, seen = make(lambda r: httpx.Response(200))
    for url in ["https://evil.example/", "https://169.254.169.254/", "http://www.cisa.gov/"]:
        with pytest.raises(FetchRejectedError):
            fetcher.get(url)
    assert seen == []


def test_follows_validated_relative_redirect() -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        if r.url.path == "/old":
            return httpx.Response(301, headers={"Location": "/new"})
        return httpx.Response(200, content=b"moved")

    fetcher, seen = make(handler)
    res = fetcher.get("https://www.cisa.gov/old")
    assert [r.url.path for r in seen] == ["/old", "/new"]
    assert res.final_url == "https://www.cisa.gov/new" and res.body == b"moved"


def test_cross_host_redirect_is_repinned() -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        if r.headers["host"] == "www.cisa.gov":
            return httpx.Response(302, headers={"Location": "https://feeds.example.org/f"})
        return httpx.Response(200, content=b"ok")

    fetcher, seen = make(handler)
    fetcher.get("https://www.cisa.gov/x")
    assert seen[1].url.host == "93.184.216.34" and seen[1].headers["host"] == "feeds.example.org"


@pytest.mark.parametrize(
    "location",
    [
        "https://169.254.169.254/latest/meta-data/",  # cloud metadata
        "https://evil.example/",  # not allowlisted
        "http://www.cisa.gov/",  # downgrade to plaintext
        "https://localhost/",
    ],
)
def test_hostile_redirects_are_blocked(location: str) -> None:
    fetcher, seen = make(lambda r: httpx.Response(302, headers={"Location": location}))
    with pytest.raises(FetchRejectedError, match="redirect blocked"):
        fetcher.get("https://www.cisa.gov/x")
    assert len(seen) == 1  # the hostile target was never contacted


def test_redirect_loop_is_bounded() -> None:
    fetcher, seen = make(lambda r: httpx.Response(302, headers={"Location": "/loop"}))
    with pytest.raises(FetchRejectedError):
        fetcher.get("https://www.cisa.gov/loop")
    assert len(seen) == 4  # original + 3 allowed redirects


def test_redirect_without_location_is_an_error() -> None:
    fetcher, _ = make(lambda r: httpx.Response(302))
    with pytest.raises(FetchHTTPError):
        fetcher.get("https://www.cisa.gov/x")


def test_conditional_get_and_304() -> None:
    fetcher, seen = make(
        lambda r: httpx.Response(304, headers={"ETag": '"v2"', "Last-Modified": "Tue, 17 Nov"})
    )
    res = fetcher.get(
        "https://www.cisa.gov/kev.json",
        validators=Validators(etag='"v1"', last_modified="Mon, 16 Nov 2026 00:00:00 GMT"),
    )
    assert seen[0].headers["if-none-match"] == '"v1"'
    assert seen[0].headers["if-modified-since"] == "Mon, 16 Nov 2026 00:00:00 GMT"
    assert res.not_modified and res.body == b"" and res.validators.etag == '"v2"'


def test_validators_captured_for_next_run() -> None:
    fetcher, _ = make(
        lambda r: httpx.Response(200, content=b"x", headers={"ETag": '"abc"', "Last-Modified": "L"})
    )
    res = fetcher.get("https://www.cisa.gov/x")
    assert res.validators == Validators(etag='"abc"', last_modified="L")


@pytest.mark.parametrize("status", [400, 403, 404, 429, 500, 503])
def test_http_errors_raise(status: int) -> None:
    fetcher, _ = make(lambda r: httpx.Response(status))
    with pytest.raises(FetchHTTPError) as exc:
        fetcher.get("https://www.cisa.gov/x")
    assert exc.value.status == status


def test_declared_content_length_over_limit_is_refused_before_reading() -> None:
    fetcher, _ = make(
        lambda r: httpx.Response(200, headers={"Content-Length": "999999999"}, content=b"")
    )
    with pytest.raises(FetchTooLargeError, match="Content-Length"):
        fetcher.get("https://www.cisa.gov/x", max_bytes=1000)


def test_streamed_body_over_limit_is_cut_off() -> None:
    def chunks() -> Iterator[bytes]:
        for _ in range(100):
            yield b"a" * 1024

    fetcher, _ = make(lambda r: httpx.Response(200, content=chunks()))  # no Content-Length
    with pytest.raises(FetchTooLargeError, match="body exceeds"):
        fetcher.get("https://www.cisa.gov/x", max_bytes=10_000)


def test_gzip_content_encoding_is_decoded_and_counted_after_decoding() -> None:
    payload = b"z" * 50_000
    fetcher, _ = make(
        lambda r: httpx.Response(
            200, content=gzip.compress(payload), headers={"Content-Encoding": "gzip"}
        )
    )
    assert fetcher.get("https://www.cisa.gov/x").body == payload
    with pytest.raises(FetchTooLargeError):
        fetcher.get("https://www.cisa.gov/x", max_bytes=10_000)  # decoded size counts


def test_rate_limiter_is_applied_per_hop() -> None:
    calls: list[tuple[str, float | None]] = []

    class Spy(HostRateLimiter):
        def acquire(self, host: str, interval: float | None = None) -> float:
            calls.append((host, interval))
            return 0.0

    def handler(r: httpx.Request) -> httpx.Response:
        if r.url.path == "/a":
            return httpx.Response(302, headers={"Location": "https://feeds.example.org/b"})
        return httpx.Response(200)

    fetcher = SafeFetcher(
        ALLOW, resolver=resolver, rate_limiter=Spy(), transport=httpx.MockTransport(handler)
    )
    fetcher.get("https://www.cisa.gov/a", min_interval=6.5)
    assert calls == [("www.cisa.gov", 6.5), ("feeds.example.org", 6.5)]
