"""SafeFetcher: the only component that makes outbound HTTP requests (THREAT_MODEL T1/T3).

Every request:
  1. passes ``check_url`` (allowlist, IP-literal rejection, all-addresses-public);
  2. is rate-limited per host;
  3. connects to one of the *validated IP addresses* (pinning), while the ``Host`` header
     and TLS SNI carry the real hostname, so certificate verification still checks the
     certificate against the hostname. DNS is never re-resolved between check and connect,
     which closes the DNS-rebinding window;
  4. never follows redirects implicitly: each ``Location`` is re-validated by
     ``check_redirect`` (hop limit, scheme downgrade blocked, internal targets blocked);
  5. streams the body with a hard byte cap (Content-Length checked first, then counted).

Proxy mode: if an egress proxy is configured (the homelab deployment uses an allowlisting
forward proxy), the client sends ``CONNECT hostname:443`` and the *proxy* resolves DNS, so
IP pinning is not possible at this layer. The URL guard still runs (allowlist, scheme,
port, IP-literal, userinfo and redirect checks) but skips local DNS, which the collector's
internal network deliberately does not have; the proxy's destination ACL (deny private
ranges after *its* resolution) is the address and rebinding defence, verified in CI by
deploy/ci/egress_probe.py. The trade-off is
recorded in ENGINEERING_LOG.md.

Residual risk: httpx inflates ``Content-Encoding: gzip`` per network chunk without an
output limit, so a single hostile chunk can briefly expand to roughly 1000x its size
before the byte cap stops the read. Bounded, accepted, and documented.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime

import httpx

from cyberintel.net.ratelimit import HostRateLimiter
from cyberintel.net.types import (
    FetchError,
    FetchHTTPError,
    FetchRejectedError,
    FetchResult,
    FetchTooLargeError,
    Validators,
)
from cyberintel.security.url_guard import (
    CheckedURL,
    HostAllowlist,
    Resolver,
    URLRejectedError,
    check_redirect,
    check_url,
    default_resolver,
)

USER_AGENT = "cyber-intel-platform/0.1 (+https://github.com/frimpongemanuele/cyber-intel-platform)"
DEFAULT_MAX_BYTES = 20 * 1024 * 1024
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
DEFAULT_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0)


class SafeFetcher:
    def __init__(
        self,
        allowlist: HostAllowlist,
        *,
        resolver: Resolver = default_resolver,
        rate_limiter: HostRateLimiter | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        max_redirects: int = 3,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
        proxy: str | None = None,
        transport: httpx.BaseTransport | None = None,
        user_agent: str = USER_AGENT,
    ) -> None:
        self._allow = allowlist
        self._resolver = resolver
        self._limiter = rate_limiter or HostRateLimiter(1.0)
        self._max_bytes = max_bytes
        self._max_redirects = max_redirects
        self._pin = proxy is None
        self._client = httpx.Client(
            transport=transport,
            proxy=proxy,
            follow_redirects=False,  # every hop is re-validated by hand
            trust_env=False,  # ignore HTTP(S)_PROXY / NO_PROXY / .netrc from the environment
            timeout=timeout,
            headers={"User-Agent": user_agent, "Accept-Encoding": "gzip"},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> SafeFetcher:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ public API

    def get(
        self,
        url: str,
        *,
        validators: Validators | None = None,
        headers: Mapping[str, str] | None = None,
        max_bytes: int | None = None,
        min_interval: float | None = None,
    ) -> FetchResult:
        limit = max_bytes or self._max_bytes
        req_headers = dict(headers or {})
        if validators and validators.etag:
            req_headers["If-None-Match"] = validators.etag
        if validators and validators.last_modified:
            req_headers["If-Modified-Since"] = validators.last_modified

        try:
            checked = check_url(url, self._allow, resolver=self._resolver, resolve=self._pin)
        except URLRejectedError as exc:
            raise FetchRejectedError(str(exc)) from None

        for hop in range(self._max_redirects + 1):
            self._limiter.acquire(checked.host, min_interval)
            response, peer = self._send(checked, req_headers)
            try:
                if response.status_code in REDIRECT_STATUSES:
                    location = response.headers.get("location")
                    if not location:
                        raise FetchHTTPError(checked.url, response.status_code)
                    try:
                        checked = check_redirect(
                            checked,
                            location,
                            self._allow,
                            hops_so_far=hop,
                            max_hops=self._max_redirects,
                            resolver=self._resolver,
                            resolve=self._pin,
                        )
                    except URLRejectedError as exc:
                        raise FetchRejectedError(f"redirect blocked: {exc}") from None
                    continue
                return self._result(url, checked, response, peer, limit)
            finally:
                response.close()
        raise FetchRejectedError(f"more than {self._max_redirects} redirects")  # pragma: no cover

    # ------------------------------------------------------------------ internals

    def _send(
        self, checked: CheckedURL, headers: Mapping[str, str]
    ) -> tuple[httpx.Response, str | None]:
        if not self._pin:
            request = self._client.build_request("GET", checked.url, headers=headers)
            return self._send_one(request), None

        last_error: Exception | None = None
        for address in checked.addresses:  # try each validated address in turn
            pinned_url = httpx.URL(checked.url).copy_with(host=address)
            request = self._client.build_request(
                "GET",
                pinned_url,
                headers={**headers, "Host": checked.host},
                extensions={"sni_hostname": checked.host},  # TLS SNI + certificate check
            )
            try:
                return self._send_one(request), address
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                last_error = exc
        raise FetchError(f"could not connect to {checked.host}: {last_error}")

    def _send_one(self, request: httpx.Request) -> httpx.Response:
        try:
            return self._client.send(request, stream=True)
        except (httpx.ConnectError, httpx.ConnectTimeout):
            raise
        except httpx.HTTPError as exc:
            raise FetchError(f"{type(exc).__name__}: {exc}") from None

    def _result(
        self,
        requested: str,
        checked: CheckedURL,
        response: httpx.Response,
        peer: str | None,
        limit: int,
    ) -> FetchResult:
        def build(body: bytes, not_modified: bool) -> FetchResult:
            return FetchResult(
                url=requested,
                final_url=checked.url,
                status=response.status_code,
                body=body,
                not_modified=not_modified,
                validators=Validators(
                    etag=response.headers.get("etag"),
                    last_modified=response.headers.get("last-modified"),
                ),
                content_type=response.headers.get("content-type"),
                fetched_at=datetime.now(UTC),
                peer_address=peer,
            )

        if response.status_code == 304:
            return build(b"", not_modified=True)
        if response.status_code >= 400:
            raise FetchHTTPError(checked.url, response.status_code)

        declared = response.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > limit:
            raise FetchTooLargeError(f"Content-Length {declared} exceeds {limit}")
        body = bytearray()
        try:
            for chunk in response.iter_bytes():
                body += chunk
                if len(body) > limit:
                    raise FetchTooLargeError(f"body exceeds {limit} bytes")
        except httpx.HTTPError as exc:
            raise FetchError(f"{type(exc).__name__} while reading: {exc}") from None
        return build(bytes(body), not_modified=False)
