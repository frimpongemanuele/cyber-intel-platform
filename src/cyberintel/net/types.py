"""Fetcher interface and result types.

Collectors depend on this protocol, not on httpx, so their logic is testable with a fake
fetcher and the HTTP implementation (``net.fetch.SafeFetcher``) can be swapped or hardened
without touching them.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


class FetchError(Exception):
    """Base class for fetch failures. Collectors record these and skip the run."""


class FetchRejectedError(FetchError):
    """The URL or a redirect target failed the SSRF policy."""


class FetchTooLargeError(FetchError):
    """The response body exceeded the configured size limit."""


class FetchHTTPError(FetchError):
    def __init__(self, url: str, status: int) -> None:
        super().__init__(f"HTTP {status} for {url[:200]}")
        self.url = url
        self.status = status


@dataclass(frozen=True, slots=True)
class Validators:
    """HTTP cache validators from a previous successful fetch (conditional GET)."""

    etag: str | None = None
    last_modified: str | None = None


@dataclass(frozen=True, slots=True)
class FetchResult:
    url: str  # the URL requested
    final_url: str  # after validated redirects
    status: int
    body: bytes  # empty when not_modified
    not_modified: bool
    validators: Validators  # to store for the next conditional GET
    content_type: str | None
    fetched_at: datetime
    peer_address: str | None  # the pinned IP actually used (audit trail)


class Fetcher(Protocol):
    def get(
        self,
        url: str,
        *,
        validators: Validators | None = None,
        headers: Mapping[str, str] | None = None,
        max_bytes: int | None = None,
        min_interval: float | None = None,
    ) -> FetchResult: ...
