"""Hardened RSS 2.0 / Atom parsing (THREAT_MODEL.md T2, T3).

- XML is parsed only through defusedxml with DTDs, entity declarations and external
  references forbidden. That blocks XXE file/SSRF reads and entity-expansion bombs.
- Size is capped BEFORE parsing; item count and field lengths are capped after.
- Links are kept only if they are absolute http(s) URLs. A kept link is still untrusted:
  it must pass ``security.url_guard`` before anything fetches it.
- Text fields are reduced to plain text, and excerpts are kept short: we store
  metadata and brief derived summaries, never full republished articles.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Literal
from urllib.parse import urlsplit
from xml.etree.ElementTree import Element, ParseError

import defusedxml
import defusedxml.ElementTree as SafeET
from pydantic import BaseModel, ConfigDict

from cyberintel.parsing.html_text import html_to_text

MAX_FEED_BYTES = 5 * 1024 * 1024
MAX_ITEMS = 500
MAX_TITLE_CHARS = 300
MAX_EXCERPT_CHARS = 500
MAX_ID_CHARS = 2048

# All three layers on. forbid_dtd alone stops every known attack, so the other two are
# defence in depth; tests pin this dict so no flag can be flipped silently.
XML_HARDENING = {"forbid_dtd": True, "forbid_entities": True, "forbid_external": True}

ATOM_NS = "{http://www.w3.org/2005/Atom}"
CONTENT_NS = "{http://purl.org/rss/1.0/modules/content/}"


class FeedError(ValueError):
    """The input could not be parsed safely. Callers record and skip the source run."""


class FeedItem(BaseModel):
    model_config = ConfigDict(frozen=True)

    title: str
    url: str | None
    guid: str | None
    published: datetime | None
    excerpt: str


class Feed(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["rss", "atom"]
    title: str
    items: tuple[FeedItem, ...]
    truncated: bool


def parse_feed(data: bytes) -> Feed:
    if len(data) > MAX_FEED_BYTES:
        raise FeedError(f"feed is {len(data)} bytes; limit is {MAX_FEED_BYTES}")
    try:
        root = SafeET.fromstring(data, **XML_HARDENING)
    except defusedxml.DefusedXmlException as exc:
        raise FeedError(f"unsafe XML construct rejected: {type(exc).__name__}") from None
    except ParseError as exc:
        raise FeedError(f"malformed XML: {exc}") from None

    if root.tag == "rss":
        channel = root.find("channel")
        if channel is None:
            raise FeedError("RSS without <channel>")
        return _build("rss", _text(channel, "title"), channel.findall("item"), _rss_item)
    if root.tag == f"{ATOM_NS}feed":
        entries = root.findall(f"{ATOM_NS}entry")
        return _build("atom", _text(root, f"{ATOM_NS}title"), entries, _atom_item)
    raise FeedError(f"unsupported feed root element {root.tag[:80]!r}")


def _build(
    kind: Literal["rss", "atom"],
    title: str,
    elements: list[Element],
    to_item: Callable[[Element], FeedItem],
) -> Feed:
    items = tuple(to_item(el) for el in elements[:MAX_ITEMS])
    return Feed(
        kind=kind,
        title=html_to_text(title, MAX_TITLE_CHARS),
        items=items,
        truncated=len(elements) > MAX_ITEMS,
    )


def _rss_item(el: Element) -> FeedItem:
    body = _text(el, f"{CONTENT_NS}encoded") or _text(el, "description")
    return FeedItem(
        title=html_to_text(_text(el, "title"), MAX_TITLE_CHARS),
        url=_safe_link(_text(el, "link")),
        guid=_text(el, "guid")[:MAX_ID_CHARS] or None,
        published=_rss_date(_text(el, "pubDate")),
        excerpt=html_to_text(body, MAX_EXCERPT_CHARS),
    )


def _atom_item(el: Element) -> FeedItem:
    href = None
    for link in el.findall(f"{ATOM_NS}link"):
        if link.get("rel", "alternate") == "alternate":
            href = link.get("href")
            break
    body = _text(el, f"{ATOM_NS}summary") or _text(el, f"{ATOM_NS}content")
    date = _text(el, f"{ATOM_NS}published") or _text(el, f"{ATOM_NS}updated")
    return FeedItem(
        title=html_to_text(_text(el, f"{ATOM_NS}title"), MAX_TITLE_CHARS),
        url=_safe_link(href or ""),
        guid=_text(el, f"{ATOM_NS}id")[:MAX_ID_CHARS] or None,
        published=_iso_date(date),
        excerpt=html_to_text(body, MAX_EXCERPT_CHARS),
    )


def _text(el: Element, path: str) -> str:
    child = el.find(path)
    return (child.text or "").strip() if child is not None else ""


def _safe_link(raw: str) -> str | None:
    raw = raw.strip()
    if not raw or len(raw) > MAX_ID_CHARS:
        return None
    parts = urlsplit(raw)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        return None  # drops javascript:, data:, file:, relative and protocol-relative links
    return raw


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _rss_date(raw: str) -> datetime | None:
    if not raw:
        return None
    try:
        return _utc(parsedate_to_datetime(raw))
    except (TypeError, ValueError, IndexError):
        return None


def _iso_date(raw: str) -> datetime | None:
    if not raw:
        return None
    try:
        return _utc(datetime.fromisoformat(raw))
    except ValueError:
        return None
