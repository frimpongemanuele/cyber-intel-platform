"""Feed parser tests (THREAT_MODEL.md section 5, "XML fixtures")."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from cyberintel.parsing import feeds
from cyberintel.parsing.feeds import FeedError, parse_feed
from cyberintel.parsing.html_text import html_to_text

FIX = Path(__file__).parent / "fixtures" / "feeds"


def load(name: str) -> bytes:
    return (FIX / name).read_bytes()


def test_rss_parses_and_sanitizes() -> None:
    feed = parse_feed(load("rss_ok.xml"))
    assert feed.kind == "rss"
    assert feed.title == "Example Research Blog"
    first, hostile, encoded = feed.items

    assert first.title == "Auth bypass in ExampleSSH & friends (CVE-2026-123158)"
    assert first.url == "https://research.example.org/posts/sshole?utm_source=rss"
    assert first.guid == "post-1001"
    assert first.published == datetime(2026, 11, 5, 13, 30, tzinfo=UTC)  # +0100 -> UTC
    assert first.excerpt == (
        "Fail-open error handling lets an oversized input match a disabled sentinel."
    )
    assert "alert" not in first.excerpt and "<" not in first.excerpt  # script dropped

    assert hostile.url is None  # javascript: link discarded
    assert hostile.published is None  # unparseable date tolerated, not fatal

    assert encoded.excerpt == "Full body text."  # content:encoded preferred


def test_atom_parses_alternate_link_and_dates() -> None:
    feed = parse_feed(load("atom_ok.xml"))
    assert feed.kind == "atom"
    adv, data_link = feed.items
    assert adv.url == "https://cert.example.org/advisories/1"  # not the enclosure
    assert adv.published == datetime(2026, 11, 9, 8, 15, tzinfo=UTC)  # published beats updated
    assert adv.excerpt == "Requests appearing to come from loopback were trusted."
    assert data_link.url is None  # data: URL discarded
    assert data_link.published == datetime(2026, 11, 10, 8, 0, tzinfo=UTC)  # falls back


@pytest.mark.parametrize(
    "fixture", ["xxe_file.xml", "xxe_ssrf.xml", "billion_laughs.xml", "external_dtd.xml"]
)
def test_hostile_xml_is_refused_before_expansion(fixture: str) -> None:
    with pytest.raises(FeedError, match="unsafe XML construct"):
        parse_feed(load(fixture))


def test_xml_hardening_flags_are_all_enabled() -> None:
    # Regression guard: each flag is redundant with forbid_dtd today, so no fixture
    # would notice one being disabled. Pin the configuration explicitly.
    assert feeds.XML_HARDENING == {
        "forbid_dtd": True,
        "forbid_entities": True,
        "forbid_external": True,
    }


@pytest.mark.parametrize(
    "link",
    [
        "javascript://research.example.org/%0Aalert(1)",  # has a hostname: scheme check needed
        "JaVaScRiPt://example.org/%0dalert(1)",
        "ftp://files.example.org/x",
        "file://localhost/etc/passwd",
        "data://example.org/x",
        "//example.org/protocol-relative",
        "/relative/path",
        "https://",
        "",
    ],
)
def test_safe_link_rejects_non_http_or_hostless(link: str) -> None:
    assert feeds._safe_link(link) is None


def test_safe_link_keeps_http_and_https() -> None:
    assert feeds._safe_link(" https://a.example/x ") == "https://a.example/x"
    assert feeds._safe_link("http://a.example/") == "http://a.example/"


def test_oversized_feed_rejected_before_parsing() -> None:
    with pytest.raises(FeedError, match="limit"):
        parse_feed(b" " * (feeds.MAX_FEED_BYTES + 1))


@pytest.mark.parametrize(
    "data", [b"", b"<rss><channel>", b"not xml at all", b"\xff\xfe\x00garbage"]
)
def test_malformed_input_raises_feed_error(data: bytes) -> None:
    with pytest.raises(FeedError):
        parse_feed(data)


def test_unsupported_and_incomplete_roots() -> None:
    with pytest.raises(FeedError, match="unsupported"):
        parse_feed(b"<html><body>hi</body></html>")
    with pytest.raises(FeedError, match="channel"):
        parse_feed(b'<rss version="2.0"></rss>')


def test_item_cap_sets_truncated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(feeds, "MAX_ITEMS", 2)
    items = "".join(f"<item><title>t{i}</title></item>" for i in range(5))
    feed = parse_feed(f"<rss><channel><title>x</title>{items}</channel></rss>".encode())
    assert len(feed.items) == 2
    assert feed.truncated is True


def test_field_lengths_are_capped() -> None:
    long_title = "A" * 5000
    long_body = "word " * 5000
    xml = (
        f"<rss><channel><title>x</title><item><title>{long_title}</title>"
        f"<description>{long_body}</description></item></channel></rss>"
    )
    item = parse_feed(xml.encode()).items[0]
    assert len(item.title) <= feeds.MAX_TITLE_CHARS
    assert len(item.excerpt) <= feeds.MAX_EXCERPT_CHARS
    assert item.excerpt.endswith("…")


@pytest.mark.parametrize(
    ("html", "expected"),
    [
        ("<p>a</p><p>b</p>", "a b"),
        ("x<script>evil()</script>y", "xy"),
        ("<svg><text>hidden</text></svg>shown", "shown"),
        ("<img src=x onerror=alert(1)>caption", "caption"),
        ("&lt;script&gt; is text", "<script> is text"),  # escaped markup becomes inert text
        ("a&nbsp;&amp;&nbsp;b", "a & b"),
    ],
)
def test_html_to_text(html: str, expected: str) -> None:
    assert html_to_text(html, 100) == expected


# --------------------------------------------------------------------- per-source DOCTYPE opt-in


def test_xml_doctype_profile_still_forbids_entities_and_external_refs() -> None:
    assert feeds.XML_HARDENING_DOCTYPE_ALLOWED == {
        "forbid_dtd": False,
        "forbid_entities": True,
        "forbid_external": True,
    }


def test_bare_doctype_requires_the_opt_in() -> None:
    data = load("plain_doctype.xml")
    with pytest.raises(FeedError, match="DTDForbidden"):
        parse_feed(data)
    feed = parse_feed(data, allow_doctype=True)
    assert feed.title == "Doctype feed" and feed.items[0].url == "https://msrc.example/post"


@pytest.mark.parametrize(
    ("fixture", "match"),
    [
        ("xxe_file.xml", "bare"),  # internal subset declaring an external entity
        ("xxe_ssrf.xml", "bare"),
        ("billion_laughs.xml", "bare"),  # internal subset with entity expansion
        ("external_dtd.xml", "bare"),  # SYSTEM identifier
    ],
)
def test_opt_in_still_refuses_every_hostile_fixture(fixture: str, match: str) -> None:
    with pytest.raises(FeedError, match=match):
        parse_feed(load(fixture), allow_doctype=True)


@pytest.mark.parametrize(
    "doctype",
    [
        b'<!DOCTYPE rss PUBLIC "-//x//DTD x//EN" "http://attacker.example/x.dtd">',
        b"<!DOCTYPE rss [ ]>",
        b"<!doctype rss SYSTEM 'file:///etc/passwd'>",
    ],
)
def test_opt_in_rejects_non_bare_doctypes(doctype: bytes) -> None:
    data = b'<?xml version="1.0"?>' + doctype + b"<rss><channel><title>x</title></channel></rss>"
    with pytest.raises(FeedError, match="bare"):
        parse_feed(data, allow_doctype=True)


def test_entity_layer_alone_blocks_xxe_if_doctype_check_were_bypassed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Defence in depth: even with the bare-DOCTYPE pre-check disabled, the parser profile
    # itself must still refuse entity-based attacks.
    import re

    monkeypatch.setattr(feeds, "_BARE_DOCTYPE", re.compile(rb".*", re.DOTALL))
    for fixture in ["xxe_file.xml", "xxe_ssrf.xml", "billion_laughs.xml"]:
        with pytest.raises(FeedError, match="EntitiesForbidden"):
            parse_feed(load(fixture), allow_doctype=True)


def test_per_call_size_limit() -> None:
    data = load("rss_ok.xml")
    with pytest.raises(FeedError, match="limit"):
        parse_feed(data, max_bytes=100)
    assert parse_feed(data, max_bytes=len(data)).items
