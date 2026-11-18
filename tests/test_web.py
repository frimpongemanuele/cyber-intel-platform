"""Dashboard web app: auth, CSRF, headers, routing, and escaping of hostile data.

Driven through the local ASGI driver (tests/asgi.py); the reader is an in-memory fake that
returns deliberately hostile content, as a compromised feed or poisoned record would.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from html.parser import HTMLParser
from typing import Any, ClassVar

import pytest

pytest.importorskip("starlette")
pytest.importorskip("jinja2")
from asgi import Resp, request

from cyberintel.web.app import create_app
from cyberintel.web.auth import (
    MIN_SCRYPT_N,
    AuthConfig,
    LoginThrottle,
    PasswordHash,
    SessionSigner,
    hash_password,
)
from cyberintel.web.views import NewsQuery, StoryQuery, VulnQuery

PASSWORD = "correct horse battery staple"
XSS = '<script>alert("x")</script>'
ATTR = '"><img src=x onerror=alert(1)>'
JS_URL = "javascript:alert(document.cookie)"
COOKIE = "__Host-cit_session"
SAME = {"sec-fetch-site": "same-origin", "content-type": "application/x-www-form-urlencoded"}


def vuln_row(cve: str = "CVE-2026-123158", **kw: Any) -> dict[str, Any]:
    return {
        "cve_id": cve,
        "title": f"Title {XSS}",
        "summary": "s",
        "priority": 87.5,
        "p_exploitation": 40,
        "p_epss": 18.9,
        "p_severity": 16.2,
        "p_ransomware": 0,
        "p_recency": 10,
        "in_kev": True,
        "kev_date_added": date(2026, 11, 9),
        "kev_due_date": None,
        "ransomware_known": False,
        "epss": 0.9,
        "epss_percentile": 0.94,
        "headline_score": 8.1,
        "headline_version": "3.1",
        "headline_origin": "nvd",
        "headline_provider": "nvd@nist.gov",
        "ssvc_exploitation": "active",
        "nvd_status": "Analyzed",
        "kev_vendor": ATTR,
        "kev_product": "OpenSSH",
        "published_at": datetime(2026, 11, 5, tzinfo=UTC),
        **kw,
    }


class FakeReader:
    def __init__(self) -> None:
        self.queries: list[Any] = []

    def summary(self) -> dict[str, Any]:
        return {
            "kev_active": 1500,
            "kev_new_7d": 4,
            "ssvc_active": 12,
            "docs_24h": 31,
            "stories_7d": 6,
            "sources_failing": 1,
            "last_ingest": datetime(2026, 11, 18, 6, tzinfo=UTC),
        }

    def list_vulns(self, query: VulnQuery) -> tuple[list[dict[str, Any]], int]:
        self.queries.append(query)
        return [vuln_row(), vuln_row("CVE-2026-1", headline_score=None, in_kev=False)], 120

    def vuln_detail(self, cve_id: str) -> dict[str, Any] | None:
        if cve_id != "CVE-2026-123158":
            return None
        return {
            "v": vuln_row(),
            "record": {
                "description": f"desc {XSS}",
                "cwes": ["CWE-394"],
                "assigner": ATTR,
                "record_state": "PUBLISHED",
                "published_at": None,
                "updated_at": None,
                "ssvc_exploitation": "active",
                "ssvc_automatable": "yes",
                "ssvc_technical_impact": "total",
                "ssvc_timestamp": None,
                "adp_kev_date": None,
                "nvd_status": "Deferred",
                "nvd_last_modified": None,
                "nvd_has_cpe": False,
            },
            "kev": {
                "vendor": "OpenBSD",
                "product": "OpenSSH",
                "name": XSS,
                "date_added": date(2026, 11, 9),
                "due_date": date(2026, 11, 30),
                "ransomware_known": False,
                "short_description": "d",
                "required_action": "a",
                "notes": "",
                "catalog_version": "v",
                "removed_at": None,
            },
            "scores": [
                {
                    "collected_from": "nvd",
                    "version": "3.1",
                    "origin": "nvd",
                    "provider": "nvd@nist.gov",
                    "base_score": 8.1,
                    "vector": XSS,
                    "severity": "HIGH",
                }
            ],
            "products": [{"vendor": ATTR, "product": "p"}],
            "references": [{"url": JS_URL}, {"url": "https://www.openssh.com/r.html"}],
            "documents": [
                {"id": 1, "source_name": "src", "title": XSS, "url": JS_URL, "published_at": None}
            ],
            "stories": [
                {
                    "slug": "2026-11-10-x",
                    "title": XSS,
                    "first_seen": date(2026, 11, 10),
                    "last_seen": date(2026, 11, 12),
                    "is_rollup": False,
                }
            ],
        }

    def list_stories(self, query: StoryQuery) -> tuple[list[dict[str, Any]], int]:
        self.queries.append(query)
        return [
            {
                "slug": "2026-11-10-x",
                "title": XSS,
                "first_seen": date(2026, 11, 10),
                "last_seen": date(2026, 11, 18),
                "status": "CONFIRMED",
                "confidence": "HIGH",
                "is_rollup": False,
                "sightings": 4,
                "max_urgency": 5,
                "cves": 9,
            }
        ], 1

    def story_detail(self, slug: str) -> dict[str, Any] | None:
        if slug != "2026-11-10-x":
            return None
        return {
            "s": {
                "id": 1,
                "slug": slug,
                "title": XSS,
                "first_seen": date(2026, 11, 10),
                "last_seen": date(2026, 11, 18),
                "status": "CONFIRMED",
                "confidence": "HIGH",
                "is_rollup": False,
            },
            "sightings": [
                {"origin": "archive", "external_id": ATTR, "day": date(2026, 11, 10), "urgency": 5}
            ],
            "cves": [
                {
                    "cve_id": "CVE-2026-123158",
                    "title": None,
                    "priority": 87.5,
                    "in_kev": True,
                    "headline_score": 8.1,
                }
            ],
            "links": [
                {
                    "direction": "in",
                    "kind": "rollup_of",
                    "method": "cve",
                    "slug": "2026-11-11-r",
                    "title": XSS,
                }
            ],
        }

    def list_news(self, query: NewsQuery) -> tuple[list[dict[str, Any]], int]:
        self.queries.append(query)
        return [
            {
                "id": 1,
                "source_name": "unit42",
                "title": XSS,
                "url": JS_URL,
                "excerpt": f"excerpt {ATTR}",
                "published_at": None,
                "first_seen_at": datetime(2026, 11, 18, tzinfo=UTC),
                "cves": ["CVE-2026-123158"],
            }
        ], 1

    def source_health(self) -> list[dict[str, Any]]:
        return [
            {
                "source_name": "first-epss",
                "last_success_at": None,
                "last_attempt_at": None,
                "consecutive_failures": 2,
                "last_error": XSS,
                "outcome": "error",
                "finished_at": None,
                "records_ok": None,
                "records_rejected": None,
                "http_status": 503,
            }
        ]


@pytest.fixture(scope="module")
def auth() -> AuthConfig:
    return AuthConfig(
        PasswordHash.parse(hash_password(PASSWORD, n=MIN_SCRYPT_N)), SessionSigner(bytes(range(32)))
    )


SOURCES = [
    {"name": "unit42", "kind": "feed", "tier": "primary"},
    {"name": "first-epss", "kind": "epss", "tier": "primary"},
    {"name": "cisa-kev", "kind": "kev", "tier": "primary"},
]


@pytest.fixture
def reader() -> FakeReader:
    return FakeReader()


@pytest.fixture
def app(reader: FakeReader, auth: AuthConfig) -> Any:
    return create_app(reader, auth, sources=SOURCES, throttle=LoginThrottle(per_client=3))


@pytest.fixture
def session(auth: AuthConfig) -> dict[str, str]:
    return {"cookie": f"{COOKIE}={auth.signer.issue()}"}


def login(
    app: Any,
    password: str = PASSWORD,
    headers: dict[str, str] | None = None,
    client: str = "10.0.0.5",
) -> Resp:
    return request(
        app,
        "POST",
        "/login",
        headers=headers if headers is not None else SAME,
        body=f"password={password}".encode(),
        client=client,
    )


# --------------------------------------------------------------------------- access control


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/vulns",
        "/vulns/CVE-2026-123158",
        "/stories",
        "/stories/2026-11-10-x",
        "/news",
        "/sources",
    ],
)
def test_every_page_requires_login(app: Any, path: str) -> None:
    r = request(app, "GET", path)
    assert r.status == 303 and r.header("location") == "/login"


def test_public_endpoints(app: Any) -> None:
    assert request(app, "GET", "/login").status == 200
    assert request(app, "GET", "/healthz").text == "ok"
    css = request(app, "GET", "/static/style.css")
    assert css.status == 200 and css.header("cache-control") is None  # static may be cached


@pytest.mark.parametrize("cookie", ["garbage", "a.b", ""])
def test_forged_session_cookies_are_rejected(app: Any, cookie: str) -> None:
    assert request(app, "GET", "/", headers={"cookie": f"{COOKIE}={cookie}"}).status == 303


def test_login_success_sets_hardened_cookie(app: Any) -> None:
    r = login(app)
    assert r.status == 303 and r.header("location") == "/"
    raw = r.header("set-cookie") or ""
    assert raw.startswith(f"{COOKIE}=")
    for flag in ("HttpOnly", "Secure", "SameSite=strict", "Path=/"):
        assert flag.lower() in raw.lower(), flag
    assert "domain" not in raw.lower()  # __Host- prefix requires no Domain
    assert (
        request(app, "GET", "/", headers={"cookie": f"{COOKIE}={r.cookie(COOKIE)}"}).status == 200
    )


def test_wrong_password_and_throttling(
    app: Any, auth: AuthConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    for _ in range(3):
        assert login(app, "wrong").status == 401
    calls = []
    monkeypatch.setattr(PasswordHash, "verify", lambda self, pw: calls.append(pw) or True)
    r = login(app, PASSWORD)  # even the right password: throttled first
    assert r.status == 429 and calls == []  # password never checked while throttled
    assert login(app, PASSWORD, client="10.0.0.9").status == 303  # other client unaffected


@pytest.mark.parametrize(
    ("headers", "status"),
    [
        ({"content-type": "application/x-www-form-urlencoded"}, 403),  # no origin info at all
        ({**SAME, "sec-fetch-site": "cross-site"}, 403),
        (
            {"content-type": "application/x-www-form-urlencoded", "origin": "https://evil.example"},
            403,
        ),
        ({"sec-fetch-site": "same-origin", "content-type": "application/json"}, 415),
    ],
)
def test_login_csrf_and_content_type(app: Any, headers: dict[str, str], status: int) -> None:
    assert login(app, headers=headers).status == status


def test_login_origin_fallback_for_browsers_without_fetch_metadata(app: Any) -> None:
    headers = {"content-type": "application/x-www-form-urlencoded", "origin": "https://localhost"}
    assert login(app, headers=headers).status == 303


def test_login_body_limit(app: Any) -> None:
    big = request(app, "POST", "/login", headers=SAME, body=b"password=" + b"a" * 5000)
    assert big.status == 413


def test_logout_requires_same_origin_and_clears_cookie(app: Any, session: dict[str, str]) -> None:
    assert request(app, "POST", "/logout", headers=session).status == 403
    r = request(app, "POST", "/logout", headers={**session, "sec-fetch-site": "same-origin"})
    assert r.status == 303 and "Max-Age=0" in (r.header("set-cookie") or "")


def test_untrusted_host_header_is_refused(app: Any) -> None:
    # DNS rebinding: attacker.example resolving to the dashboard's IP.
    assert request(app, "GET", "/healthz", headers={"host": "attacker.example"}).status == 400


def test_only_get_on_pages(app: Any, session: dict[str, str]) -> None:
    assert request(app, "POST", "/vulns", headers={**session, **SAME}).status == 405


# --------------------------------------------------------------------------- headers


@pytest.mark.parametrize("path", ["/login", "/healthz", "/nope", "/"])
def test_security_headers_on_every_response(app: Any, path: str) -> None:
    r = request(app, "GET", path)
    csp = r.header("content-security-policy") or ""
    assert "default-src 'none'" in csp and "script-src" not in csp  # no script allowed at all
    assert "frame-ancestors 'none'" in csp
    assert r.header("x-content-type-options") == "nosniff"
    assert r.header("referrer-policy") == "no-referrer"
    assert r.header("x-frame-options") == "DENY"
    assert r.header("cache-control") == "no-store"
    assert r.header("strict-transport-security") is None  # opt-in only (needs TLS in front)


def test_hsts_opt_in(reader: FakeReader, auth: AuthConfig) -> None:
    app = create_app(reader, auth, hsts=True)
    assert "max-age" in (request(app, "GET", "/healthz").header("strict-transport-security") or "")


# --------------------------------------------------------------------------- pages + escaping


class _Structure(HTMLParser):
    """Collects what XSS actually needs: dangerous elements, handlers, and URL schemes."""

    DANGEROUS_TAGS: ClassVar[frozenset[str]] = frozenset(
        {"script", "img", "iframe", "object", "embed", "svg", "math", "base"}
    )
    URL_ATTRS: ClassVar[frozenset[str]] = frozenset(
        {"href", "src", "action", "formaction", "xlink:href"}
    )

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.problems: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self.DANGEROUS_TAGS:
            self.problems.append(f"<{tag}> element")
        for name, value in attrs:
            if name.startswith("on"):
                self.problems.append(f"{name}= handler on <{tag}>")
            if name in self.URL_ATTRS and value:
                scheme = value.strip().split(":", 1)[0].lower() if ":" in value else ""
                if scheme in {"javascript", "data", "vbscript"}:
                    self.problems.append(f"{scheme}: URL in {name} on <{tag}>")


def structural_problems(html: str) -> list[str]:
    parser = _Structure()
    parser.feed(html)
    return parser.problems


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/vulns",
        "/vulns/CVE-2026-123158",
        "/vulns/cve-2026-123158",
        "/stories",
        "/stories/2026-11-10-x",
        "/news",
        "/sources",
    ],
)
def test_pages_render_and_escape_hostile_data(app: Any, session: dict[str, str], path: str) -> None:
    r = request(app, "GET", path, headers=session)
    assert r.status == 200, r.text[:300]
    assert structural_problems(r.text) == []


def test_structure_check_detects_real_injection() -> None:
    # Guard the guard: the checker must flag each thing it claims to catch.
    assert structural_problems("<p>ok</p>") == []
    bad = (
        '<script>x</script><img src=x onerror=y><a href="javascript:1">a</a>'
        '<a href=" DATA:text/html,x">b</a><form action="javascript:2"></form>'
    )
    assert structural_problems(bad) == [
        "<script> element",
        "<img> element",
        "onerror= handler on <img>",
        "javascript: URL in href on <a>",
        "data: URL in href on <a>",
        "javascript: URL in action on <form>",
    ]


def test_hostile_values_are_visible_as_text_not_markup(app: Any, session: dict[str, str]) -> None:
    html = request(app, "GET", "/vulns/CVE-2026-123158", headers=session).text
    assert "&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;" in html
    assert "&#34;&gt;&lt;img src=x onerror=alert(1)&gt;" in html
    assert 'href="#"' in html  # the javascript: reference was neutralised
    assert 'href="https://www.openssh.com/r.html"' in html
    assert "Not Scheduled" in html  # NVD Deferred explained
    assert "CNA (vendor)" in html or "NVD" in html  # provenance shown


def test_detail_404s(app: Any, session: dict[str, str]) -> None:
    for path in [
        "/vulns/CVE-2026-999",
        "/vulns/CVE-1-1",
        "/vulns/..%2F..%2Fetc",
        "/stories/NOPE",
        "/stories/unknown-story",
        "/missing",
    ]:
        assert request(app, "GET", path, headers=session).status == 404, path


@pytest.mark.parametrize(
    "query",
    [
        "sort=evil",
        "sort=priority;DROP TABLE x",
        "page=0",
        "page=1001",
        "min_priority=999",
        "q=" + "a" * 101,
        "source=Bad%20Name",
    ],
)
def test_invalid_query_parameters_are_400(app: Any, session: dict[str, str], query: str) -> None:
    path = "/news" if query.startswith("source") else "/vulns"
    r = request(app, "GET", f"{path}?{query}", headers=session)
    assert r.status == 400 and "<script" not in r.text


def test_filters_reach_the_reader_validated(
    app: Any, reader: FakeReader, session: dict[str, str]
) -> None:
    request(
        app,
        "GET",
        "/vulns?q=%20fortinet%20%20gate%20&sort=epss&kev=1&min_priority=40&page=2",
        headers=session,
    )
    q = reader.queries[-1]
    assert (q.q, q.sort, q.kev, q.exploited, q.min_priority, q.page) == (
        "fortinet gate",
        "epss",
        True,
        False,
        40,
        2,
    )


def test_pager_links_preserve_filters(app: Any, session: dict[str, str]) -> None:
    html = request(app, "GET", "/vulns?kev=1&sort=cvss", headers=session).text
    assert 'href="/vulns?sort=cvss&amp;kev=1&amp;page=2"' in html  # 120 results, 50 per page
