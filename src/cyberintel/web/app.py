"""Dashboard web application (Starlette, server-rendered, zero JavaScript).

Security posture (THREAT_MODEL T9, T13, T14):
* **No JavaScript at all.** CSP is ``default-src 'none'`` with only same-origin styles,
  forms and images. An escaping bug would have no script context to run in.
* **Host allowlist** (TrustedHostMiddleware) defeats DNS-rebinding attacks against a
  service on a private network.
* **Authentication on every page** except /login, /healthz and /static. Sessions are
  HMAC-signed, expiring cookies (``__Host-`` prefix, HttpOnly, Secure, SameSite=Strict).
* **POSTs are same-origin only** (Sec-Fetch-Site / Origin check) on top of SameSite.
  The app has exactly two POST routes: login and logout. Everything else is read-only.
* **Client identity never comes from X-Forwarded-For.** A header anyone can set is not an
  identity (the GPUStack loopback-trust lesson).
* Generic error pages (no stack traces); ``Cache-Control: no-store`` on every HTML page.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

from jinja2 import Environment
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from cyberintel.web.auth import AuthConfig, LoginThrottle
from cyberintel.web.reader import ReaderLike, merge_health
from cyberintel.web.views import (
    CVE_PATH,
    PAGE_SIZE,
    SLUG_PATH,
    BadQueryError,
    NewsQuery,
    StoryQuery,
    VulnQuery,
    build_env,
    parse_query,
    render,
)

STATIC = Path(__file__).parent / "static"
MAX_LOGIN_BODY = 4096
CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; "
    "frame-ancestors 'none'; base-uri 'none'"
)
SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
)


class SecurityHeadersMiddleware:
    """Adds security headers to every HTTP response (pure ASGI, so nothing can skip it)."""

    def __init__(self, app: ASGIApp, *, hsts: bool = False) -> None:
        self.app = app
        self.extra: tuple[tuple[bytes, bytes], ...] = (
            ((b"strict-transport-security", b"max-age=31536000"),) if hsts else ()
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [
                    h
                    for h in message.get("headers", [])
                    if h[0].lower() not in {k for k, _ in SECURITY_HEADERS}
                ]
                headers += [*SECURITY_HEADERS, *self.extra]
                if not scope["path"].startswith("/static/"):
                    headers.append((b"cache-control", b"no-store"))
                headers = [h for h in headers if h[0].lower() != b"server"]
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


def same_origin(request: Request) -> bool:
    """True only for requests the browser marks as same-origin (CSRF defence for POSTs)."""
    site = request.headers.get("sec-fetch-site")
    if site is not None:
        return site in {"same-origin", "none"}
    origin = request.headers.get("origin")
    return origin is not None and urlsplit(origin).netloc == request.headers.get("host", "")


def _pager(base: str, query: Any, total: int, keep: Mapping[str, Any]) -> dict[str, Any]:
    pages = max(1, -(-total // PAGE_SIZE))

    def url(page: int) -> str:
        params = {k: v for k, v in keep.items() if v not in (None, False, "", 0)}
        params = {k: ("1" if v is True else v) for k, v in params.items()}
        if page > 1:
            params["page"] = page
        return base + ("?" + urlencode(params) if params else "")

    return {
        "page": query.page,
        "pages": pages,
        "total": total,
        "prev": url(query.page - 1) if query.page > 1 else None,
        "next": url(query.page + 1) if query.page < pages else None,
    }


def create_app(
    reader: ReaderLike,
    auth: AuthConfig,
    *,
    sources: Sequence[Mapping[str, str]] = (),
    allowed_hosts: Iterable[str] = ("localhost", "127.0.0.1"),
    throttle: LoginThrottle | None = None,
    secure_cookies: bool = True,
    hsts: bool = False,
) -> Starlette:
    env: Environment = build_env()
    throttle = throttle or LoginThrottle()
    cookie = "__Host-cit_session" if secure_cookies else "cit_session"
    tiers = {s["name"]: s["tier"] for s in sources}
    feed_sources = [(s["name"], s["tier"]) for s in sources if s["kind"] == "feed"]

    def page(request: Request, template: str, status: int = 200, **ctx: Any) -> HTMLResponse:
        authed = auth.signer.verify(request.cookies.get(cookie))
        html = render(env, template, authenticated=authed, nav=ctx.pop("nav", ""), **ctx)
        return HTMLResponse(html, status_code=status)

    def login_required(
        fn: Callable[[Request], Response],
    ) -> Callable[[Request], Awaitable[Response]]:
        async def wrapper(request: Request) -> Response:
            if not auth.signer.verify(request.cookies.get(cookie)):
                return RedirectResponse("/login", status_code=303)
            try:
                return await run_in_threadpool(fn, request)
            except BadQueryError as exc:
                return page(request, "error.html", 400, heading="400 Bad request", message=str(exc))

        return wrapper

    # ---------------------------------------------------------------- pages

    @login_required
    def home(request: Request) -> Response:
        top, _ = reader.list_vulns(VulnQuery())
        stories, _ = reader.list_stories(StoryQuery())
        news, _ = reader.list_news(NewsQuery())
        return page(
            request,
            "dashboard.html",
            nav="home",
            summary=reader.summary(),
            top=top[:10],
            stories=stories[:8],
            news=news[:8],
        )

    @login_required
    def vulns(request: Request) -> Response:
        query = parse_query(VulnQuery, request.query_params)
        rows, total = reader.list_vulns(query)
        keep = {
            "q": query.q,
            "sort": None if query.sort == "priority" else query.sort,
            "kev": query.kev,
            "exploited": query.exploited,
            "min_priority": query.min_priority,
        }
        return page(
            request,
            "vulns.html",
            nav="vulns",
            query=query,
            rows=rows,
            pager=_pager("/vulns", query, total, keep),
        )

    @login_required
    def vuln(request: Request) -> Response:
        cve = str(request.path_params["cve_id"]).upper()
        if not CVE_PATH.match(cve):
            raise HTTPException(404)
        detail = reader.vuln_detail(cve)
        if detail is None:
            raise HTTPException(404)
        return page(request, "vuln.html", nav="vulns", **detail)

    @login_required
    def stories(request: Request) -> Response:
        query = parse_query(StoryQuery, request.query_params)
        rows, total = reader.list_stories(query)
        return page(
            request,
            "stories.html",
            nav="stories",
            query=query,
            rows=rows,
            pager=_pager("/stories", query, total, {"q": query.q, "rollups": query.rollups}),
        )

    @login_required
    def story(request: Request) -> Response:
        slug = str(request.path_params["slug"])
        if not SLUG_PATH.match(slug):
            raise HTTPException(404)
        detail = reader.story_detail(slug)
        if detail is None:
            raise HTTPException(404)
        return page(request, "story.html", nav="stories", **detail)

    @login_required
    def news(request: Request) -> Response:
        query = parse_query(NewsQuery, request.query_params)
        rows, total = reader.list_news(query)
        return page(
            request,
            "news.html",
            nav="news",
            query=query,
            rows=rows,
            tiers=tiers,
            sources=feed_sources,
            pager=_pager("/news", query, total, {"q": query.q, "source": query.source}),
        )

    @login_required
    def source_page(request: Request) -> Response:
        rows = merge_health(list(sources), reader.source_health())
        return page(request, "sources.html", nav="sources", rows=rows)

    # ---------------------------------------------------------------- auth

    async def login_form(request: Request) -> Response:
        if auth.signer.verify(request.cookies.get(cookie)):
            return RedirectResponse("/", status_code=303)
        return page(request, "login.html", error=None)

    async def login(request: Request) -> Response:
        if not same_origin(request):
            return PlainTextResponse("cross-site request refused", status_code=403)
        if request.headers.get("content-type", "").split(";")[0].strip() != (
            "application/x-www-form-urlencoded"
        ):
            return PlainTextResponse("unsupported content type", status_code=415)
        client = request.client.host if request.client else "unknown"  # never X-Forwarded-For
        if not throttle.allowed(client):
            return page(
                request,
                "login.html",
                429,
                error="Too many attempts. Wait 15 minutes and try again.",
            )
        body = bytearray()
        async for chunk in request.stream():
            body += chunk
            if len(body) > MAX_LOGIN_BODY:
                return PlainTextResponse("request too large", status_code=413)
        try:
            fields = dict(parse_qsl(body.decode("utf-8", errors="replace"), max_num_fields=5))
        except ValueError:
            return PlainTextResponse("malformed form", status_code=400)
        if await run_in_threadpool(auth.password.verify, fields.get("password", "")):
            throttle.record_success(client)
            response = RedirectResponse("/", status_code=303)
            response.set_cookie(
                cookie,
                auth.signer.issue(),
                httponly=True,
                secure=secure_cookies,
                samesite="strict",
                path="/",
            )
            return response
        throttle.record_failure(client)
        return page(request, "login.html", 401, error="Wrong password.")

    async def logout(request: Request) -> Response:
        if not same_origin(request):
            return PlainTextResponse("cross-site request refused", status_code=403)
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(
            cookie, path="/", secure=secure_cookies, httponly=True, samesite="strict"
        )
        return response

    async def healthz(request: Request) -> Response:
        return PlainTextResponse("ok")

    # ---------------------------------------------------------------- errors

    async def http_error(request: Request, exc: Exception) -> Response:
        code = exc.status_code if isinstance(exc, HTTPException) else 500
        messages = {404: "Not found.", 405: "Method not allowed.", 500: "Something went wrong."}
        return page(
            request,
            "error.html",
            code,
            heading=str(code),
            message=messages.get(code, "Request failed."),
        )

    routes = [
        Route("/", home),
        Route("/vulns", vulns),
        Route("/vulns/{cve_id}", vuln),
        Route("/stories", stories),
        Route("/stories/{slug}", story),
        Route("/news", news),
        Route("/sources", source_page),
        Route("/login", login_form, methods=["GET"]),
        Route("/login", login, methods=["POST"]),
        Route("/logout", logout, methods=["POST"]),
        Route("/healthz", healthz),
        Mount("/static", StaticFiles(directory=STATIC), name="static"),
    ]
    return Starlette(
        debug=False,
        routes=routes,
        middleware=[
            Middleware(SecurityHeadersMiddleware, hsts=hsts),
            Middleware(TrustedHostMiddleware, allowed_hosts=list(allowed_hosts)),
        ],
        exception_handlers={HTTPException: http_error, Exception: http_error},
    )
