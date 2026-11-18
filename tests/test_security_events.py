"""Security events: format, sanitisation, secret-safety, and every emission point."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from cyberintel.security_events import EVENTS, LOGGER_NAME, MAX_STR, build, emit


class Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())

    @property
    def events(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.lines]

    def names(self) -> list[str]:
        return [e["cit_event"] for e in self.events]


@pytest.fixture
def captured() -> Iterator[Capture]:
    emit("source.failed", source="warmup")  # configure the logger once
    cap = Capture()
    log = logging.getLogger(LOGGER_NAME)
    log.addHandler(cap)
    try:
        yield cap
    finally:
        log.removeHandler(cap)


# ----------------------------------------------------------------------------- format


def test_line_format(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CIT_SERVICE", "web")
    line = build(
        "auth.login_failed",
        {"client": "10.0.0.5"},
        now=datetime(2026, 11, 18, 19, 52, 1, 123456, tzinfo=UTC),
    )
    assert json.loads(line) == {
        "cit_event": "auth.login_failed",
        "severity": "medium",
        "service": "web",
        "ts": "2026-11-18T19:52:01.123Z",
        "client": "10.0.0.5",
    }
    assert "\n" not in line


@pytest.mark.parametrize(
    "hostile",
    [
        'evil"}\n{"cit_event":"auth.login_succeeded","client":"x',  # forge a second event
        "line1\r\nline2",
        "a" + chr(0x202E) + "txt.exe",  # bidi override (display spoofing)
        "zero" + chr(0x200B) + "width",
        "esc" + chr(0x1B) + "[31m",
        "nul" + chr(0),
    ],
)
def test_attacker_values_cannot_forge_or_spoof_lines(hostile: str) -> None:
    line = build("web.host_rejected", {"host": hostile, "client": "c"})
    assert line.count("\n") == 0 and "\r" not in line
    record = json.loads(line)
    assert record["cit_event"] == "web.host_rejected"
    assert not any(ord(ch) < 32 or ch in (chr(0x202E), chr(0x200B)) for ch in record["host"])


def test_values_are_capped() -> None:
    record = json.loads(build("fetch.url_rejected", {"source": "s", "reason": "x" * 5000}))
    assert len(record["reason"]) == MAX_STR
    record = json.loads(build("ai.output_rejected", {"reasons": [str(i) for i in range(50)]}))
    assert len(record["reasons"]) == 5


@pytest.mark.parametrize(
    "field",
    ["password", "api_key", "session_cookie", "token", "authorization", "dsn", "secret"],
)
def test_secret_like_fields_are_refused(field: str) -> None:
    with pytest.raises(ValueError, match="secret"):
        build("auth.login_failed", {field: "x"})


@pytest.mark.parametrize("field", ["cit_event", "severity", "ts", "service"])
def test_reserved_fields_cannot_be_overridden(field: str) -> None:
    with pytest.raises(ValueError, match="reserved"):
        build("auth.login_failed", {field: "critical"})


def test_unknown_events_and_bad_names_refused() -> None:
    with pytest.raises(ValueError, match="unknown"):
        build("auth.everything_fine", {})
    with pytest.raises(ValueError, match="bad field"):
        build("auth.login_failed", {"Client-IP": "x"})


def test_every_event_has_a_severity() -> None:
    assert set(EVENTS.values()) <= {"low", "medium", "high", "critical"}


def test_file_output(tmp_path: Any) -> None:
    import os
    import subprocess
    import sys

    path = tmp_path / "security.json"
    code = "from cyberintel.security_events import emit; emit('auth.login_failed', client='c')"
    src = str(Path(__file__).resolve().parents[1] / "src")
    env = {**os.environ, "CIT_SECURITY_LOG": str(path), "CIT_SERVICE": "web", "PYTHONPATH": src}
    subprocess.run([sys.executable, "-c", code], env=env, check=True, capture_output=True)
    record = json.loads(path.read_text().strip())
    assert record["cit_event"] == "auth.login_failed" and record["service"] == "web"


# ----------------------------------------------------------------------------- web

starlette = pytest.importorskip("starlette")
pytest.importorskip("jinja2")
from asgi import request  # noqa: E402
from test_web import PASSWORD, SOURCES, FakeReader  # noqa: E402

from cyberintel.web.app import create_app  # noqa: E402
from cyberintel.web.auth import (  # noqa: E402
    MIN_SCRYPT_N,
    AuthConfig,
    LoginThrottle,
    PasswordHash,
    SessionSigner,
    hash_password,
)

FORM = {"content-type": "application/x-www-form-urlencoded", "sec-fetch-site": "same-origin"}
WRONG = "wrong-guess-123"  # a deliberately wrong dashboard password, not a credential


def login_body(value: str) -> bytes:
    from urllib.parse import urlencode

    return urlencode({"password": value}).encode()


@pytest.fixture(scope="module")
def web_auth() -> AuthConfig:
    return AuthConfig(
        PasswordHash.parse(hash_password(PASSWORD, n=MIN_SCRYPT_N)), SessionSigner(bytes(32))
    )


@pytest.fixture
def web(web_auth: AuthConfig) -> Any:
    return create_app(FakeReader(), web_auth, sources=SOURCES, throttle=LoginThrottle(per_client=2))


def test_login_events_and_no_password_in_logs(web: Any, captured: Capture) -> None:
    bad = request(web, "POST", "/login", headers=FORM, body=login_body(WRONG))
    assert bad.status == 401
    ok = request(web, "POST", "/login", headers=FORM, body=login_body(PASSWORD))
    assert ok.status == 303
    assert captured.names() == ["auth.login_failed", "auth.login_succeeded"]
    joined = "\n".join(captured.lines)
    assert WRONG not in joined and PASSWORD not in joined


def test_throttle_event(web: Any, captured: Capture) -> None:
    for _ in range(3):
        request(web, "POST", "/login", headers=FORM, body=login_body("nope"))
    assert captured.names() == ["auth.login_failed", "auth.login_failed", "auth.login_throttled"]
    assert captured.events[-1]["severity"] == "high"


def test_csrf_event(web: Any, captured: Capture) -> None:
    headers = {**FORM, "sec-fetch-site": "cross-site"}
    assert request(web, "POST", "/login", headers=headers, body=login_body("x")).status == 403
    assert captured.events == [
        {**captured.events[0], "cit_event": "web.csrf_refused", "path": "/login"}
    ]


def test_forged_session_cookie_event(web: Any, captured: Capture) -> None:
    r = request(web, "GET", "/vulns", headers={"cookie": "__Host-cit_session=forged.value"})
    assert r.status == 303
    assert captured.names() == ["auth.session_rejected"]
    assert "forged.value" not in captured.lines[0]  # the cookie itself is never logged


def test_no_event_without_a_cookie(web: Any, captured: Capture) -> None:
    request(web, "GET", "/vulns")
    assert captured.names() == []


def test_host_rejected_event_is_sanitised(web: Any, captured: Capture) -> None:
    r = request(web, "GET", "/healthz", headers={"host": "rebind.attacker.example"})
    assert r.status == 400
    assert captured.names() == ["web.host_rejected"]
    assert captured.events[0]["host"] == "rebind.attacker.example"
    request(web, "GET", "/healthz", headers={"host": "localhost"})
    assert len(captured.lines) == 1  # allowed hosts are not logged


# ----------------------------------------------------------------------------- ingest


def test_ingest_events(captured: Capture) -> None:
    from test_ingest import FIX, KEV, Fetch, MemStore, clock

    from cyberintel.ingest import run_source
    from cyberintel.net.types import FetchHTTPError, FetchRejectedError

    # KEV fixture has 4 malformed rows -> quarantined
    run_source(KEV, Fetch({KEV.url: (FIX / "kev" / "kev_sample.json").read_bytes()}), MemStore(),
               clock=clock)  # fmt: skip
    assert captured.names() == ["feed.records_quarantined"]
    assert captured.events[0]["count"] == 4
    captured.lines.clear()

    # SSRF guard refusal: a redirect to a metadata address
    rejected = FetchRejectedError("redirect to http://169.254.169.254/latest refused\nFAKE")
    run_source(KEV, Fetch({KEV.url: rejected}), MemStore(), clock=clock, force=True)
    assert captured.names() == ["fetch.url_rejected", "source.failed"]
    assert "169.254.169.254" in captured.events[0]["reason"]
    assert "\n" not in captured.lines[0] and captured.events[0]["severity"] == "high"
    captured.lines.clear()

    run_source(KEV, Fetch({KEV.url: FetchHTTPError(KEV.url, 503)}), MemStore(), clock=clock)
    assert captured.names() == ["source.failed"]
    assert captured.events[0]["http_status"] == 503
    assert captured.events[0]["error_type"] == "FetchHTTPError"


# ----------------------------------------------------------------------------- AI


def test_ai_events(captured: Capture) -> None:
    from test_ai_runner import NOW, FakeRepo, ScriptedProvider

    from cyberintel.ai.runner import run

    run(FakeRepo(1), ScriptedProvider("not json"), now=NOW)
    assert captured.names() == ["ai.output_rejected"]
    event = captured.events[0]
    assert event["story"] == "story-1" and event["reasons"]
    captured.lines.clear()
    run(FakeRepo(3), ScriptedProvider(), now=NOW, daily_token_cap=500)
    assert "ai.token_cap_reached" in captured.names()


def test_ai_injection_and_provider_events(captured: Capture) -> None:
    from aihelpers import good_output
    from test_ai_runner import NOW, FakeRepo, ScriptedProvider

    from cyberintel.ai.providers import ProviderError
    from cyberintel.ai.runner import run

    flagged = json.dumps(good_output(injection_suspected=True))
    run(FakeRepo(1), ScriptedProvider(flagged), now=NOW)
    assert captured.names() == ["ai.injection_suspected"]
    captured.lines.clear()
    run(FakeRepo(5), ScriptedProvider(*(ProviderError("x") for _ in range(5))), now=NOW)
    assert captured.names() == ["ai.provider_failing"]
    assert captured.events[0]["errors"] == 3
