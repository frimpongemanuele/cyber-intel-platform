from __future__ import annotations

import json
import threading
from collections.abc import Iterator, Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar

import pytest
from aihelpers import make_input

from cyberintel.ai.prompt import build_prompt
from cyberintel.ai.providers import (
    MAX_RESPONSE_BYTES,
    AIDisabledError,
    AnthropicProvider,
    NoneProvider,
    OllamaProvider,
    ProviderError,
    check_endpoint,
    provider_from_env,
    urllib_post_json,
)

KEY = "fake-key-for-tests"  # gitleaks:allow (not a credential)


class FakePost:
    def __init__(self, status: int = 200, body: Any = None, raw: bytes | None = None) -> None:
        self.status, self.body, self.raw = status, body, raw
        self.calls: list[tuple[str, dict[str, str], dict[str, Any], float]] = []

    def __call__(
        self, url: str, headers: Mapping[str, str], body: bytes, timeout: float
    ) -> tuple[int, bytes]:
        self.calls.append((url, dict(headers), json.loads(body), timeout))
        return self.status, self.raw if self.raw is not None else json.dumps(self.body).encode()


PROMPT = build_prompt(make_input())


# ----------------------------------------------------------------------------- none


def test_none_provider_is_default_and_refuses_to_call() -> None:
    p = provider_from_env({})
    assert isinstance(p, NoneProvider) and not p.enabled
    with pytest.raises(AIDisabledError):
        p.complete(PROMPT)


# ----------------------------------------------------------------------------- ollama


def test_ollama_request_shape_and_parsing() -> None:
    post = FakePost(
        body={
            "message": {"role": "assistant", "content": "{}"},
            "prompt_eval_count": 900,
            "eval_count": 120,
        }
    )
    p = OllamaProvider("http://10.0.0.5:11434/", "llama3.1:8b", post=post)
    out = p.complete(PROMPT)
    assert (out.text, out.input_tokens, out.output_tokens) == ("{}", 900, 120)
    url, headers, body, _ = post.calls[0]
    assert url == "http://10.0.0.5:11434/api/chat"
    assert body["stream"] is False and body["format"] == "json" and body["model"] == "llama3.1:8b"
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    assert (
        body["messages"][0]["content"] == PROMPT.system
        and body["messages"][1]["content"] == PROMPT.user
    )
    assert "x-api-key" not in {k.lower() for k in headers}


@pytest.mark.parametrize(
    "post",
    [
        FakePost(status=500, body={}),
        FakePost(raw=b"not json"),
        FakePost(raw=b"\xff\xfe"),
        FakePost(body=["list"]),
        FakePost(body={"message": {"content": 5}}),
        FakePost(body={"message": "x"}),
        FakePost(raw=b'{"message": {"content": "{}"}}' + b" " * MAX_RESPONSE_BYTES),
    ],
    ids=["http500", "notjson", "badutf8", "list", "nonstr", "nomsg", "oversize"],
)
def test_ollama_bad_responses(post: FakePost) -> None:
    with pytest.raises(ProviderError):
        OllamaProvider("http://127.0.0.1:11434", "m", post=post).complete(PROMPT)


def test_token_counts_are_sanitised() -> None:
    post = FakePost(
        body={"message": {"content": "{}"}, "prompt_eval_count": -5, "eval_count": True}
    )
    out = OllamaProvider("http://127.0.0.1:11434", "m", post=post).complete(PROMPT)
    assert (out.input_tokens, out.output_tokens) == (0, 0)


# ----------------------------------------------------------------------------- anthropic


def _msg(*blocks: dict[str, Any], usage: Any = None) -> dict[str, Any]:
    return {"content": list(blocks), "usage": usage or {"input_tokens": 1000, "output_tokens": 200}}


def test_anthropic_request_shape_and_parsing() -> None:
    post = FakePost(body=_msg({"type": "text", "text": "{}"}))
    p = AnthropicProvider(api_key=KEY, model="claude-x", post=post)
    out = p.complete(PROMPT)
    assert (out.text, out.input_tokens, out.output_tokens) == ("{}", 1000, 200)
    url, headers, body, _ = post.calls[0]
    assert url == "https://api.anthropic.com/v1/messages"
    assert headers["x-api-key"] == KEY and headers["anthropic-version"] == "2023-06-01"
    assert body["system"] == PROMPT.system and body["messages"] == [
        {"role": "user", "content": PROMPT.user}
    ]
    assert body["model"] == "claude-x" and body["temperature"] == 0
    assert KEY not in json.dumps(body)  # key only in the header


@pytest.mark.parametrize(
    "body",
    [
        _msg(),
        _msg({"type": "text", "text": "{}"}, {"type": "text", "text": "{}"}),
        _msg({"type": "tool_use", "input": {}}),
        {"content": "x"},
    ],
    ids=["empty", "two-text", "tool-use", "content-str"],
)
def test_anthropic_rejects_unexpected_shapes(body: dict[str, Any]) -> None:
    with pytest.raises(ProviderError):
        AnthropicProvider(api_key=KEY, model="m", post=FakePost(body=body)).complete(PROMPT)


def test_api_key_never_in_repr_or_errors() -> None:
    p = AnthropicProvider(api_key=KEY, model="m", post=FakePost(status=401, body={"error": KEY}))
    assert KEY not in repr(p)
    with pytest.raises(ProviderError) as exc:
        p.complete(PROMPT)
    assert KEY not in str(exc.value) and "401" in str(exc.value)


@pytest.mark.parametrize("key", ["", "has space", "line\nbreak"])
def test_bad_api_keys_refused(key: str) -> None:
    with pytest.raises(ValueError):
        AnthropicProvider(api_key=key, model="m")


# ----------------------------------------------------------------------------- endpoints / config


@pytest.mark.parametrize(
    ("url", "https"),
    [
        ("http://api.example", True),
        ("ftp://x", False),
        ("file:///etc/passwd", False),
        ("https://user:pw@api.example", True),
        ("https://api.example/?x=1", True),
        ("https://api.example/#f", True),
        ("https://", True),
    ],
)
def test_check_endpoint_rejects(url: str, https: bool) -> None:
    with pytest.raises(ValueError):
        check_endpoint(url, require_https=https)


def test_check_endpoint_accepts_and_strips_slash() -> None:
    assert (
        check_endpoint("http://192.168.1.20:11434/", require_https=False)
        == "http://192.168.1.20:11434"
    )


def test_env_config(tmp_path: Path) -> None:
    keyfile = tmp_path / "key"
    keyfile.write_text(KEY + "\n")
    p = provider_from_env(
        {"CIT_AI_PROVIDER": "anthropic", "CIT_AI_MODEL": "m", "CIT_AI_API_KEY_FILE": str(keyfile)}
    )
    assert isinstance(p, AnthropicProvider) and p.api_key == KEY
    o = provider_from_env({"CIT_AI_PROVIDER": "Ollama", "CIT_AI_MODEL": "m"})
    assert isinstance(o, OllamaProvider) and o.base_url == "http://127.0.0.1:11434"
    with pytest.raises(ValueError):
        provider_from_env({"CIT_AI_PROVIDER": "openai"})
    with pytest.raises(ValueError):
        provider_from_env({"CIT_AI_PROVIDER": "ollama"})  # model required
    with pytest.raises(ValueError):
        provider_from_env({"CIT_AI_PROVIDER": "anthropic", "CIT_AI_MODEL": "m"})  # key required
    with pytest.raises(ValueError):
        provider_from_env(
            {
                "CIT_AI_PROVIDER": "anthropic",
                "CIT_AI_MODEL": "m",
                "CIT_AI_API_KEY": KEY,
                "CIT_AI_BASE_URL": "http://x",
            }
        )


# --------------------------------------------------------------- real transport (loopback)


class _Handler(BaseHTTPRequestHandler):
    routes: ClassVar[dict[str, tuple[int, dict[str, str], bytes]]] = {}
    seen: ClassVar[list[dict[str, str]]] = []

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        type(self).seen.append(dict(self.headers))
        status, headers, body = self.routes.get(self.path, (404, {}, b""))
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def server() -> Iterator[str]:
    _Handler.routes, _Handler.seen = {}, []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def test_transport_roundtrip(server: str) -> None:
    _Handler.routes["/api/chat"] = (200, {}, json.dumps({"message": {"content": "{}"}}).encode())
    out = OllamaProvider(server, "m").complete(PROMPT)
    assert out.text == "{}"


def test_transport_does_not_follow_redirects(server: str) -> None:
    _Handler.routes["/api/chat"] = (302, {"Location": "/elsewhere"}, b"")
    _Handler.routes["/elsewhere"] = (200, {}, b'{"message":{"content":"leak"}}')
    with pytest.raises(ProviderError, match="302"):
        OllamaProvider(server, "m").complete(PROMPT)
    assert len(_Handler.seen) == 1


def test_transport_ignores_proxy_environment(server: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    _Handler.routes["/x"] = (200, {}, b"{}")
    assert urllib_post_json(f"{server}/x", {}, b"{}", 5.0) == (200, b"{}")


def test_transport_caps_response(server: str) -> None:
    _Handler.routes["/big"] = (200, {}, b"x" * (MAX_RESPONSE_BYTES + 100))
    status, data = urllib_post_json(f"{server}/big", {}, b"{}", 5.0)
    assert status == 200 and len(data) == MAX_RESPONSE_BYTES + 1


def test_transport_error_is_generic() -> None:
    with pytest.raises(ProviderError, match="transport error"):
        urllib_post_json("http://127.0.0.1:9/x", {}, b"{}", 2.0)
