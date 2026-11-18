"""Model backends. The AI layer is optional; ``none`` is the default and makes no calls.

* ``none``      - disabled. Nothing is sent anywhere; the dashboard hides the AI panel.
* ``ollama``    - a local model on the operator's own machine/LAN (no cost, no third party).
* ``anthropic`` - a hosted API using the operator's own key (never bundled, never required).

Endpoints are fixed by the operator, never derived from collected content, so they are not
subject to the source allowlist (a LAN Ollama host is legitimately private). Transport is
stdlib ``urllib`` with: no redirects, no environment proxies, a timeout, a response size
cap, and TLS verification on. The API key travels only in its header and is never part of
``repr``, errors or logs.
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from cyberintel.ai.prompt import Prompt

MAX_RESPONSE_BYTES = 256 * 1024
DEFAULT_TIMEOUT = 120.0


class ProviderError(Exception):
    """A backend call failed. Messages never include secrets or response bodies."""


class AIDisabledError(ProviderError):
    pass


@dataclass(frozen=True, slots=True)
class Completion:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0


class Provider(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def model(self) -> str: ...

    @property
    def enabled(self) -> bool: ...

    def complete(self, prompt: Prompt) -> Completion: ...


# --------------------------------------------------------------------------- transport

PostJson = Callable[[str, Mapping[str, str], bytes, float], tuple[int, bytes]]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # urllib then raises HTTPError with the 3xx status


def urllib_post_json(
    url: str, headers: Mapping[str, str], body: bytes, timeout: float
) -> tuple[int, bytes]:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),  # ignore *_PROXY environment variables
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _NoRedirect(),
    )
    # S310: the scheme is restricted to http/https by check_endpoint at construction time.
    req = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")  # noqa: S310
    try:
        with opener.open(req, timeout=timeout) as resp:
            data = resp.read(MAX_RESPONSE_BYTES + 1)
            return resp.status, data
    except urllib.error.HTTPError as exc:
        return exc.code, b""
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProviderError(f"transport error: {type(exc).__name__}") from None


def check_endpoint(url: str, *, require_https: bool) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ({"https"} if require_https else {"http", "https"}):
        raise ValueError(
            "endpoint scheme not allowed" + (" (https required)" if require_https else "")
        )
    if not parts.hostname or parts.username or parts.password:
        raise ValueError("endpoint must have a host and no credentials")
    if parts.query or parts.fragment:
        raise ValueError("endpoint must not have a query or fragment")
    return url.rstrip("/")


def _decode(status: int, data: bytes) -> dict[str, Any]:
    if status != 200:
        raise ProviderError(f"backend returned HTTP {status}")
    if len(data) > MAX_RESPONSE_BYTES:
        raise ProviderError("backend response exceeds size cap")
    try:
        value = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ProviderError("backend response is not JSON") from None
    if not isinstance(value, dict):
        raise ProviderError("backend response is not a JSON object")
    return value


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


# --------------------------------------------------------------------------- providers


@dataclass(frozen=True, slots=True)
class NoneProvider:
    name: str = "none"
    model: str = ""

    @property
    def enabled(self) -> bool:
        return False

    def complete(self, prompt: Prompt) -> Completion:
        raise AIDisabledError("AI layer is disabled (CIT_AI_PROVIDER=none)")


@dataclass(frozen=True, slots=True)
class OllamaProvider:
    base_url: str
    model: str
    timeout: float = DEFAULT_TIMEOUT
    post: PostJson = field(default=urllib_post_json, repr=False)
    name: str = "ollama"

    def __post_init__(self) -> None:
        object.__setattr__(self, "base_url", check_endpoint(self.base_url, require_https=False))
        if not self.model:
            raise ValueError("model name required")

    @property
    def enabled(self) -> bool:
        return True

    def complete(self, prompt: Prompt) -> Completion:
        body = {
            "model": self.model,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0},
            "messages": [
                {"role": "system", "content": prompt.system},
                {"role": "user", "content": prompt.user},
            ],
        }
        status, data = self.post(
            f"{self.base_url}/api/chat",
            {"Content-Type": "application/json"},
            json.dumps(body).encode(),
            self.timeout,
        )
        value = _decode(status, data)
        message = value.get("message")
        text = message.get("content") if isinstance(message, dict) else None
        if not isinstance(text, str):
            raise ProviderError("backend response has no message content")
        return Completion(text, _int(value.get("prompt_eval_count")), _int(value.get("eval_count")))


@dataclass(frozen=True, slots=True)
class AnthropicProvider:
    api_key: str = field(repr=False)
    model: str
    base_url: str = "https://api.anthropic.com"
    max_tokens: int = 1200
    timeout: float = DEFAULT_TIMEOUT
    post: PostJson = field(default=urllib_post_json, repr=False)
    name: str = "anthropic"

    def __post_init__(self) -> None:
        object.__setattr__(self, "base_url", check_endpoint(self.base_url, require_https=True))
        if not self.model:
            raise ValueError("model name required")
        if not self.api_key or any(c.isspace() for c in self.api_key):
            raise ValueError("API key missing or malformed")

    @property
    def enabled(self) -> bool:
        return True

    def complete(self, prompt: Prompt) -> Completion:
        body = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": 0,
            "system": prompt.system,
            "messages": [{"role": "user", "content": prompt.user}],
        }
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }
        status, data = self.post(
            f"{self.base_url}/v1/messages", headers, json.dumps(body).encode(), self.timeout
        )
        value = _decode(status, data)
        blocks = value.get("content")
        texts = [
            b["text"]
            for b in (blocks if isinstance(blocks, list) else [])
            if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str)
        ]
        if len(texts) != 1:
            raise ProviderError("backend response must contain exactly one text block")
        raw_usage = value.get("usage")
        usage: dict[str, Any] = raw_usage if isinstance(raw_usage, dict) else {}
        return Completion(
            texts[0], _int(usage.get("input_tokens")), _int(usage.get("output_tokens"))
        )


# --------------------------------------------------------------------------- configuration


def _secret(env: Mapping[str, str], name: str) -> str | None:
    path = env.get(f"{name}_FILE")
    if path:
        return Path(path).read_text(encoding="utf-8").strip()
    return env.get(name)


def provider_from_env(env: Mapping[str, str] | None = None) -> Provider:
    """CIT_AI_PROVIDER = none (default) | ollama | anthropic.

    ollama:    CIT_AI_MODEL, CIT_AI_OLLAMA_URL (default http://127.0.0.1:11434)
    anthropic: CIT_AI_MODEL, CIT_AI_API_KEY[_FILE], optional CIT_AI_BASE_URL (https only)
    """
    env = os.environ if env is None else env
    kind = (env.get("CIT_AI_PROVIDER") or "none").strip().lower()
    model = (env.get("CIT_AI_MODEL") or "").strip()
    if kind == "none":
        return NoneProvider()
    if kind == "ollama":
        return OllamaProvider(env.get("CIT_AI_OLLAMA_URL") or "http://127.0.0.1:11434", model)
    if kind == "anthropic":
        key = _secret(env, "CIT_AI_API_KEY") or ""
        base = env.get("CIT_AI_BASE_URL") or "https://api.anthropic.com"
        return AnthropicProvider(api_key=key, model=model, base_url=base)
    raise ValueError(f"unknown CIT_AI_PROVIDER {kind[:20]!r} (none | ollama | anthropic)")
