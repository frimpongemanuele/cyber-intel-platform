"""Minimal ASGI test driver (no httpx needed): call the app directly, collect the response."""

from __future__ import annotations

from dataclasses import dataclass
from http.cookies import SimpleCookie
from typing import Any

import anyio


@dataclass
class Resp:
    status: int
    headers: list[tuple[str, str]]
    body: bytes

    def header(self, name: str) -> str | None:
        for k, v in self.headers:
            if k == name.lower():
                return v
        return None

    def all(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k == name.lower()]

    @property
    def text(self) -> str:
        return self.body.decode("utf-8")

    def cookie(self, name: str) -> str | None:
        for raw in self.all("set-cookie"):
            c: SimpleCookie = SimpleCookie()
            c.load(raw)
            if name in c:
                return c[name].value
        return None


def request(app: Any, method: str, path: str, *, headers: dict[str, str] | None = None,
            body: bytes = b"", client: str = "10.0.0.5") -> Resp:  # fmt: skip
    path, _, query = path.partition("?")
    hdrs = {"host": "localhost", **{k.lower(): v for k, v in (headers or {}).items()}}
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method,
        "scheme": "https", "path": path, "raw_path": path.encode(), "root_path": "",
        "query_string": query.encode(), "client": (client, 50000), "server": ("localhost", 443),
        "headers": [(k.encode("latin-1"), v.encode("latin-1")) for k, v in hdrs.items()],
    }  # fmt: skip
    sent = False
    start: dict[str, Any] = {}
    chunks: list[bytes] = []

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            start.update(message)
        elif message["type"] == "http.response.body":
            chunks.append(message.get("body", b""))

    anyio.run(app, scope, receive, send)
    headers_out = [(k.decode("latin-1").lower(), v.decode("latin-1")) for k, v in start["headers"]]
    return Resp(start["status"], headers_out, b"".join(chunks))
