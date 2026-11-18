"""Run the dashboard.

    python -m cyberintel.web.server

Configuration (environment; each secret also accepts a ``*_FILE`` variant for Docker
secrets, so secrets never need to sit in the environment of the process tree):

    CIT_WEB_PASSWORD_HASH[_FILE]   scrypt hash      (python -m cyberintel.web.auth hash-password)
    CIT_WEB_SECRET[_FILE]          session secret   (python -m cyberintel.web.auth new-secret)
    CIT_DATABASE_URL[_FILE]        libpq DSN for a SELECT-only role
    CIT_WEB_ALLOWED_HOSTS          comma-separated Host header allowlist (default localhost)
    CIT_WEB_BIND / CIT_WEB_PORT    default 127.0.0.1:8080 (put Tailscale/WireGuard in front)
    CIT_WEB_INSECURE_COOKIES=1     plain-http local development only
    CIT_WEB_HSTS=1                 when served behind TLS

Missing or unsafe auth configuration is a startup error: there is no unauthenticated mode.
"""

from __future__ import annotations

import os
from pathlib import Path


def secret(name: str) -> str | None:
    path = os.environ.get(f"{name}_FILE")
    if path:
        return Path(path).read_text(encoding="utf-8").strip()
    return os.environ.get(name)


def main() -> int:
    import uvicorn

    from cyberintel.sources import load_registry
    from cyberintel.web.app import create_app
    from cyberintel.web.auth import AuthConfig
    from cyberintel.web.reader import DbReader, psycopg_connector

    auth = AuthConfig.from_values(secret("CIT_WEB_PASSWORD_HASH"), secret("CIT_WEB_SECRET"))
    registry = load_registry(Path(os.environ.get("CIT_SOURCES", "config/sources.toml")))
    sources = [{"name": s.name, "kind": s.kind, "tier": s.trust_tier} for s in registry.sources]
    hosts = [h.strip() for h in os.environ.get("CIT_WEB_ALLOWED_HOSTS", "localhost").split(",")]
    app = create_app(
        DbReader(psycopg_connector(secret("CIT_DATABASE_URL") or "")),
        auth,
        sources=sources,
        allowed_hosts=[h for h in hosts if h],
        secure_cookies=os.environ.get("CIT_WEB_INSECURE_COOKIES") != "1",
        hsts=os.environ.get("CIT_WEB_HSTS") == "1",
    )
    uvicorn.run(
        app,
        host=os.environ.get("CIT_WEB_BIND", "127.0.0.1"),
        port=int(os.environ.get("CIT_WEB_PORT", "8080")),
        proxy_headers=False,  # never trust X-Forwarded-* for client identity
        server_header=False,
        date_header=False,
        log_level="info",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
