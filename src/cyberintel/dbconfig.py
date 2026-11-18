"""Database connection settings for every entry point (CLI, services, containers).

Resolution order (first match wins), so passwords never need to be in argv or in a
plain environment variable:

1. ``CIT_DATABASE_URL_FILE``  - a file holding a full libpq DSN;
2. ``CIT_DATABASE_URL``       - a libpq DSN (development convenience);
3. empty DSN                  - libpq reads PGHOST / PGPORT / PGDATABASE / PGUSER itself.

Then, if ``CIT_DB_PASSWORD_FILE`` is set, its content is appended as the password
(correctly quoted). This is what the Compose deployment uses: host/db/user come from
plain environment variables and only the password is a Docker secret.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path


def quote_conninfo_value(value: str) -> str:
    """Quote a libpq keyword/value value: single quotes, with ``\\`` and ``'`` escaped."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8").strip()


def database_dsn(env: Mapping[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    if env.get("CIT_DATABASE_URL_FILE"):
        dsn = _read(env["CIT_DATABASE_URL_FILE"])
    else:
        dsn = env.get("CIT_DATABASE_URL", "")
    if env.get("CIT_DB_PASSWORD_FILE"):
        password = _read(env["CIT_DB_PASSWORD_FILE"])
        if not password:
            raise ValueError("CIT_DB_PASSWORD_FILE is empty")
        if "://" in dsn:
            raise ValueError("CIT_DB_PASSWORD_FILE needs a keyword/value DSN, not a URI")
        dsn = f"{dsn} password={quote_conninfo_value(password)}".strip()
    return dsn
