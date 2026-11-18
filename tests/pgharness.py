"""Test harness: run the production SQL from ``store.sql`` through ``psql``.

Why psql: it lets the exact production statements run against a real PostgreSQL wherever
a server is reachable, including environments without a Python driver. Parameters use
psql's ``:'name'`` interpolation, which emits correctly quoted literals.

Opt-in: set ``CIT_TEST_PG=1`` plus standard libpq variables (PGHOST, PGUSER, PGPASSWORD).
Each test gets a fresh database cloned from a migrated template.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import subprocess
import uuid
from collections.abc import Iterator, Mapping
from pathlib import Path

import pytest

MIGRATIONS = Path(__file__).resolve().parents[1] / "src" / "cyberintel" / "store" / "migrations"
_PARAM = re.compile(r"%\((\w+)\)s")
_SAFE_NAME = re.compile(r"^[a-z0-9_]+$")
TEMPLATE = "cit_test_template"


class PsqlError(RuntimeError):
    pass


def enabled() -> bool:
    return os.environ.get("CIT_TEST_PG") == "1" and shutil.which("psql") is not None


def _psql(db: str, script: str, variables: Mapping[str, str] | None = None) -> str:
    args = ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "--csv", "-t", "-d", db, "-f", "-"]
    for k, v in (variables or {}).items():
        args += ["-v", f"{k}={v}"]
    proc = subprocess.run(args, input=script, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise PsqlError(proc.stderr.strip())
    return proc.stdout


def _literal_value(v: object) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, list | tuple):  # Python list -> Postgres array literal
        return "{" + ",".join(json.dumps(str(x)) for x in v) + "}"
    return str(v)


class PgDB:
    def __init__(self, name: str) -> None:
        self.name = name

    def run(self, sql: str, **params: object) -> list[list[str]]:
        """Execute production SQL (``%(x)s`` placeholders) with bound-like parameters."""
        variables: dict[str, str] = {}

        def sub(m: re.Match[str]) -> str:
            key = m.group(1)
            value = params[key]
            if value is None:
                return "NULL"
            variables[key] = _literal_value(value)
            return f":'{key}'"

        out = _psql(self.name, _PARAM.sub(sub, sql).rstrip().rstrip(";") + ";\n", variables)
        # A row whose only value is an empty string (or NULL) prints as a blank line, so
        # every output line is a row; csv.reader yields nothing for "", hence the default.
        return [next(csv.reader(io.StringIO(line)), [""]) for line in out.splitlines()]

    def scalar(self, sql: str, **params: object) -> str:
        rows = self.run(sql, **params)
        assert len(rows) == 1 and len(rows[0]) == 1, rows
        return rows[0][0]


def migration_files(direction: str) -> list[Path]:
    files = sorted(MIGRATIONS.glob(f"*.{direction}.sql"))
    return files if direction == "up" else list(reversed(files))


@pytest.fixture(scope="session")
def pg_template() -> Iterator[str]:
    if not enabled():
        pytest.skip("set CIT_TEST_PG=1 and PGHOST/PGUSER to run SQL tests")
    _psql("postgres", f"DROP DATABASE IF EXISTS {TEMPLATE};")
    _psql("postgres", f"CREATE DATABASE {TEMPLATE};")
    for f in migration_files("up"):
        _psql(TEMPLATE, "BEGIN;\n" + f.read_text() + "\nCOMMIT;\n")
    yield TEMPLATE
    _psql("postgres", f"DROP DATABASE IF EXISTS {TEMPLATE};")


@pytest.fixture
def pg(pg_template: str) -> Iterator[PgDB]:
    name = f"cit_test_{uuid.uuid4().hex[:12]}"
    assert _SAFE_NAME.match(name)
    _psql("postgres", f"CREATE DATABASE {name} TEMPLATE {pg_template};")
    try:
        yield PgDB(name)
    finally:
        _psql("postgres", f"DROP DATABASE IF EXISTS {name} WITH (FORCE);")
