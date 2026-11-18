"""Minimal, verifiable schema migrations.

Migrations are plain SQL files ``NNNN_name.up.sql`` / ``NNNN_name.down.sql`` in
``store/migrations``. Applied versions are recorded in ``schema_migrations`` together with
the SHA-256 of the file. Before anything runs:

* every applied migration must still exist and match its recorded checksum; a changed
  file means drift or tampering, and the run stops (fail closed);
* versions must be contiguous (no gaps, no duplicates);
* the database must not know a version the code does not (code older than the schema).

Each migration runs in its own transaction (PostgreSQL DDL is transactional) under a
transaction-level advisory lock, so two deployers cannot migrate concurrently.

Planning is pure and unit-tested; only ``apply``/``rollback`` touch the database.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    import psycopg

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
_FILE = re.compile(r"^(\d{4})_([a-z0-9_]+)\.(up|down)\.sql$")
ADVISORY_LOCK_KEY = 7_400_291  # arbitrary, constant: "cyber-intel migrations"

BOOTSTRAP = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     integer PRIMARY KEY CHECK (version > 0),
    name        text NOT NULL,
    checksum    text NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
    applied_at  timestamptz NOT NULL DEFAULT now()
)
"""


class MigrationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    up_sql: str
    down_sql: str

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.up_sql.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class Applied:
    version: int
    name: str
    checksum: str


def discover(directory: Path = MIGRATIONS_DIR) -> list[Migration]:
    files: dict[tuple[int, str], dict[str, str]] = {}
    for path in sorted(directory.iterdir()):
        if path.suffix != ".sql":
            continue
        m = _FILE.match(path.name)
        if not m:
            raise MigrationError(f"badly named migration file: {path.name}")
        key = (int(m.group(1)), m.group(2))
        files.setdefault(key, {})[m.group(3)] = path.read_text(encoding="utf-8")
    migrations: list[Migration] = []
    for (version, name), parts in sorted(files.items()):
        if set(parts) != {"up", "down"}:
            raise MigrationError(f"{version:04d}_{name}: needs both .up.sql and .down.sql")
        migrations.append(Migration(version, name, parts["up"], parts["down"]))
    versions = [m.version for m in migrations]
    if versions != list(range(1, len(versions) + 1)):
        raise MigrationError(f"migration versions must be 1..N with no gaps: {versions}")
    return migrations


def plan(available: Sequence[Migration], applied: Sequence[Applied]) -> list[Migration]:
    """Validate history and return the migrations still to apply, in order."""
    by_version = {m.version: m for m in available}
    for a in applied:
        m = by_version.get(a.version)
        if m is None:
            raise MigrationError(
                f"database has migration {a.version:04d}_{a.name} that this code lacks"
            )
        if m.checksum != a.checksum:
            raise MigrationError(
                f"migration {a.version:04d}_{a.name} was modified after being applied "
                f"(recorded {a.checksum[:12]}…, file {m.checksum[:12]}…)"
            )
    applied_versions = sorted(a.version for a in applied)
    if applied_versions != list(range(1, len(applied_versions) + 1)):
        raise MigrationError(f"applied versions are not contiguous: {applied_versions}")
    return [m for m in available if m.version > len(applied_versions)]


# --------------------------------------------------------------------------- database


def _applied(conn: psycopg.Connection[Any]) -> list[Applied]:
    conn.execute(BOOTSTRAP)
    rows = conn.execute(
        "SELECT version, name, checksum FROM schema_migrations ORDER BY version"
    ).fetchall()
    return [Applied(int(v), str(n), str(c)) for v, n, c in rows]


def apply(conn: psycopg.Connection[Any], directory: Path = MIGRATIONS_DIR) -> list[int]:
    """Apply all pending migrations. Returns the versions applied."""
    available = discover(directory)
    done: list[int] = []
    while True:
        with conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (ADVISORY_LOCK_KEY,))
            pending = plan(available, _applied(conn))  # re-validated under the lock
            if not pending:
                return done
            m = pending[0]
            conn.execute(m.up_sql.encode())  # whole file; no parameters
            conn.execute(
                "INSERT INTO schema_migrations (version, name, checksum) VALUES (%s, %s, %s)",
                (m.version, m.name, m.checksum),
            )
            done.append(m.version)


def rollback(
    conn: psycopg.Connection[Any], to_version: int, directory: Path = MIGRATIONS_DIR
) -> list[int]:
    """Roll back migrations above ``to_version`` (newest first). Returns versions undone."""
    available = {m.version: m for m in discover(directory)}
    undone: list[int] = []
    while True:
        with conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (ADVISORY_LOCK_KEY,))
            applied = _applied(conn)
            plan(list(available.values()), applied)  # refuse if history is inconsistent
            if not applied or applied[-1].version <= to_version:
                return undone
            top = available[applied[-1].version]
            conn.execute(top.down_sql.encode())
            conn.execute("DELETE FROM schema_migrations WHERE version = %s", (top.version,))
            undone.append(top.version)


def main(argv: Sequence[str] | None = None) -> int:
    import psycopg

    ap = argparse.ArgumentParser(description="Apply or roll back schema migrations.")
    ap.add_argument("command", choices=["up", "down", "status"])
    ap.add_argument("--to", type=int, default=0, help="target version for 'down'")
    args = ap.parse_args(argv)
    # Connection settings come from libpq environment variables (PGHOST, PGUSER,
    # PGDATABASE, PGPASSWORD / PGPASSFILE) or CIT_DATABASE_URL. Never from argv, where
    # passwords would leak into shell history and process listings.
    with psycopg.connect(os.environ.get("CIT_DATABASE_URL", ""), autocommit=True) as conn:
        if args.command == "up":
            print("applied:", apply(conn) or "nothing pending")
        elif args.command == "down":
            print("rolled back:", rollback(conn, args.to) or "nothing to roll back")
        else:
            applied = _applied(conn)
            pending = plan(discover(), applied)
            print(
                f"applied: {[a.version for a in applied]}  pending: {[m.version for m in pending]}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
