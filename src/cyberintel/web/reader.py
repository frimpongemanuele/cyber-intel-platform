"""Read-only data access for the dashboard.

Defence in depth for the web tier's database access:
1. every query is fixed SQL from ``store.read_sql`` with bound parameters;
2. the connection is opened with ``default_transaction_read_only=on`` *and* marked
   read-only in psycopg, so even a hypothetical injection could not write;
3. deployment adds a SELECT-only database role (DEPLOYMENT.md).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Protocol

from cyberintel.store import read_sql as q
from cyberintel.web.views import PAGE_SIZE, NewsQuery, StoryQuery, VulnQuery

Row = dict[str, Any]


class ReaderLike(Protocol):
    def summary(self) -> Row: ...
    def list_vulns(self, query: VulnQuery) -> tuple[list[Row], int]: ...
    def vuln_detail(self, cve_id: str) -> Row | None: ...
    def list_stories(self, query: StoryQuery) -> tuple[list[Row], int]: ...
    def story_detail(self, slug: str) -> Row | None: ...
    def list_news(self, query: NewsQuery) -> tuple[list[Row], int]: ...
    def source_health(self) -> list[Row]: ...


def _pattern(text: str | None) -> str | None:
    return q.like_pattern(text) if text else None


class DbReader:
    """``connect`` returns a new psycopg connection (dict rows, read-only session)."""

    def __init__(self, connect: Callable[[], Any]) -> None:
        self._connect = connect

    def _all(self, statement: str, **params: Any) -> list[Row]:
        with self._connect() as conn:
            conn.read_only = True
            return list(conn.execute(statement.encode(), params).fetchall())

    def _one(self, statement: str, **params: Any) -> Row | None:
        found = self._all(statement, **params)
        return found[0] if found else None

    def _count(self, statement: str, **params: Any) -> int:
        row = self._one(statement, **params)
        return int(next(iter(row.values()))) if row else 0

    def summary(self) -> Row:
        return self._one(q.SUMMARY) or {}

    def list_vulns(self, query: VulnQuery) -> tuple[list[Row], int]:
        f = {
            "kev_only": query.kev,
            "exploited_only": query.exploited,
            "min_priority": query.min_priority,
            "pattern": _pattern(query.q),
        }
        rows = self._all(q.LIST_VULNS[query.sort], limit=PAGE_SIZE, offset=query.offset, **f)
        return rows, self._count(q.COUNT_VULNS, **f)

    def vuln_detail(self, cve_id: str) -> Row | None:
        v = self._one(q.GET_VULN, cve_id=cve_id)
        if v is None:
            return None
        c = {"cve_id": cve_id}
        return {
            "v": v,
            "record": self._one(q.GET_VULN_RECORD, **c),
            "kev": self._one(q.GET_KEV, **c),
            "scores": self._all(q.LIST_SCORES, **c),
            "products": self._all(q.LIST_PRODUCTS, **c),
            "references": self._all(q.LIST_REFERENCES, **c),
            "documents": self._all(q.LIST_DOCUMENTS_FOR_CVE, **c),
            "stories": self._all(q.LIST_DEVELOPMENTS_FOR_CVE, **c),
        }

    def list_stories(self, query: StoryQuery) -> tuple[list[Row], int]:
        f = {"include_rollups": query.rollups, "pattern": _pattern(query.q)}
        rows = self._all(q.LIST_DEVELOPMENTS, limit=PAGE_SIZE, offset=query.offset, **f)
        return rows, self._count(q.COUNT_DEVELOPMENTS, **f)

    def story_detail(self, slug: str) -> Row | None:
        s = self._one(q.GET_DEVELOPMENT, slug=slug)
        if s is None:
            return None
        d = {"development_id": s["id"]}
        return {
            "s": s,
            "sightings": self._all(q.LIST_SIGHTINGS, **d),
            "cves": self._all(q.LIST_DEVELOPMENT_CVES, **d),
            "links": self._all(q.LIST_DEVELOPMENT_LINKS, **d),
        }

    def list_news(self, query: NewsQuery) -> tuple[list[Row], int]:
        f = {"source": query.source, "pattern": _pattern(query.q)}
        rows = self._all(q.LIST_DOCUMENTS, limit=PAGE_SIZE, offset=query.offset, **f)
        return rows, self._count(q.COUNT_DOCUMENTS, **f)

    def source_health(self) -> list[Row]:
        return self._all(q.LIST_SOURCE_HEALTH)


def psycopg_connector(dsn: str) -> Callable[[], Any]:
    """Factory for read-only, dict-row psycopg connections."""
    import psycopg
    from psycopg.rows import dict_row

    def connect() -> Any:
        return psycopg.connect(
            dsn, row_factory=dict_row, options="-c default_transaction_read_only=on"
        )

    return connect


def merge_health(registry_sources: list[Mapping[str, str]], health: list[Row]) -> list[Row]:
    """Every configured source appears, even if it has never run."""
    by_name = {h["source_name"]: h for h in health}
    out: list[Row] = []
    for s in registry_sources:
        h = by_name.get(s["name"], {})
        out.append(
            {
                "name": s["name"],
                "kind": s["kind"],
                "tier": s["tier"],
                "outcome": h.get("outcome"),
                "http_status": h.get("http_status"),
                "records_ok": h.get("records_ok"),
                "last_success_at": h.get("last_success_at"),
                "consecutive_failures": h.get("consecutive_failures") or 0,
                "last_error": h.get("last_error"),
            }
        )
    return out
