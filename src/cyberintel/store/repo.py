"""Repository: persists parsed source data using the statements in ``store.sql``.

Each ``store_*`` method runs in one transaction: a batch is fully written or not at all.
Values reach the database only as bound parameters; batches as a single JSON parameter.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import psycopg

from cyberintel.collectors.cve5 import Cve5Record
from cyberintel.collectors.epss import EpssSnapshot
from cyberintel.collectors.kev import KevCatalog
from cyberintel.collectors.nvd import NvdPage
from cyberintel.eval.archive import Story
from cyberintel.net.types import Validators
from cyberintel.parsing.feeds import Feed
from cyberintel.store import rows, sql

EPSS_CHUNK = 20_000


@dataclass(frozen=True, slots=True)
class SourceState:
    validators: Validators | None = None
    consecutive_failures: int = 0
    last_success_at: datetime | None = None
    last_attempt_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class KevStoreResult:
    upserted: int
    removed: tuple[str, ...]
    removal_check_skipped: bool  # True when rejected rows made the catalog untrustworthy


class Store:
    def __init__(self, conn: psycopg.Connection[Any]) -> None:
        self._conn = conn

    def _exec(self, statement: str, **params: Any) -> list[tuple[Any, ...]]:
        cur = self._conn.execute(statement.encode(), params)
        return cur.fetchall() if cur.description else []

    # ------------------------------------------------------------------ facts

    def store_kev(self, catalog: KevCatalog, seen_at: datetime) -> KevStoreResult:
        data = rows.kev_rows(catalog)
        with self._conn.transaction():
            self._exec(
                sql.UPSERT_KEV,
                rows=rows.to_json(data),
                catalog_version=catalog.catalog_version,
                seen_at=seen_at,
            )
            # Only a cleanly parsed catalog may mark removals (and the SQL adds its own
            # 90% guard on top). A partly rejected catalog says nothing about absence.
            if catalog.rejected:
                return KevStoreResult(len(data), (), removal_check_skipped=True)
            present = rows.to_json([e.cve_id for e in catalog.entries])
            removed = self._exec(sql.MARK_KEV_REMOVED, present=present, seen_at=seen_at)
        return KevStoreResult(len(data), tuple(r[0] for r in removed), False)

    def store_epss(self, snapshot: EpssSnapshot, seen_at: datetime) -> int:
        data = rows.epss_rows(snapshot)
        score_date = snapshot.score_date.date() if snapshot.score_date else None
        with self._conn.transaction():
            for i in range(0, len(data), EPSS_CHUNK):
                self._exec(
                    sql.UPSERT_EPSS,
                    rows=rows.to_json(data[i : i + EPSS_CHUNK]),
                    score_date=score_date,
                    model_version=snapshot.model_version,
                    seen_at=seen_at,
                )
        return len(data)

    def store_cve5(self, records: Iterable[Cve5Record], seen_at: datetime) -> list[str]:
        vulns, scores, products, refs = rows.cve5_rows(records)
        if not vulns:
            return []
        with self._conn.transaction():
            written = [
                r[0] for r in self._exec(sql.UPSERT_CVE5, rows=rows.to_json(vulns), seen_at=seen_at)
            ]
            if written:
                keep = set(written)  # replace dependents only for records actually written
                self._replace_scores(
                    "cve5", written, [s for s in scores if s["cve_id"] in keep], seen_at
                )
                self._exec(sql.DELETE_PRODUCTS, cve_ids=written)
                self._exec(
                    sql.INSERT_PRODUCTS,
                    rows=rows.to_json([p for p in products if p["cve_id"] in keep]),
                )
                self._exec(sql.DELETE_REFERENCES, cve_ids=written)
                self._exec(
                    sql.INSERT_REFERENCES,
                    rows=rows.to_json([r for r in refs if r["cve_id"] in keep]),
                )
                self._recompute_headline(written)
        return written

    def store_nvd_page(self, page: NvdPage, seen_at: datetime) -> list[str]:
        vulns, scores = rows.nvd_rows(page.cves)
        if not vulns:
            return []
        with self._conn.transaction():
            written = [
                r[0] for r in self._exec(sql.UPSERT_NVD, rows=rows.to_json(vulns), seen_at=seen_at)
            ]
            if written:
                keep = set(written)
                self._replace_scores(
                    "nvd", written, [s for s in scores if s["cve_id"] in keep], seen_at
                )
                self._recompute_headline(written)
        return written

    def _replace_scores(
        self,
        collected_from: str,
        cve_ids: Sequence[str],
        score_rows: list[rows.Row],
        seen_at: datetime,
    ) -> None:
        self._exec(sql.DELETE_SCORES, collected_from=collected_from, cve_ids=list(cve_ids))
        if score_rows:
            self._exec(
                sql.INSERT_SCORES,
                rows=rows.to_json(score_rows),
                collected_from=collected_from,
                seen_at=seen_at,
            )

    def _recompute_headline(self, cve_ids: Sequence[str]) -> None:
        self._exec(sql.RECOMPUTE_HEADLINE, cve_ids=list(cve_ids))
        self._exec(sql.CLEAR_HEADLINE_WITHOUT_SCORES, cve_ids=list(cve_ids))

    # ------------------------------------------------------------------ evidence

    def store_documents(self, source_name: str, feed: Feed, seen_at: datetime) -> tuple[int, int]:
        """-> (inserted, updated)."""
        data = rows.document_rows(feed)
        if not data:
            return 0, 0
        with self._conn.transaction():
            result = self._exec(
                sql.UPSERT_DOCUMENTS,
                rows=rows.to_json(data),
                source_name=source_name,
                seen_at=seen_at,
            )
        inserted = sum(1 for (flag,) in result if flag)
        return inserted, len(result) - inserted

    # ------------------------------------------------------------------ bookkeeping

    def state(self, source_name: str) -> SourceState:
        found = self._exec(sql.GET_SOURCE_STATE, source_name=source_name)
        if not found:
            return SourceState()
        etag, last_modified, failures, last_success, last_attempt = found[0]
        validators = (
            Validators(etag=etag, last_modified=last_modified)
            if etag is not None or last_modified is not None
            else None
        )
        return SourceState(validators, int(failures), last_success, last_attempt)

    def validators(self, source_name: str) -> Validators | None:
        return self.state(source_name).validators

    def consecutive_failures(self, source_name: str) -> int:
        return self.state(source_name).consecutive_failures

    def cve5_queue(self, limit: int) -> list[str]:
        return [str(r[0]) for r in self._exec(sql.CVE5_QUEUE, limit=limit)]

    def record_success(self, source_name: str, validators: Validators, at: datetime) -> None:
        with self._conn.transaction():
            self._exec(
                sql.RECORD_SUCCESS,
                source_name=source_name,
                etag=validators.etag,
                last_modified=validators.last_modified,
                at=at,
            )

    def record_failure(self, source_name: str, error: str, at: datetime) -> None:
        with self._conn.transaction():
            self._exec(sql.RECORD_FAILURE, source_name=source_name, error=error, at=at)

    # ------------------------------------------------------------------ developments

    def import_archive_stories(self, stories: Sequence[Story]) -> int:
        """Rebuild archive-derived developments from linked stories, atomically."""
        from cyberintel.store.archive_import import story_slug

        slug_of = {m.id: story_slug(s) for s in stories for m in s.members}
        with self._conn.transaction():
            self._exec(sql.DELETE_ARCHIVE_DEVELOPMENTS)
            for story in stories:
                latest = story.members[-1]
                found = self._exec(
                    sql.UPSERT_DEVELOPMENT,
                    slug=story_slug(story),
                    title=latest.title[:500],
                    first_seen=story.first_seen,
                    last_seen=story.last_seen,
                    status=latest.status,
                    confidence=latest.confidence,
                    is_rollup=story.is_rollup,
                )
                dev_id = found[0][0]
                sightings = [
                    {"external_id": m.id, "day": m.day, "urgency": m.urgency} for m in story.members
                ]
                self._exec(
                    sql.INSERT_SIGHTINGS,
                    development_id=dev_id,
                    origin="archive",
                    rows=rows.to_json(sightings),
                )
                self._exec(
                    sql.INSERT_DEVELOPMENT_CVES,
                    development_id=dev_id,
                    cves=rows.to_json(sorted(story.cves)),
                )
            for story in stories:
                for related in story.related:
                    if related in slug_of and slug_of[related] != story_slug(story):
                        self._exec(
                            sql.INSERT_DEVELOPMENT_LINK,
                            a_slug=story_slug(story),
                            b_slug=slug_of[related],
                            kind="rollup_of",
                            method="cve",
                        )
        return len(stories)

    def record_fetch_run(self, **fields: Any) -> None:
        with self._conn.transaction():
            self._exec(sql.INSERT_FETCH_RUN, **fields)
