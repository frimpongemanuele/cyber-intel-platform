"""Ingest runner: for each due source, collect -> store -> record the outcome.

    python -m cyberintel.ingest              # run every due source once
    python -m cyberintel.ingest --source cisa-kev --force

Failure policy (the important part):
* *Expected* source failures (network, policy rejection, HTTP errors, malformed or unsafe
  payloads) are recorded in ``fetch_runs`` / ``source_state`` and the run moves on.
* *Anything else* (a database error, a bug) propagates and fails the run loudly. A bug
  must never be filed as "the source was flaky".
* Failing sources back off exponentially instead of being hammered every cycle.

Depends on the ``StoreLike`` protocol rather than psycopg, so all of this logic is unit
tested without a database.
"""

from __future__ import annotations

import argparse
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from cyberintel.collectors.cve5 import Cve5Error, Cve5Record
from cyberintel.collectors.epss import EpssError, EpssSnapshot
from cyberintel.collectors.kev import KevCatalog, KevError
from cyberintel.collectors.nvd import NvdError, NvdPage
from cyberintel.collectors.run import (
    NVD_MAX_WINDOW,
    CollectError,
    collect_cve5,
    collect_epss,
    collect_feed,
    collect_kev,
    iter_nvd_modified,
)
from cyberintel.net.decompress import DecompressionError
from cyberintel.net.types import Fetcher, FetchError, FetchResult, Validators
from cyberintel.parsing.feeds import Feed, FeedError
from cyberintel.sources import Kind, Registry, Source

# Failures that mean "this source, this time" -- recorded, not raised.
SOURCE_ERRORS: tuple[type[Exception], ...] = (
    FetchError,
    FeedError,
    KevError,
    EpssError,
    NvdError,
    Cve5Error,
    CollectError,
    DecompressionError,
)
MAX_BACKOFF_DOUBLINGS = 6  # cap: poll interval x 64
NVD_OVERLAP = timedelta(hours=1)  # re-read the window edge so nothing falls between runs
NVD_FIRST_RUN = timedelta(days=1)
CVE5_PER_RUN = 25


class SourceStateLike(Protocol):
    @property
    def validators(self) -> Validators | None: ...
    @property
    def consecutive_failures(self) -> int: ...
    @property
    def last_success_at(self) -> datetime | None: ...
    @property
    def last_attempt_at(self) -> datetime | None: ...


class StoreLike(Protocol):
    def state(self, source_name: str) -> SourceStateLike: ...
    def store_kev(self, catalog: KevCatalog, seen_at: datetime) -> Any: ...
    def store_epss(self, snapshot: EpssSnapshot, seen_at: datetime) -> int: ...
    def store_documents(
        self, source_name: str, feed: Feed, seen_at: datetime
    ) -> tuple[int, int]: ...
    def store_nvd_page(self, page: NvdPage, seen_at: datetime) -> list[str]: ...
    def store_cve5(self, records: Sequence[Cve5Record], seen_at: datetime) -> list[str]: ...
    def cve5_queue(self, limit: int) -> list[str]: ...
    def record_success(self, source_name: str, validators: Validators, at: datetime) -> None: ...
    def record_failure(self, source_name: str, error: str, at: datetime) -> None: ...
    def record_fetch_run(self, **fields: Any) -> None: ...


@dataclass(frozen=True, slots=True)
class RunReport:
    source: str
    outcome: str  # ok | not_modified | error | skipped
    records_ok: int = 0
    records_rejected: int = 0
    detail: str = ""


def is_due(source: Source, state: SourceStateLike, now: datetime) -> bool:
    """Due if never attempted, or the (backed-off) poll interval has elapsed."""
    if state.last_attempt_at is None:
        return True
    doublings = min(state.consecutive_failures, MAX_BACKOFF_DOUBLINGS)
    interval = timedelta(minutes=source.poll_minutes) * (1 << doublings)
    return now - state.last_attempt_at >= interval


def nvd_window(state: SourceStateLike, now: datetime) -> tuple[datetime, datetime]:
    start = (state.last_success_at - NVD_OVERLAP) if state.last_success_at else now - NVD_FIRST_RUN
    return max(start, now - NVD_MAX_WINDOW + timedelta(minutes=1)), now


@dataclass
class _Outcome:
    fetched: FetchResult | None = None
    not_modified: bool = False
    ok: int = 0
    rejected: int = 0


def _collect_and_store(
    source: Source,
    fetcher: Fetcher,
    store: StoreLike,
    state: SourceStateLike,
    now: datetime,
    nvd_api_key: str | None,
) -> _Outcome:
    out = _Outcome()
    if source.kind == "kev":
        kev = collect_kev(fetcher, source, state.validators)
        out.fetched, out.not_modified = kev.fetched, kev.data is None
        if kev.data is not None:
            store.store_kev(kev.data, now)
            out.ok, out.rejected = len(kev.data.entries), len(kev.data.rejected)
    elif source.kind == "epss":
        epss = collect_epss(fetcher, source, state.validators)
        out.fetched, out.not_modified = epss.fetched, epss.data is None
        if epss.data is not None:
            out.ok, out.rejected = store.store_epss(epss.data, now), epss.data.rejected_rows
    elif source.kind == "feed":
        feed = collect_feed(fetcher, source, state.validators)
        out.fetched, out.not_modified = feed.fetched, feed.data is None
        if feed.data is not None:
            inserted, updated = store.store_documents(source.name, feed.data, now)
            out.ok = inserted + updated
    elif source.kind == "nvd":
        start, end = nvd_window(state, now)
        for page in iter_nvd_modified(fetcher, source, start, end, api_key=nvd_api_key):
            out.ok += len(store.store_nvd_page(page, now))
            out.rejected += len(page.rejected)
    elif source.kind == "cve5":
        records = [collect_cve5(fetcher, source, cve) for cve in store.cve5_queue(CVE5_PER_RUN)]
        out.ok = len(store.store_cve5(records, now))
    else:
        raise CollectError(f"no ingest job for source kind {source.kind!r}")
    return out


def run_source(
    source: Source,
    fetcher: Fetcher,
    store: StoreLike,
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    force: bool = False,
    nvd_api_key: str | None = None,
) -> RunReport:
    started = clock()
    state = store.state(source.name)
    if not force and not is_due(source, state, started):
        return RunReport(source.name, "skipped", detail="not due")
    try:
        result = _collect_and_store(source, fetcher, store, state, started, nvd_api_key)
    except SOURCE_ERRORS as exc:
        message = f"{type(exc).__name__}: {exc}"[:500]
        finished = clock()
        store.record_failure(source.name, message, finished)
        store.record_fetch_run(
            source_name=source.name,
            started_at=started,
            finished_at=finished,
            outcome="error",
            http_status=getattr(exc, "status", None),
            bytes=None,
            peer_address=None,
            records_ok=None,
            records_rejected=None,
            error=message,
        )
        return RunReport(source.name, "error", detail=message)

    finished = clock()
    f = result.fetched
    store.record_success(source.name, f.validators if f else Validators(), finished)
    outcome = "not_modified" if result.not_modified else "ok"
    store.record_fetch_run(
        source_name=source.name,
        started_at=started,
        finished_at=finished,
        outcome=outcome,
        http_status=f.status if f else None,
        bytes=len(f.body) if f else None,
        peer_address=f.peer_address if f else None,
        records_ok=result.ok,
        records_rejected=result.rejected,
        error=None,
    )
    return RunReport(source.name, outcome, result.ok, result.rejected)


INGEST_KINDS: tuple[Kind, ...] = ("kev", "epss", "feed", "nvd", "cve5")  # cve5 last: enriches


def run_once(
    registry: Registry,
    fetcher: Fetcher,
    store: StoreLike,
    *,
    only: str | None = None,
    force: bool = False,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    nvd_api_key: str | None = None,
) -> list[RunReport]:
    if only:
        sources = [registry.get(only)]
    else:
        sources = [s for kind in INGEST_KINDS for s in registry.enabled(kind)]
    return [
        run_source(s, fetcher, store, clock=clock, force=force, nvd_api_key=nvd_api_key)
        for s in sources
    ]


def main(argv: Sequence[str] | None = None) -> int:
    import psycopg

    from cyberintel.dbconfig import database_dsn
    from cyberintel.net.fetch import SafeFetcher
    from cyberintel.sources import load_registry
    from cyberintel.store.repo import Store

    ap = argparse.ArgumentParser(description="Run due ingestion jobs.")
    ap.add_argument("--config", type=Path, default=Path("config/sources.toml"))
    ap.add_argument("--source", help="run only this source")
    ap.add_argument("--force", action="store_true", help="ignore poll intervals / backoff")
    ap.add_argument(
        "--every", type=float, help="keep running: check for due sources every N seconds"
    )
    args = ap.parse_args(argv)

    registry = load_registry(args.config)
    proxy = os.environ.get("CIT_EGRESS_PROXY") or None
    nvd_key = _optional_secret("CIT_NVD_API_KEY")  # never logged or put in URLs

    def once() -> int:
        with (
            psycopg.connect(database_dsn(), autocommit=True) as conn,
            SafeFetcher(registry.allowlist(), proxy=proxy) as fetcher,
        ):
            reports = run_once(
                registry,
                fetcher,
                Store(conn),
                only=args.source,
                force=args.force,
                nvd_api_key=nvd_key,
            )
        for r in reports:
            print(
                f"{r.source:28} {r.outcome:13} ok={r.records_ok:<7}"
                f" rejected={r.records_rejected:<5} {r.detail[:80]}",
                flush=True,
            )
        return 1 if any(r.outcome == "error" for r in reports) else 0

    if args.every:
        from cyberintel.loop import run_every

        run_every(once, every=args.every, jitter=min(60.0, args.every / 10))
        return 0
    return once()


def _optional_secret(name: str) -> str | None:
    path = os.environ.get(f"{name}_FILE")
    if path:
        return Path(path).read_text(encoding="utf-8").strip() or None
    return os.environ.get(name) or None


if __name__ == "__main__":
    raise SystemExit(main())
