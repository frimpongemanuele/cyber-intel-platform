"""CLI for the optional AI layer.

    python -m cyberintel.ai status              # which backend is configured (no calls)
    python -m cyberintel.ai prompt <slug>       # print the exact prompt for one story (no calls)
    python -m cyberintel.ai run [--limit N]     # analyse recent stories, within the token cap

Configuration: see ``providers.provider_from_env`` plus
    CIT_DATABASE_URL[_FILE]     libpq DSN (needs INSERT on ai_analyses / ai_usage only)
    CIT_AI_DAILY_TOKEN_CAP      default 200000 (input + output, all models, per UTC day)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from cyberintel.ai.prompt import PROMPT_SHA256, PROMPT_VERSION, build_prompt
from cyberintel.ai.providers import provider_from_env
from cyberintel.ai.runner import (
    AnalysisRecord,
    Candidate,
    input_from_rows,
    record_params,
    run,
    usage_params,
)
from cyberintel.ai.schema import AnalysisInput
from cyberintel.store import ai_sql


class PgAIRepo:
    """psycopg-backed ``AIRepo``. Writes only ``ai_analyses`` and ``ai_usage``."""

    def __init__(self, conn: Any, tiers: Mapping[str, str]) -> None:
        self._conn, self._tiers = conn, tiers

    def _rows(self, statement: str, **params: Any) -> list[tuple[Any, ...]]:
        cur = self._conn.execute(statement.encode(), params)
        return cur.fetchall() if cur.description else []

    def candidates(self, since: date, limit: int) -> list[Candidate]:
        return [Candidate(*r) for r in self._rows(ai_sql.AI_CANDIDATES, since=since, limit=limit)]

    def by_slug(self, slug: str) -> Candidate | None:
        rows = self._rows(ai_sql.AI_DEVELOPMENT_BY_SLUG, slug=slug)
        return Candidate(*rows[0]) if rows else None

    def build_input(self, candidate: Candidate) -> AnalysisInput:
        cves = self._rows(ai_sql.AI_CVE_FACTS, development_id=candidate.id)
        docs = self._rows(ai_sql.AI_EVIDENCE, cve_ids=[r[0] for r in cves]) if cves else []
        return input_from_rows(candidate, cves, docs, self._tiers)

    def exists(self, development_id: int, provider: str, model: str, input_hash: str) -> bool:
        params = {"development_id": development_id, "provider": provider, "model": model}
        return bool(self._rows(ai_sql.AI_ANALYSIS_EXISTS, input_hash=input_hash, **params)[0][0])

    def tokens_on(self, day: date) -> int:
        return int(self._rows(ai_sql.AI_TOKENS_ON_DAY, day=day)[0][0])

    def record(self, development_id: int, record: AnalysisRecord, day: date) -> None:
        with self._conn.transaction():
            self._rows(ai_sql.INSERT_AI_ANALYSIS, **record_params(development_id, record))
            self._rows(ai_sql.ADD_AI_USAGE, **usage_params(record, day))


def _dsn() -> str:
    path = os.environ.get("CIT_DATABASE_URL_FILE")
    if path:
        return Path(path).read_text(encoding="utf-8").strip()
    return os.environ.get("CIT_DATABASE_URL", "")


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m cyberintel.ai", description="Optional AI analysis layer."
    )
    ap.add_argument("--config", type=Path, default=Path("config/sources.toml"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    p_prompt = sub.add_parser("prompt")
    p_prompt.add_argument("slug")
    p_run = sub.add_parser("run")
    p_run.add_argument("--limit", type=int, default=20)
    p_run.add_argument("--since-days", type=int, default=14)
    args = ap.parse_args(argv)

    provider = provider_from_env()
    if args.cmd == "status":
        status = {
            "provider": provider.name,
            "model": provider.model,
            "enabled": provider.enabled,
            "prompt_version": PROMPT_VERSION,
            "prompt_sha256": PROMPT_SHA256,
        }
        print(json.dumps(status, indent=2))
        return 0
    if args.cmd == "run" and not provider.enabled:
        print("AI layer disabled (CIT_AI_PROVIDER=none); nothing to do.")
        return 0

    import psycopg

    from cyberintel.sources import load_registry

    tiers = {s.name: s.trust_tier for s in load_registry(args.config).sources}
    with psycopg.connect(_dsn(), autocommit=True) as conn:
        repo = PgAIRepo(conn, tiers)
        if args.cmd == "prompt":
            cand = repo.by_slug(args.slug)
            if cand is None:
                print("no such story", file=sys.stderr)
                return 2
            prompt = build_prompt(repo.build_input(cand))
            print(prompt.system, "\n---\n", prompt.user, sep="")
            return 0
        cap = int(os.environ.get("CIT_AI_DAILY_TOKEN_CAP", "200000"))
        report = run(
            repo,
            provider,
            now=datetime.now(UTC),
            since_days=args.since_days,
            limit=args.limit,
            daily_token_cap=cap,
        )
    print(json.dumps(report.as_dict(), indent=2))
    return 1 if report.stopped == "too many consecutive provider errors" else 0


if __name__ == "__main__":
    raise SystemExit(main())
