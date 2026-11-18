"""AI layer against a real PostgreSQL (production SQL via the psql harness).

The headline test runs the whole injection corpus through the real runner and the real
SQL with a worst-case malicious model, and proves that no fact table (nor the priority
view) changes and that only validated rows are visible to the dashboard query.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, date, datetime
from typing import Any

import pytest
from aihelpers import CVE_A, CVE_B, URL_A, URL_B
from pgharness import PgDB, PsqlError
from test_ai_containment import CASES, MaliciousProvider

from cyberintel.ai.providers import Completion
from cyberintel.ai.runner import (
    AnalysisRecord,
    Candidate,
    input_from_rows,
    record_params,
    run,
    usage_params,
)
from cyberintel.ai.schema import MAX_EVIDENCE_ITEMS, AnalysisInput
from cyberintel.store import ai_sql, read_sql

NOW = datetime(2026, 11, 18, 7, 0, tzinfo=UTC)
FACT_TABLES = (
    "vulnerabilities",
    "cvss_scores",
    "kev_entries",
    "epss_scores",
    "documents",
    "developments",
    "development_sightings",
    "development_vulnerabilities",
    "development_links",
    "vulnerability_overview",
)


def _b(v: str) -> bool:
    return v == "t"


def _f(v: str) -> float | None:
    return float(v) if v else None


def _d(v: str) -> date | None:
    return date.fromisoformat(v) if v else None


def _ts(v: str) -> datetime | None:
    return datetime.fromisoformat(v) if v else None


class HarnessRepo:
    """``AIRepo`` over psql, executing exactly the production statements in ``ai_sql``."""

    def __init__(self, pg: PgDB) -> None:
        self.pg = pg

    def candidates(self, since: date, limit: int) -> list[Candidate]:
        rows = self.pg.run(ai_sql.AI_CANDIDATES, since=since, limit=limit)
        return [
            Candidate(int(r[0]), r[1], r[2], date.fromisoformat(r[3]), date.fromisoformat(r[4]))
            for r in rows
        ]

    def build_input(self, c: Candidate) -> AnalysisInput:
        cves: list[list[Any]] = [
            [
                r[0],
                r[1] or None,
                _b(r[2]),
                _d(r[3]),
                _b(r[4]),
                _f(r[5]),
                _f(r[6]),
                r[7] or None,
                r[8] or None,
                r[9] or None,
                _f(r[10]),
            ]
            for r in self.pg.run(ai_sql.AI_CVE_FACTS, development_id=c.id)
        ]
        docs: list[list[Any]] = []
        if cves:
            docs = [
                [int(r[0]), r[1], r[2], r[3], r[4], _ts(r[5])]
                for r in self.pg.run(ai_sql.AI_EVIDENCE, cve_ids=[x[0] for x in cves])
            ]
        return input_from_rows(c, cves, docs, {"vendor-psirt": "primary"})

    def exists(self, development_id: int, provider: str, model: str, input_hash: str) -> bool:
        return _b(
            self.pg.scalar(
                ai_sql.AI_ANALYSIS_EXISTS,
                development_id=development_id,
                provider=provider,
                model=model,
                input_hash=input_hash,
            )
        )

    def tokens_on(self, day: date) -> int:
        return int(self.pg.scalar(ai_sql.AI_TOKENS_ON_DAY, day=day))

    def record(self, development_id: int, rec: AnalysisRecord, day: date) -> None:
        self.pg.run(ai_sql.INSERT_AI_ANALYSIS, **record_params(development_id, rec))
        self.pg.run(ai_sql.ADD_AI_USAGE, **usage_params(rec, day))


def seed(pg: PgDB, n_stories: int, excerpts: list[str]) -> None:
    """n stories, each with its own CVE in KEV and one document per excerpt."""
    for i in range(1, n_stories + 1):
        cve = f"CVE-2026-{20000 + i}"
        pg.run(
            "INSERT INTO kev_entries (cve_id, vendor, product, name, date_added, ransomware_known,"
            " short_description, required_action, catalog_version)"
            " VALUES (%(c)s, 'Widget', 'Gateway', 'Widget Gateway RCE', '2026-11-10', true,"
            " 'RCE', 'Patch', '2026.11.10')",
            c=cve,
        )
        pg.run(
            "INSERT INTO epss_scores (cve_id, epss, percentile) VALUES (%(c)s, 0.9, 0.99)", c=cve
        )
        pg.run(
            "INSERT INTO developments (slug, title, first_seen, last_seen, status, confidence)"
            " VALUES (%(s)s, %(t)s, '2026-11-10', '2026-11-12', 'CONFIRMED', 'HIGH')",
            s=f"story-{i}",
            t=f"Widget Gateway story {i}",
        )
        pg.run(
            "INSERT INTO development_vulnerabilities (development_id, cve_id)"
            " SELECT id, %(c)s FROM developments WHERE slug = %(s)s",
            c=cve,
            s=f"story-{i}",
        )
        pg.run(
            "INSERT INTO documents (source_name, canonical_url, url, title, excerpt, cves)"
            " VALUES ('vendor-psirt', %(u)s, %(u)s, 'Advisory', 'Fixed in 4.2.1.',"
            " %(cves)s::text[])",
            u=f"https://vendor.example/adv/{i}",
            cves=[cve],
        )
        pg.run(
            "INSERT INTO documents (source_name, canonical_url, url, title, excerpt, cves)"
            " VALUES ('research-blog', %(u)s, %(u)s, 'Write-up', %(e)s, %(cves)s::text[])",
            u=f"https://research.example/p/{i}",
            # PostgreSQL text cannot hold NUL at all, so a stored document never contains one
            e=excerpts[(i - 1) % len(excerpts)][:600].replace("\x00", ""),
            cves=[cve],
        )


def snapshot(pg: PgDB) -> dict[str, str]:
    return {
        t: pg.scalar(
            f"SELECT md5(COALESCE(string_agg(x::text, '|' ORDER BY x::text), '')) FROM {t} x"
        )
        for t in FACT_TABLES
    }


class CorpusProvider:
    """Worst case for every story: story-i gets the attacker output of corpus case i."""

    name, model, enabled = "malicious", "worst-case", True

    def __init__(self) -> None:
        self.i = 0

    def complete(self, prompt: Any) -> Any:
        # adapt the per-case payloads to this story's real evidence URL and CVE
        case = CASES[self.i]
        self.i += 1
        docs = prompt.user.split(f"\n{prompt.boundary}\n")[1].splitlines()
        urls = [json.loads(d)["url"] for d in docs if d.strip()]
        head = "FACTS (authoritative, from the platform database):\n"
        cve = json.loads(prompt.user.split(head)[1].split("\n\nEVIDENCE")[0])["cves"][0]["cve_id"]
        comp = MaliciousProvider(case).complete(prompt)
        # re-target the generic payload at this story's real evidence URLs and CVE
        text = comp.text.replace(URL_A, urls[0]).replace(URL_B, urls[1])
        text = text.replace(CVE_A, cve).replace(CVE_B, cve)
        return Completion(text, comp.input_tokens, comp.output_tokens)


def test_constants_match_schema() -> None:
    assert "LIMIT 8" in ai_sql.AI_EVIDENCE and MAX_EVIDENCE_ITEMS == 8
    assert "LIMIT 20" in ai_sql.AI_CVE_FACTS


AI_STATEMENTS = {n: s for n, s in vars(ai_sql).items() if n.isupper() and isinstance(s, str)}


@pytest.mark.parametrize("name", sorted(AI_STATEMENTS))
def test_ai_sql_writes_only_ai_tables(name: str) -> None:
    writes = re.findall(
        r"\b(INSERT\s+INTO|(?<!DO\s)UPDATE|DELETE\s+FROM|TRUNCATE|ALTER|DROP|CREATE)\s+(\w+)",
        AI_STATEMENTS[name],
        re.IGNORECASE,
    )
    assert all(table.startswith("ai_") for _, table in writes), writes


def test_whole_corpus_cannot_change_any_fact(pg: PgDB) -> None:
    seed(pg, len(CASES), [c["document"] for c in CASES])
    before = snapshot(pg)
    report = run(HarnessRepo(pg), CorpusProvider(), now=NOW, limit=100, daily_token_cap=10**9)

    assert report.analysed == len(CASES)
    n_rejected = sum(c["expect"] == "rejected" for c in CASES)
    assert report.rejected == n_rejected and report.accepted == len(CASES) - n_rejected
    assert snapshot(pg) == before, "AI run changed a fact table or the priority view"

    # rejected rows keep reasons and a forensic raw copy, never an output
    assert pg.scalar(
        "SELECT count(*) FROM ai_analyses WHERE NOT validated AND output IS NULL"
    ) == str(n_rejected)
    # the dashboard query can only ever see validated rows
    for slug_row in pg.run("SELECT id, slug FROM developments ORDER BY id"):
        rows = pg.run(read_sql.LATEST_AI_ANALYSIS, development_id=int(slug_row[0]))
        case = CASES[int(slug_row[1].split("-")[1]) - 1]
        assert (len(rows) == 1) == (case["expect"] == "contained"), case["id"]
    usage = pg.run("SELECT calls, rejected FROM ai_usage")
    assert usage == [[str(len(CASES)), str(n_rejected)]]


def test_rerun_is_idempotent_and_token_cap_applies(pg: PgDB) -> None:
    seed(pg, 3, ["benign"])
    from test_ai_runner import ScriptedProvider

    run(HarnessRepo(pg), ScriptedProvider(), now=NOW, limit=1)
    again = ScriptedProvider()
    report = run(HarnessRepo(pg), again, now=NOW, limit=10, daily_token_cap=500)
    assert report.cached == 1 and again.calls == 0 and report.stopped == "daily token cap reached"


def test_constraints(pg: PgDB) -> None:
    seed(pg, 1, ["x"])
    base = (
        "INSERT INTO ai_analyses (development_id, provider, model, prompt_version, prompt_sha256,"
        " input_hash, document_ids, cve_ids, validated, output, rejected_reasons)"
        " SELECT id, 'p', 'm', 'v1', repeat('a', 64), repeat('b', 64), '{}', '{}', <V>, <O>, <R>"
        " FROM developments"
    )
    bad = [
        ("true", "NULL", "'{}'"),  # validated without output
        ("false", "'{}'::jsonb", "'{x}'"),  # rejected with output
        ("false", "NULL", "'{}'"),  # rejected without a reason
        ("true", "'{}'::jsonb", "'{x}'"),  # validated with reasons
        ("true", "'[1]'::jsonb", "'{}'"),  # output not an object
    ]
    for v, o, r in bad:
        with pytest.raises(PsqlError, match="check constraint"):
            pg.run(base.replace("<V>", v).replace("<O>", o).replace("<R>", r))
    ok = base.replace("<V>", "true").replace("<O>", "'{}'::jsonb").replace("<R>", "'{}'")
    pg.run(ok)
    with pytest.raises(PsqlError, match="duplicate key"):
        pg.run(ok)
