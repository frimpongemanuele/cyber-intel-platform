"""Run the optional AI analysis over recent stories.

The runner is deliberately boring: pick candidates, build the input from fact tables,
skip anything already analysed with the same prompt + input, stop at the daily token cap,
call the provider, validate, and record the result (accepted or rejected) in
``ai_analyses``. It never writes anywhere else.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any, Protocol

from cyberintel.ai.prompt import PROMPT_SHA256, PROMPT_VERSION, build_prompt, input_hash
from cyberintel.ai.providers import Provider, ProviderError
from cyberintel.ai.schema import AnalysisInput, CveFact, Evidence
from cyberintel.ai.validate import MAX_RAW_CHARS, validate_output
from cyberintel.security_events import emit

MAX_CONSECUTIVE_ERRORS = 3


@dataclass(frozen=True, slots=True)
class Candidate:
    id: int
    slug: str
    title: str
    first_seen: date
    last_seen: date


@dataclass(frozen=True, slots=True)
class AnalysisRecord:
    provider: str
    model: str
    input_hash: str
    document_ids: tuple[int, ...]
    cve_ids: tuple[str, ...]
    validated: bool
    output: dict[str, Any] | None
    rejected_reasons: tuple[str, ...]
    raw_output: str
    injection_suspected: bool
    input_tokens: int
    output_tokens: int
    prompt_version: str = PROMPT_VERSION
    prompt_sha256: str = PROMPT_SHA256

    @property
    def raw_sha256(self) -> str:
        return hashlib.sha256(self.raw_output.encode()).hexdigest()


def analyse(
    given: AnalysisInput, provider: Provider, *, token: Callable[[int], str] = secrets.token_hex
) -> AnalysisRecord:
    """One call: prompt -> provider -> validator. Raises ProviderError on transport failure."""
    prompt = build_prompt(given, token=token)
    completion = provider.complete(prompt)
    result = validate_output(completion.text, given, canary=prompt.canary, boundary=prompt.boundary)
    out = result.output
    return AnalysisRecord(
        provider=provider.name,
        model=provider.model,
        input_hash=input_hash(given),
        document_ids=tuple(e.id for e in given.evidence),
        cve_ids=tuple(c.cve_id for c in given.cves),
        validated=result.ok,
        output=out.model_dump(mode="json") if result.ok and out is not None else None,
        rejected_reasons=tuple(r[:300] for r in result.reasons[:20]),
        # PostgreSQL text cannot hold NUL; a hostile model must not be able to crash the insert
        raw_output=completion.text[:MAX_RAW_CHARS].replace("\x00", "\ufffd"),
        injection_suspected=bool(out and out.injection_suspected),
        input_tokens=completion.input_tokens,
        output_tokens=completion.output_tokens,
    )


class AIRepo(Protocol):
    def candidates(self, since: date, limit: int) -> Sequence[Candidate]: ...
    def build_input(self, candidate: Candidate) -> AnalysisInput: ...
    def exists(self, development_id: int, provider: str, model: str, input_hash: str) -> bool: ...
    def tokens_on(self, day: date) -> int: ...
    def record(self, development_id: int, record: AnalysisRecord, day: date) -> None: ...


@dataclass(slots=True)
class RunReport:
    analysed: int = 0
    accepted: int = 0
    rejected: int = 0
    cached: int = 0
    no_evidence: int = 0
    errors: int = 0
    stopped: str | None = None
    rejected_slugs: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "analysed": self.analysed,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "cached": self.cached,
            "no_evidence": self.no_evidence,
            "errors": self.errors,
            "stopped": self.stopped,
            "rejected_slugs": list(self.rejected_slugs),
        }


def run(
    repo: AIRepo,
    provider: Provider,
    *,
    now: datetime,
    since_days: int = 14,
    limit: int = 20,
    daily_token_cap: int = 200_000,
) -> RunReport:
    report = RunReport()
    if not provider.enabled:
        report.stopped = "provider disabled"
        return report
    today = now.date()
    consecutive_errors = 0
    for cand in repo.candidates(today - timedelta(days=since_days), limit):
        given = repo.build_input(cand)
        if not given.evidence:
            report.no_evidence += 1
            continue
        if repo.exists(cand.id, provider.name, provider.model, input_hash(given)):
            report.cached += 1
            continue
        if repo.tokens_on(today) >= daily_token_cap:
            report.stopped = "daily token cap reached"
            emit("ai.token_cap_reached", provider=provider.name, cap=daily_token_cap)
            break
        try:
            record = analyse(given, provider)
        except ProviderError:
            report.errors += 1
            consecutive_errors += 1
            if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                report.stopped = "too many consecutive provider errors"
                emit("ai.provider_failing", provider=provider.name, errors=consecutive_errors)
                break
            continue
        consecutive_errors = 0
        repo.record(cand.id, record, today)
        report.analysed += 1
        if record.injection_suspected:
            emit("ai.injection_suspected", story=cand.slug, provider=provider.name)
        if record.validated:
            report.accepted += 1
        else:
            report.rejected += 1
            report.rejected_slugs.append(cand.slug)
            # what the gate caught (reasons are validator text, already length-capped)
            emit(
                "ai.output_rejected",
                story=cand.slug,
                provider=provider.name,
                model=provider.model,
                reasons=list(record.rejected_reasons[:3]),
            )
    return report


# --------------------------------------------------------------------------- row mapping


def input_from_rows(
    cand: Candidate,
    cve_rows: Sequence[Sequence[Any]],
    doc_rows: Sequence[Sequence[Any]],
    tiers: Mapping[str, str],
) -> AnalysisInput:
    cves = tuple(
        CveFact(
            cve_id=r[0],
            title=r[1],
            in_kev=bool(r[2]),
            kev_date_added=r[3],
            ransomware_known=bool(r[4]),
            epss_percentile=None if r[5] is None else float(r[5]),
            headline_score=None if r[6] is None else float(r[6]),
            headline_version=r[7],
            headline_origin=r[8],
            ssvc_exploitation=r[9],
            priority=None if r[10] is None else float(r[10]),
        )
        for r in cve_rows
    )
    evidence = tuple(
        Evidence(
            id=int(r[0]),
            url=r[1],
            source_name=r[2],
            trust_tier=tiers.get(r[2], "unknown"),
            title=r[3],
            excerpt=r[4] or "",
            published_at=r[5],
        )
        for r in doc_rows
    )
    return AnalysisInput(
        development_slug=cand.slug,
        development_title=cand.title,
        first_seen=cand.first_seen,
        last_seen=cand.last_seen,
        cves=cves,
        evidence=evidence,
    )


def record_params(development_id: int, rec: AnalysisRecord) -> dict[str, Any]:
    return {
        "development_id": development_id,
        "provider": rec.provider,
        "model": rec.model,
        "prompt_version": rec.prompt_version,
        "prompt_sha256": rec.prompt_sha256,
        "input_hash": rec.input_hash,
        "document_ids": list(rec.document_ids),
        "cve_ids": list(rec.cve_ids),
        "validated": rec.validated,
        "output": None if rec.output is None else json.dumps(rec.output, sort_keys=True),
        "rejected_reasons": list(rec.rejected_reasons),
        "raw_output": rec.raw_output,
        "injection_suspected": rec.injection_suspected,
        "input_tokens": rec.input_tokens,
        "output_tokens": rec.output_tokens,
    }


def usage_params(rec: AnalysisRecord, day: date) -> dict[str, Any]:
    return {
        "day": day,
        "provider": rec.provider,
        "model": rec.model,
        "rejected": 0 if rec.validated else 1,
        "input_tokens": rec.input_tokens,
        "output_tokens": rec.output_tokens,
    }
