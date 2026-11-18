from __future__ import annotations

import json
from datetime import UTC, date, datetime
from typing import Any

from aihelpers import good_output, make_input

from cyberintel.ai.prompt import Prompt, input_hash
from cyberintel.ai.providers import Completion, NoneProvider, ProviderError
from cyberintel.ai.runner import AnalysisRecord, Candidate, record_params, run, usage_params
from cyberintel.ai.schema import AnalysisInput

NOW = datetime(2026, 11, 18, 7, 0, tzinfo=UTC)


def cand(i: int) -> Candidate:
    return Candidate(i, f"story-{i}", f"Story {i}", date(2026, 11, 10), date(2026, 11, 12))


class FakeRepo:
    def __init__(self, n: int = 3, *, no_evidence: set[int] | None = None) -> None:
        self.cands = [cand(i) for i in range(1, n + 1)]
        self.no_evidence = no_evidence or set()
        self.recorded: list[tuple[int, AnalysisRecord]] = []
        self.tokens = 0
        self.since: date | None = None

    def candidates(self, since: date, limit: int) -> list[Candidate]:
        self.since = since
        return self.cands[:limit]

    def build_input(self, c: Candidate) -> AnalysisInput:
        if c.id in self.no_evidence:
            return make_input(development_slug=c.slug, evidence=())
        return make_input(development_slug=c.slug)

    def exists(self, development_id: int, provider: str, model: str, h: str) -> bool:
        return any(d == development_id and r.input_hash == h for d, r in self.recorded)

    def tokens_on(self, day: date) -> int:
        return self.tokens

    def record(self, development_id: int, rec: AnalysisRecord, day: date) -> None:
        self.recorded.append((development_id, rec))
        self.tokens += rec.input_tokens + rec.output_tokens


class ScriptedProvider:
    name, model, enabled = "scripted", "m1", True

    def __init__(self, *outputs: str | Exception) -> None:
        self.outputs = list(outputs)
        self.calls = 0

    def complete(self, prompt: Prompt) -> Completion:
        self.calls += 1
        out = self.outputs.pop(0) if self.outputs else json.dumps(good_output())
        if isinstance(out, Exception):
            raise out
        return Completion(out, 400, 100)


def test_disabled_provider_makes_no_calls_and_touches_nothing() -> None:
    repo = FakeRepo()
    report = run(repo, NoneProvider(), now=NOW)
    assert report.stopped == "provider disabled" and repo.recorded == [] and repo.since is None


def test_accepts_rejects_and_records_both() -> None:
    repo = FakeRepo(2)
    report = run(
        repo, ScriptedProvider(json.dumps(good_output()), "not json"), now=NOW, since_days=7
    )
    assert repo.since == date(2026, 11, 11)
    assert (report.accepted, report.rejected, report.rejected_slugs) == (1, 1, ["story-2"])
    ok, bad = repo.recorded[0][1], repo.recorded[1][1]
    assert ok.validated and ok.output is not None and ok.output["confidence"] == "HIGH"
    assert (
        not bad.validated
        and bad.output is None
        and bad.rejected_reasons
        and bad.raw_output == "not json"
    )


def test_idempotent_rerun_makes_no_calls() -> None:
    repo = FakeRepo(2)
    run(repo, ScriptedProvider(), now=NOW)
    provider = ScriptedProvider()
    report = run(repo, provider, now=NOW)
    assert provider.calls == 0 and report.cached == 2


def test_rejected_results_are_cached_too() -> None:
    # A hostile document that makes the model misbehave is not re-sent every run.
    repo = FakeRepo(1)
    run(repo, ScriptedProvider("garbage"), now=NOW)
    provider = ScriptedProvider()
    assert run(repo, provider, now=NOW).cached == 1 and provider.calls == 0


def test_daily_token_cap_stops_before_the_next_call() -> None:
    repo = FakeRepo(5)
    provider = ScriptedProvider()
    report = run(repo, provider, now=NOW, daily_token_cap=1000)
    assert provider.calls == 2 and report.stopped == "daily token cap reached"


def test_stories_without_evidence_are_skipped_without_a_call() -> None:
    repo = FakeRepo(2, no_evidence={1})
    provider = ScriptedProvider()
    report = run(repo, provider, now=NOW)
    assert report.no_evidence == 1 and provider.calls == 1


def test_provider_errors_are_not_recorded_and_stop_after_three() -> None:
    repo = FakeRepo(5)
    provider = ScriptedProvider(*(ProviderError("x") for _ in range(5)))
    report = run(repo, provider, now=NOW)
    assert report.errors == 3 and report.stopped == "too many consecutive provider errors"
    assert repo.recorded == []


def test_error_counter_resets_after_success() -> None:
    repo = FakeRepo(5)
    p = ScriptedProvider(
        ProviderError("a"), ProviderError("b"), json.dumps(good_output()), ProviderError("c")
    )
    report = run(repo, p, now=NOW)
    assert report.errors == 3 and report.stopped is None and report.accepted == 2


def test_record_params_shape() -> None:
    repo = FakeRepo(1)
    run(repo, ScriptedProvider(), now=NOW)
    dev_id, rec = repo.recorded[0]
    params: dict[str, Any] = record_params(dev_id, rec)
    assert params["input_hash"] == input_hash(make_input(development_slug="story-1"))
    assert json.loads(params["output"])["confidence"] == "HIGH"
    assert params["document_ids"] == [1, 2] and params["validated"] is True
    assert usage_params(rec, date(2026, 11, 18))["rejected"] == 0


def test_nul_in_raw_output_is_neutralised() -> None:
    repo = FakeRepo(1)
    run(repo, ScriptedProvider("bad\x00output"), now=NOW)
    assert repo.recorded[0][1].raw_output == "bad" + chr(0xFFFD) + "output"
