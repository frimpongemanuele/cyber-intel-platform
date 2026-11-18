"""Evaluation harness: archive loading, cross-day story linking, recall@k."""

from datetime import date
from pathlib import Path

import pytest

from cyberintel.eval.archive import (
    GoldDevelopment,
    Story,
    evaluate,
    idf_weights,
    link_stories,
    load_archive,
    title_similarity,
)

FIX = Path(__file__).parent / "fixtures" / "archive"


def g(
    id_: str, day: int, title: str, cves: tuple[str, ...] = (), urgency: int = 3
) -> GoldDevelopment:
    return GoldDevelopment(
        id=f"2026-11-{day:02d}-{id_}",
        day=date(2026, 11, day),
        title=title,
        cves=frozenset(cves),
        urgency=urgency,
        confidence="HIGH",
        status="CONFIRMED",
        in_kev=False,
    )


def story_ids(stories: list[Story]) -> set[tuple[str, ...]]:
    return {tuple(m.id[11:] for m in s.members) for s in stories if len(s.members) > 1}


# --------------------------------------------------------------------- loading


def test_load_archive_reads_valid_files_and_reports_broken_ones() -> None:
    res = load_archive(FIX)
    assert len(res.developments) == 11
    assert len(res.problems) == 1 and "2026-11-04.json" in res.problems[0]


# --------------------------------------------------------------------- linking


def test_fixture_archive_stories() -> None:
    stories = link_stories(load_archive(FIX).developments)
    assert story_ids(stories) == {
        ("acme-vpn-authbypass", "acme-vpn-mass-exploitation"),
        ("widgetdb-sqli", "widgetdb-sqli-patch"),
    }
    rollups = {s.members[0].id[11:]: s.related for s in stories if s.is_rollup and s.related}
    assert set(rollups) == {"kev-carryover"}
    assert any("zebra" in r for r in rollups["kev-carryover"])


def test_rollup_bridging_unrelated_stories_does_not_chain_them() -> None:
    # The real bug found in the archive: a carry-over item lists two unrelated CVEs.
    devs = [
        g("checkpoint", 15, "Check Point gateway bug", ("CVE-2026-1",)),
        g("unrealircd", 15, "UnrealIRCd response injection", ("CVE-2026-2",)),
        g("carryover", 16, "KEV carry-over due today", ("CVE-2026-1", "CVE-2026-2")),
    ]
    stories = link_stories(devs)
    assert story_ids(stories) == set()
    (rollup,) = [s for s in stories if s.is_rollup]
    assert rollup.members[0].id.endswith("carryover")
    assert {r[11:] for r in rollup.related} == {"checkpoint", "unrealircd"}


def test_bundles_never_merge_by_cve() -> None:
    big = tuple(f"CVE-2026-{n}" for n in range(100, 106))
    devs = [g("patch-tuesday", 11, "Patch Tuesday", big), g("one-bug", 12, "Some bug", big[:1])]
    assert story_ids(link_stories(devs)) == set()


def test_focused_entries_sharing_a_cve_link_across_days() -> None:
    devs = [
        g("sshole", 10, "SSHole auth bypass", ("CVE-2026-123158",)),
        g("openssh-kev", 12, "OpenSSH added to KEV", ("CVE-2026-123158",)),
    ]
    assert story_ids(link_stories(devs)) == {("sshole", "openssh-kev")}


def test_no_links_on_same_day_or_beyond_gap() -> None:
    devs = [
        g("a", 1, "Same title here", ("CVE-2026-1",)),
        g("b", 1, "Same title here", ("CVE-2026-1",)),  # same day: not our job
        g("c", 20, "Same title here", ("CVE-2026-1",)),  # 19 days later: beyond 14-day gap
    ]
    assert story_ids(link_stories(devs)) == set()


def test_rare_shared_title_token_links_cve_less_stories() -> None:
    filler = [g(f"noise{i}", 2, f"ransomware report number {i}") for i in range(8)]
    devs = [
        *filler,
        g("fragnesia", 3, "Fragnesia kernel LPE"),
        g("fragnesia-chain", 5, "Fragnesia kernel LPE chained on firewalls"),
    ]
    assert ("fragnesia", "fragnesia-chain") in story_ids(link_stories(devs))


def test_common_shared_token_alone_does_not_link() -> None:
    filler = [g(f"ms{i}", 2, f"microsoft windows item {i}") for i in range(8)]
    devs = [*filler, g("x", 3, "microsoft outlook ntlm leak"), g("y", 5, "microsoft teams vishing")]
    assert not any("x" in s and "y" in s for s in story_ids(link_stories(devs)))


def test_idf_weighting() -> None:
    devs = [g(f"d{i}", 1, "common " + ("rare" if i == 0 else f"w{i}")) for i in range(6)]
    idf = idf_weights(devs)
    assert idf["rare"] > idf["common"]
    assert title_similarity(frozenset(), frozenset({"a"}), idf) == 0.0
    assert title_similarity(frozenset({"a"}), frozenset({"a"}), idf) == pytest.approx(1.0)


@pytest.mark.xfail(
    strict=True,
    reason="Known limitation: a terse first report and a verbose, renamed follow-up "
    "('Able2Shell' -> '4EverAble2Shell', no shared CVE) are not linked by title "
    "heuristics. Needs entity matching (vendor/product) + embeddings in the Phase 7 "
    "processor. strict=True makes this test flag when the limitation is fixed.",
)
def test_known_miss_renamed_verbose_followup() -> None:
    devs = [
        g("able2shell", 10, "N-able N-central Able2Shell: 33 alleged zero-days published"),
        g(
            "ncentral-4ever",
            17,
            "4EverAble2Shell: unauthenticated Apache Axis chain mass-exploited within "
            "hours of HF2; root on unnamed legacy builds; patched build effective",
            ("CVE-2026-1", "CVE-2026-2", "CVE-2026-3", "CVE-2026-4", "CVE-2026-5"),
        ),
    ]
    assert story_ids(link_stories(devs)) == {("able2shell", "ncentral-4ever")}


# --------------------------------------------------------------------- evaluation


def test_evaluate_recall_lookback_and_unevaluable() -> None:
    gold = load_archive(FIX).developments
    ranked = {
        date(2026, 11, 1): [frozenset({"CVE-2026-10001"})],
        date(2026, 11, 2): [frozenset({"CVE-2026-99999"})],
        date(2026, 11, 3): [frozenset({"CVE-2026-30003"})],
    }
    rep = evaluate(gold, ranked, k=10, urgency_min=4)
    # urgency>=4 with CVEs: acme(11-01), widgetdb(11-01), acme follow-up(11-02), zebra(11-03)
    assert rep.evaluable == 4
    assert rep.hits == 3  # acme follow-up found via 1-day lookback
    assert rep.misses == ("2026-11-01-widgetdb-sqli",)
    assert rep.not_evaluable == ("2026-11-01-quokka-ransomware",)
    assert rep.recall == pytest.approx(0.75)


def test_evaluate_respects_k_and_empty_inputs() -> None:
    gold = [g("x", 1, "x", ("CVE-2026-1",), urgency=5)]
    ranked = {date(2026, 11, 1): [frozenset({f"CVE-2026-{n}"}) for n in range(2, 12)]
              + [frozenset({"CVE-2026-1"})]}  # fmt: skip
    assert evaluate(gold, ranked, k=10).hits == 0  # it's at position 11
    assert evaluate(gold, ranked, k=11).hits == 1
    assert evaluate([], {}).recall == 0.0
