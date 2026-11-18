"""Evaluation harness: archive loading, cross-day story linking, recall@k."""

from datetime import date
from pathlib import Path

import pytest

from cyberintel.eval.archive import (
    GoldDevelopment,
    Story,
    entity_tokens,
    evaluate,
    idf_weights,
    link_stories,
    load_archive,
    title_similarity,
)

FIX = Path(__file__).parent / "fixtures" / "archive"


def g(
    id_: str,
    day: int,
    title: str,
    cves: tuple[str, ...] = (),
    urgency: int = 3,
    vendors: tuple[str, ...] = (),
    products: tuple[str, ...] = (),
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
        vendors=vendors,
        products=products,
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


def filler(n: int = 8) -> list[GoldDevelopment]:
    return [
        g(f"noise{i}", 2, f"unrelated item {i}", vendors=(f"Vendor{i}",), products=(f"Product{i}",))
        for i in range(n)
    ]


def ncentral_case() -> list[GoldDevelopment]:
    return [
        *filler(),
        g(
            "able2shell",
            10,
            "N-able N-central Able2Shell: 33 alleged zero-days published",
            vendors=("N-able",),
            products=("N-central",),
        ),
        g(
            "ncentral-4ever",
            17,
            "4EverAble2Shell: unauthenticated Apache Axis chain mass-exploited within hours of "
            "HF2; root on unnamed legacy builds; patched build effective",
            ("CVE-2026-1", "CVE-2026-2", "CVE-2026-3", "CVE-2026-4", "CVE-2026-5"),
            vendors=("N-able", "Apache (Axis)"),
            products=("N-able N-central", "N-able N-central managed Windows agents"),
        ),
    ]


def test_renamed_verbose_followup_links_via_entities() -> None:
    # Formerly xfail(strict=True): the title-only linker missed this real N-central case.
    assert ("able2shell", "ncentral-4ever") in story_ids(link_stories(ncentral_case()))


def test_title_only_linker_still_misses_it() -> None:
    # Documents WHY entity matching exists: titles alone are not enough.
    assert not story_ids(link_stories(ncentral_case(), use_entities=False))


def test_cve_veto_keeps_same_product_different_bugs_apart() -> None:
    devs = [
        *filler(),
        g(
            "chrome-a",
            3,
            "Chrome zero-day A",
            ("CVE-2026-1001",),
            vendors=("Google",),
            products=("Chrome",),
        ),
        g(
            "chrome-b",
            10,
            "Chrome zero-day B",
            ("CVE-2026-2002",),
            vendors=("Google",),
            products=("Chrome",),
        ),
    ]
    assert story_ids(link_stories(devs)) == set()


def test_shared_package_ecosystem_is_not_identity() -> None:
    # Real wrong merge found on the archive: two supply-chain stories sharing "npm".
    devs = [
        *filler(),
        g(
            "gha",
            13,
            "GitHub Actions workflow compromise",
            vendors=("GitHub",),
            products=("GitHub Actions", "npm", "crates.io"),
        ),
        g("facestealer", 14, "DPRK fake-Zoom infostealer", vendors=("Zoom", "npm", "crates.io")),
    ]
    assert story_ids(link_stories(devs)) == set()


def test_common_entity_alone_does_not_link() -> None:
    devs = [
        *[g(f"ms{i}", 2, f"item {i}", vendors=("Microsoft",)) for i in range(8)],
        g("x", 3, "Outlook NTLM leak", vendors=("Microsoft",), products=("Outlook",)),
        g("y", 5, "Teams vishing", vendors=("Microsoft",), products=("Teams",)),
    ]
    assert not any({"x", "y"} <= set(s) for s in story_ids(link_stories(devs)))


@pytest.mark.parametrize(
    ("cves", "vendors", "products", "bundle"),
    [
        (5, (), (), True),  # no entity data: conservative CVE-count fallback
        (4, ("A", "B", "C"), (), False),  # few CVEs: never a bundle
        (8, ("N-able",), ("N-central",), False),  # one product's hotfix set
        (5, ("N-able", "Apache (Axis)"), ("N-central", "agents"), False),  # + a component
        (12, ("Citrix",), ("ADC", "Gateway", "SDX", "VPX"), False),  # one advisory
        (7, ("Microsoft",), ("Exchange", "SharePoint", "Windows", "Office", "Edge"), True),
        (10, ("Zenitel", "D-Link", "TRENDnet"), (), True),  # multi-vendor cluster
    ],
)
def test_bundle_definition(
    cves: int, vendors: tuple[str, ...], products: tuple[str, ...], bundle: bool
) -> None:
    d = g(
        "x",
        1,
        "x",
        tuple(f"CVE-2026-{1000 + i}" for i in range(cves)),
        vendors=vendors,
        products=products,
    )
    assert d.is_bundle is bundle


@pytest.mark.parametrize(
    ("names", "expected"),
    [
        (("N-central",), {"ncentral", "central"}),
        (("N-able N-central",), {"nable", "able", "ncentral", "central"}),
        (("GS1900-8HP",), {"gs19008hp", "gs1900", "8hp"}),
        (("GS1900 series switches",), {"gs1900"}),
        (("npm", "PyPI", "crates.io"), set()),
        (("N/A (offensive framework)",), {"offensive"}),
    ],
)
def test_entity_tokens(names: tuple[str, ...], expected: set[str]) -> None:
    assert entity_tokens(names) == expected


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
    ranked = {
        date(2026, 11, 1): [frozenset({f"CVE-2026-{n}"}) for n in range(2, 12)]
        + [frozenset({"CVE-2026-1"})]
    }
    assert evaluate(gold, ranked, k=10).hits == 0  # it's at position 11
    assert evaluate(gold, ranked, k=11).hits == 1
    assert evaluate([], {}).recall == 0.0


def test_rarity_blocks_perfect_overlap_on_a_common_entity() -> None:
    # Two entries that list ONLY "Microsoft" overlap perfectly (1.0); only the rarity
    # rule stops every vendor-only Microsoft item from merging into one story.
    # Fillers make "microsoft" common (df > ENTITY_MAX_DF) but sit > 14 days away, so no
    # roll-up/bridge logic can mask the result: only the rarity rule decides.
    devs = [
        *[g(f"ms{i}", 25 + i // 2, f"item {i}", vendors=("Microsoft",)) for i in range(8)],
        g("x", 3, "Exchange issue", vendors=("Microsoft",)),
        g("y", 5, "Defender bypass", vendors=("Microsoft",)),
    ]
    stories = link_stories(devs)
    assert not any({"x", "y"} <= set(s) for s in story_ids(stories))
    assert not any(s.is_rollup for s in stories if s.members[0].id.endswith(("-x", "-y")))
