"""Evaluation harness: the agent-written archive as a labelled test set.

The scheduled research agent writes one ``data/YYYY/MM/YYYY-MM-DD.json`` per day
(schema 0.1). This module:

1. loads those files as *gold* developments;
2. links the same story across days (the archive assigns a new date-stamped ID every day,
   so "Chrome 0-day" on Nov 10, 11 and 17 shows up as three unrelated records);
3. scores a pipeline against the gold set: of the developments the agent rated
   urgency >= 4, how many did the pipeline surface in its top-k?

Story-linking rules (deliberately conservative: a wrong merge is worse than a missed one):
  - Two developments on different days are *compatible* if they share a CVE and BOTH are
    "focused" (<= BUNDLE_MAX CVEs), or if their titles are similar. Title similarity is
    IDF-weighted Jaccard, so a rare shared token ("able2shell", "sshole") counts heavily
    and a common one ("microsoft", "linux") barely counts.
  - Links only form within ``max_gap_days``.
  - Roll-ups never merge stories. An entry is a roll-up if it is a bundle (many CVEs), or
    if it is compatible with two entries that are not compatible with each other: a
    "KEV carry-over" item mentioning both a Check Point bug and an UnrealIRCd bug would
    otherwise chain two unrelated stories. Roll-ups stay single-member stories and record
    the stories they touch as ``related``. (Rule found by hand-inspecting real clusters.)

The archive is private and is never vendored into this repo; pass its path at runtime.
Tests use synthetic fixtures.
"""

from __future__ import annotations

import argparse
import json
import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, timedelta
from itertools import combinations
from pathlib import Path

from cyberintel.normalize import entity_norm

BUNDLE_MAX = 4
TITLE_SIMILARITY = 0.4
MAX_GAP_DAYS = 14
ENTITY_OVERLAP = 0.6  # IDF-weighted overlap coefficient of vendor/product tokens
ENTITY_MAX_DF = 4  # at least one shared entity token must be this rare in the corpus
BUNDLE_MIN_VENDORS = 3  # a multi-CVE entry spanning this many vendors is a roll-up...
BUNDLE_MIN_PRODUCTS = 5  # ...as is one listing this many products (Patch Tuesday, PSIRT)

# Words that appear in product strings but identify nothing.
_ENTITY_STOP = frozenset(
    {
        "agent", "agents", "and", "api", "app", "application", "applications", "build",
        "builds", "cloud", "component", "components", "device", "devices", "edition",
        "firmware", "for", "framework", "library", "linux", "managed", "module", "multiple",
        "none", "other", "platform", "plugin", "plugins", "portal", "product", "products",
        "sdk", "series", "server", "servers", "service", "services", "software", "switch",
        "switches", "system", "systems", "the", "tool", "tools", "unknown", "various",
        "version", "versions", "web", "windows",
        # Package ecosystems and code platforms are shared infrastructure, not story
        # identity: two unrelated supply-chain stories both "mention npm" (found on the
        # real archive: GitHub Actions compromise vs. a DPRK fake-Zoom infostealer).
        "cargo", "crates", "cratesio", "docker", "dockerhub", "github", "maven", "modules",
        "npm", "nuget", "packagist", "pip", "pypi", "rubygems",
    }
)  # fmt: skip
_PART_SPLIT = re.compile(r"[-_/.():,]+")


def entity_tokens(names: Iterable[str]) -> frozenset[str]:
    """Normalized identity tokens from vendor/product strings.

    Each whitespace word is normalized whole ("N-central" -> "ncentral") AND split on
    punctuation ("GS1900-8HP" -> "gs1900"), so naming variants still meet.
    """
    out: set[str] = set()
    for name in names:
        for word in name.split():
            for candidate in (word, *_PART_SPLIT.split(word)):
                t = entity_norm(candidate)
                if len(t) >= 3 and not t.isdigit() and t not in _ENTITY_STOP:
                    out.add(t)
    return frozenset(out)


_TOKEN = re.compile(r"[a-z0-9]+")
_STOP = frozenset(
    {
        "actively", "after", "and", "are", "attack", "attacks", "critical", "cve", "day",
        "exploit", "exploited", "flaw", "flaws", "for", "from", "has", "have", "into",
        "issue", "issues", "its", "new", "over", "patch", "patches", "security", "that",
        "the", "this", "update", "via", "vulnerabilities", "vulnerability", "was", "with", "zero",
    }
)  # fmt: skip


@dataclass(frozen=True, slots=True)
class GoldDevelopment:
    id: str
    day: date
    title: str
    cves: frozenset[str]
    urgency: int
    confidence: str
    status: str
    in_kev: bool
    vendors: tuple[str, ...] = ()
    products: tuple[str, ...] = ()

    @property
    def vendor_norms(self) -> frozenset[str]:
        return frozenset(t for v in self.vendors if (t := entity_norm(v)))

    @property
    def entities(self) -> frozenset[str]:
        return entity_tokens((*self.vendors, *self.products))

    @property
    def is_bundle(self) -> bool:
        """Roll-up = many CVEs spread over many vendors or many products (Patch Tuesday,
        a monthly PSIRT, a multi-vendor IoT cluster). Many CVEs about one product (an
        N-central hotfix set, one Citrix advisory) is a focused story. Thresholds come
        from the archive's real multi-CVE entries (ENGINEERING_LOG). Without entity data,
        fall back to the conservative CVE-count rule."""
        if len(self.cves) <= BUNDLE_MAX:
            return False
        if not self.vendor_norms and not self.products:
            return True
        return (
            len(self.vendor_norms) >= BUNDLE_MIN_VENDORS
            or len(self.products) >= BUNDLE_MIN_PRODUCTS
        )

    @property
    def tokens(self) -> frozenset[str]:
        slug = self.id[11:] if re.match(r"^\d{4}-\d{2}-\d{2}-", self.id) else self.id
        words = _TOKEN.findall(f"{self.title} {slug.replace('-', ' ')}".lower())
        return frozenset(w for w in words if len(w) >= 3 and w not in _STOP and not w.isdigit())


@dataclass(frozen=True, slots=True)
class Story:
    members: tuple[GoldDevelopment, ...]  # sorted by day
    is_rollup: bool = False
    related: tuple[str, ...] = ()  # ids of developments a roll-up touches

    @property
    def first_seen(self) -> date:
        return self.members[0].day

    @property
    def last_seen(self) -> date:
        return self.members[-1].day

    @property
    def cves(self) -> frozenset[str]:
        return frozenset().union(*(m.cves for m in self.members))


@dataclass(slots=True)
class LoadResult:
    developments: list[GoldDevelopment] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


def load_archive(root: Path) -> LoadResult:
    result = LoadResult()
    for path in sorted(root.glob("data/*/*/*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            day = date.fromisoformat(doc["report_date"])
            rows = doc["developments"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            result.problems.append(f"{path.name}: unreadable ({exc})")
            continue
        for row in rows:
            try:
                result.developments.append(
                    GoldDevelopment(
                        id=str(row["id"]),
                        day=day,
                        title=str(row["title"]),
                        cves=frozenset(c.upper() for c in row.get("cves", [])),
                        urgency=int(row["scores"]["urgency"]),
                        confidence=str(row["confidence"]),
                        status=str(row["status"]),
                        in_kev=bool(row.get("in_kev", False)),
                        vendors=_strings(row.get("vendors")),
                        products=_strings(row.get("products")),
                    )
                )
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                result.problems.append(f"{path.name}: bad development ({exc!r})")
    return result


def _strings(v: object) -> tuple[str, ...]:
    return tuple(x[:300] for x in v if isinstance(x, str)) if isinstance(v, list) else ()


def document_frequency(token_sets: Iterable[frozenset[str]]) -> dict[str, int]:
    df: dict[str, int] = {}
    for tokens in token_sets:
        for t in tokens:
            df[t] = df.get(t, 0) + 1
    return df


def idf_from_df(df: Mapping[str, int], n: int) -> dict[str, float]:
    return {t: math.log((n + 1) / (c + 1)) + 1.0 for t, c in df.items()}


def idf_weights(devs: Sequence[GoldDevelopment]) -> dict[str, float]:
    """Smoothed inverse document frequency of title tokens across the corpus."""
    return idf_from_df(document_frequency(d.tokens for d in devs), len(devs))


@dataclass(frozen=True, slots=True)
class Corpus:
    """Corpus statistics used by ``compatible``."""

    title_idf: Mapping[str, float]
    entity_idf: Mapping[str, float]
    entity_df: Mapping[str, int]

    @classmethod
    def of(cls, devs: Sequence[GoldDevelopment]) -> Corpus:
        edf = document_frequency(d.entities for d in devs)
        return cls(idf_weights(devs), idf_from_df(edf, len(devs)), edf)


def entity_overlap(a: frozenset[str], b: frozenset[str], idf: Mapping[str, float]) -> float:
    """IDF-weighted overlap coefficient: shared weight / weight of the smaller set.

    Overlap (not Jaccard) because one report may list one product and the follow-up
    six variants of it; the smaller, more specific set should be able to match.
    """
    shared = a & b
    if not shared:
        return 0.0
    w = lambda t: idf.get(t, 1.0)  # noqa: E731
    return sum(map(w, shared)) / min(sum(map(w, a)), sum(map(w, b)))


def title_similarity(a: frozenset[str], b: frozenset[str], idf: Mapping[str, float]) -> float:
    """IDF-weighted Jaccard: sum(w, shared) / sum(w, union). 0 for empty inputs."""
    union = a | b
    if not union or not (a & b):
        return 0.0
    w = lambda t: idf.get(t, 1.0)  # noqa: E731
    return sum(map(w, a & b)) / sum(map(w, union))


def cve_veto(a: GoldDevelopment, b: GoldDevelopment) -> bool:
    """Negative evidence: two focused developments naming different CVEs are different
    stories, however similar their product or title (two Chrome zero-days a week apart)."""
    return (
        bool(a.cves) and bool(b.cves) and not (a.cves & b.cves)
        and not a.is_bundle and not b.is_bundle
    )  # fmt: skip


def compatible(
    a: GoldDevelopment,
    b: GoldDevelopment,
    corpus: Corpus,
    *,
    title_threshold: float = TITLE_SIMILARITY,
    max_gap_days: int = MAX_GAP_DAYS,
    use_entities: bool = True,
) -> bool:
    if a.day == b.day or abs((a.day - b.day).days) > max_gap_days:
        return False  # same-day duplicates are the agent's own dedup problem, not ours
    if a.cves & b.cves and not a.is_bundle and not b.is_bundle:
        return True
    if cve_veto(a, b):
        return False
    if title_similarity(a.tokens, b.tokens, corpus.title_idf) >= title_threshold:
        return True
    if not use_entities:
        return False
    shared = a.entities & b.entities
    rare = any(corpus.entity_df.get(t, 0) <= ENTITY_MAX_DF for t in shared)
    return rare and entity_overlap(a.entities, b.entities, corpus.entity_idf) >= ENTITY_OVERLAP


def link_stories(
    devs: Sequence[GoldDevelopment],
    *,
    title_threshold: float = TITLE_SIMILARITY,
    max_gap_days: int = MAX_GAP_DAYS,
    use_entities: bool = True,
) -> list[Story]:
    corpus = Corpus.of(devs)
    n = len(devs)
    adj: list[set[int]] = [set() for _ in range(n)]
    for i, j in combinations(range(n), 2):
        if compatible(
            devs[i],
            devs[j],
            corpus,
            title_threshold=title_threshold,
            max_gap_days=max_gap_days,
            use_entities=use_entities,
        ):
            adj[i].add(j)
            adj[j].add(i)

    # A node bridging two mutually incompatible neighbours is a roll-up, as is any bundle.
    rollup = {
        i
        for i in range(n)
        if devs[i].is_bundle or any(b not in adj[a] for a, b in combinations(adj[i], 2))
    }

    parent = list(range(n))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(n):
        if i in rollup:
            continue
        for j in adj[i]:
            if j not in rollup:
                parent[find(i)] = find(j)

    groups: dict[int, list[GoldDevelopment]] = {}
    for i, d in enumerate(devs):
        groups.setdefault(find(i), []).append(d)
    stories: list[Story] = []
    for root, members in groups.items():
        ordered = tuple(sorted(members, key=lambda d: (d.day, d.id)))
        if root in rollup:
            related = tuple(sorted(devs[j].id for j in adj[root]))
            stories.append(Story(ordered, is_rollup=True, related=related))
        else:
            stories.append(Story(ordered))
    return sorted(stories, key=lambda s: (s.first_seen, s.members[0].id))


# --------------------------------------------------------------------------- evaluation


@dataclass(frozen=True, slots=True)
class EvalReport:
    k: int
    urgency_min: int
    evaluable: int
    hits: int
    misses: tuple[str, ...]
    not_evaluable: tuple[str, ...]  # gold items with no CVE: a CVE-driven pipeline can't match

    @property
    def recall(self) -> float:
        return self.hits / self.evaluable if self.evaluable else 0.0


def evaluate(
    gold: Sequence[GoldDevelopment],
    ranked_by_day: Mapping[date, Sequence[frozenset[str]]],
    *,
    k: int = 10,
    urgency_min: int = 4,
    lookback_days: int = 1,
) -> EvalReport:
    """Recall@k of high-urgency gold developments.

    ``ranked_by_day[d]`` is the pipeline's ranked list of developments for day ``d``,
    each represented by its CVE set. A gold item counts as found if any of the top-k
    pipeline items on its day, or up to ``lookback_days`` earlier, shares a CVE with it.
    (The pipeline may legitimately see a KEV addition the day before the brief does.)
    """
    hits, misses, unevaluable, evaluable = 0, [], [], 0
    for g in gold:
        if g.urgency < urgency_min:
            continue
        if not g.cves:
            unevaluable.append(g.id)
            continue
        evaluable += 1
        window = [g.day - timedelta(days=n) for n in range(lookback_days + 1)]
        found = any(g.cves & item for d in window for item in ranked_by_day.get(d, ())[:k])
        if found:
            hits += 1
        else:
            misses.append(g.id)
    return EvalReport(k, urgency_min, evaluable, hits, tuple(misses), tuple(unevaluable))


# --------------------------------------------------------------------------- CLI


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Summarize the intel archive as a test set.")
    ap.add_argument("archive", type=Path, help="path to a local clone of cyber-intel-archive")
    args = ap.parse_args(argv)

    loaded = load_archive(args.archive)
    devs = loaded.developments
    stories = link_stories(devs)
    multi = [s for s in stories if len(s.members) > 1]
    days = sorted({d.day for d in devs})

    print(f"days: {len(days)} ({days[0]} .. {days[-1]})" if days else "days: 0")
    print(f"developments: {len(devs)}  ->  stories: {len(stories)} "
          f"({len(multi)} span multiple days)")  # fmt: skip
    print(f"high-urgency (>=4): {sum(d.urgency >= 4 for d in devs)}, "
          f"of which without CVE: {sum(d.urgency >= 4 and not d.cves for d in devs)}")  # fmt: skip
    for p in loaded.problems:
        print(f"PROBLEM: {p}")
    print("\nmulti-day stories:")
    for s in multi:
        span = f"{s.first_seen}..{s.last_seen}"
        print(f"  [{len(s.members)}x {span}] " + " | ".join(m.id[11:] for m in s.members))
    print("\nroll-ups (kept separate; touch these developments):")
    for s in stories:
        if s.is_rollup and s.related:
            print(f"  {s.members[0].id} -> {', '.join(r[11:] for r in s.related)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
