"""FIRST EPSS daily scores: parse + validate.

Source: FIRST EPSS daily bulk CSV (~300k rows/day). The download host has moved before;
confirm the current URL against https://www.first.org/epss/data_stats in DATA_SOURCES.md.
Input is the decompressed CSV as an iterable of lines, so the full file never needs to sit
in memory. Format:

    #model_version:v2025.03.14,score_date:2026-11-17T12:55:00Z
    cve,epss,percentile
    CVE-1999-0001,0.01017,0.76734

EPSS is a *probability of exploitation in the next 30 days*, not evidence of exploitation.
Store it next to KEV; never let it stand in for KEV.
"""

from __future__ import annotations

import csv
from collections.abc import Iterable, Iterator
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from cyberintel.normalize import CVE_ID

MAX_ROWS = 1_000_000


class EpssError(ValueError):
    pass


class EpssScore(BaseModel):
    model_config = ConfigDict(frozen=True)

    epss: float
    percentile: float


class EpssSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True)

    model_version: str | None
    score_date: datetime | None
    scores: dict[str, EpssScore]
    rejected_rows: int


def parse_epss(lines: Iterable[str]) -> EpssSnapshot:
    it: Iterator[str] = iter(lines)
    model_version: str | None = None
    score_date: datetime | None = None

    first = next(it, None)
    if first is None:
        raise EpssError("empty input")
    if first.startswith("#"):
        meta = dict(kv.split(":", 1) for kv in first[1:].strip().split(",") if ":" in kv)
        model_version = meta.get("model_version", "")[:40] or None
        score_date = _parse_dt(meta.get("score_date"))
        header = next(it, None)
    else:
        header = first
    if header is None or [h.strip() for h in header.split(",")] != ["cve", "epss", "percentile"]:
        raise EpssError(f"unexpected header: {str(header)[:80]!r}")

    scores: dict[str, EpssScore] = {}
    rejected = 0
    for n, row in enumerate(csv.reader(it)):
        if n >= MAX_ROWS:
            raise EpssError(f"more than {MAX_ROWS} rows")
        try:
            cve, epss_s, pct_s = (c.strip() for c in row)
            epss, pct = float(epss_s), float(pct_s)
        except ValueError:
            rejected += 1
            continue
        if not CVE_ID.match(cve) or not (0.0 <= epss <= 1.0) or not (0.0 <= pct <= 1.0):
            rejected += 1
            continue
        scores[cve] = EpssScore(epss=epss, percentile=pct)
    return EpssSnapshot(
        model_version=model_version, score_date=score_date, scores=scores, rejected_rows=rejected
    )


def _parse_dt(v: str | None) -> datetime | None:
    if not v:
        return None
    try:
        return datetime.fromisoformat(v)
    except ValueError:
        return None
