"""CVSS scores with provenance, and the headline-score policy.

Since April 2026 NVD no longer scores most CVEs, and does not add its own score when the
CNA already supplied one. A CVE may therefore carry scores from NVD, the CNA, CISA-ADP,
or several of them, and they can disagree by 1-2 points. So:

* every score records its ``origin`` (nvd / cna / adp / other) and ``provider``;
* all scores are kept;
* one *headline* score is picked by the explicit policy below, and the UI shows its origin.

Headline policy (first match wins):
  1. CVSS v3.x before v4.0: v3.x is populated across far more of the corpus, so it keeps
     rankings comparable. v4.0 is stored and displayed alongside it.
  2. Within a version family: NVD (independent analysis) > CNA (vendor) > CISA-ADP > other.
  3. CVSS v2 only as a last resort.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

CvssVersion = Literal["2.0", "3.0", "3.1", "4.0"]
ScoreOrigin = Literal["nvd", "cna", "adp", "other"]

_ORIGIN_RANK: dict[str, int] = {"nvd": 0, "cna": 1, "adp": 2, "other": 3}
_FAMILY_RANK: dict[str, int] = {"3.1": 0, "3.0": 0, "4.0": 1, "2.0": 2}
_VERSION_TIEBREAK: dict[str, int] = {"3.1": 0, "3.0": 1, "4.0": 0, "2.0": 0}


class CvssScore(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: CvssVersion
    base_score: float = Field(ge=0.0, le=10.0)
    vector: str | None = Field(default=None, max_length=300)
    severity: str | None = Field(default=None, max_length=20)
    origin: ScoreOrigin
    provider: str = Field(max_length=200)


def headline(scores: Iterable[CvssScore]) -> CvssScore | None:
    """The single score to show and rank by, per the module policy. ``None`` if unscored."""
    ranked = sorted(
        scores,
        key=lambda s: (
            _FAMILY_RANK[s.version],
            _ORIGIN_RANK[s.origin],
            _VERSION_TIEBREAK[s.version],
        ),
    )
    return ranked[0] if ranked else None


def make_score(
    version: CvssVersion, data: object, origin: ScoreOrigin, provider: str
) -> CvssScore | None:
    """Build a score from a CVSS data object (NVD ``cvssData`` or CVE 5 ``cvssV3_1``...).

    Returns ``None`` when the object is unusable instead of raising: one malformed metric
    must not discard the rest of an otherwise valid record.
    """
    if not isinstance(data, dict):
        return None
    try:
        base = float(data["baseScore"])
    except (KeyError, TypeError, ValueError):
        return None
    if not 0.0 <= base <= 10.0:
        return None
    vector = data.get("vectorString")
    severity = data.get("baseSeverity")
    return CvssScore(
        version=version,
        base_score=base,
        vector=vector[:300] if isinstance(vector, str) else None,
        severity=severity[:20].upper() if isinstance(severity, str) else None,
        origin=origin,
        provider=provider[:200],
    )
