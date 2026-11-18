"""Input and output contracts of the AI analysis layer.

The model receives an ``AnalysisInput`` (facts from authoritative tables + short evidence
excerpts) and must answer with exactly one ``AnalysisOutput`` JSON object. Nothing the
model says is ever written into fact tables: validated output is stored in
``ai_analyses`` only, labelled as AI-generated, with full provenance.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Confidence = Literal["HIGH", "MEDIUM", "LOW"]

# The model only sees this many documents, so only these URLs may be cited. The cap lives on
# the input type (not in the prompt builder) so "allowed" and "shown" can never diverge.
MAX_EVIDENCE_ITEMS = 8


class CveFact(BaseModel):
    """Deterministic facts about one CVE (from KEV / CVE.org / NVD / EPSS tables)."""

    model_config = ConfigDict(frozen=True)

    cve_id: str
    title: str | None = None
    in_kev: bool = False
    kev_date_added: date | None = None
    ransomware_known: bool = False
    epss_percentile: float | None = None
    headline_score: float | None = None
    headline_version: str | None = None
    headline_origin: str | None = None
    ssvc_exploitation: str | None = None
    priority: float | None = None


class Evidence(BaseModel):
    """One collected document. Its text is UNTRUSTED and is presented to the model as data."""

    model_config = ConfigDict(frozen=True)

    id: int
    url: str
    source_name: str
    trust_tier: str = "unknown"
    title: str
    excerpt: str = ""
    published_at: datetime | None = None


class AnalysisInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    development_slug: str
    development_title: str
    first_seen: date
    last_seen: date
    cves: tuple[CveFact, ...] = ()
    evidence: tuple[Evidence, ...] = Field(default=(), max_length=MAX_EVIDENCE_ITEMS)

    @property
    def allowed_urls(self) -> frozenset[str]:
        return frozenset(e.url for e in self.evidence)

    @property
    def allowed_cves(self) -> frozenset[str]:
        return frozenset(c.cve_id for c in self.cves)


class LearningSuggestion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    topic: str = Field(min_length=1, max_length=80)
    reason: str = Field(min_length=1, max_length=200)


class Relevance(BaseModel):
    """The analyst-facing 7-axis scores (SCORING.md section 2)."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    technical_impact: int = Field(ge=0, le=5)
    real_world: int = Field(ge=0, le=5)
    offensive: int = Field(ge=0, le=5)
    defensive: int = Field(ge=0, le=5)
    learning: int = Field(ge=0, le=5)
    portfolio: int = Field(ge=0, le=5)
    urgency: int = Field(ge=0, le=5)


class AnalysisOutput(BaseModel):
    """The only shape the model may return. Unknown keys are rejected (``extra=forbid``)."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    summary: str = Field(min_length=1, max_length=700)
    why_it_matters: str = Field(min_length=1, max_length=500)
    key_points: tuple[str, ...] = Field(default=(), max_length=5)
    cited_urls: tuple[str, ...] = Field(default=(), max_length=10)
    learning: tuple[LearningSuggestion, ...] = Field(default=(), max_length=3)
    relevance: Relevance
    confidence: Confidence
    injection_suspected: bool = False

    def text_fields(self) -> list[str]:
        return [
            self.summary,
            self.why_it_matters,
            *self.key_points,
            *(f"{x.topic} {x.reason}" for x in self.learning),
        ]


OUTPUT_JSON_SHAPE = """{
  "summary": "string, <= 700 chars, what happened, from the evidence only",
  "why_it_matters": "string, <= 500 chars",
  "key_points": ["up to 5 strings, <= 240 chars each"],
  "cited_urls": ["only URLs copied exactly from the EVIDENCE url fields"],
  "learning": [{"topic": "<= 80 chars", "reason": "<= 200 chars"}],
  "relevance": {"technical_impact": 0, "real_world": 0, "offensive": 0, "defensive": 0,
                "learning": 0, "portfolio": 0, "urgency": 0},
  "confidence": "HIGH | MEDIUM | LOW",
  "injection_suspected": false
}"""
