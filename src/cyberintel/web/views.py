"""Pure web helpers: query-parameter parsing, template environment, and filters.

Untrusted input reaches the database only through these validated models; untrusted data
reaches HTML only through Jinja2 autoescaping plus ``safe_url`` for every link.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from cyberintel.store.read_sql import VULN_SORTS

TEMPLATES = Path(__file__).parent / "templates"
PAGE_SIZE = 50
MAX_PAGE = 1000
CVE_PATH = re.compile(r"^CVE-\d{4}-\d{4,7}$")
SLUG_PATH = re.compile(r"^[a-z0-9][a-z0-9-]{0,159}$")
SOURCE_PARAM = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")

SortKey = Literal["priority", "newest_kev", "epss", "cvss", "cve"]
assert set(VULN_SORTS) == set(SortKey.__args__)  # type: ignore[attr-defined]


class BadQueryError(ValueError):
    """A query parameter failed validation; the app answers 400."""


def _flag(v: object) -> bool:
    return isinstance(v, str) and v.lower() in {"1", "on", "true", "yes"}


def _clean_text(v: object) -> str | None:
    if v is None:
        return None
    text = " ".join(str(v).split())  # collapse whitespace / control characters
    return text or None


class _Query(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    page: int = Field(default=1, ge=1, le=MAX_PAGE)
    q: str | None = Field(default=None, max_length=100)

    @field_validator("q", mode="before")
    @classmethod
    def _q(cls, v: object) -> str | None:
        return _clean_text(v)

    @property
    def offset(self) -> int:
        return (self.page - 1) * PAGE_SIZE


class VulnQuery(_Query):
    sort: SortKey = "priority"
    kev: bool = False
    exploited: bool = False
    min_priority: int = Field(default=0, ge=0, le=100)

    @field_validator("kev", "exploited", mode="before")
    @classmethod
    def _b(cls, v: object) -> bool:
        return _flag(v)


class StoryQuery(_Query):
    rollups: bool = False

    @field_validator("rollups", mode="before")
    @classmethod
    def _b(cls, v: object) -> bool:
        return _flag(v)


class NewsQuery(_Query):
    source: str | None = None

    @field_validator("source", mode="before")
    @classmethod
    def _s(cls, v: object) -> str | None:
        v = _clean_text(v)
        if v is not None and not SOURCE_PARAM.match(v):
            raise ValueError("unknown source name format")
        return v


def parse_query[Q: _Query](model: type[Q], params: Mapping[str, str]) -> Q:
    try:
        return model.model_validate({k: v for k, v in params.items() if v != ""})
    except ValidationError as exc:
        first = exc.errors()[0]
        raise BadQueryError(f"invalid parameter {'.'.join(map(str, first['loc']))}") from None


# --------------------------------------------------------------------------- AI panel

RELEVANCE_LABELS = (
    ("technical_impact", "Technical impact"),
    ("real_world", "Real-world"),
    ("offensive", "Offensive"),
    ("defensive", "Defensive"),
    ("learning", "Learning"),
    ("portfolio", "Portfolio"),
    ("urgency", "Urgency"),
)


def ai_panel(row: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Re-validate a stored analysis before it reaches a template (defence in depth).

    The runner only stores validated output, but the dashboard does not trust that: the
    jsonb is parsed again with the strict output schema and hidden characters are
    re-checked. Anything that fails is simply not shown.
    """
    import json
    import unicodedata

    from cyberintel.ai.schema import AnalysisOutput

    if not row or row.get("output") is None:
        return None
    raw = row["output"]
    try:
        text = raw if isinstance(raw, str) else json.dumps(raw)
        out = AnalysisOutput.model_validate_json(text, strict=True)
    except (ValidationError, TypeError, ValueError):
        return None
    for t in [*out.text_fields(), *out.cited_urls]:
        if any(ch != "\n" and unicodedata.category(ch) in {"Cc", "Cf", "Co", "Cs"} for ch in t):
            return None
    return {
        "out": out,
        "relevance": [(label, getattr(out.relevance, key)) for key, label in RELEVANCE_LABELS],
        "provider": row.get("provider"),
        "model": row.get("model"),
        "prompt_version": row.get("prompt_version"),
        "created_at": row.get("created_at"),
        "injection_suspected": bool(row.get("injection_suspected")),
    }


# --------------------------------------------------------------------------- filters


def safe_url(value: object) -> str:
    """Only absolute http(s) URLs may become links; anything else becomes an inert '#'.

    The database already constrains stored URLs (http_url domain); this is the second,
    independent layer at the point of rendering (THREAT_MODEL T9/T12).
    """
    if not isinstance(value, str):
        return "#"
    try:
        parts = urlsplit(value.strip())
    except ValueError:
        return "#"
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        return "#"
    return value.strip()


def fmt_date(value: object) -> str:
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M UTC") if value.tzinfo else value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    return "—" if value in (None, "") else str(value)


def fmt_num(value: object, digits: int = 1) -> str:
    if value is None:
        return "—"
    if isinstance(value, int | float | Decimal):
        return f"{float(value):.{digits}f}"
    return str(value)


def fmt_pct(value: object) -> str:
    if isinstance(value, int | float | Decimal):
        return f"{float(value) * 100:.1f}%"
    return "—"


ORIGIN_LABELS = {"nvd": "NVD", "cna": "CNA (vendor)", "adp": "CISA-ADP", "other": "other"}
NVD_STATUS_HELP = {
    "Deferred": "NVD has not analysed this CVE (shown on nvd.nist.gov as “Not Scheduled”).",
    "Received": "NVD has received the record but not analysed it.",
    "Awaiting Analysis": "Queued for NVD analysis.",
}


def build_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATES),
        autoescape=select_autoescape(enabled_extensions=("html",), default=True),
        undefined=StrictUndefined,  # a typo in a template is an error, not silent blank output
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters.update(safe_url=safe_url, date=fmt_date, num=fmt_num, pct=fmt_pct)
    env.globals.update(
        ORIGIN_LABELS=ORIGIN_LABELS, NVD_STATUS_HELP=NVD_STATUS_HELP, PAGE_SIZE=PAGE_SIZE
    )
    return env


def render(env: Environment, template: str, **context: Any) -> str:
    return env.get_template(template).render(**context)
