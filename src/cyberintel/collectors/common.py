"""Helpers shared by the collectors."""

from __future__ import annotations

import re
from datetime import UTC, date, datetime

from pydantic import BaseModel, ConfigDict, ValidationError

CWE_ID = re.compile(r"^(?:CWE-\d{1,5}|NVD-CWE-(?:noinfo|Other))$")


class RejectedRecord(BaseModel):
    """A row that failed validation. Kept for auditing; never silently dropped."""

    model_config = ConfigDict(frozen=True)

    index: int
    cve_id: str | None
    error: str


def brief_error(exc: Exception) -> str:
    if isinstance(exc, KeyError):
        return f"missing field {exc.args[0]!r}"
    if isinstance(exc, ValidationError):
        err = exc.errors()[0]
        return f"{'.'.join(map(str, err['loc']))}: {err['msg']}"[:200]
    return f"{type(exc).__name__}: {exc}"[:200]


def str_or_none(v: object, limit: int = 40) -> str | None:
    return v[:limit] if isinstance(v, str) else None


def parse_utc(v: object) -> datetime | None:
    """ISO-8601 timestamp to an aware UTC datetime. Naive input is taken as UTC."""
    if not isinstance(v, str) or not v:
        return None
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def parse_date(v: object) -> date | None:
    if not isinstance(v, str) or not v:
        return None
    try:
        return date.fromisoformat(v[:10])
    except ValueError:
        return None
