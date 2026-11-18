"""CISA Known Exploited Vulnerabilities (KEV) catalog: parse + validate.

Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
This module is pure (bytes in, validated records out); fetching lives in the network layer.

KEV is authoritative for exactly one fact: "CISA has evidence this CVE is exploited".
Rows are validated one at a time. A malformed row is reported in ``rejected`` and skipped,
so one bad record cannot block enrichment of the rest. A broken top-level structure is fatal.
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from cyberintel.normalize import CVE_ID

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_KEV_BYTES = 50 * 1024 * 1024  # real catalog is ~1-2 MB; anything near this is suspect
_CWE = re.compile(r"^(?:CWE-\d{1,5}|NVD-CWE-(?:noinfo|Other))$")


class KevError(ValueError):
    pass


class KevEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    cve_id: str
    vendor: str = Field(max_length=200)
    product: str = Field(max_length=200)
    name: str = Field(max_length=500)
    date_added: date
    due_date: date | None
    short_description: str = Field(max_length=4000)
    required_action: str = Field(max_length=2000)
    ransomware_known: bool
    notes: str = Field(default="", max_length=4000)
    cwes: tuple[str, ...] = ()

    @field_validator("cve_id")
    @classmethod
    def _cve_format(cls, v: str) -> str:
        v = v.strip().upper()
        if not CVE_ID.match(v):
            raise ValueError(f"not a CVE ID: {v[:40]!r}")
        return v

    @field_validator("cwes")
    @classmethod
    def _cwe_format(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(c for c in (s.strip() for s in v) if _CWE.match(c))


class RejectedRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    index: int
    cve_id: str | None
    error: str


class KevCatalog(BaseModel):
    model_config = ConfigDict(frozen=True)

    catalog_version: str
    date_released: datetime | None
    declared_count: int | None
    entries: tuple[KevEntry, ...]
    rejected: tuple[RejectedRecord, ...]

    @property
    def count_mismatch(self) -> bool:
        total = len(self.entries) + len(self.rejected)
        return self.declared_count is not None and self.declared_count != total


def _row_to_entry(row: dict[str, Any]) -> KevEntry:
    return KevEntry(
        cve_id=row["cveID"],
        vendor=row.get("vendorProject", ""),
        product=row.get("product", ""),
        name=row.get("vulnerabilityName", ""),
        date_added=row["dateAdded"],
        due_date=row.get("dueDate") or None,
        short_description=row.get("shortDescription", ""),
        required_action=row.get("requiredAction", ""),
        ransomware_known=str(row.get("knownRansomwareCampaignUse", "")).strip().lower() == "known",
        notes=row.get("notes", "") or "",
        cwes=tuple(row.get("cwes") or ()),
    )


def parse_kev(data: bytes) -> KevCatalog:
    if len(data) > MAX_KEV_BYTES:
        raise KevError(f"KEV payload is {len(data)} bytes; limit is {MAX_KEV_BYTES}")
    try:
        doc = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise KevError(f"invalid JSON: {exc}") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        raise KevError("missing 'vulnerabilities' list")

    entries: list[KevEntry] = []
    rejected: list[RejectedRecord] = []
    seen: set[str] = set()
    for i, row in enumerate(doc["vulnerabilities"]):
        cve = row.get("cveID") if isinstance(row, dict) else None
        try:
            if not isinstance(row, dict):
                raise TypeError("row is not an object")
            entry = _row_to_entry(row)
        except (KeyError, TypeError, ValidationError) as exc:
            rejected.append(RejectedRecord(index=i, cve_id=_str_or_none(cve), error=_brief(exc)))
            continue
        if entry.cve_id in seen:
            rejected.append(RejectedRecord(index=i, cve_id=entry.cve_id, error="duplicate cveID"))
            continue
        seen.add(entry.cve_id)
        entries.append(entry)

    count = doc.get("count")
    return KevCatalog(
        catalog_version=str(doc.get("catalogVersion", "unknown"))[:40],
        date_released=_parse_dt(doc.get("dateReleased")),
        declared_count=count if isinstance(count, int) else None,
        entries=tuple(entries),
        rejected=tuple(rejected),
    )


def _str_or_none(v: object) -> str | None:
    return v[:40] if isinstance(v, str) else None


def _brief(exc: Exception) -> str:
    if isinstance(exc, KeyError):
        return f"missing field {exc.args[0]!r}"
    if isinstance(exc, ValidationError):
        err = exc.errors()[0]
        return f"{'.'.join(map(str, err['loc']))}: {err['msg']}"[:200]
    return str(exc)[:200]


def _parse_dt(v: object) -> datetime | None:
    if not isinstance(v, str):
        return None
    try:
        return datetime.fromisoformat(v)
    except ValueError:
        return None
