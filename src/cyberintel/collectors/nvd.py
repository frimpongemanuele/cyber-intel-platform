"""NVD CVE API 2.0: parse one response page.

Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0 (see docs/DATA_SOURCES.md).
Pure: bytes in, validated records out. Paging and rate limiting live in the collector.

What NVD is authoritative for (post-April-2026): its own ``vulnStatus``, any NIST-authored
("Primary") CVSS, and CPE configurations. CNA scores it relays are kept, marked ``cna``.
``vulnStatus == "Deferred"`` means *NVD has not analysed it* (shown on nvd.nist.gov as
"Not Scheduled"), not that it is unimportant.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from cyberintel.collectors.common import (
    CWE_ID,
    RejectedRecord,
    brief_error,
    parse_date,
    parse_utc,
    str_or_none,
)
from cyberintel.collectors.cvss import CvssScore, CvssVersion, ScoreOrigin, make_score
from cyberintel.normalize import CVE_ID

MAX_NVD_PAGE_BYTES = 64 * 1024 * 1024  # 2000 records/page; real pages are well below this
MAX_REFERENCES = 50
NVD_PRIMARY_SOURCE = "nvd@nist.gov"

_METRIC_KEYS: tuple[tuple[str, CvssVersion], ...] = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)


class NvdError(ValueError):
    pass


class NvdCve(BaseModel):
    model_config = ConfigDict(frozen=True)

    cve_id: str
    source_identifier: str = Field(max_length=200)  # the CNA
    published: datetime
    last_modified: datetime
    vuln_status: str = Field(max_length=40)
    description: str = Field(max_length=8000)
    scores: tuple[CvssScore, ...]
    cwes: tuple[str, ...]
    references: tuple[str, ...]
    has_cpe: bool
    kev_date_added: date | None  # NVD's own copy of KEV membership; cross-check only

    @field_validator("cve_id")
    @classmethod
    def _cve(cls, v: str) -> str:
        if not CVE_ID.match(v):
            raise ValueError(f"not a CVE ID: {v[:40]!r}")
        return v


class NvdPage(BaseModel):
    model_config = ConfigDict(frozen=True)

    start_index: int
    results_per_page: int
    total_results: int
    timestamp: datetime | None
    cves: tuple[NvdCve, ...]
    rejected: tuple[RejectedRecord, ...]

    @property
    def next_start_index(self) -> int | None:
        nxt = self.start_index + self.results_per_page
        return nxt if self.results_per_page > 0 and nxt < self.total_results else None


def parse_nvd_page(data: bytes) -> NvdPage:
    if len(data) > MAX_NVD_PAGE_BYTES:
        raise NvdError(f"NVD page is {len(data)} bytes; limit is {MAX_NVD_PAGE_BYTES}")
    try:
        doc = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise NvdError(f"invalid JSON: {exc}") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        raise NvdError("missing 'vulnerabilities' list")
    try:
        start = int(doc.get("startIndex", 0))
        per_page = int(doc.get("resultsPerPage", 0))
        total = int(doc.get("totalResults", 0))
    except (TypeError, ValueError):
        raise NvdError("non-integer paging fields") from None
    if min(start, per_page, total) < 0:
        raise NvdError("negative paging fields")

    cves: list[NvdCve] = []
    rejected: list[RejectedRecord] = []
    for i, wrapper in enumerate(doc["vulnerabilities"]):
        cve = wrapper.get("cve") if isinstance(wrapper, dict) else None
        cve_id = cve.get("id") if isinstance(cve, dict) else None
        try:
            if not isinstance(cve, dict):
                raise TypeError("entry has no 'cve' object")
            cves.append(_parse_cve(cve))
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            rejected.append(
                RejectedRecord(index=i, cve_id=str_or_none(cve_id), error=brief_error(exc))
            )
    return NvdPage(
        start_index=start,
        results_per_page=per_page,
        total_results=total,
        timestamp=parse_utc(doc.get("timestamp")),
        cves=tuple(cves),
        rejected=tuple(rejected),
    )


def _parse_cve(cve: dict[str, Any]) -> NvdCve:
    source_id = str(cve.get("sourceIdentifier", ""))
    published = parse_utc(cve["published"])
    modified = parse_utc(cve["lastModified"])
    if published is None or modified is None:
        raise ValueError("unparseable published/lastModified")
    return NvdCve(
        cve_id=cve["id"],
        source_identifier=source_id[:200],
        published=published,
        last_modified=modified,
        vuln_status=str(cve.get("vulnStatus", "unknown"))[:40],
        description=_english(cve.get("descriptions")),
        scores=tuple(_scores(cve.get("metrics"), source_id)),
        cwes=_cwes(cve.get("weaknesses")),
        references=_references(cve.get("references")),
        has_cpe=bool(cve.get("configurations")),
        kev_date_added=parse_date(cve.get("cisaExploitAdd")),
    )


def _english(descriptions: object) -> str:
    if isinstance(descriptions, list):
        for d in descriptions:
            if isinstance(d, dict) and d.get("lang") == "en" and isinstance(d.get("value"), str):
                return str(d["value"])[:8000]
    return ""


def _origin(metric: dict[str, Any], cna_source: str) -> ScoreOrigin:
    if metric.get("type") == "Primary" or metric.get("source") == NVD_PRIMARY_SOURCE:
        return "nvd"
    if cna_source and metric.get("source") == cna_source:
        return "cna"
    return "other"  # e.g. CISA-ADP relayed by NVD: kept, but not over-claimed


def _scores(metrics: object, cna_source: str) -> list[CvssScore]:
    out: list[CvssScore] = []
    if not isinstance(metrics, dict):
        return out
    for key, version in _METRIC_KEYS:
        entries = metrics.get(key)
        if not isinstance(entries, list):
            continue
        for m in entries:
            if not isinstance(m, dict):
                continue
            data = m.get("cvssData")
            if version == "2.0" and isinstance(data, dict) and "baseSeverity" not in data:
                data = {**data, "baseSeverity": m.get("baseSeverity")}  # v2 keeps it outside
            score = make_score(version, data, _origin(m, cna_source), str(m.get("source", "")))
            if score is not None:
                out.append(score)
    return out


def _cwes(weaknesses: object) -> tuple[str, ...]:
    found: dict[str, None] = {}
    if isinstance(weaknesses, list):
        for w in weaknesses:
            for d in (w.get("description") or []) if isinstance(w, dict) else []:
                v = d.get("value") if isinstance(d, dict) else None
                if isinstance(v, str) and CWE_ID.match(v.strip()):
                    found[v.strip()] = None
    return tuple(found)


def _references(refs: object) -> tuple[str, ...]:
    urls: dict[str, None] = {}
    if isinstance(refs, list):
        for r in refs:
            url = r.get("url") if isinstance(r, dict) else None
            if isinstance(url, str) and url.startswith(("https://", "http://")):
                urls[url[:2048]] = None
            if len(urls) >= MAX_REFERENCES:
                break
    return tuple(urls)
