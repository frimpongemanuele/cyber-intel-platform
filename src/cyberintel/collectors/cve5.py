"""CVE.org record (CVE Record Format 5.x): parse one record.

Endpoint: https://cveawg.mitre.org/api/cve/{CVE-ID} (public read, no auth).
Bulk mirror: github.com/CVEProject/cvelistV5.

This is the *CNA's own* record, which makes it the primary source for CVSS now that NVD
only scores a minority of CVEs. It also carries CISA-ADP "Vulnrichment" containers:
SSVC decision points (Exploitation: none/poc/active, Automatable, Technical Impact), a
KEV marker, and CVSS/CWE where the CNA supplied none.

The record format has had 5.0, 5.1 and 5.2 revisions in the wild and optional fields
everywhere, so parsing is defensive: unknown or malformed parts are skipped, never fatal,
unless the record has no usable CVE ID or state.
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cyberintel.collectors.common import CWE_ID, parse_date, parse_utc
from cyberintel.collectors.cvss import CvssScore, CvssVersion, ScoreOrigin, make_score
from cyberintel.normalize import CVE_ID

MAX_CVE5_BYTES = 8 * 1024 * 1024
MAX_AFFECTED = 50
MAX_REFERENCES = 50
_CWE_IN_TEXT = re.compile(r"\bCWE-\d{1,5}\b")

_CVSS_KEYS: tuple[tuple[str, CvssVersion], ...] = (
    ("cvssV4_0", "4.0"),
    ("cvssV3_1", "3.1"),
    ("cvssV3_0", "3.0"),
    ("cvssV2_0", "2.0"),
)


class Cve5Error(ValueError):
    pass


class AffectedProduct(BaseModel):
    model_config = ConfigDict(frozen=True)

    vendor: str = Field(max_length=200)
    product: str = Field(max_length=200)


class CisaSsvc(BaseModel):
    """CISA-ADP SSVC decision points (lower-cased as published)."""

    model_config = ConfigDict(frozen=True)

    exploitation: str | None = Field(default=None, max_length=20)  # none | poc | active
    automatable: str | None = Field(default=None, max_length=20)  # yes | no
    technical_impact: str | None = Field(default=None, max_length=20)  # partial | total
    timestamp: datetime | None = None


class Cve5Record(BaseModel):
    model_config = ConfigDict(frozen=True)

    cve_id: str
    state: str = Field(max_length=20)  # PUBLISHED | REJECTED
    assigner: str | None = Field(default=None, max_length=100)
    date_published: datetime | None
    date_updated: datetime | None
    title: str | None = Field(default=None, max_length=500)
    description: str = Field(max_length=8000)
    scores: tuple[CvssScore, ...]
    cwes: tuple[str, ...]
    affected: tuple[AffectedProduct, ...]
    references: tuple[str, ...]
    ssvc: CisaSsvc | None
    adp_kev_date: date | None

    @property
    def is_rejected(self) -> bool:
        return self.state.upper() == "REJECTED"


def parse_cve5(data: bytes) -> Cve5Record:
    if len(data) > MAX_CVE5_BYTES:
        raise Cve5Error(f"CVE record is {len(data)} bytes; limit is {MAX_CVE5_BYTES}")
    try:
        doc = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise Cve5Error(f"invalid JSON: {exc}") from None
    if not isinstance(doc, dict):
        raise Cve5Error("record is not an object")

    meta = _obj(doc.get("cveMetadata"))
    cve_id = str(meta.get("cveId", "")).strip().upper()
    if not CVE_ID.match(cve_id):
        raise Cve5Error(f"missing or invalid cveMetadata.cveId: {cve_id[:40]!r}")
    state = str(meta.get("state", "")).strip().upper()
    if state not in {"PUBLISHED", "REJECTED"}:
        raise Cve5Error(f"unknown record state {state[:20]!r}")

    containers = _obj(doc.get("containers"))
    cna = _obj(containers.get("cna"))
    cna_name = str(_obj(cna.get("providerMetadata")).get("shortName") or meta.get(
        "assignerShortName") or "cna")  # fmt: skip

    scores: list[CvssScore] = _scores(cna.get("metrics"), "cna", cna_name)
    cwes: dict[str, None] = dict.fromkeys(_cwes(cna.get("problemTypes")))
    ssvc: CisaSsvc | None = None
    adp_kev: date | None = None
    for adp in _list(containers.get("adp")):
        adp = _obj(adp)
        name = str(_obj(adp.get("providerMetadata")).get("shortName") or "adp")
        scores += _scores(adp.get("metrics"), "adp", name)
        cwes.update(dict.fromkeys(_cwes(adp.get("problemTypes"))))
        for metric in _list(adp.get("metrics")):
            other = _obj(_obj(metric).get("other"))
            kind = str(other.get("type", "")).lower()
            content = _obj(other.get("content"))
            if kind == "ssvc" and ssvc is None:
                ssvc = _ssvc(content)
            elif kind == "kev" and adp_kev is None:
                adp_kev = parse_date(content.get("dateAdded"))

    description_source = (
        cna.get("rejectedReasons") if state == "REJECTED" else cna.get("descriptions")
    )
    title = cna.get("title")
    return Cve5Record(
        cve_id=cve_id,
        state=state,
        assigner=str(meta.get("assignerShortName"))[:100]
        if meta.get("assignerShortName")
        else None,
        date_published=parse_utc(meta.get("datePublished")),
        date_updated=parse_utc(meta.get("dateUpdated")),
        title=title[:500] if isinstance(title, str) else None,
        description=_english(description_source),
        scores=tuple(scores),
        cwes=tuple(cwes),
        affected=_affected(cna.get("affected")),
        references=_references(cna.get("references")),
        ssvc=ssvc,
        adp_kev_date=adp_kev,
    )


def _obj(v: object) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _list(v: object) -> list[Any]:
    return v if isinstance(v, list) else []


def _english(descriptions: object) -> str:
    entries = [_obj(d) for d in _list(descriptions)]
    for d in entries:  # prefer "en", then "en-US" etc., then anything
        if d.get("lang") == "en" and isinstance(d.get("value"), str):
            return str(d["value"])[:8000]
    for d in entries:
        if str(d.get("lang", "")).lower().startswith("en") and isinstance(d.get("value"), str):
            return str(d["value"])[:8000]
    return ""


def _scores(metrics: object, origin: ScoreOrigin, provider: str) -> list[CvssScore]:
    out: list[CvssScore] = []
    for metric in _list(metrics):
        metric = _obj(metric)
        for key, version in _CVSS_KEYS:
            if key in metric:
                score = make_score(version, metric[key], origin, provider)
                if score is not None:
                    out.append(score)
    return out


def _cwes(problem_types: object) -> list[str]:
    found: list[str] = []
    for pt in _list(problem_types):
        for d in _list(_obj(pt).get("descriptions")):
            d = _obj(d)
            cwe = d.get("cweId")
            if isinstance(cwe, str) and CWE_ID.match(cwe.strip()):
                found.append(cwe.strip())
            elif isinstance(d.get("description"), str):
                found += _CWE_IN_TEXT.findall(d["description"])[:3]
    return found


def _ssvc(content: dict[str, Any]) -> CisaSsvc:
    values: dict[str, str] = {}
    for option in _list(content.get("options")):
        for k, v in _obj(option).items():
            if isinstance(v, str):
                values[k.strip().lower()] = v.strip().lower()[:20]
    return CisaSsvc(
        exploitation=values.get("exploitation"),
        automatable=values.get("automatable"),
        technical_impact=values.get("technical impact"),
        timestamp=parse_utc(content.get("timestamp")),
    )


def _affected(affected: object) -> tuple[AffectedProduct, ...]:
    out: dict[tuple[str, str], None] = {}
    for a in _list(affected)[: MAX_AFFECTED * 4]:
        a = _obj(a)
        vendor, product = a.get("vendor"), a.get("product")
        if isinstance(vendor, str) and isinstance(product, str) and vendor and product:
            out[(vendor.strip()[:200], product.strip()[:200])] = None
        if len(out) >= MAX_AFFECTED:
            break
    return tuple(AffectedProduct(vendor=v, product=p) for v, p in out)


def _references(refs: object) -> tuple[str, ...]:
    urls: dict[str, None] = {}
    for r in _list(refs):
        url = _obj(r).get("url")
        if isinstance(url, str) and url.startswith(("https://", "http://")):
            urls[url[:2048]] = None
        if len(urls) >= MAX_REFERENCES:
            break
    return tuple(urls)
