"""Pure mappers: parsed source models -> JSON-ready rows for ``store.sql`` statements.

No database access here, so every mapping rule is unit-tested without Postgres. The SQL
layer receives the result as a single ``jsonb`` parameter.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from datetime import date, datetime
from typing import Any

from cyberintel.collectors.cve5 import Cve5Record
from cyberintel.collectors.cvss import CvssScore
from cyberintel.collectors.epss import EpssSnapshot
from cyberintel.collectors.kev import KevCatalog
from cyberintel.collectors.nvd import NvdCve
from cyberintel.normalize import canonical_url, entity_norm, extract_cves
from cyberintel.parsing.feeds import Feed

Row = dict[str, Any]
norm = entity_norm  # re-exported; parity with SQL is tested in test_store_sql.py


def to_json(rows: Sequence[Row] | Sequence[str]) -> str:
    return json.dumps(rows, default=_json_default, separators=(",", ":"), ensure_ascii=False)


def _json_default(o: object) -> str:
    if isinstance(o, datetime | date):
        return o.isoformat()
    raise TypeError(f"not JSON serializable: {type(o).__name__}")


# --------------------------------------------------------------------------- KEV / EPSS


def kev_rows(catalog: KevCatalog) -> list[Row]:
    return [
        {
            "cve_id": e.cve_id,
            "vendor": e.vendor,
            "product": e.product,
            "name": e.name,
            "date_added": e.date_added,
            "due_date": e.due_date,
            "ransomware_known": e.ransomware_known,
            "short_description": e.short_description,
            "required_action": e.required_action,
            "notes": e.notes,
            "cwes": list(e.cwes),
        }
        for e in catalog.entries
    ]


def epss_rows(snapshot: EpssSnapshot) -> list[Row]:
    return [
        {"cve_id": cve, "epss": round(s.epss, 5), "percentile": round(s.percentile, 5)}
        for cve, s in snapshot.scores.items()
    ]


# --------------------------------------------------------------------------- CVE scores


def _score_rows(cve_id: str, scores: Iterable[CvssScore]) -> list[Row]:
    seen: set[tuple[str, str, str]] = set()
    out: list[Row] = []
    for s in scores:
        key = (s.version, s.origin, s.provider)
        if key in seen:  # same metric listed twice: keep the first
            continue
        seen.add(key)
        out.append(
            {
                "cve_id": cve_id,
                "version": s.version,
                "origin": s.origin,
                "provider": s.provider,
                "base_score": round(s.base_score, 1),
                "vector": s.vector,
                "severity": s.severity,
            }
        )
    return out


def cve5_rows(records: Iterable[Cve5Record]) -> tuple[list[Row], list[Row], list[Row], list[Row]]:
    """-> (vulnerability rows, score rows, affected-product rows, reference rows)."""
    vulns: list[Row] = []
    scores: list[Row] = []
    products: list[Row] = []
    refs: list[Row] = []
    for r in records:
        ssvc = r.ssvc
        vulns.append(
            {
                "cve_id": r.cve_id,
                "record_state": r.state,
                "assigner": r.assigner,
                "title": r.title,
                "description": r.description,
                "published_at": r.date_published,
                "updated_at": r.date_updated,
                "cwes": list(r.cwes),
                "ssvc_exploitation": _enum(
                    ssvc.exploitation if ssvc else None, {"none", "poc", "active"}
                ),
                "ssvc_automatable": _enum(ssvc.automatable if ssvc else None, {"yes", "no"}),
                "ssvc_technical_impact": _enum(
                    ssvc.technical_impact if ssvc else None, {"partial", "total"}
                ),
                "ssvc_timestamp": ssvc.timestamp if ssvc else None,
                "adp_kev_date": r.adp_kev_date,
            }
        )
        scores += _score_rows(r.cve_id, r.scores)
        products += [
            {"cve_id": r.cve_id, "vendor": a.vendor, "product": a.product} for a in r.affected
        ]
        refs += [{"cve_id": r.cve_id, "url": u} for u in r.references]
    return vulns, scores, products, refs


def _enum(value: str | None, allowed: set[str]) -> str | None:
    # Unknown SSVC values (a future CISA vocabulary) become NULL rather than failing the
    # whole batch on the database CHECK constraint.
    return value if value in allowed else None


def nvd_rows(cves: Iterable[NvdCve]) -> tuple[list[Row], list[Row]]:
    """-> (vulnerability rows, score rows)."""
    vulns: list[Row] = []
    scores: list[Row] = []
    for c in cves:
        vulns.append(
            {
                "cve_id": c.cve_id,
                "description": c.description or None,
                "published_at": c.published,
                "cwes": list(c.cwes),
                "nvd_status": c.vuln_status,
                "nvd_last_modified": c.last_modified,
                "nvd_has_cpe": c.has_cpe,
            }
        )
        scores += _score_rows(c.cve_id, c.scores)
    return vulns, scores


# --------------------------------------------------------------------------- documents


def document_rows(feed: Feed) -> list[Row]:
    """One row per distinct canonical URL (first occurrence wins). Items without a usable
    link are skipped: an item we cannot point back to is not citable evidence."""
    out: dict[str, Row] = {}
    for item in feed.items:
        if not item.url:
            continue
        key = canonical_url(item.url)
        if key in out or len(key) > 2048:
            continue
        out[key] = {
            "canonical_url": key,
            "url": item.url,
            "guid": item.guid,
            "title": item.title or "(untitled)",
            "excerpt": item.excerpt,
            "published_at": item.published,
            "cves": list(extract_cves(f"{item.title} {item.excerpt}")),
        }
    return list(out.values())
