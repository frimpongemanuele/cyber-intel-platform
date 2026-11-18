"""Shared builders for AI-layer tests (synthetic data only)."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from typing import Any

from cyberintel.ai.schema import AnalysisInput, CveFact, Evidence

URL_A = "https://vendor.example/advisories/2026-001"
URL_B = "https://research.example/blog/widget-gateway-rce"
CVE_A = "CVE-2026-10001"
CVE_B = "CVE-2026-10002"


def make_input(
    *, excerpt_b: str = "Researchers describe a pre-auth flaw.", **kw: Any
) -> AnalysisInput:
    base: dict[str, Any] = {
        "development_slug": "widget-gateway-rce",
        "development_title": "Widget Gateway pre-auth RCE exploited",
        "first_seen": date(2026, 11, 10),
        "last_seen": date(2026, 11, 12),
        "cves": (
            CveFact(cve_id=CVE_A, title="Widget Gateway RCE", in_kev=True, epss_percentile=0.97),
            CveFact(cve_id=CVE_B, title="Widget Gateway auth bypass"),
        ),
        "evidence": (
            Evidence(
                id=1,
                url=URL_A,
                source_name="vendor-psirt",
                trust_tier="vendor",
                title="Security advisory 2026-001",
                excerpt="Widget Gateway 4.x is affected; update to 4.2.1.",
                published_at=datetime(2026, 11, 10, tzinfo=UTC),
            ),
            Evidence(
                id=2,
                url=URL_B,
                source_name="research-blog",
                trust_tier="research",
                title="Analysing the Widget Gateway bug",
                excerpt=excerpt_b,
            ),
        ),
    }
    base.update(kw)
    return AnalysisInput(**base)


def good_output(**overrides: Any) -> dict[str, Any]:
    out: dict[str, Any] = {
        "summary": f"{CVE_A} in Widget Gateway 4.x is exploited; the vendor fixed it in 4.2.1.",
        "why_it_matters": "Internet-facing gateways are a common initial-access target.",
        "key_points": ["Listed in KEV", f"{CVE_B} is a related auth bypass"],
        "cited_urls": [URL_A, URL_B],
        "learning": [
            {
                "topic": "Edge device patch verification",
                "reason": "Confirm fixed versions in a lab.",
            }
        ],
        "relevance": {
            "technical_impact": 5,
            "real_world": 5,
            "offensive": 3,
            "defensive": 5,
            "learning": 3,
            "portfolio": 2,
            "urgency": 5,
        },
        "confidence": "HIGH",
        "injection_suspected": False,
    }
    out.update(overrides)
    return out


def dumps(obj: Any) -> str:
    return json.dumps(obj)
