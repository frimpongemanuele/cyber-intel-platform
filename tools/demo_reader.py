"""Synthetic, in-memory data for screenshots and demos (no database needed).

Every vendor, product, story and article here is invented ("Example" names; CVE numbers
in a high, unused range) so the published screenshots can never be mistaken for real
intelligence or leak the private archive. Row shapes match ``web.reader.DbReader``.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any

NOW = datetime(2026, 11, 18, 7, 30, tzinfo=UTC)
TODAY = NOW.date()


def _vuln(
    n: int,
    title: str,
    *,
    kev: date | None,
    ransomware: bool = False,
    ssvc: str | None = None,
    epss: float,
    cvss: float | None,
    origin: str = "nvd",
    vendor: str = "Example",
    product: str = "Product",
) -> dict[str, Any]:
    p_exp = 40 if kev else 30 if ssvc == "active" else 10 if ssvc == "poc" else 0
    p_epss = round(epss * 20, 1)
    p_sev = round((cvss or 0) * 2, 1)
    p_ran = 10 if kev and ransomware else 0
    p_rec = 10 if kev and kev >= TODAY - timedelta(days=14) else 0
    return {
        "cve_id": f"CVE-2026-9{n:05d}",
        "title": title,
        "summary": title,
        "priority": round(p_exp + p_epss + p_sev + p_ran + p_rec, 1),
        "p_exploitation": p_exp,
        "p_epss": p_epss,
        "p_severity": p_sev,
        "p_ransomware": p_ran,
        "p_recency": p_rec,
        "in_kev": kev is not None,
        "kev_date_added": kev,
        "kev_due_date": kev + timedelta(days=21) if kev else None,
        "ransomware_known": ransomware,
        "epss": round(epss * 0.6, 4),
        "epss_percentile": epss,
        "headline_score": cvss,
        "headline_version": "3.1" if cvss is not None else None,
        "headline_origin": origin if cvss is not None else None,
        "headline_provider": {"nvd": "nvd@nist.gov", "cna": "psirt@example.com"}.get(origin),
        "ssvc_exploitation": ssvc,
        "nvd_status": "Analyzed" if origin == "nvd" else "Deferred",
        "kev_vendor": vendor if kev else None,
        "kev_product": product if kev else None,
        "published_at": NOW - timedelta(days=n % 40 + 1),
    }


VULNS = sorted(
    [
        _vuln(
            1,
            "Example Gateway pre-authentication remote code execution",
            kev=TODAY - timedelta(days=1),
            ssvc="active",
            epss=0.97,
            cvss=9.8,
            vendor="Example",
            product="Gateway",
        ),
        _vuln(
            2,
            "Acme VPN Appliance authentication bypass",
            kev=TODAY - timedelta(days=6),
            ransomware=True,
            epss=0.94,
            cvss=9.1,
            origin="cna",
            vendor="Acme",
            product="VPN Appliance",
        ),
        _vuln(
            3,
            "Contoso File Transfer deserialization of untrusted data",
            kev=TODAY - timedelta(days=40),
            ransomware=True,
            epss=0.999,
            cvss=None,
            vendor="Contoso",
            product="File Transfer",
        ),
        _vuln(
            4,
            "Fabrikam Mail Server missing authentication for critical function",
            kev=TODAY - timedelta(days=90),
            ransomware=True,
            epss=0.998,
            cvss=9.8,
        ),
        _vuln(
            5,
            "Northwind ERP server-side request forgery",
            kev=TODAY - timedelta(days=12),
            epss=0.71,
            cvss=8.6,
            origin="cna",
        ),
        _vuln(
            6,
            "Example Router command injection in diagnostics page",
            kev=None,
            ssvc="active",
            epss=0.88,
            cvss=8.8,
        ),
        _vuln(7, "Tailwind CI server path traversal", kev=None, ssvc="poc", epss=0.62, cvss=7.5),
        _vuln(
            8,
            "Example Browser use-after-free in rendering engine",
            kev=TODAY - timedelta(days=3),
            epss=0.41,
            cvss=8.8,
            origin="cna",
        ),
        _vuln(9, "Woodgrove Banking SDK hard-coded credentials", kev=None, epss=0.12, cvss=7.4),
        _vuln(
            10,
            "Litware SCADA HMI JWT 'none' algorithm accepted",
            kev=None,
            ssvc="poc",
            epss=0.33,
            cvss=10.0,
            origin="cna",
        ),
    ],
    key=lambda r: -r["priority"],
)

STORIES = [
    (
        "example-gateway-preauth-rce",
        "Example Gateway pre-auth RCE exploited in the wild; emergency patch released",
        1,
        0,
        3,
        5,
        [1],
    ),
    (
        "acme-vpn-auth-bypass-ransomware",
        "Acme VPN authentication bypass used by a ransomware affiliate",
        8,
        0,
        6,
        5,
        [2],
    ),
    (
        "example-browser-zero-day",
        "Example Browser zero-day patched after targeted attacks",
        3,
        1,
        2,
        4,
        [8],
    ),
    (
        "litware-scada-jwt-none",
        "Litware SCADA HMI accepts unsigned JWTs (CVSS 10)",
        1,
        1,
        1,
        4,
        [10],
    ),
    (
        "tailwind-ci-path-traversal-poc",
        "Public PoC for Tailwind CI path traversal",
        2,
        2,
        1,
        3,
        [7],
    ),
    (
        "monthly-patch-rollup",
        "Monthly vendor patch roll-up: 3 exploited issues",
        1,
        1,
        1,
        3,
        [1, 2, 8],
    ),
]

NEWS = [
    ("research-blog", "Inside the Example Gateway exploit chain: from header parsing to RCE", 2),
    ("vendor-psirt", "Security advisory: Example Gateway 4.x critical update", 5),
    ("national-cert", "Alert: active exploitation of Acme VPN appliances", 9),
    ("security-news", "Ransomware affiliate pivots to edge devices, report says", 12),
    ("research-blog", "Fuzzing industrial HMIs: what we found in token validation", 16),
    ("security-news", "Browser vendor ships emergency fix for exploited flaw", 20),
    ("vendor-psirt", "Tailwind CI 3.2.1 released with security fixes", 23),
    ("research-blog", "Detection notes: hunting for gateway exploitation in proxy logs", 26),
]


def _brand(v: dict[str, Any]) -> str:
    """'Acme VPN Appliance ...' -> 'Acme': related demo news must mention the same vendor."""
    return str(v["title"]).split()[0]


class DemoReader:
    def summary(self) -> dict[str, Any]:
        return {
            "kev_active": 1782,
            "kev_new_7d": 3,
            "ssvc_active": 2,
            "docs_24h": 214,
            "stories_7d": len(STORIES),
            "sources_failing": 0,
            "last_ingest": NOW,
        }

    def list_vulns(self, query: Any) -> tuple[list[dict[str, Any]], int]:
        rows = [r for r in VULNS if (not query.kev or r["in_kev"])]
        if query.q:
            rows = [r for r in rows if query.q.lower() in r["title"].lower()]
        return rows, len(rows)

    def vuln_detail(self, cve_id: str) -> dict[str, Any] | None:
        v = next((r for r in VULNS if r["cve_id"] == cve_id), None)
        if v is None:
            return None
        return {
            "v": v,
            "record": {
                "description": v["title"]
                + ". A remote, unauthenticated attacker can send a crafted "
                "request to the management interface and execute code as the service user.",
                "cwes": ["CWE-306"],
                "assigner": "psirt@example.com",
                "record_state": "PUBLISHED",
                "published_at": v["published_at"],
                "updated_at": NOW,
                "ssvc_exploitation": v["ssvc_exploitation"] or "active",
                "ssvc_automatable": "yes",
                "ssvc_technical_impact": "total",
                "ssvc_timestamp": NOW,
                "adp_kev_date": v["kev_date_added"],
                "nvd_status": v["nvd_status"],
                "nvd_last_modified": NOW,
                "nvd_has_cpe": True,
            },
            "kev": None
            if not v["in_kev"]
            else {
                "vendor": v["kev_vendor"],
                "product": v["kev_product"],
                "name": v["title"],
                "date_added": v["kev_date_added"],
                "due_date": v["kev_due_date"],
                "ransomware_known": v["ransomware_known"],
                "short_description": "Exploited in the wild; apply vendor updates.",
                "required_action": "Apply mitigations per vendor instructions or discontinue use.",
                "notes": "",
                "catalog_version": "2026.11.17",
                "removed_at": None,
            },
            "scores": [
                {
                    "collected_from": "nvd",
                    "version": "3.1",
                    "origin": "nvd",
                    "provider": "nvd@nist.gov",
                    "base_score": v["headline_score"] or 9.8,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "severity": "CRITICAL",
                },
                {
                    "collected_from": "cve5",
                    "version": "4.0",
                    "origin": "cna",
                    "provider": "psirt@example.com",
                    "base_score": 9.3,
                    "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                    "severity": "CRITICAL",
                },
            ],
            "products": [
                {"vendor": v["kev_vendor"] or "Example", "product": v["kev_product"] or "Product"}
            ],
            "references": [{"url": "https://vendor.example/advisories/2026-001"}],
            "documents": [
                {
                    "id": i,
                    "source_name": s,
                    "title": t,
                    "url": f"https://news.example/{i}",
                    "published_at": NOW - timedelta(hours=h),
                }
                for i, (s, t, h) in enumerate(NEWS, 1)
                if _brand(v) in t
            ],
            "stories": [
                {
                    "slug": s[0],
                    "title": s[1],
                    "first_seen": TODAY - timedelta(days=s[2]),
                    "last_seen": TODAY - timedelta(days=s[3]),
                    "is_rollup": False,
                }
                for s in STORIES
                if int(v["cve_id"][-5:]) in s[6]
            ],
        }

    def list_stories(self, query: Any) -> tuple[list[dict[str, Any]], int]:
        rows = [
            {
                "slug": slug,
                "title": title,
                "first_seen": TODAY - timedelta(days=first),
                "last_seen": TODAY - timedelta(days=last),
                "status": "CONFIRMED" if urg >= 4 else "DEVELOPING",
                "confidence": "HIGH" if urg >= 4 else "MEDIUM",
                "is_rollup": slug.startswith("monthly"),
                "sightings": sightings,
                "max_urgency": urg,
                "cves": len(cves),
            }
            for slug, title, first, last, sightings, urg, cves in STORIES
        ]
        return rows, len(rows)

    def story_detail(self, slug: str) -> dict[str, Any] | None:
        s = next((x for x in STORIES if x[0] == slug), None)
        if s is None:
            return None
        cves = [VULNS_BY_N[n] for n in s[6]]
        return {
            "s": {
                "id": 1,
                "slug": s[0],
                "title": s[1],
                "first_seen": TODAY - timedelta(days=s[2]),
                "last_seen": TODAY - timedelta(days=s[3]),
                "status": "CONFIRMED",
                "confidence": "HIGH",
                "is_rollup": False,
            },
            "sightings": [
                {
                    "origin": "archive",
                    "external_id": f"{s[0]}-{d}",
                    "day": TODAY - timedelta(days=d),
                    "urgency": s[5],
                }
                for d in range(s[2], s[3] - 1, -1)
            ],
            "cves": [
                {
                    "cve_id": c["cve_id"],
                    "title": c["title"],
                    "priority": c["priority"],
                    "in_kev": c["in_kev"],
                    "headline_score": c["headline_score"],
                }
                for c in cves
            ],
            "links": [
                {
                    "direction": "in",
                    "kind": "rollup_of",
                    "method": "cve",
                    "slug": "monthly-patch-rollup",
                    "title": STORIES[-1][1],
                }
            ],
        }

    def story_ai(self, development_id: int) -> dict[str, Any] | None:
        return {
            "output": {
                "summary": f"{VULNS_BY_N[1]['cve_id']} lets an unauthenticated attacker run code"
                " on Example Gateway 4.x through the management interface. It was added to KEV a"
                " day after the vendor advisory, and a research write-up describes the exploit"
                " chain.",
                "why_it_matters": "Internet-facing gateways are a common initial-access target,"
                " and exploitation is already confirmed. Exposure is easy to check and patching"
                " is urgent.",
                "key_points": [
                    "Fixed in Example Gateway 4.2.1",
                    "Exploited in the wild (KEV, SSVC active)",
                    "Management interface should not be internet-facing",
                ],
                "cited_urls": [
                    "https://vendor.example/advisories/2026-001",
                    "https://news.example/1",
                ],
                "learning": [
                    {
                        "topic": "Detecting edge-device exploitation in proxy logs",
                        "reason": "Build a lab detection from the published request pattern.",
                    },
                    {
                        "topic": "Patch verification for appliances",
                        "reason": "Confirm fixed versions in an authorised lab.",
                    },
                ],
                "relevance": {
                    "technical_impact": 5,
                    "real_world": 5,
                    "offensive": 3,
                    "defensive": 5,
                    "learning": 4,
                    "portfolio": 3,
                    "urgency": 5,
                },
                "confidence": "HIGH",
                "injection_suspected": False,
            },
            "provider": "ollama",
            "model": "llama3.1:8b",
            "prompt_version": "analysis-v1",
            "created_at": NOW,
            "injection_suspected": False,
        }

    def list_news(self, query: Any) -> tuple[list[dict[str, Any]], int]:
        rows = [
            {
                "id": i,
                "source_name": s,
                "title": t,
                "url": f"https://news.example/{i}",
                "excerpt": "Synthetic demo article used for screenshots. "
                "The dashboard shows a short, escaped excerpt and the CVEs it mentions.",
                "published_at": NOW - timedelta(hours=h),
                "first_seen_at": NOW - timedelta(hours=h),
                "cves": [VULNS[i % 4]["cve_id"]],
            }
            for i, (s, t, h) in enumerate(NEWS, 1)
        ]
        return rows, len(rows)

    def source_health(self) -> list[dict[str, Any]]:
        names = [
            ("cisa-kev", 1782),
            ("first-epss", 408395),
            ("nvd-cve-api", 2744),
            ("cve-org-records", 40),
            ("research-blog", 15),
            ("vendor-psirt", 10),
            ("national-cert", 8),
            ("security-news", 30),
        ]
        return [
            {
                "source_name": n,
                "last_success_at": NOW - timedelta(minutes=i * 3),
                "last_attempt_at": NOW - timedelta(minutes=i * 3),
                "consecutive_failures": 0,
                "last_error": None,
                "outcome": "ok",
                "finished_at": NOW - timedelta(minutes=i * 3),
                "records_ok": ok,
                "records_rejected": 0,
                "http_status": 200,
            }
            for i, (n, ok) in enumerate(names)
        ]


VULNS_BY_N = {int(r["cve_id"][-5:]): r for r in VULNS}
