"""Read-side SQL for the dashboard (psycopg ``%(name)s`` parameters; psql-harness tested).

* Sorting uses an allowlist of *complete, prebuilt* statements: user input selects a key,
  it is never interpolated into ORDER BY (the one place bound parameters cannot help).
* Text search escapes LIKE wildcards in Python (``like_pattern``) and uses ``ESCAPE``.
* Every list is bounded by LIMIT/OFFSET; page sizes are fixed by the application.
"""

from __future__ import annotations

from typing import Final

CVE_NUMERIC_DESC: Final = (
    "split_part(o.cve_id, '-', 2)::int DESC, split_part(o.cve_id, '-', 3)::int DESC"
)


def like_pattern(term: str) -> str:
    """User text -> ILIKE pattern matching it literally anywhere (wildcards escaped)."""
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


_VULN_COLUMNS: Final = """
    o.cve_id, o.title, o.summary, o.priority, o.p_exploitation, o.p_epss, o.p_severity,
    o.p_ransomware, o.p_recency, o.in_kev, o.kev_date_added, o.kev_due_date,
    o.ransomware_known, o.epss, o.epss_percentile, o.headline_score, o.headline_version,
    o.headline_origin, o.headline_provider, o.ssvc_exploitation, o.nvd_status,
    o.kev_vendor, o.kev_product, o.published_at
"""

_VULN_FILTERS: Final = r"""
    (NOT %(kev_only)s OR o.in_kev)
    AND (NOT %(exploited_only)s OR o.in_kev OR o.ssvc_exploitation = 'active')
    AND o.priority >= %(min_priority)s
    AND (%(pattern)s::text IS NULL
         OR o.cve_id ILIKE %(pattern)s ESCAPE '\'
         OR o.title ILIKE %(pattern)s ESCAPE '\'
         OR o.kev_vendor ILIKE %(pattern)s ESCAPE '\'
         OR o.kev_product ILIKE %(pattern)s ESCAPE '\'
         OR EXISTS (SELECT 1 FROM affected_products ap
                    WHERE ap.cve_id = o.cve_id
                      AND (ap.vendor ILIKE %(pattern)s ESCAPE '\'
                           OR ap.product ILIKE %(pattern)s ESCAPE '\')))
"""

VULN_SORTS: Final[dict[str, str]] = {
    "priority": f"o.priority DESC, {CVE_NUMERIC_DESC}",
    "newest_kev": f"o.kev_date_added DESC NULLS LAST, o.priority DESC, {CVE_NUMERIC_DESC}",
    "epss": f"o.epss DESC NULLS LAST, {CVE_NUMERIC_DESC}",
    "cvss": f"o.headline_score DESC NULLS LAST, {CVE_NUMERIC_DESC}",
    "cve": CVE_NUMERIC_DESC,
}

LIST_VULNS: Final[dict[str, str]] = {
    key: f"""SELECT {_VULN_COLUMNS} FROM vulnerability_overview o
             WHERE {_VULN_FILTERS} ORDER BY {order}
             LIMIT %(limit)s OFFSET %(offset)s"""
    for key, order in VULN_SORTS.items()
}

COUNT_VULNS: Final = f"SELECT count(*) FROM vulnerability_overview o WHERE {_VULN_FILTERS}"

GET_VULN: Final = (
    f"SELECT {_VULN_COLUMNS} FROM vulnerability_overview o WHERE o.cve_id = %(cve_id)s"
)

GET_VULN_RECORD: Final = """
SELECT description, cwes, assigner, record_state, published_at, updated_at,
       ssvc_exploitation, ssvc_automatable, ssvc_technical_impact, ssvc_timestamp,
       adp_kev_date, nvd_status, nvd_last_modified, nvd_has_cpe
FROM vulnerabilities WHERE cve_id = %(cve_id)s
"""

GET_KEV: Final = """
SELECT vendor, product, name, date_added, due_date, ransomware_known, short_description,
       required_action, notes, catalog_version, removed_at
FROM kev_entries WHERE cve_id = %(cve_id)s
"""

LIST_SCORES: Final = """
SELECT collected_from, version, origin, provider, base_score, vector, severity
FROM cvss_scores WHERE cve_id = %(cve_id)s
ORDER BY CASE version WHEN '3.1' THEN 0 WHEN '3.0' THEN 0 WHEN '4.0' THEN 1 ELSE 2 END,
         CASE origin WHEN 'nvd' THEN 0 WHEN 'cna' THEN 1 WHEN 'adp' THEN 2 ELSE 3 END,
         collected_from, provider
"""

LIST_PRODUCTS: Final = """
SELECT vendor, product FROM affected_products WHERE cve_id = %(cve_id)s
ORDER BY vendor_norm, product_norm LIMIT 50
"""

LIST_REFERENCES: Final = """
SELECT url FROM vulnerability_references WHERE cve_id = %(cve_id)s ORDER BY url LIMIT 50
"""

LIST_DOCUMENTS_FOR_CVE: Final = """
SELECT id, source_name, title, url, published_at
FROM documents WHERE cves @> ARRAY[%(cve_id)s]::text[]
ORDER BY COALESCE(published_at, first_seen_at) DESC, id DESC LIMIT 20
"""

LIST_DEVELOPMENTS_FOR_CVE: Final = """
SELECT d.slug, d.title, d.first_seen, d.last_seen, d.is_rollup
FROM development_vulnerabilities x JOIN developments d ON d.id = x.development_id
WHERE x.cve_id = %(cve_id)s ORDER BY d.last_seen DESC, d.id DESC LIMIT 20
"""

SUMMARY: Final = """
SELECT
  (SELECT count(*) FROM kev_entries WHERE removed_at IS NULL) AS kev_active,
  (SELECT count(*) FROM kev_entries
    WHERE removed_at IS NULL AND date_added >= current_date - 7) AS kev_new_7d,
  (SELECT count(*) FROM vulnerabilities WHERE ssvc_exploitation = 'active') AS ssvc_active,
  (SELECT count(*) FROM documents
    WHERE first_seen_at >= now() - interval '24 hours') AS docs_24h,
  (SELECT count(*) FROM developments WHERE last_seen >= current_date - 7) AS stories_7d,
  (SELECT count(*) FROM source_state WHERE consecutive_failures > 0) AS sources_failing,
  (SELECT max(finished_at) FROM fetch_runs WHERE outcome <> 'error') AS last_ingest
"""

_DEV_LIST: Final = """
SELECT d.slug, d.title, d.first_seen, d.last_seen, d.status, d.confidence, d.is_rollup,
       count(s.external_id)                                                     AS sightings,
       max(s.urgency)                                                           AS max_urgency,
       (SELECT count(*) FROM development_vulnerabilities x WHERE x.development_id = d.id) AS cves
FROM developments d
LEFT JOIN development_sightings s ON s.development_id = d.id
WHERE (%(include_rollups)s OR NOT d.is_rollup)
  AND (%(pattern)s::text IS NULL OR d.title ILIKE %(pattern)s ESCAPE '\\')
GROUP BY d.id
"""

LIST_DEVELOPMENTS: Final = (
    _DEV_LIST
    + "ORDER BY d.last_seen DESC, max(s.urgency) DESC NULLS LAST, d.id DESC "
    + "LIMIT %(limit)s OFFSET %(offset)s"
)

COUNT_DEVELOPMENTS: Final = f"SELECT count(*) FROM ({_DEV_LIST}) AS q"

GET_DEVELOPMENT: Final = """
SELECT id, slug, title, first_seen, last_seen, status, confidence, is_rollup
FROM developments WHERE slug = %(slug)s
"""

LIST_SIGHTINGS: Final = """
SELECT origin, external_id, day, urgency FROM development_sightings
WHERE development_id = %(development_id)s ORDER BY day, external_id
"""

LIST_DEVELOPMENT_CVES: Final = f"""
SELECT x.cve_id, o.title, o.priority, o.in_kev, o.headline_score
FROM development_vulnerabilities x
LEFT JOIN vulnerability_overview o ON o.cve_id = x.cve_id
WHERE x.development_id = %(development_id)s
ORDER BY o.priority DESC NULLS LAST, {CVE_NUMERIC_DESC.replace("o.cve_id", "x.cve_id")}
LIMIT 100
"""

LIST_DEVELOPMENT_LINKS: Final = """
SELECT CASE WHEN l.a = %(development_id)s THEN 'out' ELSE 'in' END AS direction,
       l.kind, l.method, d.slug, d.title
FROM development_links l
JOIN developments d ON d.id = CASE WHEN l.a = %(development_id)s THEN l.b ELSE l.a END
WHERE l.a = %(development_id)s OR l.b = %(development_id)s
ORDER BY d.last_seen DESC, d.id DESC LIMIT 50
"""

_DOC_FILTERS: Final = r"""
    (%(source)s::text IS NULL OR d.source_name = %(source)s)
    AND (%(pattern)s::text IS NULL OR d.title ILIKE %(pattern)s ESCAPE '\'
         OR d.excerpt ILIKE %(pattern)s ESCAPE '\')
"""

LIST_DOCUMENTS: Final = f"""
SELECT d.id, d.source_name, d.title, d.url, d.excerpt, d.published_at, d.first_seen_at, d.cves
FROM documents d WHERE {_DOC_FILTERS}
ORDER BY COALESCE(d.published_at, d.first_seen_at) DESC, d.id DESC
LIMIT %(limit)s OFFSET %(offset)s
"""

COUNT_DOCUMENTS: Final = f"SELECT count(*) FROM documents d WHERE {_DOC_FILTERS}"

LIST_SOURCE_HEALTH: Final = """
SELECT s.source_name, s.last_success_at, s.last_attempt_at, s.consecutive_failures,
       s.last_error, r.outcome, r.finished_at, r.records_ok, r.records_rejected, r.http_status
FROM source_state s
LEFT JOIN LATERAL (
    SELECT f.outcome, f.finished_at, f.records_ok, f.records_rejected, f.http_status
    FROM fetch_runs f WHERE f.source_name = s.source_name
    ORDER BY f.started_at DESC, f.id DESC LIMIT 1
) AS r ON true
ORDER BY s.source_name
"""
