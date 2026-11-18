"""SQL for the AI layer. Writes touch ``ai_analyses`` and ``ai_usage`` only (tested)."""

from __future__ import annotations

from typing import Final

# Literal LIMITs below (no string-built SQL): 20 CVEs and 8 documents per analysis;
# tests assert 8 == schema.MAX_EVIDENCE_ITEMS so "shown" and "citable" never diverge.

# Recent, non-roll-up stories that have at least one CVE, most important first.
AI_CANDIDATES: Final = """
SELECT d.id, d.slug, d.title, d.first_seen, d.last_seen
FROM developments d
WHERE NOT d.is_rollup
  AND d.last_seen >= %(since)s
  AND EXISTS (SELECT 1 FROM development_vulnerabilities x WHERE x.development_id = d.id)
ORDER BY (
    SELECT max(o.priority)
    FROM development_vulnerabilities x
    JOIN vulnerability_overview o ON o.cve_id = x.cve_id
    WHERE x.development_id = d.id
) DESC NULLS LAST, d.last_seen DESC, d.id
LIMIT %(limit)s
"""

AI_DEVELOPMENT_BY_SLUG: Final = """
SELECT d.id, d.slug, d.title, d.first_seen, d.last_seen
FROM developments d WHERE d.slug = %(slug)s
"""

AI_CVE_FACTS: Final = """
SELECT x.cve_id, o.title, COALESCE(o.in_kev, false), o.kev_date_added,
       COALESCE(o.ransomware_known, false), o.epss_percentile, o.headline_score,
       o.headline_version, o.headline_origin, o.ssvc_exploitation, o.priority
FROM development_vulnerabilities x
LEFT JOIN vulnerability_overview o ON o.cve_id = x.cve_id
WHERE x.development_id = %(development_id)s
ORDER BY o.priority DESC NULLS LAST, x.cve_id
LIMIT 20
"""

# Evidence = collected documents that mention the story's CVEs (most overlap, newest first).
AI_EVIDENCE: Final = """
SELECT doc.id, doc.url, doc.source_name, doc.title, doc.excerpt, doc.published_at
FROM documents doc
WHERE doc.cves && %(cve_ids)s::text[]
ORDER BY cardinality(ARRAY(
             SELECT unnest(doc.cves) INTERSECT SELECT unnest(%(cve_ids)s::text[])
         )) DESC,
         doc.published_at DESC NULLS LAST, doc.id DESC
LIMIT 8
"""

AI_ANALYSIS_EXISTS: Final = """
SELECT EXISTS (
    SELECT 1 FROM ai_analyses
    WHERE development_id = %(development_id)s AND provider = %(provider)s
      AND model = %(model)s AND input_hash = %(input_hash)s
)
"""

AI_TOKENS_ON_DAY: Final = """
SELECT COALESCE(sum(input_tokens + output_tokens), 0) FROM ai_usage WHERE day = %(day)s
"""

INSERT_AI_ANALYSIS: Final = """
INSERT INTO ai_analyses (
    development_id, provider, model, prompt_version, prompt_sha256, input_hash,
    document_ids, cve_ids, validated, output, rejected_reasons, raw_output,
    injection_suspected, input_tokens, output_tokens
) VALUES (
    %(development_id)s, %(provider)s, %(model)s, %(prompt_version)s, %(prompt_sha256)s,
    %(input_hash)s, %(document_ids)s::bigint[], %(cve_ids)s::text[], %(validated)s,
    %(output)s::jsonb, %(rejected_reasons)s::text[], %(raw_output)s,
    %(injection_suspected)s, %(input_tokens)s, %(output_tokens)s
)
ON CONFLICT (development_id, provider, model, input_hash) DO NOTHING
RETURNING id
"""

ADD_AI_USAGE: Final = """
INSERT INTO ai_usage AS u (day, provider, model, calls, rejected, input_tokens, output_tokens)
VALUES (%(day)s, %(provider)s, %(model)s, 1, %(rejected)s, %(input_tokens)s, %(output_tokens)s)
ON CONFLICT (day, provider, model) DO UPDATE SET
    calls         = u.calls + 1,
    rejected      = u.rejected + EXCLUDED.rejected,
    input_tokens  = u.input_tokens + EXCLUDED.input_tokens,
    output_tokens = u.output_tokens + EXCLUDED.output_tokens
"""
