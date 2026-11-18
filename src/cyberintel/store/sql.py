"""All application SQL, as constants with psycopg named parameters (``%(name)s``).

Conventions:
* Every untrusted value is a bound parameter. Batches travel as ONE ``jsonb`` parameter
  expanded server-side with ``jsonb_to_recordset``, so a 1,500-row KEV catalog is one
  round trip and no SQL text is ever built from data.
* Integrity rules live in the SQL itself, so a caller bug cannot bypass them:
    - facts never move backwards (older CVE records / EPSS snapshots cannot overwrite
      newer ones);
    - a truncated KEV catalog cannot mass-mark entries as removed (90% guard).
* The same text is executed by psycopg in production and by psql in the local test
  harness (``%(x)s`` -> ``:'x'``), so tests exercise the exact production statements.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- KEV

UPSERT_KEV = """
INSERT INTO kev_entries AS k (
    cve_id, vendor, product, name, date_added, due_date, ransomware_known,
    short_description, required_action, notes, cwes, catalog_version,
    first_seen_at, last_seen_at, removed_at)
SELECT r.cve_id, r.vendor, r.product, r.name, r.date_added, r.due_date, r.ransomware_known,
       r.short_description, r.required_action, r.notes, r.cwes, %(catalog_version)s,
       %(seen_at)s::timestamptz, %(seen_at)s::timestamptz, NULL
FROM jsonb_to_recordset(%(rows)s::jsonb) AS r(
    cve_id text, vendor text, product text, name text, date_added date, due_date date,
    ransomware_known boolean, short_description text, required_action text, notes text,
    cwes text[])
ON CONFLICT (cve_id) DO UPDATE SET
    vendor = EXCLUDED.vendor, product = EXCLUDED.product, name = EXCLUDED.name,
    date_added = EXCLUDED.date_added, due_date = EXCLUDED.due_date,
    ransomware_known = EXCLUDED.ransomware_known,
    short_description = EXCLUDED.short_description,
    required_action = EXCLUDED.required_action, notes = EXCLUDED.notes,
    cwes = EXCLUDED.cwes, catalog_version = EXCLUDED.catalog_version,
    last_seen_at = EXCLUDED.last_seen_at, removed_at = NULL
"""

# Marks entries absent from the new catalog as removed. Guarded: does nothing unless the
# new catalog holds >= 90% of the currently active entries (a truncated or partial
# download must not "un-exploit" hundreds of CVEs). Returns the CVEs marked.
MARK_KEV_REMOVED = """
WITH present AS (
    SELECT jsonb_array_elements_text(%(present)s::jsonb) AS cve_id
), guard AS (
    SELECT (SELECT count(*) FROM present)
           >= 0.9 * (SELECT count(*) FROM kev_entries WHERE removed_at IS NULL) AS ok
)
UPDATE kev_entries AS k SET removed_at = %(seen_at)s::timestamptz
FROM guard
WHERE guard.ok
  AND k.removed_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM present p WHERE p.cve_id = k.cve_id)
RETURNING k.cve_id
"""

# --------------------------------------------------------------------------- EPSS

# Older snapshots never overwrite newer ones; unchanged rows are not rewritten.
UPSERT_EPSS = """
INSERT INTO epss_scores AS e (cve_id, epss, percentile, score_date, model_version, updated_at)
SELECT r.cve_id, r.epss, r.percentile, %(score_date)s::date, %(model_version)s,
       %(seen_at)s::timestamptz
FROM jsonb_to_recordset(%(rows)s::jsonb) AS r(cve_id text, epss numeric, percentile numeric)
ON CONFLICT (cve_id) DO UPDATE SET
    epss = EXCLUDED.epss, percentile = EXCLUDED.percentile, score_date = EXCLUDED.score_date,
    model_version = EXCLUDED.model_version, updated_at = EXCLUDED.updated_at
WHERE (e.score_date IS NULL OR EXCLUDED.score_date IS NULL
       OR EXCLUDED.score_date >= e.score_date)
  AND (e.epss, e.percentile, e.score_date)
      IS DISTINCT FROM (EXCLUDED.epss, EXCLUDED.percentile, EXCLUDED.score_date)
"""

# --------------------------------------------------------------------------- CVE.org

# Record fields are owned by CVE.org. A record older than the stored one is ignored
# (RETURNING lists only the CVEs actually written; dependent rows are replaced for those).
UPSERT_CVE5 = """
INSERT INTO vulnerabilities AS v (
    cve_id, record_state, assigner, title, description, published_at, updated_at, cwes,
    ssvc_exploitation, ssvc_automatable, ssvc_technical_impact, ssvc_timestamp,
    adp_kev_date, cve5_fetched_at)
SELECT r.cve_id, r.record_state, r.assigner, r.title, r.description, r.published_at,
       r.updated_at, r.cwes, r.ssvc_exploitation, r.ssvc_automatable,
       r.ssvc_technical_impact, r.ssvc_timestamp, r.adp_kev_date, %(seen_at)s::timestamptz
FROM jsonb_to_recordset(%(rows)s::jsonb) AS r(
    cve_id text, record_state text, assigner text, title text, description text,
    published_at timestamptz, updated_at timestamptz, cwes text[], ssvc_exploitation text,
    ssvc_automatable text, ssvc_technical_impact text, ssvc_timestamp timestamptz,
    adp_kev_date date)
ON CONFLICT (cve_id) DO UPDATE SET
    record_state = EXCLUDED.record_state, assigner = EXCLUDED.assigner,
    title = EXCLUDED.title, description = EXCLUDED.description,
    published_at = EXCLUDED.published_at, updated_at = EXCLUDED.updated_at,
    cwes = ARRAY(SELECT DISTINCT c FROM unnest(v.cwes || EXCLUDED.cwes) AS c ORDER BY c),
    ssvc_exploitation = EXCLUDED.ssvc_exploitation,
    ssvc_automatable = EXCLUDED.ssvc_automatable,
    ssvc_technical_impact = EXCLUDED.ssvc_technical_impact,
    ssvc_timestamp = EXCLUDED.ssvc_timestamp, adp_kev_date = EXCLUDED.adp_kev_date,
    cve5_fetched_at = EXCLUDED.cve5_fetched_at
WHERE v.updated_at IS NULL OR EXCLUDED.updated_at IS NULL
   OR EXCLUDED.updated_at >= v.updated_at
RETURNING v.cve_id
"""

# --------------------------------------------------------------------------- NVD

# NVD owns only its nvd_* columns; it fills record fields solely where CVE.org has not.
UPSERT_NVD = """
INSERT INTO vulnerabilities AS v (
    cve_id, description, published_at, cwes,
    nvd_status, nvd_last_modified, nvd_has_cpe, nvd_fetched_at)
SELECT r.cve_id, r.description, r.published_at, r.cwes,
       r.nvd_status, r.nvd_last_modified, r.nvd_has_cpe, %(seen_at)s::timestamptz
FROM jsonb_to_recordset(%(rows)s::jsonb) AS r(
    cve_id text, description text, published_at timestamptz, cwes text[],
    nvd_status text, nvd_last_modified timestamptz, nvd_has_cpe boolean)
ON CONFLICT (cve_id) DO UPDATE SET
    description = COALESCE(v.description, EXCLUDED.description),
    published_at = COALESCE(v.published_at, EXCLUDED.published_at),
    cwes = ARRAY(SELECT DISTINCT c FROM unnest(v.cwes || EXCLUDED.cwes) AS c ORDER BY c),
    nvd_status = EXCLUDED.nvd_status, nvd_last_modified = EXCLUDED.nvd_last_modified,
    nvd_has_cpe = EXCLUDED.nvd_has_cpe, nvd_fetched_at = EXCLUDED.nvd_fetched_at
WHERE v.nvd_last_modified IS NULL OR EXCLUDED.nvd_last_modified >= v.nvd_last_modified
RETURNING v.cve_id
"""

# --------------------------------------------------------------------------- dependents

DELETE_SCORES = """
DELETE FROM cvss_scores
WHERE collected_from = %(collected_from)s AND cve_id = ANY(%(cve_ids)s::text[])
"""

INSERT_SCORES = """
INSERT INTO cvss_scores (
    cve_id, collected_from, version, origin, provider, base_score, vector, severity,
    collected_at)
SELECT r.cve_id, %(collected_from)s, r.version, r.origin, r.provider, r.base_score,
       r.vector, r.severity, %(seen_at)s::timestamptz
FROM jsonb_to_recordset(%(rows)s::jsonb) AS r(
    cve_id text, version text, origin text, provider text, base_score numeric,
    vector text, severity text)
ON CONFLICT DO NOTHING
"""

DELETE_PRODUCTS = "DELETE FROM affected_products WHERE cve_id = ANY(%(cve_ids)s::text[])"

# Normalization here must equal entities.norm() in Python (parity-tested).
INSERT_PRODUCTS = """
INSERT INTO affected_products (cve_id, vendor, product, vendor_norm, product_norm)
SELECT r.cve_id, r.vendor, r.product, n.vendor_norm, n.product_norm
FROM jsonb_to_recordset(%(rows)s::jsonb) AS r(cve_id text, vendor text, product text)
CROSS JOIN LATERAL (SELECT
    lower(regexp_replace(r.vendor, '[^A-Za-z0-9]', '', 'g')) AS vendor_norm,
    lower(regexp_replace(r.product, '[^A-Za-z0-9]', '', 'g')) AS product_norm) AS n
WHERE n.vendor_norm <> '' AND n.product_norm <> ''
ON CONFLICT DO NOTHING
"""

DELETE_REFERENCES = "DELETE FROM vulnerability_references WHERE cve_id = ANY(%(cve_ids)s::text[])"

INSERT_REFERENCES = """
INSERT INTO vulnerability_references (cve_id, url)
SELECT r.cve_id, r.url
FROM jsonb_to_recordset(%(rows)s::jsonb) AS r(cve_id text, url text)
ON CONFLICT DO NOTHING
"""

# Headline policy, mirrored from collectors/cvss.py:headline() (parity-tested):
# v3.x family first, then NVD > CNA > ADP > other, then 3.1 over 3.0, v2 last.
RECOMPUTE_HEADLINE = """
UPDATE vulnerabilities AS v SET
    headline_score = h.base_score, headline_version = h.version,
    headline_origin = h.origin, headline_provider = h.provider
FROM (
    SELECT DISTINCT ON (s.cve_id) s.cve_id, s.base_score, s.version, s.origin, s.provider
    FROM cvss_scores s
    WHERE s.cve_id = ANY(%(cve_ids)s::text[])
    ORDER BY s.cve_id,
        CASE s.version WHEN '3.1' THEN 0 WHEN '3.0' THEN 0 WHEN '4.0' THEN 1 ELSE 2 END,
        CASE s.origin WHEN 'nvd' THEN 0 WHEN 'cna' THEN 1 WHEN 'adp' THEN 2 ELSE 3 END,
        CASE s.version WHEN '3.0' THEN 1 ELSE 0 END,
        s.collected_from, s.provider
) AS h
WHERE v.cve_id = h.cve_id
"""

CLEAR_HEADLINE_WITHOUT_SCORES = """
UPDATE vulnerabilities AS v SET
    headline_score = NULL, headline_version = NULL,
    headline_origin = NULL, headline_provider = NULL
WHERE v.cve_id = ANY(%(cve_ids)s::text[])
  AND NOT EXISTS (SELECT 1 FROM cvss_scores s WHERE s.cve_id = v.cve_id)
"""

# --------------------------------------------------------------------------- documents

# Callers must de-duplicate canonical_url within a batch (Postgres refuses to update the
# same row twice in one statement). Returns one row per input: inserted or updated.
UPSERT_DOCUMENTS = """
INSERT INTO documents AS d (
    source_name, canonical_url, url, guid, title, excerpt, published_at, cves,
    first_seen_at, last_seen_at)
SELECT %(source_name)s, r.canonical_url, r.url, r.guid, r.title, r.excerpt,
       r.published_at, r.cves, %(seen_at)s::timestamptz, %(seen_at)s::timestamptz
FROM jsonb_to_recordset(%(rows)s::jsonb) AS r(
    canonical_url text, url text, guid text, title text, excerpt text,
    published_at timestamptz, cves text[])
ON CONFLICT (canonical_url) DO UPDATE SET
    title = EXCLUDED.title, excerpt = EXCLUDED.excerpt, cves = EXCLUDED.cves,
    published_at = COALESCE(d.published_at, EXCLUDED.published_at),
    last_seen_at = GREATEST(d.last_seen_at, EXCLUDED.last_seen_at)
RETURNING (xmax = 0) AS inserted
"""

# --------------------------------------------------------------------------- bookkeeping

GET_SOURCE_STATE = """
SELECT etag, last_modified, consecutive_failures, last_success_at, last_attempt_at
FROM source_state WHERE source_name = %(source_name)s
"""

RECORD_SUCCESS = """
INSERT INTO source_state AS s (
    source_name, etag, last_modified, last_attempt_at, last_success_at,
    consecutive_failures, last_error)
VALUES (%(source_name)s, %(etag)s, %(last_modified)s, %(at)s::timestamptz,
        %(at)s::timestamptz, 0, NULL)
ON CONFLICT (source_name) DO UPDATE SET
    etag = COALESCE(EXCLUDED.etag, s.etag),
    last_modified = COALESCE(EXCLUDED.last_modified, s.last_modified),
    last_attempt_at = EXCLUDED.last_attempt_at, last_success_at = EXCLUDED.last_success_at,
    consecutive_failures = 0, last_error = NULL
"""

RECORD_FAILURE = """
INSERT INTO source_state AS s (source_name, last_attempt_at, consecutive_failures, last_error)
VALUES (%(source_name)s, %(at)s::timestamptz, 1, left(%(error)s, 500))
ON CONFLICT (source_name) DO UPDATE SET
    last_attempt_at = EXCLUDED.last_attempt_at,
    consecutive_failures = s.consecutive_failures + 1,
    last_error = EXCLUDED.last_error
"""

INSERT_FETCH_RUN = """
INSERT INTO fetch_runs (
    source_name, started_at, finished_at, outcome, http_status, bytes, peer_address,
    records_ok, records_rejected, error)
VALUES (%(source_name)s, %(started_at)s::timestamptz, %(finished_at)s::timestamptz,
        %(outcome)s, %(http_status)s::integer, %(bytes)s::bigint, %(peer_address)s::inet,
        %(records_ok)s::integer, %(records_rejected)s::integer, left(%(error)s, 500))
"""

# --------------------------------------------------------------------------- developments

UPSERT_DEVELOPMENT = """
INSERT INTO developments AS d (slug, title, first_seen, last_seen, status, confidence,
                               is_rollup)
VALUES (%(slug)s, %(title)s, %(first_seen)s::date, %(last_seen)s::date, %(status)s,
        %(confidence)s, %(is_rollup)s::boolean)
ON CONFLICT (slug) DO UPDATE SET
    title = EXCLUDED.title,
    first_seen = LEAST(d.first_seen, EXCLUDED.first_seen),
    last_seen = GREATEST(d.last_seen, EXCLUDED.last_seen),
    status = EXCLUDED.status, confidence = EXCLUDED.confidence,
    is_rollup = EXCLUDED.is_rollup
RETURNING id
"""

INSERT_SIGHTINGS = """
INSERT INTO development_sightings (development_id, origin, external_id, day, urgency)
SELECT %(development_id)s::bigint, %(origin)s, r.external_id, r.day, r.urgency
FROM jsonb_to_recordset(%(rows)s::jsonb) AS r(external_id text, day date, urgency smallint)
ON CONFLICT (origin, external_id) DO UPDATE SET
    development_id = EXCLUDED.development_id, day = EXCLUDED.day, urgency = EXCLUDED.urgency
"""

INSERT_DEVELOPMENT_CVES = """
INSERT INTO development_vulnerabilities (development_id, cve_id)
SELECT %(development_id)s::bigint, c
FROM jsonb_array_elements_text(%(cves)s::jsonb) AS c
ON CONFLICT DO NOTHING
"""

INSERT_DEVELOPMENT_LINK = """
INSERT INTO development_links (a, b, kind, method)
SELECT a.id, b.id, %(kind)s, %(method)s
FROM developments a, developments b
WHERE a.slug = %(a_slug)s AND b.slug = %(b_slug)s
ON CONFLICT DO NOTHING
"""

# Archive-derived developments are a rebuildable projection of immutable archive files:
# importing deletes them and rebuilds, so improving the linker never leaves stale merges.
DELETE_ARCHIVE_DEVELOPMENTS = """
DELETE FROM developments
WHERE id IN (SELECT development_id FROM development_sightings WHERE origin = 'archive')
"""

# Enrichment queue: CVEs we know matter (in KEV, or named in collected articles) but have
# no CVE.org record for yet. Newest first; bounded per run.
CVE5_QUEUE = """
SELECT q.cve_id FROM (
    SELECT cve_id, date_added::timestamptz AS seen FROM kev_entries WHERE removed_at IS NULL
    UNION ALL
    SELECT c, d.first_seen_at FROM documents d CROSS JOIN LATERAL unnest(d.cves) AS c
) AS q
WHERE q.cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,7}$'
  AND NOT EXISTS (SELECT 1 FROM vulnerabilities v
                  WHERE v.cve_id = q.cve_id AND v.cve5_fetched_at IS NOT NULL)
GROUP BY q.cve_id
ORDER BY max(q.seen) DESC, q.cve_id
LIMIT %(limit)s
"""
