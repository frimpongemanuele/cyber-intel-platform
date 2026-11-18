-- 0002_overview: one read model for "what should I look at first?"
--
-- Rule-based, deterministic priority (0-100). Every component is exposed as its own column
-- so the dashboard can always explain a rank (docs/SCORING.md). This is the baseline the
-- AI layer (Phase 9) is measured against; it is never silently replaced.
--
--   exploitation  40  in CISA KEV (active entry)
--                 30  else CISA-ADP SSVC exploitation = active
--                 10  else SSVC exploitation = poc
--   epss          20 x EPSS percentile                      (prediction)
--   severity       2 x headline CVSS base score             (impact)
--   ransomware    10  KEV knownRansomwareCampaignUse = Known
--   recency       10  added to KEV in the last 14 days
--
-- Base set: CVEs we hold a record or a KEV entry for (not every EPSS-scored CVE).

CREATE VIEW vulnerability_overview AS
WITH base AS (
    SELECT
        COALESCE(v.cve_id, k.cve_id)                       AS cve_id,
        COALESCE(v.title, k.name)                          AS title,
        left(COALESCE(v.description, k.short_description), 400) AS summary,
        v.record_state, v.assigner, v.published_at, v.nvd_status,
        v.headline_score, v.headline_version, v.headline_origin, v.headline_provider,
        v.ssvc_exploitation, v.ssvc_automatable, v.ssvc_technical_impact,
        (k.cve_id IS NOT NULL AND k.removed_at IS NULL)     AS in_kev,
        k.date_added   AS kev_date_added,
        k.due_date     AS kev_due_date,
        COALESCE(k.ransomware_known, false)                AS ransomware_known,
        k.vendor       AS kev_vendor,
        k.product      AS kev_product,
        e.epss, e.percentile AS epss_percentile, e.score_date AS epss_date
    FROM vulnerabilities v
    FULL OUTER JOIN kev_entries k ON k.cve_id = v.cve_id
    LEFT JOIN epss_scores e ON e.cve_id = COALESCE(v.cve_id, k.cve_id)
), parts AS (
    SELECT b.*,
        CASE WHEN b.in_kev THEN 40
             WHEN b.ssvc_exploitation = 'active' THEN 30
             WHEN b.ssvc_exploitation = 'poc' THEN 10
             ELSE 0 END                                              AS p_exploitation,
        round(COALESCE(b.epss_percentile, 0) * 20, 1)                AS p_epss,
        round(COALESCE(b.headline_score, 0) * 2, 1)                  AS p_severity,
        CASE WHEN b.in_kev AND b.ransomware_known THEN 10 ELSE 0 END AS p_ransomware,
        CASE WHEN b.in_kev AND b.kev_date_added >= current_date - 14
             THEN 10 ELSE 0 END                                      AS p_recency
    FROM base b
    WHERE b.record_state IS DISTINCT FROM 'REJECTED' OR b.in_kev
)
SELECT p.*,
       (p.p_exploitation + p.p_epss + p.p_severity + p.p_ransomware + p.p_recency)::numeric(4, 1)
           AS priority
FROM parts p;
