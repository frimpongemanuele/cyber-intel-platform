-- Least-privilege grants for the deployed services (DEPLOYMENT.md, THREAT_MODEL T5/T10/T14).
--
-- Applied by `python -m cyberintel.store.migrate up --grants`, as the schema owner, after
-- migrations. Idempotent: it revokes everything from the service roles and grants again,
-- so a grant removed here is also removed from a running database.
--
--   cit_ingest  collectors + archive import: read/write fact tables; nothing in ai_*
--   cit_web     dashboard: SELECT only; on ai_analyses only the columns it renders
--               (never raw model output); nothing on ai_usage
--   cit_ai      AI runner: read facts and documents; insert ai_analyses; upsert ai_usage
--
-- Roles are created (with passwords) by deploy/postgres/initdb/10-roles.sh. In a
-- development database without them this script does nothing.

DO $grants$
BEGIN
    IF (SELECT count(*) FROM pg_roles WHERE rolname IN ('cit_ingest', 'cit_web', 'cit_ai')) <> 3 THEN
        RAISE NOTICE 'service roles not present; grants skipped';
        RETURN;
    END IF;

    REVOKE CREATE ON SCHEMA public FROM PUBLIC;
    GRANT USAGE ON SCHEMA public TO cit_ingest, cit_web, cit_ai;
    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC, cit_ingest, cit_web, cit_ai;
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC, cit_ingest, cit_web, cit_ai;

    -- ingest -----------------------------------------------------------------------
    GRANT SELECT, INSERT, UPDATE ON
        source_state, fetch_runs, vulnerabilities, cvss_scores, affected_products,
        vulnerability_references, kev_entries, epss_scores, documents, developments,
        development_sightings, development_vulnerabilities, development_links
        TO cit_ingest;
    -- the only deletes the store performs (replace-on-refresh child rows; archive re-import)
    GRANT DELETE ON cvss_scores, affected_products, vulnerability_references, developments
        TO cit_ingest;
    GRANT SELECT ON vulnerability_overview TO cit_ingest;

    -- web (read-only) --------------------------------------------------------------
    GRANT SELECT ON
        source_state, fetch_runs, vulnerabilities, cvss_scores, affected_products,
        vulnerability_references, kev_entries, epss_scores, documents, developments,
        development_sightings, development_vulnerabilities, development_links,
        vulnerability_overview
        TO cit_web;
    GRANT SELECT (id, development_id, provider, model, prompt_version, validated, output,
                  injection_suspected, created_at)
        ON ai_analyses TO cit_web;

    -- ai -----------------------------------------------------------------------------
    GRANT SELECT ON
        vulnerabilities, kev_entries, epss_scores, documents, developments,
        development_vulnerabilities, vulnerability_overview
        TO cit_ai;
    GRANT SELECT, INSERT ON ai_analyses TO cit_ai;
    GRANT SELECT, INSERT, UPDATE ON ai_usage TO cit_ai;
END
$grants$;
