-- Reverts 0001_initial. Order respects foreign keys.
DROP TABLE IF EXISTS development_links;
DROP TABLE IF EXISTS development_vulnerabilities;
DROP TABLE IF EXISTS development_sightings;
DROP TABLE IF EXISTS developments;
DROP TABLE IF EXISTS documents;
DROP TABLE IF EXISTS epss_scores;
DROP TABLE IF EXISTS kev_entries;
DROP TABLE IF EXISTS vulnerability_references;
DROP TABLE IF EXISTS affected_products;
DROP TABLE IF EXISTS cvss_scores;
DROP TABLE IF EXISTS vulnerabilities;
DROP TABLE IF EXISTS fetch_runs;
DROP TABLE IF EXISTS source_state;
DROP DOMAIN IF EXISTS http_url;
DROP DOMAIN IF EXISTS source_name;
DROP DOMAIN IF EXISTS cve_id;
