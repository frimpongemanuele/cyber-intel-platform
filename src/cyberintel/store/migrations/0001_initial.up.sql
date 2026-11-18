-- 0001_initial: facts, raw evidence, developments, and ingestion bookkeeping.
--
-- Design rules (docs/ARCHITECTURE.md section 5):
--   * Facts from authoritative sources, collected evidence, and (later) AI interpretation
--     live in separate tables. No AI-written column exists in this migration.
--   * Constraints are a security layer, not decoration: even if application validation
--     regressed, the database refuses malformed CVE IDs, out-of-range scores, non-http
--     URLs and oversized text.
--   * Every score keeps its provenance (collected_from + origin + provider).

-- ------------------------------------------------------------------ helpers

CREATE DOMAIN cve_id AS text
    CHECK (VALUE ~ '^CVE-[0-9]{4}-[0-9]{4,7}$');

CREATE DOMAIN source_name AS text
    CHECK (VALUE ~ '^[a-z0-9][a-z0-9-]{1,62}$');

CREATE DOMAIN http_url AS text
    CHECK (VALUE ~ '^https?://' AND length(VALUE) <= 2048);

-- ------------------------------------------------------------------ ingestion bookkeeping

CREATE TABLE source_state (
    source_name           source_name PRIMARY KEY,
    etag                  text CHECK (length(etag) <= 512),
    last_modified         text CHECK (length(last_modified) <= 128),
    last_attempt_at       timestamptz,
    last_success_at       timestamptz,
    consecutive_failures  integer NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    last_error            text CHECK (length(last_error) <= 500)
);

CREATE TABLE fetch_runs (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_name       source_name NOT NULL,
    started_at        timestamptz NOT NULL,
    finished_at       timestamptz NOT NULL,
    outcome           text NOT NULL CHECK (outcome IN ('ok', 'not_modified', 'error')),
    http_status       integer CHECK (http_status BETWEEN 100 AND 599),
    bytes             bigint CHECK (bytes >= 0),
    peer_address      inet,
    records_ok        integer CHECK (records_ok >= 0),
    records_rejected  integer CHECK (records_rejected >= 0),
    error             text CHECK (length(error) <= 500),
    CHECK (finished_at >= started_at)
);
CREATE INDEX fetch_runs_source_time ON fetch_runs (source_name, started_at DESC);

-- ------------------------------------------------------------------ vulnerability facts

CREATE TABLE vulnerabilities (
    cve_id                 cve_id PRIMARY KEY,
    -- from CVE.org (the CNA's record + CISA-ADP)
    record_state           text CHECK (record_state IN ('PUBLISHED', 'REJECTED')),
    assigner               text CHECK (length(assigner) <= 100),
    title                  text CHECK (length(title) <= 500),
    description            text CHECK (length(description) <= 8000),
    published_at           timestamptz,
    updated_at             timestamptz,
    cwes                   text[] NOT NULL DEFAULT '{}',
    ssvc_exploitation      text CHECK (ssvc_exploitation IN ('none', 'poc', 'active')),
    ssvc_automatable       text CHECK (ssvc_automatable IN ('yes', 'no')),
    ssvc_technical_impact  text CHECK (ssvc_technical_impact IN ('partial', 'total')),
    ssvc_timestamp         timestamptz,
    adp_kev_date           date,
    cve5_fetched_at        timestamptz,
    -- from NVD
    nvd_status             text CHECK (length(nvd_status) <= 40),
    nvd_last_modified      timestamptz,
    nvd_has_cpe            boolean,
    nvd_fetched_at         timestamptz,
    -- derived from cvss_scores by the documented headline policy (collectors/cvss.py)
    headline_score         numeric(3, 1) CHECK (headline_score BETWEEN 0 AND 10),
    headline_version       text CHECK (headline_version IN ('2.0', '3.0', '3.1', '4.0')),
    headline_origin        text CHECK (headline_origin IN ('nvd', 'cna', 'adp', 'other')),
    headline_provider      text CHECK (length(headline_provider) <= 200),
    first_seen_at          timestamptz NOT NULL DEFAULT now(),
    CHECK ((headline_score IS NULL) = (headline_version IS NULL)),
    CHECK ((headline_score IS NULL) = (headline_origin IS NULL))
);
CREATE INDEX vulnerabilities_headline ON vulnerabilities (headline_score DESC NULLS LAST);
CREATE INDEX vulnerabilities_ssvc_active ON vulnerabilities (cve_id)
    WHERE ssvc_exploitation = 'active';

CREATE TABLE cvss_scores (
    cve_id          cve_id NOT NULL REFERENCES vulnerabilities (cve_id) ON DELETE CASCADE,
    collected_from  text NOT NULL CHECK (collected_from IN ('nvd', 'cve5')),
    version         text NOT NULL CHECK (version IN ('2.0', '3.0', '3.1', '4.0')),
    origin          text NOT NULL CHECK (origin IN ('nvd', 'cna', 'adp', 'other')),
    provider        text NOT NULL CHECK (length(provider) <= 200),
    base_score      numeric(3, 1) NOT NULL CHECK (base_score BETWEEN 0 AND 10),
    vector          text CHECK (length(vector) <= 300),
    severity        text CHECK (length(severity) <= 20),
    collected_at    timestamptz NOT NULL,
    PRIMARY KEY (cve_id, collected_from, version, origin, provider)
);

CREATE TABLE affected_products (
    cve_id        cve_id NOT NULL REFERENCES vulnerabilities (cve_id) ON DELETE CASCADE,
    vendor        text NOT NULL CHECK (length(vendor) BETWEEN 1 AND 200),
    product       text NOT NULL CHECK (length(product) BETWEEN 1 AND 200),
    vendor_norm   text NOT NULL CHECK (vendor_norm ~ '^[a-z0-9]+$'),
    product_norm  text NOT NULL CHECK (product_norm ~ '^[a-z0-9]+$'),
    PRIMARY KEY (cve_id, vendor_norm, product_norm)
);
CREATE INDEX affected_products_product ON affected_products (vendor_norm, product_norm);

CREATE TABLE vulnerability_references (
    cve_id  cve_id NOT NULL REFERENCES vulnerabilities (cve_id) ON DELETE CASCADE,
    url     http_url NOT NULL,
    PRIMARY KEY (cve_id, url)
);

-- CISA KEV. Independent of `vulnerabilities` (KEV can list a CVE before we fetch its
-- record); join on cve_id. Rows are never deleted: removal from the catalog is recorded.
CREATE TABLE kev_entries (
    cve_id             cve_id PRIMARY KEY,
    vendor             text NOT NULL CHECK (length(vendor) <= 200),
    product            text NOT NULL CHECK (length(product) <= 200),
    name               text NOT NULL CHECK (length(name) <= 500),
    date_added         date NOT NULL,
    due_date           date,
    ransomware_known   boolean NOT NULL,
    short_description  text NOT NULL CHECK (length(short_description) <= 4000),
    required_action    text NOT NULL CHECK (length(required_action) <= 2000),
    notes              text NOT NULL DEFAULT '' CHECK (length(notes) <= 4000),
    cwes               text[] NOT NULL DEFAULT '{}',
    catalog_version    text NOT NULL CHECK (length(catalog_version) <= 40),
    first_seen_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at       timestamptz NOT NULL DEFAULT now(),
    removed_at         timestamptz
);
CREATE INDEX kev_entries_added ON kev_entries (date_added DESC);

-- FIRST EPSS: latest score per CVE (a prediction, not evidence of exploitation).
CREATE TABLE epss_scores (
    cve_id         cve_id PRIMARY KEY,
    epss           numeric(6, 5) NOT NULL CHECK (epss BETWEEN 0 AND 1),
    percentile     numeric(6, 5) NOT NULL CHECK (percentile BETWEEN 0 AND 1),
    score_date     date,
    model_version  text CHECK (length(model_version) <= 40),
    updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX epss_scores_epss ON epss_scores (epss DESC);

-- ------------------------------------------------------------------ collected evidence

-- One row per distinct article/advisory (deduplicated by canonical URL). Metadata and
-- a short derived excerpt only: never a republished article body.
CREATE TABLE documents (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_name    source_name NOT NULL,
    canonical_url  http_url NOT NULL UNIQUE,
    url            http_url NOT NULL,
    guid           text CHECK (length(guid) <= 2048),
    title          text NOT NULL CHECK (length(title) <= 300),
    excerpt        text NOT NULL CHECK (length(excerpt) <= 600),
    published_at   timestamptz,
    cves           text[] NOT NULL DEFAULT '{}',
    first_seen_at  timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX documents_cves ON documents USING gin (cves);
CREATE INDEX documents_published ON documents (published_at DESC NULLS LAST);

-- ------------------------------------------------------------------ developments (stories)

-- A development persists across days; each daily mention is a sighting. Fixes the
-- archive's re-ID-every-day problem (ENGINEERING_LOG 2026-11-18).
CREATE TABLE developments (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    slug           text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,159}$'),
    title          text NOT NULL CHECK (length(title) <= 500),
    first_seen     date NOT NULL,
    last_seen      date NOT NULL,
    status         text NOT NULL CHECK (status IN ('CONFIRMED', 'DEVELOPING', 'UNVERIFIED')),
    confidence     text NOT NULL CHECK (confidence IN ('HIGH', 'MEDIUM', 'LOW')),
    is_rollup      boolean NOT NULL DEFAULT false,
    CHECK (last_seen >= first_seen)
);

CREATE TABLE development_sightings (
    development_id  bigint NOT NULL REFERENCES developments (id) ON DELETE CASCADE,
    origin          text NOT NULL CHECK (origin IN ('archive', 'pipeline')),
    external_id     text NOT NULL CHECK (length(external_id) <= 200),
    day             date NOT NULL,
    urgency         smallint CHECK (urgency BETWEEN 0 AND 5),
    PRIMARY KEY (origin, external_id)
);
CREATE INDEX development_sightings_dev ON development_sightings (development_id, day);

CREATE TABLE development_vulnerabilities (
    development_id  bigint NOT NULL REFERENCES developments (id) ON DELETE CASCADE,
    cve_id          cve_id NOT NULL,
    PRIMARY KEY (development_id, cve_id)
);
CREATE INDEX development_vulnerabilities_cve ON development_vulnerabilities (cve_id);

CREATE TABLE development_links (
    a       bigint NOT NULL REFERENCES developments (id) ON DELETE CASCADE,
    b       bigint NOT NULL REFERENCES developments (id) ON DELETE CASCADE,
    kind    text NOT NULL CHECK (kind IN ('related', 'rollup_of')),
    method  text NOT NULL CHECK (method IN ('cve', 'title', 'entity', 'embedding', 'human')),
    PRIMARY KEY (a, b, kind),
    CHECK (a <> b)
);
