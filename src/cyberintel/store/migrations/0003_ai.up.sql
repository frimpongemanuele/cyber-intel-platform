-- Phase 9: optional AI analysis layer.
--
-- AI output is never a fact. It lives only in these two tables; nothing in the fact
-- tables or in vulnerability_overview reads from them, so a compromised model cannot
-- change a priority, a KEV flag, a score or a story. Every row records what the model
-- saw (prompt version + hash, input hash, document and CVE ids) so it can be reproduced.

CREATE TABLE ai_analyses (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    development_id      bigint NOT NULL REFERENCES developments (id) ON DELETE CASCADE,
    provider            text NOT NULL CHECK (provider ~ '^[a-z0-9-]{1,32}$'),
    model               text NOT NULL CHECK (length(model) BETWEEN 1 AND 200),
    prompt_version      text NOT NULL CHECK (prompt_version ~ '^[a-z0-9.-]{1,40}$'),
    prompt_sha256       text NOT NULL CHECK (prompt_sha256 ~ '^[0-9a-f]{64}$'),
    input_hash          text NOT NULL CHECK (input_hash ~ '^[0-9a-f]{64}$'),
    document_ids        bigint[] NOT NULL,
    cve_ids             text[] NOT NULL,
    validated           boolean NOT NULL,
    output              jsonb CHECK (output IS NULL OR jsonb_typeof(output) = 'object'),
    rejected_reasons    text[] NOT NULL DEFAULT '{}',
    -- forensic copy of what the model returned; never rendered by the dashboard
    raw_output          text CHECK (length(raw_output) <= 20000),
    injection_suspected boolean NOT NULL DEFAULT false,
    input_tokens        integer NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens       integer NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (development_id, provider, model, input_hash),
    -- a validated row has output and no reasons; a rejected row has reasons and no output
    CHECK (validated = (output IS NOT NULL)),
    CHECK (validated = (cardinality(rejected_reasons) = 0))
);

CREATE INDEX ai_analyses_latest ON ai_analyses (development_id, created_at DESC) WHERE validated;

CREATE TABLE ai_usage (
    day            date NOT NULL,
    provider       text NOT NULL CHECK (provider ~ '^[a-z0-9-]{1,32}$'),
    model          text NOT NULL CHECK (length(model) BETWEEN 1 AND 200),
    calls          integer NOT NULL DEFAULT 0 CHECK (calls >= 0),
    rejected       integer NOT NULL DEFAULT 0 CHECK (rejected >= 0),
    input_tokens   bigint NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens  bigint NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    PRIMARY KEY (day, provider, model)
);
