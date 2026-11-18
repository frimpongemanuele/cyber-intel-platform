#!/bin/sh
# Runs once, when the database volume is first initialised (docker-entrypoint-initdb.d).
# Creates the schema owner and the three service roles, each with its own password
# from a Docker secret. Grants on tables are applied later, after migrations, by
# `python -m cyberintel.store.migrate up --grants` (src/cyberintel/store/grants.sql).
set -eu

export SECRETS_DIR="${SECRETS_DIR:-/run/secrets}"
for s in pg_owner_password pg_ingest_password pg_web_password pg_ai_password; do
    [ -s "$SECRETS_DIR/$s" ] || { echo "missing or empty secret: $s" >&2; exit 1; }
done

# Passwords are read by psql itself (\set from a file) and quoted by psql (:'var'): they
# never appear in a command line, in the environment, or in SQL text built by the shell.
psql -v ON_ERROR_STOP=1 --no-psqlrc --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -v db="$POSTGRES_DB" <<'SQL'
\set owner_pw `cat "$SECRETS_DIR/pg_owner_password"`
\set ingest_pw `cat "$SECRETS_DIR/pg_ingest_password"`
\set web_pw `cat "$SECRETS_DIR/pg_web_password"`
\set ai_pw `cat "$SECRETS_DIR/pg_ai_password"`
SET password_encryption = 'scram-sha-256';
CREATE ROLE cit_owner  LOGIN PASSWORD :'owner_pw'  CONNECTION LIMIT 5;
CREATE ROLE cit_ingest LOGIN PASSWORD :'ingest_pw' CONNECTION LIMIT 5;
CREATE ROLE cit_web    LOGIN PASSWORD :'web_pw'    CONNECTION LIMIT 20;
CREATE ROLE cit_ai     LOGIN PASSWORD :'ai_pw'     CONNECTION LIMIT 3;

ALTER DATABASE :"db" OWNER TO cit_owner;   -- in PG 15+ this also makes it own schema public
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO cit_owner, cit_ingest, cit_web, cit_ai;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- defence in depth for the service roles
ALTER ROLE cit_web    SET default_transaction_read_only = on;
ALTER ROLE cit_ingest SET statement_timeout = '15min';
ALTER ROLE cit_web    SET statement_timeout = '30s';
ALTER ROLE cit_ai     SET statement_timeout = '2min';
SQL
echo "roles created"
