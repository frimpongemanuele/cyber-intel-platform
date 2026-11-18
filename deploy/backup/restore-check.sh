#!/bin/sh
# Prove a backup restores: restore a dump into a scratch database, check it, drop it.
#
#   docker compose exec db sh /backup-tools/restore-check.sh [/backups/cit-....dump]
#
# Defaults to the newest dump. Checks: SHA-256 matches, pg_restore succeeds with
# --exit-on-error, every migration in the dump is recorded, the core tables and the
# priority view are queryable, and row counts are reported for comparison with
# production. Exit code 0 only if every check passes. Needs a role with CREATEDB
# (the postgres superuser inside the db container).
set -eu

: "${BACKUP_DIR:=/backups}" "${SCRATCH_DB:=cit_restore_check}"
if [ -z "${PGPASSWORD:-}" ] && [ -r /run/secrets/pg_superuser_password ]; then
    PGPASSWORD="$(cat /run/secrets/pg_superuser_password)"
    export PGPASSWORD
fi
: "${PGUSER:=postgres}"
export PGUSER

newest=""
for f in "$BACKUP_DIR"/cit-*.dump; do # names sort by UTC timestamp: the last is newest
    [ -e "$f" ] && newest="$f"
done
dump="${1:-$newest}"
[ -n "$dump" ] && [ -f "$dump" ] || { echo "no dump found" >&2; exit 1; }
echo "checking $dump"

if [ -f "$dump.sha256" ]; then
    (cd "$(dirname "$dump")" && sha256sum -c "$(basename "$dump").sha256" >/dev/null) \
        || { echo "FAIL: checksum mismatch" >&2; exit 1; }
    echo "ok   checksum"
else
    echo "warn no checksum file"
fi

psql -X -q -v ON_ERROR_STOP=1 -d postgres -c "DROP DATABASE IF EXISTS $SCRATCH_DB WITH (FORCE)"
psql -X -q -v ON_ERROR_STOP=1 -d postgres -c "CREATE DATABASE $SCRATCH_DB"
cleanup() { psql -X -q -d postgres -c "DROP DATABASE IF EXISTS $SCRATCH_DB WITH (FORCE)" || true; }
trap cleanup EXIT

pg_restore --exit-on-error --no-owner --no-privileges -d "$SCRATCH_DB" "$dump"
echo "ok   pg_restore"

q() { psql -X -q -t -A -v ON_ERROR_STOP=1 -d "$SCRATCH_DB" -c "$1"; }
versions="$(q "SELECT string_agg(version::text, ',' ORDER BY version) FROM schema_migrations")"
[ -n "$versions" ] || { echo "FAIL: no migrations recorded" >&2; exit 1; }
echo "ok   migrations $versions"
for t in vulnerabilities kev_entries epss_scores documents developments fetch_runs; do
    echo "ok   $t: $(q "SELECT count(*) FROM $t") rows"
done
q "SELECT count(*), round(max(priority), 1) FROM vulnerability_overview" >/dev/null
echo "ok   vulnerability_overview queryable"
echo "RESTORE CHECK PASSED"
