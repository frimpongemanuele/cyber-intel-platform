#!/bin/sh
# Create the Docker secret files for compose.yaml (run once, on the VM, with sudo).
#
#   sudo deploy/scripts/make-secrets.sh            # create missing secrets (+ log/backup dirs)
#   sudo deploy/scripts/make-secrets.sh --web-password   # (re)set the dashboard password
#
# Existing files are never overwritten (rotating a database password also needs an
# ALTER ROLE; see DEPLOYMENT.md). Files are owned root:10001, mode 0440: readable by
# the app user (uid/gid 10001) and by the postgres containers (group_add 10001), by no
# one else on the host.
set -eu

cd "$(dirname "$0")/../.."
dir=deploy/secrets
umask 077
mkdir -p "$dir"
chmod 0750 "$dir"

rand_hex() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

new() {
    if [ -s "$dir/$1" ]; then
        echo "keep    $1"
    else
        rand_hex >"$dir/$1"
        echo "created $1"
    fi
}

for s in pg_superuser_password pg_owner_password pg_ingest_password pg_web_password pg_ai_password; do
    new "$s"
done
new web_session_secret # hex, as `python -m cyberintel.web.auth new-secret` produces
for s in nvd_api_key ai_api_key web_password_hash; do
    [ -e "$dir/$s" ] || { : >"$dir/$s"; echo "created $s (empty)"; }
done

if [ "${1:-}" = "--web-password" ] || [ ! -s "$dir/web_password_hash" ]; then
    printf 'Dashboard password (min 12 chars): '
    stty -echo 2>/dev/null || true
    read -r pw
    stty echo 2>/dev/null || true
    echo
    # Hash inside the application image so the host needs no Python packages.
    printf '%s\n' "$pw" | docker compose run --rm --no-deps -T web \
        cyberintel.web.auth hash-password --stdin >"$dir/web_password_hash.new"
    mv "$dir/web_password_hash.new" "$dir/web_password_hash"
    unset pw
    echo "set     web_password_hash"
fi

chown root:10001 "$dir" "$dir"/*
chmod 0440 "$dir"/*

# Security event logs (docs/DETECTIONS.md): one directory per service, writable only by
# the app user, read by the SIEM agent as root. Docker would otherwise create missing
# bind-mount sources as root, and the services could not write their events.
for svc in web ingest ai; do
    mkdir -p "logs/$svc"
    chown 10001:10001 "logs/$svc"
    chmod 0750 "logs/$svc"
done
chmod 0755 logs

# Backup target for the `backup` service (runs as the postgres uid 999). If you set
# CIT_BACKUP_DIR in .env to a mounted share, give that directory the same ownership.
mkdir -p backups
chown 999:999 backups
chmod 0700 backups
echo "secrets ready in $dir (root:10001, 0440). Optional: put your NVD / AI API keys in"
echo "nvd_api_key / ai_api_key (keep the ownership and mode)."
