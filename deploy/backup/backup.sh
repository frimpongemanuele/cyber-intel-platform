#!/bin/sh
# Nightly logical backup (runs in the `backup` service; THREAT_MODEL A4, DEPLOYMENT.md).
#
# Every BACKUP_EVERY_SECONDS: pg_dump in custom format to a temp file, verify that
# pg_restore can read its table of contents, write a SHA-256 next to it, then atomically
# rename. Dumps older than BACKUP_KEEP_DAYS are deleted. Copy BACKUP_DIR off the host
# (Proxmox Backup Server, NAS); a backup on the same disk is not a backup.
set -eu

: "${BACKUP_DIR:=/backups}" "${BACKUP_KEEP_DAYS:=14}" "${BACKUP_EVERY_SECONDS:=86400}"
if [ -n "${PGPASSWORD_FILE:-}" ]; then
    PGPASSWORD="$(cat "$PGPASSWORD_FILE")"
    export PGPASSWORD
fi
umask 077
running=1
trap 'running=0' TERM INT

backup_once() {
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    final="$BACKUP_DIR/cit-$stamp.dump"
    tmp="$final.partial"
    pg_dump --format=custom --compress=6 --no-owner --file="$tmp"
    pg_restore --list "$tmp" >/dev/null # unreadable dump -> fail now, not at restore time
    (cd "$BACKUP_DIR" && sha256sum "$(basename "$tmp")" | sed 's/\.partial$//' >"cit-$stamp.dump.sha256")
    mv "$tmp" "$final"
    find "$BACKUP_DIR" -maxdepth 1 -name 'cit-*.dump*' -mtime +"$BACKUP_KEEP_DAYS" -delete
    echo "backup ok: $(basename "$final") ($(wc -c <"$final") bytes)"
}

if [ "${1:-}" = "--once" ]; then
    backup_once
    exit 0
fi
while [ "$running" = 1 ]; do
    backup_once || echo "backup FAILED" >&2
    # sleep in short steps so `docker compose stop` is prompt
    i=0
    while [ "$running" = 1 ] && [ "$i" -lt "$BACKUP_EVERY_SECONDS" ]; do
        sleep 5
        i=$((i + 5))
    done
done
