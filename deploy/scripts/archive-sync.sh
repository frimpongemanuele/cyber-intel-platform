#!/bin/sh
# Pull the research archive (read-only deploy key) and re-import its stories.
# Run daily after the research agent has committed the morning brief
# (deploy/systemd/cit-archive-sync@.timer). Safe to run by hand at any time.
#
#   ARCHIVE_DIR  clone of cyber-intel-archive      (default: ~/cyber-intel-archive)
#   ARCHIVE_KEY  read-only GitHub deploy key       (default: ~/.ssh/cit_archive)
#   CIT_DIR      this repository on the server     (default: /srv/cit)
set -eu

ARCHIVE_DIR="${ARCHIVE_DIR:-$HOME/cyber-intel-archive}"
ARCHIVE_KEY="${ARCHIVE_KEY:-$HOME/.ssh/cit_archive}"
CIT_DIR="${CIT_DIR:-/srv/cit}"

[ -d "$ARCHIVE_DIR/.git" ] || { echo "no archive clone at $ARCHIVE_DIR" >&2; exit 1; }
[ -r "$ARCHIVE_KEY" ] || { echo "deploy key not readable: $ARCHIVE_KEY" >&2; exit 1; }

before="$(git -C "$ARCHIVE_DIR" rev-parse HEAD)"
GIT_SSH_COMMAND="ssh -i $ARCHIVE_KEY -o IdentitiesOnly=yes -o BatchMode=yes" \
    git -C "$ARCHIVE_DIR" pull --ff-only --quiet
after="$(git -C "$ARCHIVE_DIR" rev-parse HEAD)"

if [ "$before" = "$after" ] && [ "${1:-}" != "--force" ]; then
    echo "archive unchanged at $after; nothing to import"
    exit 0
fi

cd "$CIT_DIR"
docker compose run --rm --no-deps -T -v "$ARCHIVE_DIR:/archive:ro" ingest \
    cyberintel.store.archive_import /archive
echo "imported archive at $after"
