#!/bin/sh
# Install the cyber-intel collection block and detection rules into the local Wazuh
# manager (run as root).
#
#   sudo detections/wazuh/install.sh [CIT_DIR]      # default /srv/cit
#   sudo detections/wazuh/install.sh --uninstall
#
# Idempotent: the block lives between markers and is replaced on every run. ossec.conf is
# backed up first; if the manager does not come back up, the backup is restored.
set -eu

OSSEC="${WAZUH_HOME:-/var/ossec}"     # overridable for tests only
SYSTEMCTL="${SYSTEMCTL:-systemctl}"
CONF="$OSSEC/etc/ossec.conf"
RULES_DST="$OSSEC/etc/rules/cit_rules.xml"
HERE="$(cd "$(dirname "$0")" && pwd)"
BEGIN="<!-- BEGIN cyber-intel-platform (managed by detections/wazuh/install.sh) -->"
END="<!-- END cyber-intel-platform -->"

[ "$(id -u)" = 0 ] || [ -n "${WAZUH_HOME:-}" ] || { echo "run as root (sudo)" >&2; exit 1; }
[ -f "$CONF" ] || { echo "no Wazuh manager config at $CONF" >&2; exit 1; }

mode=install
if [ "${1:-}" = "--uninstall" ]; then mode=uninstall; shift; fi
CIT_DIR="${1:-/srv/cit}"
case "$CIT_DIR" in
    /*) ;;
    *) echo "CIT_DIR must be an absolute path" >&2; exit 1 ;;
esac
[ "$mode" = uninstall ] || [ -f "$CIT_DIR/compose.yaml" ] || {
    echo "no compose.yaml in $CIT_DIR" >&2; exit 1; }

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="$CONF.cit-backup.$stamp"
cp -p "$CONF" "$backup"
rules_backup=""
if [ -f "$RULES_DST" ]; then
    rules_backup="$RULES_DST.cit-backup.$stamp"
    cp -p "$RULES_DST" "$rules_backup"
fi

rollback() {
    cp -p "$backup" "$CONF"
    if [ -n "$rules_backup" ]; then cp -p "$rules_backup" "$RULES_DST"; else rm -f "$RULES_DST"; fi
}

# drop any previous managed block (lines between the markers, inclusive)
tmp="$(mktemp)"
awk -v b="$BEGIN" -v e="$END" '$0 == b {skip=1} !skip {print} $0 == e {skip=0}' "$CONF" >"$tmp"

if [ "$mode" = install ]; then
    {
        echo "$BEGIN"
        sed "s#@CIT_DIR@#$CIT_DIR#g" "$HERE/ossec-cit.conf"
        echo "$END"
    } >>"$tmp"
fi
cat "$tmp" >"$CONF" # keep owner, group and mode of the original file
rm -f "$tmp"

# detection rules (detections/wazuh/rules/cit_rules.xml)
if [ "$mode" = install ]; then
    mkdir -p "$(dirname "$RULES_DST")"
    cp "$HERE/rules/cit_rules.xml" "$RULES_DST"
    chmod 0660 "$RULES_DST"
    if getent group wazuh >/dev/null 2>&1; then chown root:wazuh "$RULES_DST"; fi
else
    rm -f "$RULES_DST"
fi

if [ "$mode" = install ] && [ -z "${WAZUH_HOME:-}" ]; then
    # The Docker listener runs with the system python3 and needs the docker SDK. Use the
    # distribution package: never pip-install into Wazuh's bundled Python (it would
    # change libraries the Wazuh API depends on).
    if ! python3 -c "import docker" 2>/dev/null; then
        echo "installing python3-docker for the Wazuh docker-listener"
        apt-get install -y -q python3-docker >/dev/null
    fi
fi

# Validate before restarting: each daemon parses its own sections in test mode (-t).
# A bad block is rolled back while the running manager keeps running untouched.
failed=""
for daemon in wazuh-logcollector wazuh-syscheckd wazuh-modulesd wazuh-analysisd; do
    bin="$OSSEC/bin/$daemon"
    [ -x "$bin" ] || continue
    if ! out="$("$bin" -t 2>&1)"; then
        failed="$daemon"
        echo "config check failed in $daemon:" >&2
        printf '%s\n' "$out" | grep -iE "error|critical|invalid" | head -n 10 >&2
        break
    fi
done
if [ -n "$failed" ]; then
    rollback
    echo "restored $backup; wazuh-manager was not restarted" >&2
    exit 1
fi

if $SYSTEMCTL restart wazuh-manager && sleep "${CIT_RESTART_WAIT:-5}" \
    && $SYSTEMCTL is-active --quiet wazuh-manager; then
    echo "wazuh-manager restarted with the cyber-intel block ($mode); backup: $backup"
else
    echo "wazuh-manager failed to restart: restoring $backup" >&2
    rollback
    $SYSTEMCTL restart wazuh-manager || true
    exit 1
fi
