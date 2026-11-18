#!/bin/sh
# Safe attack simulation: trigger every host-verifiable detection against YOUR OWN lab
# and check that Wazuh raised the expected alerts (docs/DETECTIONS.md, step 4).
#
#   cd /srv/cit && sudo detections/simulate.sh
#
# Everything targets this host only: wrong passwords and bogus Host headers against the
# local dashboard, a harmless `true` inside a container, outbound connections that the
# proxy and the host firewall must block, wrong database passwords, and timestamp-only
# changes to watched files (no content is modified).
#
# Note: the wrong-login burst exhausts the login budget for the simulation's client
# address for 15 minutes; your browser comes from a different address and is unaffected.
set -eu

[ "$(id -u)" = 0 ] || { echo "run with sudo (needs to read Wazuh alerts and touch watched files)" >&2; exit 1; }
cd "$(dirname "$0")/.."
[ -f compose.yaml ] || { echo "run from the platform directory" >&2; exit 1; }

ALERTS=/var/ossec/logs/alerts/alerts.json
BASE=http://127.0.0.1:${CIT_WEB_HOST_PORT:-8080}
HOST="Host: localhost"
start="$(date -u +%Y-%m-%dT%H:%M:%S)"
step() { printf '\n== %s\n' "$1"; }

step "1. six wrong dashboard passwords (expect 100101, 100102 brute force, 100103 throttled)"
for i in 1 2 3 4 5 6; do
    curl -s -o /dev/null -H "$HOST" -H 'Sec-Fetch-Site: same-origin' \
        --data-urlencode "password=simulated-wrong-$i" "$BASE/login"
done

step "2. burst of bogus Host headers (expect 100108, 100109)"
for i in $(seq 1 25); do
    curl -s -o /dev/null -H 'Host: rebind.attacker.example' "$BASE/healthz"
done

step "3. forged session cookie (expect 100106)"
curl -s -o /dev/null -H "$HOST" -H 'Cookie: __Host-cit_session=forged.simulation' "$BASE/vulns"

step "4. cross-site login POST (expect 100107)"
curl -s -o /dev/null -H "$HOST" -H 'Sec-Fetch-Site: cross-site' --data 'password=x' "$BASE/login"

step "5. command inside the web container (expect 100151)"
docker compose exec -T web true

step "6. web container tries to connect out (expect 100140; must be blocked)"
if docker compose exec -T web python -c \
    'import socket; socket.create_connection(("1.1.1.1", 443), timeout=5)' 2>/dev/null; then
    echo "!! the connection SUCCEEDED: is deploy/scripts/host-firewall.sh applied?"
else
    echo "blocked, as expected"
fi

step "7. collector asks the proxy for a non-allowlisted host (expect 100131; must be refused)"
docker compose run --rm --no-deps -T --entrypoint python ingest -c '
import http.client
c = http.client.HTTPConnection("egress", 3128, timeout=10)
c.request("CONNECT", "example.com:443", headers={"Host": "example.com:443"})
print("proxy answered", c.getresponse().status, "(403 expected)")'

step "8. six wrong database passwords (expect 100132, 100133)"
for i in 1 2 3 4 5 6; do
    docker compose exec -T db sh -c \
        "PGPASSWORD=simulated-wrong-$i psql -X -q -h 127.0.0.1 -U cit_web -d cit -c 'select 1'" \
        >/dev/null 2>&1 || true
done

step "9. timestamp-only changes to watched files (expect 100160 secret, 100161 config)"
touch deploy/secrets/nvd_api_key compose.yaml

step "waiting 45 s for Wazuh (log collection, Docker listener, real-time FIM)"
sleep 45

step "results"
python3 - "$ALERTS" "$start" <<'PY'
import json, sys
path, start = sys.argv[1], sys.argv[2]
expected = {
    "100101": "dashboard login failed", "100102": "brute force", "100103": "login throttled",
    "100106": "forged session cookie", "100107": "cross-site POST",
    "100108": "unexpected Host header", "100109": "Host header burst",
    "100131": "egress proxy refused a destination", "100132": "DB password failure",
    "100133": "repeated DB password failures", "100140": "web container outbound attempt",
    "100151": "command inside platform container", "100160": "secret file changed",
    "100161": "configuration changed",
}
seen = {}
with open(path, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        try:
            alert = json.loads(line)
        except ValueError:
            continue
        rule = alert.get("rule", {})
        if alert.get("timestamp", "")[:19] >= start and rule.get("id") in expected:
            seen[rule["id"]] = seen.get(rule["id"], 0) + 1
missing = 0
for rid, what in expected.items():
    n = seen.get(rid, 0)
    missing += n == 0
    print(f"{'PASS' if n else 'MISS'}  {rid}  {what:38} {n} alert(s)")
print(f"\n{len(expected) - missing}/{len(expected)} detections fired")
sys.exit(1 if missing else 0)
PY
