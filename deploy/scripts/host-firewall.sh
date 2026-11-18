#!/bin/sh
# Block, and log, new outbound connections from the dashboard container (run as root).
#
# The `web` network cannot be `internal` (Docker publishes ports only from non-internal
# networks), so without this rule a compromised dashboard could reach the internet or the
# LAN. Replies to inbound requests are still allowed (conntrack ESTABLISHED).
#
# Blocked attempts are also logged to the kernel log with the prefix "CIT-WEB-EGRESS "
# (rate-limited) so the SIEM can alert on them: a dashboard that tries to connect out is
# a compromise indicator (docs/DETECTIONS.md).
#
# Idempotent: re-running replaces the rules instead of stacking them.
#
#   sudo deploy/scripts/host-firewall.sh [subnet]     # default: CIT_WEB_SUBNET or 172.31.250.0/24
set -eu

subnet="${1:-${CIT_WEB_SUBNET:-172.31.250.0/24}}"
match="-s $subnet ! -d $subnet -m conntrack --ctstate NEW"

iptables -N DOCKER-USER 2>/dev/null || true

# remove previous copies of our rules (any subnet), found by comment and deleted by
# position: rule text cannot be round-tripped safely (the log prefix contains quotes)
while n="$(iptables -L DOCKER-USER -n --line-numbers \
        | awk '/\/\* cit-web-no-egress(-log)? \*\// {print $1; exit}')" && [ -n "$n" ]; do
    iptables -D DOCKER-USER "$n"
done

# insert DROP first, then LOG above it, so the order is: LOG -> DROP
# shellcheck disable=SC2086
iptables -I DOCKER-USER 1 $match -m comment --comment cit-web-no-egress -j DROP
# shellcheck disable=SC2086
iptables -I DOCKER-USER 1 $match -m limit --limit 6/min --limit-burst 10 \
    -m comment --comment cit-web-no-egress-log -j LOG --log-prefix "CIT-WEB-EGRESS " --log-level 4
echo "rules set: $subnet (log + drop)"
