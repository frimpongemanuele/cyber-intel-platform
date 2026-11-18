#!/bin/sh
# Block new outbound connections from the dashboard container (run on the VM, as root).
#
# The `web` network cannot be `internal` (Docker publishes ports only from non-internal
# networks), so without this rule a compromised dashboard could reach the internet or the
# LAN. Replies to inbound requests are still allowed (conntrack ESTABLISHED). Idempotent;
# re-run after reboot (DEPLOYMENT.md installs it as a systemd unit).
#
#   sudo deploy/scripts/host-firewall.sh [subnet]     # default: CIT_WEB_SUBNET or 172.31.250.0/24
set -eu

subnet="${1:-${CIT_WEB_SUBNET:-172.31.250.0/24}}"
rule="-s $subnet ! -d $subnet -m conntrack --ctstate NEW -m comment --comment cit-web-no-egress -j DROP"

# DOCKER-USER is evaluated before Docker's own forwarding rules and survives restarts
# of the Docker daemon (Docker creates the chain if missing; we create it to be safe).
iptables -N DOCKER-USER 2>/dev/null || true
# shellcheck disable=SC2086 # $rule is a list of iptables arguments by design
if iptables -C DOCKER-USER $rule 2>/dev/null; then
    echo "rule present: $subnet"
else
    # shellcheck disable=SC2086
    iptables -I DOCKER-USER 1 $rule
    echo "rule added: $subnet"
fi
