# DETECTIONS.md — detecting attacks on the platform itself

> Status: **steps 1–2 of 6 built** (security events, Wazuh collection). Rules, simulations
> and CI rule tests follow. Target SIEM: Wazuh 4.14 (manager on the same host).

The threat model (THREAT_MODEL.md) says what an attacker would try; the platform's controls stop it. This document adds the third layer: **noticing the attempt**. Each detection is tied to a threat, a log source, an ATT&CK technique and, once built, a test.

## 1. Security events (built)

The platform emits **one JSON object per line** for security-relevant decisions (`src/cyberintel/security_events.py`), to stderr (container log) and, when `CIT_SECURITY_LOG` is set, to a size-rotated file. In the Compose deployment each service writes `logs/<service>/security.json` (directories created by `make-secrets.sh`, owned by the app user, mode 0750). If the file cannot be opened the service says so once on stderr and keeps logging there.

```json
{"cit_event":"auth.login_failed","severity":"medium","service":"web","ts":"2026-11-18T19:52:01.123Z","client":"172.31.250.1"}
```

Properties the SIEM can rely on:

- **Closed vocabulary:** only the events below exist, each with a fixed severity, so decoders never parse free text.
- **No log injection:** values are attacker-influenced (Host headers, feed URLs, model output). Each line is a single `json.dumps` object; control, bidi/zero-width and private-use characters are stripped and strings capped at 200 characters. Tests try to forge a second event through a header value and fail.
- **No secrets:** field names that could carry a credential are rejected at the call site. Tests assert that passwords and session cookies never appear in a log line.

| Event | Severity | Emitted when | Fields | Threat / ATT&CK |
|---|---|---|---|---|
| `auth.login_failed` | medium | wrong dashboard password | `client` | T13 · T1110 |
| `auth.login_throttled` | high | login budget exhausted (per client or global) | `client` | T13 · T1110 |
| `auth.login_succeeded` | low | successful login | `client` | T13 · T1078 (when preceded by failures) |
| `auth.session_rejected` | medium | a session cookie was sent but is forged, tampered or expired | `client`, `path` | T13 · T1550 / T1539 |
| `web.csrf_refused` | medium | cross-site POST to login/logout refused | `client`, `path` | T14 |
| `web.host_rejected` | low | Host header not on the allowlist (DNS-rebinding probe, scanner) | `host`, `client` | T13 · T1190 recon |
| `fetch.url_rejected` | high | SSRF guard refused a URL or redirect (private address, off-allowlist host) | `source`, `reason` | T1 · poisoned/hijacked source |
| `source.failed` | low | a source run failed | `source`, `error_type`, `http_status` | availability |
| `feed.records_quarantined` | medium | malformed records were rejected from a feed | `source`, `count` | T4 / T10 · T1565 |
| `ai.output_rejected` | medium | the AI output gate rejected a model answer | `story`, `provider`, `model`, `reasons` | T6 · ATLAS AML.T0051 |
| `ai.injection_suspected` | medium | the model reported instruction-like text in sources | `story`, `provider` | T6 · AML.T0051 |
| `ai.token_cap_reached` | low | daily token budget exhausted | `provider`, `cap` | cost abuse |
| `ai.provider_failing` | low | model backend failed 3 times in a row | `provider`, `errors` | availability |

`client` is the peer address seen by the server. Behind `tailscale serve` or a published Docker port it is a gateway or loopback address, so brute-force rules count attempts per host rather than per client.

### Other signals already available

| Signal | Where | Use |
|---|---|---|
| Web container tried to open an outbound connection | kernel log, prefix `CIT-WEB-EGRESS ` (rate-limited LOG rule from `host-firewall.sh`) | **critical**: compromise indicator, T1041 |
| Proxy refused a destination | squid access log (`egress` container), `TCP_DENIED/403` | high: poisoned feed redirect or compromised collector, T1041 / T1090 |
| Database authentication failures | PostgreSQL log (`db` container), `password authentication failed` | T1110 |
| Changes to secrets and config | Wazuh FIM on `deploy/secrets/`, `.env`, `compose.yaml`, `deploy/squid/squid.conf` | T1565 / T1098 |
| `docker exec`, unexpected or privileged containers | Wazuh Docker listener | T1609 / T1610 |

## 2. Collection in Wazuh (built)

`detections/wazuh/ossec-cit.conf`, installed into the manager's `ossec.conf` by `detections/wazuh/install.sh` (idempotent, backs up the config, rolls back if the manager does not restart; tested against a fake manager):

| # | Source | Wazuh input | Fields you can search |
|---|---|---|---|
| 1 | `logs/*/security.json` | `localfile`, `json` | `data.cit_event`, `data.severity`, `data.service`, `data.client`, … and label `cit_source: platform` |
| 2 | every container's log (`/var/lib/docker/containers/*/*-json.log`) | `localfile`, `json` | `data.log` (the line), `data.attrs.CIT_SERVICE` (`egress`, `db`, `web`, …), label `cit_source: docker` |
| 3 | kernel log (`CIT-WEB-EGRESS ` lines) | journald (already in the default config) | full log line |
| 4 | `deploy/secrets/` | FIM, realtime, **no `report_changes`** (Wazuh must never store secret contents) | `syscheck.path`, changed attributes |
| 5 | `.env`, `compose*.yaml`, `deploy/squid`, `deploy/postgres`, `deploy/scripts` | FIM, realtime, with diffs | `syscheck.path`, `syscheck.diff` |
| 6 | Docker events (`exec`, create, start, pull) | `docker-listener` wodle (needs `python3-docker`, installed by the script from the Ubuntu package, never into Wazuh's bundled Python) | `data.docker.*` |

Install on the VM:

```bash
cd /srv/cit && git pull
sudo deploy/scripts/make-secrets.sh          # creates logs/<service>/ (keeps existing secrets)
docker compose up -d                          # services start writing logs/*/security.json
sudo detections/wazuh/install.sh              # add the collection block, restart the manager
```

Verify:

```bash
# 1. a platform event is decoded with its fields
sudo /var/ossec/bin/wazuh-logtest    # paste a line from logs/web/security.json
# 2. FIM: touching a watched file raises a built-in syscheck alert within seconds
sudo touch /srv/cit/compose.yaml && sudo tail -n 20 /var/ossec/logs/alerts/alerts.json | grep compose.yaml
# 3. Docker listener: a docker exec shows up as a built-in Docker alert
docker compose exec web python -c "print(1)"
sudo grep -i docker /var/ossec/logs/ossec.log | tail -n 5     # listener started, no errors
```

Expected false positives, by design: `git pull` and upgrades change watched configuration files and the Docker listener sees containers being recreated. Step 3 rules will treat changes during a declared maintenance window differently.

## 3. Roadmap

| Step | Deliverable | Status |
|---|---|---|
| 1 | Security events in the platform; logging firewall rule | ✅ |
| 2 | Wazuh collection on the manager: container logs, kernel log, FIM, Docker listener | ✅ (verify on host) |
| 3 | Decoders and rules in `detections/wazuh/`, each mapped to ATT&CK | next |
| 4 | Safe attack simulations against the lab that trigger every rule | |
| 5 | Rule tests in CI with `wazuh-logtest` (sample lines → expected rule IDs) | |
| 6 | One page per detection: logic, false positives, response; coverage table | |
