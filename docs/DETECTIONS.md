# DETECTIONS.md — detecting attacks on the platform itself

> Status: **all 6 steps built.** Security events, Wazuh collection, 25 rules (22 alerting), a safe attack
> simulation, and behavioural rule tests on a real Wazuh manager in CI (28/28 cases).
> Target SIEM: Wazuh 4.14 (manager on the same host).

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

## 3. Rules (`detections/wazuh/rules/cit_rules.xml`, IDs 100100–100199)

| Rule | Lvl | Detects | Logic | Likely false positives | First response |
|---|---|---|---|---|---|
| 100101 | 5 | Dashboard login failed | `auth.login_failed` | Typos | None alone |
| 100102 | 10 | Password brute force (T1110) | 5 × 100101 in 5 min (fires on the 5th, measured) | Forgotten password after an update | Check the source address; rotate the password if not you |
| 100103 | 10 | Login budget exhausted (T1110) | `auth.login_throttled` | Same as above | As 100102 |
| 100104 | 3 | Login succeeded | `auth.login_succeeded` | Every normal login | None |
| 100105 | **12** | **Login succeeded after a brute force (T1110, T1078)** | 100104 within 15 min of a `cit_bruteforce` alert | You, after mistyping 5+ times | Confirm it was you; otherwise rotate the password and session secret, review recent dashboard use |
| 100106 | 6 | Forged, tampered or expired session cookie (T1550.004) | `auth.session_rejected` | A browser keeping a cookie past expiry or after a secret rotation | Repeated → someone is replaying or forging cookies |
| 100107 | 6 | Cross-site POST refused (CSRF attempt) | `web.csrf_refused` | Unusual browser extensions | Review which page was open |
| 100108 | 3 | Unexpected Host header | `web.host_rejected` | A new access path not yet in `CIT_WEB_ALLOWED_HOSTS` | Add the name if it is yours |
| 100109 | 7 | Host-header burst: scanning or DNS rebinding (T1595) | 20 × 100108 in 60 s | Misconfigured reverse proxy | Check what is reaching the dashboard port |
| 100110 | 10 | SSRF guard refused a URL (T1190) | `fetch.url_rejected` | A source moved to a new host (legitimate redirect) | Inspect the source; add the host to `extra_hosts` only after review |
| 100111 | 3 | Source failed | `source.failed` | Rate limits, CDN blocks | See DEPLOYMENT.md §8 |
| 100112 | 7 | Malformed feed records quarantined (T1565.001) | `feed.records_quarantined` | Upstream format change | Compare with the upstream feed |
| 100113 | 7 | AI output gate rejected an answer (prompt injection, ATLAS AML.T0051) | `ai.output_rejected` | Weak local models breaking JSON | Read the `reasons`; look at the story's sources |
| 100114 | 7 | Model reported instruction-like text (AML.T0051) | `ai.injection_suspected` | Articles *about* prompt injection | As 100113 |
| 100115 | 5 | AI layer degraded | token cap or provider failing | Expected with small caps | Check the backend |
| 100131 | 10 | Egress proxy refused a destination (T1041, T1090) | `egress` container log contains `TCP_DENIED/403` | A source added without regenerating the proxy config | Which collector asked for what? Possible poisoned feed or compromised collector |
| 100132 | 6 | Database password failure (T1110) | `db` container log | Rotated password not yet updated in a secret | Check which role |
| 100133 | 10 | Repeated database password failures | 5 × 100132 in 5 min | As above | Something is guessing DB passwords inside the Docker network |
| 100140 | **13** | **Dashboard container tried to connect out (T1041, T1071)** | kernel `CIT-WEB-EGRESS ` line, child of built-in 4100 | None by design: the dashboard never connects out | Treat as compromise: stop `web`, keep logs, rebuild the image |
| 100150 | 0 | Platform health check executed | exact health-check commands from `compose.yaml` | — | — (silences built-in 87907, which fired 106 times in the first hour) |
| 100151 | 10 | Command executed inside a platform container (T1609) | Docker `exec_start` in project `cit`, not a health check | You debugging with `docker compose exec` | Confirm it was you |
| 100160 | 12 | Platform secret file changed (T1098, T1565.001) | FIM change under `deploy/secrets/` (no diff stored) | Running `make-secrets.sh` | Confirm a maintenance action; otherwise rotate all secrets |
| 100161 | 8 | Platform configuration changed (T1565.001) | FIM change to `.env`, compose files, squid, postgres or scripts | `git pull` / upgrades | Review the stored diff |

### How the rules are tested

- **On a real Wazuh manager in CI** (`.github/workflows/detections.yml`): the newest official 4.14 manager image loads the rules (`wazuh-analysisd -t` must pass), then `detections/wazuh/tests/run_logtest.py` replays the 28 sequences in `cases.json` through Wazuh's logtest engine, one session per sequence so frequency and correlation rules see the history. Cases include the noise that must stay silent: allowed proxy tunnels, ordinary container output, the three health checks, and look-alike commands that must *not* be silenced.
- **Statically** (`tests/test_wazuh_rules.py`): unique IDs in range; every platform event has a rule; every alerting rule has a CI case (FIM rules are listed explicitly as host-verified); the health-check silencer matches exactly the health checks in `compose.yaml` and none of four look-alikes.
- **On the host** (step 4): `detections/simulate.sh`.

Findings from the first CI replay, now encoded in the rules: kernel lines with `SRC=`/`DST=` are claimed by Wazuh's iptables decoder and land in built-in rule 4100 first, so the egress rule must be its child. And Wazuh's XML parser does not decode `&lt;`/`&gt;`, so the health-check pattern uses `\x3c\x3e`.

## 4. Safe attack simulation (step 4)

```bash
cd /srv/cit && git pull
sudo detections/wazuh/install.sh       # installs/updates the rules (validated before restart)
sudo detections/simulate.sh            # ~1 minute; prints PASS/MISS for 14 detections
```

It only touches this host (details in the script header). Rules for SSRF refusals, quarantined records and the AI layer need a hostile upstream or a model; they are covered by the CI replay instead. The wrong-login burst exhausts the login budget for the simulation's client address for 15 minutes; your browser through VirtualBox comes from a different address. Access through `tailscale serve` shares the simulation's address, so it is affected.

## 5. Roadmap

| Step | Deliverable | Status |
|---|---|---|
| 1 | Security events in the platform; logging firewall rule | ✅ |
| 2 | Wazuh collection on the manager: container logs, kernel log, FIM, Docker listener | ✅ (verify on host) |
| 3 | Rules in `detections/wazuh/rules/`, each mapped to ATT&CK | ✅ |
| 4 | Safe attack simulation against the lab (`detections/simulate.sh`) | ✅ (run on the host) |
| 5 | Rule tests in CI on the official manager image (28 cases) | ✅ |
| 6 | Logic, false positives and first response per detection (§3) | ✅ |
