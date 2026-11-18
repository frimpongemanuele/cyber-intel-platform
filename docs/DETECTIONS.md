# DETECTIONS.md — detecting attacks on the platform itself

> Status: **step 1 of 6 built** (security events). Wazuh collection, rules, simulations
> and CI rule tests follow. Target SIEM: Wazuh 4.14 (manager on the same host).

The threat model (THREAT_MODEL.md) says what an attacker would try; the platform's controls stop it. This document adds the third layer: **noticing the attempt**. Each detection is tied to a threat, a log source, an ATT&CK technique and, once built, a test.

## 1. Security events (built)

The platform emits **one JSON object per line** for security-relevant decisions (`src/cyberintel/security_events.py`), to stderr (container log) and, when `CIT_SECURITY_LOG` is set, to a size-rotated file.

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

## 2. Roadmap

| Step | Deliverable | Status |
|---|---|---|
| 1 | Security events in the platform; logging firewall rule | ✅ |
| 2 | Wazuh collection on the manager: container logs, kernel log, FIM, Docker listener | next |
| 3 | Decoders and rules in `detections/wazuh/`, each mapped to ATT&CK | |
| 4 | Safe attack simulations against the lab that trigger every rule | |
| 5 | Rule tests in CI with `wazuh-logtest` (sample lines → expected rule IDs) | |
| 6 | One page per detection: logic, false positives, response; coverage table | |
