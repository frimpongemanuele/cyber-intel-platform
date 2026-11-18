# cyber-intel-platform

A self-hosted cyber threat-intelligence platform for one analyst's homelab. It collects vulnerability and threat data from authoritative sources, enriches and de-duplicates it, and produces a daily briefing. An AI layer explains and connects the data but is **never the source of truth**.

> **Status: Phases 6–8 complete.** Hardened ingestion with weekly live verification of every source; a PostgreSQL store with integrity rules enforced in SQL; cross-day story identity; and a zero-JavaScript dashboard with a transparent priority score. The AI analysis layer (Phase 9) is next. See the [roadmap](#roadmap).

## Why it exists

It started as a scheduled AI research agent that writes a daily intel brief into a private archive. That works, but it is non-deterministic, it owns none of its data, and an LLM is a poor source of record for facts like "is this CVE in CISA KEV?". This platform moves the *facts* into a deterministic, testable pipeline and leaves the AI to do what it is good at: summarizing, connecting stories and explaining. The agent's archive becomes this project's **labelled test set**. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), ADR-001.

## Design principles

1. **Everything collected from the internet is hostile input.** The system's job is to ingest attacker-controllable content, so it is threat-modelled as such: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
2. **Facts, raw evidence and AI interpretation live in separate layers.** CVSS, KEV and EPSS come only from authoritative APIs; AI output is stored separately with links to the exact inputs it saw.
3. **Fail closed.** When a check is unsure (an ambiguous URL, an odd XML construct, a malformed row), the answer is no.
4. **Every protection has a test that would fail without it.** Verified by mutation testing, not assumed.

## What's built

| Module | Purpose | Threat model |
|---|---|---|
| `security/url_guard.py` | SSRF guard: host allowlist; IP-literal rejection in every encoding (decimal, octal, hex, IPv6, mapped); requires *all* resolved addresses to be public; returns pinned addresses to defeat DNS rebinding; re-validates every redirect | T1 |
| `parsing/feeds.py` | RSS/Atom via `defusedxml` with DTDs, entities and external references forbidden; size, item and field caps; drops `javascript:`/`data:` links | T2, T3 |
| `parsing/html_text.py` | Untrusted HTML → plain text (scripts, styles and SVG dropped) for excerpts and LLM input | T9 |
| `collectors/kev.py` | CISA KEV parser. Validates row by row: one bad record is quarantined, not fatal; flags count mismatches | T4, T10 |
| `collectors/epss.py` | FIRST EPSS CSV parser (streaming, range-validated) | T10 |
| `normalize.py` | CVE extraction (handles Unicode dashes), canonical URLs for exact de-duplication | — |
| `net/fetch.py` | The only outbound HTTP client: connects to guard-validated **pinned IPs** (Host + SNI = hostname), re-validates every redirect, caps bytes, conditional GET | T1, T3 |
| `net/ratelimit.py`, `net/decompress.py` | Per-host pacing (provably within NVD's 5/30 s); bounded gunzip (decompression-bomb defence) | T3 |
| `collectors/nvd.py`, `cve5.py`, `cvss.py` | NVD 2.0 + CVE.org 5.x parsers; **CVSS with provenance** (NVD/CNA/ADP) and an explicit headline policy; CISA-ADP SSVC | T10 |
| `collectors/run.py`, `sources.py` | Collector jobs over a `Fetcher` protocol; validated source registry that **generates the SSRF allowlist** | T1 |
| `store/migrations/`, `store/sql.py` | SQL-first schema + statements: constraints as a security layer; facts never move backwards; KEV anti-wipe guard; source ownership rules | T10 |
| `store/migrate.py` | Migration runner: SHA-256 tamper/drift detection, advisory lock for concurrent deployers | T15 |
| `store/repo.py`, `store/rows.py` | Transactional repository; pure row mappers; batches as one `jsonb` parameter | T10, T14 |
| `ingest.py` | Runner: due/backoff scheduling, incremental NVD windows, CVE.org enrichment queue, `fetch_runs` audit trail | T1, T4 |
| `web/app.py`, `web/auth.py` | Dashboard: Starlette, **zero JavaScript**, CSP `default-src 'none'`, host allowlist (anti DNS-rebinding), scrypt + signed `__Host-` sessions, throttled login, same-origin POSTs only, read-only DB sessions | T9, T13, T14 |
| `store/migrations/0002_overview.up.sql` | Transparent 0–100 priority (exploitation evidence, EPSS, CVSS, ransomware, recency), every component visible | — |
| `ai/` (optional, off by default) | AI analyst notes from a **local (Ollama) or your own hosted API key**, never required. Strict output validator (foreign URLs, unknown CVEs, links, commands, hidden text, prompt leaks), random boundary + canary, re-validation at render. Release gate: **containment under a malicious-model simulator** across a 29-document injection corpus, with fact tables proven unchanged | T6, T10, T11 |
| `compose.yaml`, `Dockerfile`, `deploy/` | Hardened single-host deployment: non-root, read-only, no capabilities, digest-pinned images, `--require-hashes` dependencies, internal networks, allowlisting egress proxy **generated from the source registry**, least-privilege DB roles per service, verified backups with a restore check. **Proven on the live stack in CI** | T1, T5, T13–T16 |
| `eval/archive.py` | Loads the agent's archive as gold data; links stories across days by CVE, title and **rarity-weighted vendor/product entities**, with a CVE-disagreement veto and roll-up isolation; recall@k | — |

**Test suite:** ~560 offline tests (incl. the full web layer and the AI containment gate), ~80 PostgreSQL tests, and a deployment smoke test that brings up the real Compose stack in CI (SQL via psql + repository via psycopg, in CI against a PostgreSQL 16 service), and a weekly live-source job. Integrity rules are verified by mutation testing. `mypy --strict` and `ruff` clean. Hostile fixtures include XXE file/SSRF reads, billion-laughs, external DTDs, SSRF via DNS records pointing at metadata/loopback/CGNAT/NAT64, redirect downgrades and URL-parser confusion.

## Deploy it (Proxmox / any Docker host)

See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md). In short: `cp .env.example .env`, `docker compose build`, `sudo deploy/scripts/make-secrets.sh`, `sudo deploy/scripts/host-firewall.sh`, `docker compose up -d`, then `tailscale serve` for HTTPS on your tailnet.

## Run it (development)

```bash
python -m pip install -e ".[dev,net,db]"
pytest                                   # offline unit tests (fixtures; no network)
CIT_TEST_PG=1 PGHOST=... PGUSER=... pytest  # + PostgreSQL tests

# Connection settings come from libpq env vars (PGHOST, PGUSER, PGDATABASE, PGPASSFILE)
# or CIT_DATABASE_URL, never from command-line arguments.
python -m cyberintel.store.migrate up    # apply schema (checksum-verified)
python -m cyberintel.ingest              # run every due source once (cron/systemd timer)
python -m cyberintel.store.archive_import /path/to/cyber-intel-archive
python -m cyberintel.eval.archive /path/to/cyber-intel-archive   # story-linking report

# Dashboard (binds 127.0.0.1:8080; put Tailscale/WireGuard in front)
python -m cyberintel.web.auth hash-password   # -> CIT_WEB_PASSWORD_HASH
python -m cyberintel.web.auth new-secret      # -> CIT_WEB_SECRET
python -m cyberintel.web.server

# Optional AI layer (docs/AI.md): off unless configured; no paid service required
CIT_AI_PROVIDER=ollama CIT_AI_MODEL=llama3.1:8b python -m cyberintel.ai run --limit 20
CIT_WEB_AI=1 python -m cyberintel.web.server
```

## Roadmap

| Phase | Deliverable | Status |
|---|---|---|
| 1–4 | Scheduled research agent, sources, scoring, report formats | ✅ running daily |
| 5 | Architecture + threat model | ✅ draft accepted |
| 6 | Ingestion: pure core | ✅ |
| 6b | Network layer + collectors + live source verification | ✅ |
| 7 | PostgreSQL (SQL-first), integrity rules in SQL, story identity with entity linking, ingest runner | ✅ |
| 8 | Dashboard: Starlette, zero-JS, strict CSP, auth, priority view | ✅ |
| 9 | Optional AI layer: local or own-key backends, strict output gate, provenance, injection corpus + compromised-model containment tests | ✅ |
| 10 | Hardened Docker Compose for Proxmox: VPN-only, least-privilege roles, egress proxy, backups; CI deploys and probes the real stack | ✅ |
| 11 | **next:** Docs polish: screenshots, walkthrough, final review | |

## Docs

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): decision record, pipeline, data model, deployment
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md): trust boundaries, STRIDE, mitigations, verification
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md): Proxmox VM, Tailscale, install, backups/restore, operations
- [`docs/AI.md`](docs/AI.md): the optional AI layer, its backends, and the containment gate
- [`docs/SCORING.md`](docs/SCORING.md): the priority model, development scores, CVSS headline policy
- [`docs/DATA_SOURCES.md`](docs/DATA_SOURCES.md): endpoints, limits, and what the 2026 NVD change means for the design
- [`docs/ENGINEERING_LOG.md`](docs/ENGINEERING_LOG.md): decisions and findings, including the ones that didn't work

## License

MIT
