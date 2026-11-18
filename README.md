# cyber-intel-platform

A self-hosted cyber threat-intelligence platform for one analyst's homelab. It collects vulnerability and threat data from authoritative sources, enriches and de-duplicates it, and produces a daily briefing. An AI layer explains and connects the data but is **never the source of truth**.

> **Status: Phases 6–7 complete.** Hardened ingestion with weekly live verification of every source; PostgreSQL store whose constraints and integrity rules are enforced in SQL; cross-day story identity; an ingest runner with backoff and an audit trail. Dashboard (Phase 8) is next. See the [roadmap](#roadmap).

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
| `eval/archive.py` | Loads the agent's archive as gold data; links stories across days by CVE, title and **rarity-weighted vendor/product entities**, with a CVE-disagreement veto and roll-up isolation; recall@k | — |

**Test suite:** ~250 offline tests, ~40 PostgreSQL tests (SQL via psql + repository via psycopg, in CI against a PostgreSQL 16 service), and a weekly live-source job. Integrity rules are verified by mutation testing. `mypy --strict` and `ruff` clean. Hostile fixtures include XXE file/SSRF reads, billion-laughs, external DTDs, SSRF via DNS records pointing at metadata/loopback/CGNAT/NAT64, redirect downgrades and URL-parser confusion.

## Run it

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
```

## Roadmap

| Phase | Deliverable | Status |
|---|---|---|
| 1–4 | Scheduled research agent, sources, scoring, report formats | ✅ running daily |
| 5 | Architecture + threat model | ✅ draft accepted |
| 6 | Ingestion: pure core | ✅ |
| 6b | Network layer + collectors + live source verification | ✅ |
| 7 | PostgreSQL (SQL-first), integrity rules in SQL, story identity with entity linking, ingest runner | ✅ |
| 8 | **next:** FastAPI + HTMX dashboard | |
| 9 | AI layer: structured outputs, provenance, prompt-injection test corpus | |
| 10 | Hardened Docker Compose on Proxmox, VPN-only access | |
| 11 | Docs: DATA_SOURCES, SCORING, DEPLOYMENT, screenshots | |

## Docs

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): decision record, pipeline, data model, deployment
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md): trust boundaries, STRIDE, mitigations, verification
- [`docs/DATA_SOURCES.md`](docs/DATA_SOURCES.md): endpoints, limits, and what the 2026 NVD change means for the design
- [`docs/ENGINEERING_LOG.md`](docs/ENGINEERING_LOG.md): decisions and findings, including the ones that didn't work

## License

MIT
