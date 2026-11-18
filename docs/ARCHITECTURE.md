# ARCHITECTURE.md — Cyber Intelligence Platform

> Status: **v0.2, accepted** (2026-11-18). Phase 6 slice 1 (pure core) built; see ENGINEERING_LOG.md.
> Companion docs: `THREAT_MODEL.md` (security design), `SCHEMA.md` (current archive format).

## 1. Decision record (ADR-001): hybrid architecture

**Context.** Two goals: (A) a reliable daily briefing for one analyst; (B) a portfolio system that shows security engineering, data pipelines and careful AI integration.

**Options considered** (scored 1–10 over 14 criteria in the initial analysis):

| Option | Score /140 | Verdict |
|---|---|---|
| A. AI research agent only | 76 | Fast and good at discovery, but no data ownership, results vary run to run, little portfolio value |
| B. Custom app only | 102 | Deterministic and self-hosted, but blind to research that isn't in a configured feed |
| **C. Hybrid** | **113** | **Chosen** |
| D. Deploy OpenCTI / MISP | — | Too heavy for a homelab; built for structured threat-intel management, not daily curation. Interoperate via STIX export instead |

**Decision.** A *deterministic pipeline owns the facts*; an *AI layer owns discovery, connecting stories, and explanation*. The scheduled agent (already running) is stage 1. The pipeline replaces its fact-gathering step by step, and the agent ends up as one component that queries the platform's API.

**Consequences.**
- Facts (CVE, CVSS, KEV, EPSS, ATT&CK) always come from authoritative APIs, never from LLM output.
- AI output is stored as a separate, versioned, source-linked record.
- Two trust boundaries need care: internet → collectors, and stored content → LLM (see THREAT_MODEL).

## 2. System overview

```
                 ┌──────────────── INTERNET (untrusted) ────────────────┐
                 │  CISA KEV · NVD · EPSS · GHSA/OSV · ATT&CK · RSS     │
                 └──────────────────────────┬───────────────────────────┘
                                            │ egress via allowlist proxy
┌───────────────────────────────────────────▼───────────────────────────┐
│ collector (worker)    fetch → parse → sanitize → store RAW            │
│   no inbound ports · read-only FS · no LLM keys · no DB admin role    │
└───────────────────────────────────────────┬───────────────────────────┘
                                            ▼
┌───────────────────────────────────────────────────────────────────────┐
│ processor (worker)   normalize → dedupe/cluster → enrich → score     │
│   deterministic only; writes FACTS tables                             │
└───────────────────────────────────────────┬───────────────────────────┘
                                            ▼
                 ┌──────────────────────────────────────────┐
                 │ PostgreSQL 16 + pgvector                 │
                 │  facts  │  raw docs  │  ai_analyses      │
                 └────┬──────────────┬──────────────┬───────┘
                      │              │              │
          ┌───────────▼──┐   ┌───────▼────────┐  ┌──▼─────────────────┐
          │ api (FastAPI)│   │ analyst (AI)   │  │ reporter           │
          │ + web UI     │   │ summarize,     │  │ daily/weekly .md + │
          │ (Jinja+HTMX) │   │ correlate,     │  │ .json → git archive│
          └──────┬───────┘   │ explain, learn │  └────────────────────┘
                 │           │ structured out │
                 │           └────────────────┘
     Tailscale/WireGuard only (no public exposure)
```

## 3. Pipeline stages

| Stage | Does | Deterministic? | Output |
|---|---|---|---|
| COLLECT | Poll feeds/APIs on schedule; conditional GET (ETag/If-Modified-Since); per-source rate limits | Yes | `raw_documents` |
| PARSE | Feed/JSON parsing with hardened parsers (no XXE, size caps, timeouts) | Yes | structured fields |
| NORMALIZE | Canonical URL, UTC dates, CVE/ATT&CK ID extraction by regex, vendor/product aliasing | Yes | `documents` |
| DEDUPLICATE | Exact (content hash, canonical URL) then near-duplicate (shared CVE IDs + embedding similarity) → cluster into one **development** | Mostly; embeddings are a model, but no generated text | `developments` |
| ENRICH | Join CVE → NVD/CVE.org (CVSS, CWE), KEV (date, ransomware flag), EPSS (probability), ATT&CK (technique names) | Yes | facts tables |
| SCORE | Rule-based baseline (KEV, EPSS, CVSS, profile keyword weights) + optional LLM adjustment, both stored | Hybrid, recorded separately | `scores` |
| CORRELATE | Link developments sharing CVEs, actors, products, techniques | Rules + AI suggestion (flagged) | `development_links` |
| SUMMARIZE | LLM writes per-development and daily summaries from **stored facts and excerpts only** | AI | `ai_analyses` |
| PRESENT | UI, API, Markdown/JSON reports pushed to `cyber-intel-archive` | Yes (rendering) | reports |

## 4. Technology choices (evaluated, not assumed)

| Concern | Choice | Rejected / deferred | Why |
|---|---|---|---|
| Language | Python 3.12 | — | Ecosystem (feedparser, httpx, pydantic), your strength |
| API | FastAPI + Pydantic v2 | Flask, Django | Typed request/response models, OpenAPI docs for free, async HTTP |
| DB | PostgreSQL 16 + **pgvector** | SQLite, Elasticsearch | Relational facts + vector dedup in one system; ES too heavy for a homelab |
| Migrations | Alembic | — | Schema history is itself portfolio evidence |
| Jobs / scheduling | **APScheduler** in workers + Postgres-backed job table | Celery + Redis/RabbitMQ | Removes a broker from the attack surface and from maintenance; scale is ~hundreds of documents a day |
| HTTP client | httpx with explicit timeouts, size caps, redirect limits | requests | Async support, fine-grained limits (SSRF defence) |
| HTML handling | `nh3` (Rust ammonia) sanitizer; strip to text for LLM input | bleach (deprecated) | XSS defence, maintained |
| XML/feeds | `defusedxml` + feedparser | lxml defaults | XXE / billion-laughs defence |
| Frontend | Server-rendered Jinja2 + **HTMX** | Next.js/React | Days instead of weeks to a working UI; much smaller JS supply chain. Revisit only if the UI needs it |
| AI | LLM API with **structured outputs** (JSON schema); optional local Ollama for classification | Agent frameworks | Small, auditable calls. The model gets no tools and no network access |
| Deploy | Docker Compose on a Proxmox VM | k8s | One node; Compose is honest about the scale |
| Remote access | Tailscale or WireGuard | Port forwarding / public reverse proxy | Zero public attack surface |
| CI | GitHub Actions: ruff, mypy, pytest, pip-audit, Trivy, gitleaks | — | Security engineering evidence in the repo |

## 5. Data model (v1)

The core design rule: **facts, raw evidence, and AI interpretation live in different tables.** AI rows reference the evidence they were produced from.

```
sources(id, name, kind[api|rss|atom|github], url, trust_tier[primary|secondary|community],
        poll_interval, etag, last_modified, enabled)

raw_documents(id, source_id→, url, fetched_at, http_status, content_hash, bytes,
              raw_excerpt TEXT  -- capped, for audit; not full article republishing
              )

documents(id, raw_document_id→, canonical_url, title, published_at, summary_excerpt,
          lang, embedding VECTOR(…), extracted_cves TEXT[], extracted_techniques TEXT[])

developments(id, slug, title, first_seen, last_seen, status[CONFIRMED|DEVELOPING|UNVERIFIED],
             confidence[HIGH|MEDIUM|LOW], primary_track)
development_documents(development_id→, document_id→, role[primary|secondary|community])
development_sightings(development_id→, day, report_id→)   -- one development, many dated sightings
development_links(a→, b→, kind[same_story|related|rollup_of], method[cve|title|entity|embedding|human])

vulnerabilities(cve_id PK, published, description, cvss_v3, cvss_v4, vector, cwe TEXT[],
                epss, epss_percentile, epss_date, in_kev, kev_date_added,
                kev_ransomware, nvd_last_modified)              -- deterministic only
development_vulnerabilities(development_id→, cve_id→)

vendors(id, name, aliases TEXT[]); products(id, vendor_id→, name, aliases TEXT[])
techniques(attack_id PK, name, tactic TEXT[], attack_version)  -- from ATT&CK STIX
development_techniques(development_id→, attack_id→, mapped_by[rule|ai|human])
threat_actors(id, name, aliases TEXT[], attack_group_id)
tools / repositories(id, name, url, kind, stars, last_release, risk_note)

scores(development_id→, scorer[rule|llm|human], scorer_version,
       technical_impact, real_world, offensive, defensive, learning, portfolio, urgency,
       created_at)

ai_analyses(id, development_id→ NULL, report_id→ NULL, kind[summary|correlation|lesson|lab],
            model, prompt_version, input_document_ids BIGINT[], input_hash,
            output JSONB, validated BOOL, created_at)

reports(id, kind[daily|weekly|monthly], period_start, period_end, markdown, json, git_commit)
learning_items(id, development_id→, topic, status[todo|doing|done], notes)
```

Notes:
- **Developments persist across days** (`first_seen`/`last_seen` plus sightings). The archive showed why: it re-IDs the same story every day, so 21 CVEs appeared under 2–3 IDs in 9 days.
- **Roll-ups never merge stories.** A carry-over or Patch Tuesday entry that touches several stories gets `rollup_of` links, not identity (ENGINEERING_LOG 2026-11-18).
- `vulnerabilities` is written only by the enrichment job. An LLM can never set `in_kev` or `cvss`.
- `ai_analyses.input_document_ids` + `input_hash` make every AI claim traceable and reproducible.
- `scores` keeps the rule score and LLM score side by side, so drift and disagreement can be measured.
- `mapped_by` records whether an ATT&CK mapping came from a rule, the AI, or a human.

## 6. Authoritative sources (Phase 2 will detail in DATA_SOURCES.md)

| Data | Source | Access |
|---|---|---|
| Exploited vulns | CISA KEV | JSON feed |
| CVE records | CVE.org (cvelistV5) and NVD CVE API 2.0 | Git repo / REST (API key raises rate limit) |
| Exploit probability | FIRST EPSS | REST / daily CSV |
| OSS advisories | GitHub Advisory Database, OSV | REST/GraphQL, OSV API |
| Techniques | MITRE ATT&CK | STIX 2.1 JSON (attack-stix-data repo) |
| Research & news | Curated RSS/Atom from vendor research teams, CERTs, researcher blogs | RSS |

Collection follows the priority APIs → RSS → official feeds → structured datasets → permitted extraction, honouring robots.txt, ToS, and rate limits. The platform stores metadata and short derived summaries, never whole copyrighted articles.

Before Phase 2, check the current state of the CVE/NVD ecosystem (enrichment backlog and program funding status), because it affects how much the platform can rely on NVD alone.

## 7. Deployment on Proxmox

- One VM (Debian 12/13, 4 vCPU / 8 GB / 60 GB) on an **isolated VLAN**. Docker Compose services: `db`, `collector`, `processor`, `analyst`, `reporter`, `api`, `egress-proxy`.
- Docker networks: `ingest_net` (collector ↔ egress-proxy only), `data_net` (workers ↔ db), `web_net` (api ↔ Tailscale sidecar). The DB is not reachable from the collector's egress path.
- Egress through a Squid/Tinyproxy allowlist of source domains. The LLM API domain is allowed **only** for `analyst`.
- Secrets via Docker secrets / `.env` outside the repo, never baked into images; LLM key scoped to `analyst` only.
- Backups: nightly `pg_dump` to a Proxmox Backup Server datastore; the git archive is a second, human-readable copy.

## 8. Build phases (maps to the original plan)

| Phase | Deliverable | Done when |
|---|---|---|
| 5 | This doc + THREAT_MODEL + repo skeleton | Reviewed; ADR accepted |
| 6 | Collectors: KEV, NVD, EPSS, ATT&CK, 20 RSS | Re-running is idempotent; tests use recorded fixtures |
| 7 | Schema + Alembic migrations + enrichment | KEV/NVD/EPSS joins verified against the archive's JSON |
| 8 | FastAPI + HTMX dashboard | Lists developments, CVE detail, filters by score/track |
| 9 | AI layer (structured outputs, provenance) | Every summary links its input docs; injection test suite passes |
| 10 | Compose deployment on Proxmox | Deployed and reachable only over the VPN; restore from backup tested |
| 11 | Documentation | README, ARCHITECTURE, THREAT_MODEL, DATA_SOURCES, SCORING, DEPLOYMENT, screenshots |

**MVP cut (2–3 weekends):** KEV + NVD + EPSS + ~20 RSS → Postgres → a daily Markdown report that matches the agent's brief on at least the top vulnerabilities. Everything else comes after.

**Evaluation method:** the archive's daily JSON files are the labelled test set. Metric: of the developments the agent rated urgency ≥4, what share did the pipeline independently surface and rank in its top 10?
