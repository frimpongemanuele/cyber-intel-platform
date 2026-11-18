# ENGINEERING_LOG.md

Decisions and findings, newest first. Negative results are recorded on purpose: knowing what was measured and rejected is as useful as knowing what shipped.

---

## 2026-11-18 — Detections, step 1: the platform reports on itself

Before writing SIEM rules, the platform had to become detectable: until now a failed login was visible only as an access-log line (`POST /login 401`) and an SSRF refusal only as a source error string. `security_events.py` adds a closed vocabulary of 13 events, one JSON object per line.

- **The log is an attack surface too.** Values such as a Host header, a feed URL or a model's rejection reason are attacker-influenced, so a naive log line could be split or spoofed. A test sends a Host header containing `"}\n{"cit_event":"auth.login_succeeded"...` and asserts it stays one line with the original event. Bidi and zero-width characters are stripped so an analyst's view cannot be spoofed.
- **Secrets cannot be logged by mistake.** Field names matching password/token/cookie/key/… raise at the call site, and tests assert the submitted password and session cookie never appear.
- **Mutation-checked:** removing any emission point (9 tried) or any safeguard in the module (6 tried) fails a test.
- **Firewall rule now logs as well as drops.** Re-running the script must replace, not stack, the rules. The first version deleted rules by replaying `iptables -S` output, which broke on the quoted log prefix (`"CIT-WEB-EGRESS "`); rules are now found by comment and deleted by position. Tested locally: idempotent, subnet change, a foreign rule preserved, LOG before DROP. CI checks that the blocked attempt appears in the kernel log.

---

## 2026-11-18 — Phase 11: documentation, and the first real install

### First install on real hardware: a VirtualBox VM shared with a SIEM
The stack was installed on an existing Ubuntu 24.04 VirtualBox VM running a Wazuh manager (8 GB RAM; about 5 GB free). It came up first time. The first ingest pulled 1,782 KEV entries, 408,395 EPSS scores, 2,744 NVD changes and 15 feeds, and the archive import produced 54 stories from 65 developments. What the install taught us is now in DEPLOYMENT.md §8–9:

- **Host-header allowlist vs `tailscale serve`.** The first request was refused as "Invalid host header"; adding `127.0.0.1` to the allowlist fixed it. Requests forwarded by `tailscale serve` can carry the loopback host name. Allowing it is safe because the port is loopback-only, so `.env.example` now includes it.
- **Port 443 was taken** by the SIEM's dashboard: `tailscale serve --https=8443` instead.
- **VPN-free access from the host PC** needed a second published address (the VirtualBox NAT address, reachable only through a port-forwarding rule) and `localhost` in the allowlist. Shipped as `deploy/compose.localhost.example.yaml`, with the reasoning for why it does not expose the LAN.
- **The first port-forwarding rule silently did not exist.** Windows' Hyper-V port reservations were checked and ruled out; the guide now says how to check both.
- **Two flaky sources** surfaced (CISA advisories 403 from some networks; CVE.org disconnects under bursts). Both degrade gracefully by design and are documented as known issues rather than hidden.

### Screenshots without leaking anything
The dashboard on the real instance shows titles from the private archive, and real screenshots also capture a personal browser. The published images are instead rendered by `tools/screenshots.py`: the real app (same templates, CSP and login flow) served with an in-memory synthetic dataset (`tools/demo_reader.py`; invented vendors, a high unused CVE range, `.example` domains) and captured with headless Chrome. A test renders every demo page and checks it for injection, so the demo cannot drift from the real page shapes. Reviewing the first renders caught one incoherence (a CVE page listing news about a different product), now fixed and tested.

### Daily archive sync
`deploy/scripts/archive-sync.sh` pulls the archive with the read-only deploy key and re-imports it only when the archive changed. A templated systemd timer runs it at 08:00 Europe/Rome, after the 07:00 research run. The script was tested against a local git remote with a stubbed `docker` (unchanged, changed, forced, missing clone); the calendar spec was checked with `systemd-analyze calendar`.

### Final review
- ARCHITECTURE's data-model section now separates *built* from *planned*, so the original sketch (embeddings, ATT&CK, reports) is not mistaken for shipped features.
- No stale "next phase" statements remain, and every relative link and image in the docs resolves (checked by script).
- WALKTHROUGH.md gives reviewers a 10-minute path: problem, decisions, where each claim is tested, honest limits.

---

## 2026-11-18 — Phase 10: hardened deployment

### Verification strategy: the real stack, in CI
This environment can run Docker but cannot pull images, so every deployment control is proven on the CI runner instead: real images from digest-pinned bases, the real `make-secrets.sh`, `docker compose up`, then probes from inside the containers. Passing run: 5/5 container hardening checks, 6/6 egress checks, web egress blocked by the host rule (and shown to be open without it), 1,782 KEV entries ingested through the proxy, login and an authenticated page over that data, backup plus a passing restore check. Locally: the role init script, owner-run migrations and grants, password quoting and backup/restore were tested against a fresh scram-auth PostgreSQL 16 cluster, including a tampered dump that the restore check must reject.

### Findings the real stack produced (none visible in unit tests)
- **Proxy mode needs no local DNS, so the guard must not ask for it.** The URL guard resolved names to check that every address is public; on the collector's internal network there is no outside DNS, so every fetch failed. In proxy mode the guard now keeps allowlist, scheme, port, IP-literal, userinfo and redirect checks and skips DNS; the proxy's post-resolution private-range deny takes over, and the egress probe proves it (metadata IP refused).
- **Squid stores IPv4 as IPv4-mapped IPv6.** The deny list included `::ffff:0:0/96`, which to squid means *all of IPv4*. Squid warned and dropped a conflicting entry; a different ordering could have silently denied, or worse, mis-scoped the rule. Removed, with a test that it stays out and a test that no directive carries an inline comment (squid has none).
- **Supplementary groups vanish on the root→postgres switch.** Secrets are `root:10001 0440`; the PostgreSQL entrypoint starts as root and `gosu`s to postgres, which resets groups, so `group_add` would not have applied. Running the db container as uid 999 from the start fixed it and removed every capability the container had (CHOWN, SETUID, …).
- **The squid pinger needs CAP_NET_RAW.** Disabled rather than granting the capability.
- **`stat %G` prints UNKNOWN** for a gid with no host name; CI compares numeric ids.
- **Package data.** `grants.sql` sat outside the declared package-data glob; it would have been missing from the wheel. Fixed before the image build.

### Least privilege, tested both ways
`grants.sql` is checked twice: with PostgreSQL's privilege functions plus real `SET ROLE` attempts (what each role must *not* do; each grant mutation is caught), and by running the production Store, AI runner and dashboard reader under their roles (what each role *must* do). The first catches over-granting, the second under-granting.

### Pins without network access here
Dependency hashes and image digests cannot be resolved from this environment, and CI artifact downloads are blocked, so the `pins` job prints the resolved lock and digests into its log; they were read from there and committed. The build only ever uses committed pins.

---

## 2026-11-18 — Phase 9: optional AI layer

### Gate defined before code: containment under a compromised model
Asking a model to ignore injected instructions is not testable. What is testable is what happens when it does not. The gate therefore uses a **malicious provider** that reads the real prompt (knowing the canary, boundary and allowed URLs) and returns exactly what each of 29 hostile documents wanted. 26 cases must be rejected with the expected reason; 3 are schema-valid by nature (in-range score manipulation, plausible misinformation, a suppressed injection flag) and are documented as *contained* rather than claimed as blocked (AI.md §3.2). A PostgreSQL test then runs the whole corpus through the real runner and production SQL and compares an md5 of every fact table and of the priority view before and after: identical. Planting one `UPDATE epss_scores` in the test repository makes it fail, so the check is live.

### Mutation results
Each validator check is load-bearing for the corpus: link syntax off → 5 cases get through; executable-instruction check off → 5; cited-URL check off → 3; unknown-CVE check off → 3; canary/boundary check off → 3; hidden-character check narrowed to `Cc` → 3. Unit-level: duplicate-key refusal, strict mode (blocks `"5"`, `true` and `4.0` as scores), fence handling, key-point length, NaN refusal each caught. Prompt builder: NFKC, format-character stripping, ASCII encoding, excerpt and title sanitising, random boundary each caught. Providers: proxy bypass, no-redirect, response cap, endpoint credential/query checks, key-out-of-`repr`, one-text-block rule, token-count sanitising each caught. Web: render-time re-validation, hidden-character recheck and the `ai_enabled` gate each caught.

### Findings that changed the design
- **"Allowed" and "shown" must be the same set.** The first prompt builder silently kept the first 8 documents while the validator allowed URLs from all of them, so a model could cite a document it never saw. The cap moved onto the input type (`AnalysisInput.evidence` max 8) and the SQL `LIMIT 8` is asserted equal to it.
- **Titles are untrusted too.** Mutation testing showed development titles reached the FACTS block unsanitised; they come from feeds and CNAs, so they are now sanitised like evidence.
- **A hostile model must not be able to crash storage.** PostgreSQL `text` cannot hold NUL; a model emitting `\x00` would have failed the insert and turned one document into a retry loop. Raw output is neutralised before storage, and rejected results are cached by input hash so a hostile document is not re-sent (and re-billed) every run.
- **Parser differentials.** `{"summary": "a", "summary": "b"}` is accepted by most JSON parsers with differing "winner" semantics; the validator refuses duplicate keys outright.
- **The boundary marker appears in the prompt preamble as well as around the block,** which broke a naive "split on boundary" test. Tests now split on the boundary as a full line.

### Providers on the standard library
httpx is not installed in the build environment, so the providers use `urllib` with an explicit opener: `ProxyHandler({})` (environment proxies ignored), a redirect handler that refuses all redirects (an API key must never follow a 3xx), TLS verification, timeouts and a 256 KiB read cap. This removed a dependency and made the transport testable here against a loopback HTTP server rather than only with mocks in CI.

### Tooling note
The file-writing tool turned `\u200b`-style escapes in test sources into the raw invisible characters. Ruff's confusable-character rule (RUF001) flagged them, and test files now build such characters with `chr()` so the sources stay ASCII.

### A flaky Phase 8 test, found by CI
`test_session_rejects_tampering_and_other_keys` "tampered" a session MAC by replacing its last character with `A`. Whenever the random MAC already ended in `A` the token was unchanged, so the assertion failed about once in 64 runs. The signer was correct (it compares the canonical MAC string in constant time); the test now always substitutes a different character.

### Not done here
No real model was run in this environment (no network, no model). The gate does not depend on one; AI.md §5 describes how to measure a real backend's rejection rate on the corpus.

---

## 2026-11-18 — Phase 8: dashboard

### Decisions forced by the environment turned out better
FastAPI was missing but Starlette 1.7, Jinja2 and uvicorn were present, and HTMX could not be downloaded. Both constraints pointed to the stronger design: server-rendered Starlette with **zero JavaScript** and CSP `default-src 'none'` (ADR-003). Starlette's TestClient needs httpx (also missing), so a ~40-line ASGI driver (`tests/asgi.py`) calls the app directly. The full web layer (auth, CSRF, headers, routing, templates) is tested locally, not just in CI.

### Priority as a transparent baseline
A SQL view (`0002_overview`) computes a 0–100 priority from exploitation evidence (KEV 40 / SSVC active 30 / PoC 10), EPSS percentile (20), CVSS (20), ransomware (10) and recency (10). Every component is a column and is shown on the CVE page. This is the baseline the AI layer will be measured against (SCORING.md).

### Escaping tested structurally, not by string matching
The first XSS assertions used `or`-chained substring checks that could pass in cases they should not. They were replaced by parsing each rendered page with the stdlib HTML parser and asserting there are no dangerous elements, no `on*` handlers and no `javascript:`/`data:` URLs, which is what an attacker actually needs. The checker has its own test proving it flags each pattern. The fake reader serves script tags, attribute breakouts and `javascript:` URLs on every page.

### Mutation results
Autoescape off → 10 failures; auth gate removed → 10; `safe_url` disabled → 5; weak CSP → 4; login CSRF check removed → 3; host allowlist removed → 1. Read model: wildcard escaping, numeric CVE ordering and rejected-record hiding each caught.

### Bugs the tests caught
- `page()` took `status` as the HTTP code while the error template also used a `status` variable, so **every error page would have crashed**. Renamed the template variable.
- `{{ "s" if n != 1 }}` with no `else` is *undefined*, which `StrictUndefined` turns into an error instead of blank output.
- **Packaging:** Starlette/Jinja2/uvicorn were never declared as dependencies, and neither were the migration SQL files or templates as package data. Both worked only because of the local environment and editable installs; a built wheel would have shipped without a schema. Fixed (`web` extra, `package-data`).

### Auth in the standard library
scrypt hashing with cost floors enforced at startup (no silent downgrade); HMAC-signed expiring sessions in `__Host-` cookies; login throttling (per client and global) applied **before** the password is checked; client identity never taken from `X-Forwarded-For`; no unauthenticated mode.

---

## 2026-11-18 — Phase 7: database, story identity, ingest runner

### SQL-first, tested against real PostgreSQL without a Python driver
The build environment had a PostgreSQL 16 server but no Python driver and no package access. Rather than write untested ORM code, the design became SQL-first (ADR-002): the schema and every statement are plain SQL, and a small harness runs the *exact production text* through `psql` (`%(x)s` → `:'x'`, which psql quotes correctly). Production executes the same strings via psycopg; CI runs both layers against a PostgreSQL service.

### Integrity rules live in the database
- Constraints as a security layer: `DOMAIN`s for CVE IDs, source names and http(s) URLs; `CHECK`s on score ranges, enums and text lengths; headline fields must be all-or-nothing.
- Facts never move backwards: an older CVE.org record, NVD page or EPSS snapshot is ignored (`WHERE EXCLUDED.x >= existing.x`).
- No mass deletion from a broken feed: KEV removals are recorded (never deleted), only from a cleanly parsed catalog, and the SQL itself refuses unless the new catalog has ≥ 90% of active entries.
- Source ownership: CVE.org owns record text; NVD only fills gaps; CWEs are the union of both.
- **Mutation testing** removed each rule in turn. 5/6 were caught; the survivor (NVD overwriting the CNA description) exposed that no test put the same CVE through both sources. Test added.

### Migration runner with tamper detection
Applied migrations are recorded with a SHA-256; a modified applied file, a version gap, or a database ahead of the code all stop the run. An advisory lock serializes concurrent deployers (tested with 4 threads: each migration applied exactly once).

### Story identity: entity linking, built from the archive's evidence
The title-only linker missed N-central (a 4-day story) and ARTEX. Adding vendor/product matching surfaced two traps, both resolved from the real data rather than by threshold tuning:
1. **Same product, different bug.** Entity overlap alone would merge two Chrome zero-days. Fix: a **CVE-disagreement veto**: two focused developments with disjoint CVE sets are different stories.
2. **"Bundle" was mis-defined.** More than 4 CVEs ⇒ roll-up excluded N-central's hotfix sets. Inspecting every multi-CVE entry showed the real split: roll-ups span **≥ 3 vendors or ≥ 5 products** (Patch Tuesday, monthly PSIRT, multi-vendor IoT cluster); one product's 8 CVEs or one Citrix advisory's 12 are focused stories.

The first entity version also produced a new wrong merge (GitHub Actions compromise ↔ DPRK fake-Zoom infostealer) through shared `npm`/`crates.io`: package ecosystems are infrastructure, not identity. They are now non-identifying tokens.

Result on the archive: 8 multi-day stories, 0 wrong merges, stable across thresholds 0.3–0.5. N-central links across all four days. The former `xfail(strict=True)` started passing and was promoted to a regular test. ARTEX remains isolated: "AntiFox (ARTEX successor)" matches equally well, so the conservative roll-up outcome is accepted and documented.

A mutation of the rarity rule initially *survived* because a test's filler items sat within the 14-day window, so the bridge/roll-up rule masked the result. The fillers were moved outside the window so only the rule under test decides.

### Ingest runner
Expected source failures are recorded (`fetch_runs`, `source_state`) and the run continues; anything else propagates. Failing sources back off exponentially (×2 per failure, capped at ×64). NVD windows start from the last success minus one hour of overlap. An enrichment queue fetches CVE.org records for CVEs in KEV or named in collected articles. Queue values come from untrusted text, so a poisoned entry fails the job through the CVE-ID validator and never becomes a URL.

---

## 2026-11-18 — Phase 6b: network layer and collectors

### Source verification changed the design
Checking every endpoint before writing collectors turned up the April 2026 NVD change: risk-based triage, ~29k backlogged CVEs moved to *Not Scheduled* (API: `Deferred`), and no NIST score when the CNA already supplied one. NVD can no longer be "the CVSS source". Consequences:
- **CVE.org (CVE Services) became a primary source.** It carries the CNA's own CVSS plus CISA-ADP Vulnrichment (SSVC *Exploitation: active*, a free exploitation signal that complements KEV).
- **Every CVSS score carries provenance** (`nvd`/`cna`/`adp`/`other`). Scores that disagree are all kept.
- **One explicit headline policy** (`collectors/cvss.py`): v3.x before v4.0 for corpus-wide comparability, then NVD > CNA > ADP > other, v2 last. The policy is tested case by case.
- NVD relays CISA-ADP scores under a UUID source. Rather than hard-code that UUID, those are labelled `other`: under-claiming provenance is safer than over-claiming it.
- EPSS moved hosts in 2025 (`epss.cyentia.com` → `epss.empiricalsecurity.com`, old host 301s). A collector built from memory would have broken here. Feed URLs are therefore verified by a weekly live CI job (`network.yml`), not trusted.

### Fetcher design
- **IP pinning with SNI.** The client connects to the guard-validated address (`Host` header + TLS SNI = hostname, so certificate checks still run against the name). DNS is resolved exactly once, which closes the rebinding window between check and connect.
- **Proxy-mode trade-off.** Behind the homelab's allowlisting egress proxy, the proxy resolves DNS (`CONNECT host:443`), so pinning moves to the proxy's destination ACL. Accepted and documented rather than hidden.
- **Redirects are never followed implicitly.** Each hop is re-validated (allowlist, downgrade, internal targets, hop limit) and re-pinned.
- **Bounded gunzip** for EPSS. Mutation check: an unbounded decompressor peaks at 458 MB on the 200 MiB bomb fixture; the bounded one stays under 32 MB, and the test asserts it.
- **Residual risk:** httpx inflates `Content-Encoding: gzip` per chunk without an output limit. The byte cap stops the read, but one chunk can briefly expand about 1000×. Bounded and accepted.

### Untrusted IDs never become URL paths unchecked
`collect_cve5` builds `…/api/cve/{id}` from IDs extracted from untrusted text, so IDs are matched against the strict CVE pattern first. Traversal and injection attempts (`../../admin`, `%2F..`, `?x=`, `#`) are refused before any request, and the returned record must match the requested ID.

### Paging is checked, not trusted
The NVD iterator verifies `startIndex` on every page (a repeated page is an error, not an infinite loop), caps pages, enforces the 120-day window, and keeps the API key in a header, never in the URL where logs and proxies would capture it.

### First live run: 18/21 sources passed; the 3 failures were controls working
The `network` job's first run validated pinning+SNI against real TLS, the NVD date format, and every structured source. The three feed failures were each a control doing its job, and each was resolved with a *scoped* decision rather than a global relaxation:
- **Google Project Zero** moved to `projectzero.google`; the redirect was blocked by the allowlist. Fix: point at the new URL (no redirect hop to allow).
- **MSRC** declares a `<!DOCTYPE>` → `DTDForbidden`. Fix: a per-source opt-in that admits **only a bare `<!DOCTYPE name>`** (no SYSTEM/PUBLIC, no internal subset) while entities and external references stay forbidden. The two flags that mutation testing had shown to be "redundant" behind `forbid_dtd` are now the active defence for this source, and a test disables the pre-check to prove they hold on their own.
- **Elastic Security Labs** is an 8.5 MB full-content feed. Fix: a per-source size limit; the 5 MB default is unchanged.

Second live run: 20/21. MSRC passed the bare-DOCTYPE check but is **not well-formed XML** (invalid token). Rather than adopting a lenient, recovering XML parser (new attack surface for one feed), the source is disabled with a dated note; Microsoft remains covered by its security blog feed and by CVE.org, where Microsoft is the CNA. Disabled sources are excluded from the allowlist automatically.

### What could not be verified locally
The workspace has no package access, so `net/fetch.py` (httpx) is type-checked and tested only in CI. The pure parts (rate limiter, gunzip, collectors via a fake `Fetcher`) are fully tested locally.

---

## 2026-11-18 — Phase 6 slice 1: pure core

### Context: the archive after 9 days
The scheduled agent produced 9 daily files and 1 weekly report: 65 developments, 100 unique CVEs, 17 in KEV. Schema 0.1 held across all runs. All 8 developments without a primary source were rated MEDIUM/LOW, never HIGH, so confidence is calibrated as specified.

**Finding that drives the data model:** the archive has no cross-day identity. Each brief gives a development a new date-stamped ID, so 21 CVEs appear under 2–3 different IDs (e.g. the Chrome zero-day on Nov 10, 11 and 17). The platform needs one persistent *development* with dated sightings, not one row per day.

### Mutation testing found three real issues
Each protection was deliberately broken to confirm a test fails:

| Mutation | Result | Action |
|---|---|---|
| SSRF guard: "any address public" instead of "all" | caught | — |
| SSRF guard: drop IPv4-mapped unwrapping | **survived** | Python's `ipaddress` already treats `::ffff:127.0.0.1` as non-global, and the unwrap made the guard *more* permissive (`::ffff:8.8.8.8` passed). Changed to reject all IPv4-mapped addresses (fail closed); added tests. |
| Feed links: allow `javascript:`/`data:` schemes | **survived** | The hostname check hid the gap: `javascript:alert(1)` has no host. Added `javascript://host/%0Aalert(1)`, which has a host, plus `ftp://` and `file://localhost` cases. |
| defusedxml: disable `forbid_entities` or `forbid_external` | **survived** | `forbid_dtd` already blocks every fixture, so each other flag could be switched off silently. Pinned the full config in a test. |

### Cross-day story linking
- First version: union-find over "shares a CVE" or "similar title". Hand inspection of the real clusters found 6 correct and **1 wrong merge**: a "KEV carry-over" item mentioning a Check Point CVE and an UnrealIRCd CVE chained two unrelated stories.
- The fix is structural, not a threshold: an entry compatible with two entries that are not compatible with each other is a **roll-up**. Roll-ups keep `related` links but never merge. Bundles (more than 4 CVEs) are roll-ups by definition. Result on real data: 6 correct multi-day stories, 0 wrong merges, stable across title thresholds 0.3–0.6.

### Rejected: IDF-weighted overlap coefficient for titles
- **Motivation:** N-able N-central is really a 4-day story (Nov 10, 15, 17, 18) that the linker misses. Later entries are verbose and renamed ("Able2Shell" → "4EverAble2Shell"), so Jaccard over the union is diluted.
- **Experiment:** de-hyphenated tokens + IDF-weighted overlap coefficient, at thresholds 0.35–0.6, compared against the baseline on the full archive.
- **Result:** N-central never linked at any threshold. At 0.35 the change introduced a wrong merge (cPGuard supply chain ↔ an Android TV botnet) and *lost* correct stories (the extra links triggered the roll-up rule). Results also jumped around from one threshold to the next.
- **Decision:** keep the conservative Jaccard linker. Record the miss as `xfail(strict=True)` so the test starts failing once it is fixed. **Fix properly in Phase 7** with entity matching (normalized vendor/product weighted by rarity) plus embeddings, not more title heuristics.

### Supply-chain hygiene: confusable characters in source
Ruff flagged literal Cyrillic `с` and Unicode dashes in test and source files (they were written as escapes but saved as raw characters). Invisible look-alikes in source are the mechanism behind "Trojan Source" attacks, so all of them were rewritten as explicit `\uXXXX` escapes, and the only non-ASCII left in `.py` files is an intentional `…`.

### Constraints of this slice
The build workspace had no package access, so this slice is limited to code testable with the standard library, Pydantic, defusedxml and pytest. That boundary is also a good architecture: the security-critical logic is pure and dependency-light, and the I/O layers (httpx, SQLAlchemy) wrap it. Those layers are tested in CI.
