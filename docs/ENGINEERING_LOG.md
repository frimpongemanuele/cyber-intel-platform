# ENGINEERING_LOG.md

Decisions and findings, newest first. Negative results are recorded on purpose: knowing what was measured and rejected is as useful as knowing what shipped.

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
