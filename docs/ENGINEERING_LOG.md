# ENGINEERING_LOG.md

Decisions and findings, newest first. Negative results are recorded on purpose: knowing what was measured and rejected is as useful as knowing what shipped.

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
