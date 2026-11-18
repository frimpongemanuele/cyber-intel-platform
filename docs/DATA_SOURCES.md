# DATA_SOURCES.md

> Verified 2026-11-18. Machine-readable registry: [`config/sources.toml`](../config/sources.toml).
> RSS/Atom URLs are re-verified weekly by the `network` CI job, which fails if a feed stops parsing.

## Collection priority

APIs → official structured feeds → RSS/Atom → (later, if ever) permitted page extraction. We honour rate limits and terms of service, identify ourselves with a descriptive `User-Agent`, use conditional GET, and store metadata plus short excerpts only, never republished articles.

## Structured fact sources

| Source | What it is authoritative for | Endpoint | Limits / notes |
|---|---|---|---|
| **CISA KEV** | "CISA has evidence this CVE is exploited" + date added, due date, ransomware flag | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Single ~1–2 MB file; poll hourly with conditional GET |
| **CVE.org (CVE Services)** | The CVE record as published by the assigning CNA: description, affected products, **CNA CVSS**, CWE; plus **CISA-ADP "Vulnrichment"** (SSVC exploitation/automatable/technical impact, CVSS/CWE where the CNA gave none) | `https://cveawg.mitre.org/api/cve/{CVE-ID}` (public read, no auth). Bulk: `github.com/CVEProject/cvelistV5` | Record format 5.x (5.1/5.2 in the wild): parse defensively |
| **NVD CVE API 2.0** | NIST's enrichment *when it exists*: `vulnStatus`, NIST CVSS, CPE configurations, CWE | `https://services.nvd.nist.gov/rest/json/cves/2.0` | 5 req / rolling 30 s without key; 50 with a key (header `apiKey`). Paged (`startIndex`, `resultsPerPage` ≤ 2000) |
| **FIRST EPSS** | Probability of exploitation in the next 30 days (a *prediction*, not evidence) | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (dated: `epss_scores-YYYY-mm-dd.csv.gz`) | Bulk CSV preferred over the API for full refresh. Moved from `epss.cyentia.com` in 2025 (old host 301-redirects) |
| **MITRE ATT&CK** | Technique/tactic IDs and names | `raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json` | STIX 2.1; that path always points to the latest release. Weekly poll. (Parser: Phase 7) |
| GitHub Advisory DB / OSV | Open-source package advisories | GHSA REST/GraphQL; `api.osv.dev` | Planned (Phase 7+) |

## The 2026 NVD change and what it means for this design

On 15 April 2026 NIST moved NVD from universal enrichment to **risk-based triage**. Full enrichment is reserved for CVEs in CISA KEV, software used by the federal government, and EO 14028 "critical software". Roughly 29,000 backlogged CVEs published before 1 March 2026 were reclassified as *Not Scheduled*, which the API exposes as `vulnStatus: "Deferred"`. NIST also stopped adding its own CVSS score when the CNA already supplied one. Third-party tracking puts NVD's enrichment rate at a small fraction of 2025 levels by Q3 2026.

Design consequences, already reflected in the code:

1. **NVD is one source among several, not the source.** CVSS is collected from NVD (`Primary`), the CNA (via NVD `Secondary` or the CVE.org record), and CISA-ADP, and **every score keeps its provenance** (`nvd` / `cna` / `adp` / `other`).
2. **The headline score is chosen by an explicit, documented policy**, never by "whichever field was filled". See `collectors/cvss.py`.
3. **`vulnStatus` is stored.** "Deferred" means *NVD has not looked*, not *not important*. The UI must say so.
4. **CISA-ADP SSVC "Exploitation: active"** is a strong, free exploitation signal from CVE.org that complements KEV.

## RSS / Atom sources

Chosen for original research and early exploitation reporting. `primary` = vendor research teams, CERTs and independent research labs; `secondary` = security journalism (used for context and discovery, never as sole evidence). Full list in `config/sources.toml`.

**Known gaps:** no dedicated automotive/embedded feed yet. Candidates to evaluate: VicOne research, Auto-ISAC public updates, Binarly research, academic venues (USENIX Security, IEEE S&P, escar). Add each only after the CI feed check passes.

## Allowlist

The SSRF allowlist (`security/url_guard.py`) is generated from the hosts in this registry plus explicitly reviewed `extra_hosts` (redirect targets). A new source therefore cannot be fetched until it is added here in a reviewed commit.
