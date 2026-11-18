# SCORING.md

Two different scores exist, and they must never be confused.

## 1. Priority (the dashboard's ranking): deterministic, rule-based, explainable

Defined once, in SQL (`store/migrations/0002_overview.up.sql`, view `vulnerability_overview`), so the dashboard, any API and any future AI evaluation all use the same definition. Every component is stored as its own column and shown on each CVE page under "Why this priority".

| Component | Points | Evidence type | Why |
|---|---|---|---|
| Exploitation | **40** if in CISA KEV (active entry) · else **30** if CISA-ADP SSVC `Exploitation: active` · else **10** if SSVC `poc` | Observed | Evidence of exploitation outranks every prediction |
| EPSS | **20 × percentile** | Predicted | Likelihood of exploitation in the next 30 days |
| Severity | **2 × headline CVSS** | Assessed | Impact if exploited; the headline score comes from the policy in `collectors/cvss.py` |
| Ransomware | **10** if KEV marks known ransomware use | Observed | Real-world stakes |
| Recency | **10** if added to KEV in the last 14 days | — | A daily intelligence tool should surface what is new |

Maximum 100. Rejected CVE records are hidden unless they are in KEV.

**Design notes**
- KEV and SSVC "active" do not stack: both are evidence of the same fact (exploitation), and stacking would double-count it.
- EPSS uses the *percentile*, not the raw probability: raw EPSS is heavily skewed (most CVEs < 1%), and the percentile spreads the ranking usefully.
- The weights are a starting point. The archive's agent-written briefs provide labelled data to calibrate them against (`eval/archive.py`, recall@k), and that calibration is planned work, not a claim.

## 2. Development scores (the briefs): seven axes, analyst-facing

The daily briefs (and later the AI layer) score each *development* 0–5 on technical impact, real-world relevance, offensive value, defensive value, learning value, portfolio value and urgency, plus confidence (HIGH/MEDIUM/LOW) and status (CONFIRMED/DEVELOPING/UNVERIFIED). These describe relevance *to this analyst*, not the risk of a CVE. Confidence reflects source quality and corroboration, never how many outlets repeated a claim.

## 3. CVSS headline policy (provenance)

Since April 2026 NVD scores only a minority of CVEs, so a CVE can carry CVSS from NVD, the CNA (vendor), CISA-ADP, or several of them, and they can disagree. All are stored with provenance; one headline is chosen by: v3.x before v4.0 (comparability), then NVD > CNA > CISA-ADP > other, then 3.1 over 3.0, v2 last. Implemented in both Python and SQL, with a parity test.
