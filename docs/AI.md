# AI.md — the optional AI analysis layer

> Status: Phase 9 (2026-11-18). **Off by default.** The platform is complete without it.

## 1. What it does, and what it never does

For each recent story that has CVEs and collected documents, a language model writes a short analyst note: summary, why it matters, key points, a 7-axis relevance opinion (SCORING.md §2), learning topics, and the URLs it used.

It **never** decides a fact. KEV status, EPSS, CVSS, SSVC, the 0–100 priority and story identity come only from authoritative feeds and deterministic code (ADR-001). AI output is stored in `ai_analyses` and nowhere else; no fact table, and not the priority view, reads from it. The dashboard shows it in a separate, dashed panel labelled **"AI-generated · may be wrong"**, under the facts.

## 2. Backends: no paid LLM is required

| `CIT_AI_PROVIDER` | What happens | Cost / data flow |
|---|---|---|
| `none` (default) | No calls, no panel. `ai_*` tables are never queried. | Nothing leaves the host |
| `ollama` | Local model over the Ollama HTTP API (`/api/chat`, JSON mode, temperature 0) | Free; stays on your machine/LAN |
| `anthropic` | Hosted API with **your own** key (`/v1/messages`) | Billed to the operator's account; public collected text only is sent |

Configuration:

```bash
CIT_AI_PROVIDER=ollama   CIT_AI_MODEL=llama3.1:8b   CIT_AI_OLLAMA_URL=http://192.168.1.20:11434
# or
CIT_AI_PROVIDER=anthropic CIT_AI_MODEL=<model id> CIT_AI_API_KEY_FILE=/run/secrets/ai_key
CIT_AI_DAILY_TOKEN_CAP=200000          # input+output per UTC day, all models

python -m cyberintel.ai status         # what is configured (no calls)
python -m cyberintel.ai prompt <slug>  # print the exact prompt for one story (no calls)
python -m cyberintel.ai run --limit 20 # analyse recent stories (cron/systemd timer)
CIT_WEB_AI=1 python -m cyberintel.web.server   # show the panel
```

The model name is configuration, never hard-coded. The key is read from a `*_FILE` secret, sent only in the `x-api-key` header, and excluded from `repr`, errors and logs.

## 3. Security design: containment, not trust

Prompt injection cannot be prevented by asking a model nicely. The design therefore **assumes the model is fully compromised** by whatever it reads, and makes the outcome harmless anyway.

| Layer | Mechanism | Stops |
|---|---|---|
| No capability | The model has no tools, no network, no database access, no secrets in its prompt. It can only return text. | Exfiltration, actions, lateral movement |
| Input shaping (`ai/prompt.py`) | Facts and evidence in separate labelled sections. Every evidence string is NFKC-normalised, stripped of control/zero-width/bidi characters, length-capped, then **JSON-encoded with `ensure_ascii`**, one document per line, inside a **per-call random boundary**. A **per-call canary** sits in the system prompt. | Section forgery, hidden text, string break-out (lowers attack rate; not relied upon) |
| Output gate (`ai/validate.py`) | Size cap → exactly one JSON object (duplicate keys and NaN refused) → strict schema (unknown keys rejected, enums, 0–5 ints, length caps) → no control/zero-width/bidi characters → **every URL anywhere must be an input evidence URL** → no markdown/HTML link syntax → **every CVE mentioned must be an input CVE** → no executable instructions → canary/boundary must not appear. | Phishing links, beacons, planted CVEs, commands, hidden text, prompt leaks, smuggled control fields |
| Storage (`0003_ai`) | Only `ai_analyses` / `ai_usage`. Constraints: validated ⇔ output present ⇔ no reasons. Unique per (story, provider, model, input hash). Rejected outputs are kept as forensic text and **never selected** by the dashboard. | Fact corruption, accidental display of rejected text |
| Render (`web/views.ai_panel`) | Stored jsonb is **re-validated** with the strict schema and hidden-character check; failures are not shown. Autoescape, `safe_url` on every link, CSP `default-src 'none'`. Plain text only, never markdown. | A bad row (bug, manual edit, older prompt version) reaching HTML |
| Cost | Daily token cap; idempotent on input hash (rejected results are cached too, so a hostile document is not re-sent every run); stop after 3 consecutive provider errors. | Runaway spend, retry storms |
| Transport (`ai/providers.py`) | stdlib `urllib`: operator-fixed endpoint, **no redirects**, **environment proxies ignored**, timeout, 256 KiB response cap, TLS verification on, https required for hosted APIs. | Credential forwarding via redirect, proxy hijack, memory exhaustion |

### 3.1 The release gate

`tests/fixtures/injection/corpus.json` holds 29 hostile documents (instruction override, forged system message, delimiter forgery, boundary echo, fake download URL, markdown/HTML/image exfiltration, `javascript:` and `data:` URIs, score manipulation, schema smuggling, planted CVEs, `curl | sh`, encoded PowerShell, reverse shell, base64 relay, zero-width and bidi text, HTML-comment instructions, role-play, chatty wrappers, duplicate-key smuggling, output floods, NUL bytes, misinformation, flag suppression).

For each, a **malicious provider** reads the real prompt (so it knows the canary, the boundary and the allowed URLs) and returns exactly what the attacker wanted. The gate:

1. every case marked `rejected` (26) is rejected with the expected reason and leaves no displayable output (`test_ai_containment.py`);
2. running the *whole corpus* through the real runner and the production SQL against PostgreSQL changes **no fact table and not the priority view** (md5 of every table before/after), and the dashboard query sees only validated rows (`test_ai_db.py`);
3. each validator check is load-bearing: disabling any one of them fails the gate (mutation-tested; see ENGINEERING_LOG).

### 3.2 What is contained but not blocked (residual risk)

Three corpus cases are schema-valid by nature and are marked `contained`:

- **In-range score manipulation** ("rate everything 0"). The relevance scores are an opinion panel; nothing ranks, filters or alerts on them.
- **Plausible misinformation** ("researchers now say it was a false alarm"). No mechanical check can tell a wrong summary from a right one. Mitigation: the panel sits under the authoritative KEV/EPSS/priority facts, is labelled, names its model and prompt version, and lists the sources it used so the claim can be checked.
- **Flag suppression** (the model hides that it saw an injection). `injection_suspected` is informational; no control decision depends on it.

These are the honest limits of any LLM summariser. The design makes them visible rather than claiming immunity.

## 4. Provenance and reproducibility

Every row stores provider, model, `prompt_version`, `prompt_sha256` (hash of the prompt templates), `input_hash` (canonical hash of the exact facts and evidence), the document and CVE ids, token counts and time. Changing the prompt text changes the hash and causes a fresh analysis; the old rows remain for comparison.

## 5. Evaluating a real model (optional)

The containment gate does not need a model. To see how a real model behaves on the corpus, run your configured backend through `python -m cyberintel.ai prompt <slug>` / `run` against a test database seeded with the corpus documents and compare rejection rates; results belong in ENGINEERING_LOG. A real model that follows an injection should show up as a **rejected** row, never as a displayed panel.
