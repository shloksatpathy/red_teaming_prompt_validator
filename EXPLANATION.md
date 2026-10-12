# Explanation

How the repo works today, before anything in `PLAN.md` is implemented. Everything here is derived from `prompt_injection_detector.py` and `server.py`.

## 1. Concept

A **static, rule-based scanner** for prompt injection. A prompt goes in; the tool looks for phrasings and words that are commonly used to hijack an LLM, and returns:

- a list of findings (category, matched text, severity, remediation advice),
- a 0-100 risk score,
- an overall risk level (low / medium / high / critical),
- a one-line summary.

It never calls an LLM and never sends the prompt anywhere. It judges the text only by surface form (regex and word lists). It has no model of meaning, context or intent.

Repo layout:

| File | Role |
|---|---|
| `prompt_injection_detector.py` | The whole detection engine (`PromptInjectionDetector`) |
| `server.py` | Flask REST API and file-based result storage |
| `index.html` | Dashboard UI for analyzing prompts |
| `submissions.html` | Second page (history/submissions view) |
| `test_detector.py` | Tests for the detector |
| `render.yaml` | Render deployment config |
| `prompts/`, `input/`, `config/` | Leftovers from the earlier academic-validator project; unused by the current code |

## 2. Data model

- `RiskLevel` enum: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- `VulnerabilityFinding` dataclass: `category`, `description`, `pattern_matched`, `risk_level`, `suggestion`.

## 3. Detection algorithm (`detect_vulnerabilities`)

Two passes, then a dedup step.

### Pass 1: regex patterns (9 categories)
For each category there is one compiled, case-insensitive regex with a fixed severity. `pattern.search(prompt)` is called, so **at most one finding per category**, for the first match only. The finding's `pattern_matched` is the matched substring.

| Category | Idea | Severity |
|---|---|---|
| `instruction_override` | ignore/override/bypass/disregard ... instructions/rules/guidelines/constraints/prompts (anything in between, lazily) | Critical |
| `jailbreak_attempt` | `DAN`, "do anything now", `unrestricted`, "no safety", `disable ... filter` | Critical |
| `role_override` | `forget`, `pretend`, `imagine`, `assume`, "act as if", or `roleplay ... ignore/forget/bypass` | High |
| `context_injection` | "from now on / henceforth / starting now" ... ignore/forget/"act as" | High |
| `prompt_leaking` | reveal/show/print/display/output ... "system prompt"/"original prompt"/instructions/rules | High |
| `encoding_bypass` | base64/rot13/unicode/encoded/escaped ... decode | High |
| `delimiter_manipulation` | `---`, `===`, `###`, `<<<`, `>>>`, `$$$` followed by ignore/override/end | Medium |
| `nested_injection` | `[` or `{` ... ignore/override/execute ... `]` or `}` | Medium |
| `meta_prompt_exposure` | what/who ... were/are/was/is ... told/instructed/programmed/designed | Medium |

The patterns lean on `.*?` (lazy wildcard) to allow arbitrary text between trigger words. That makes them tolerant of rephrasing, but also prone to matching unrelated sentences.

### Pass 2: keyword lists (4 categories)
For every keyword in a category, search `\bkeyword\b` (whole word, case-insensitive). Each matching keyword becomes its own finding, unless an existing finding's `pattern_matched` already equals that keyword.

| Category | Keywords | Severity |
|---|---|---|
| `instruction_keywords` | ignore, bypass, override, disregard, forget | High |
| `system_keywords` | system prompt, original prompt, initial instructions, true instructions, real purpose | High |
| `dangerous_commands` | execute, run, eval, sys.exit, os.system, subprocess, shell | Critical |
| `extraction_keywords` | reveal, show, print, display, output, dump, leak | Medium |

Keywords are matched with no context, so a single word is enough to trigger a finding.

### Dedup
Findings are keyed by `category + "_" + pattern_matched.lower()`. On a key collision the one with the "greater" `risk_level.value` is kept. Note this compares the **strings** (`"critical"`, `"high"`, ...) alphabetically, not severity order. In practice collisions are rare because the category is part of the key, so it seldom changes anything.

## 4. Scoring

### Risk score (`calculate_risk_score`)
Weights: LOW=1, MEDIUM=3, HIGH=5, CRITICAL=10.

```
score = (sum of weights) / (number_of_findings * 10) * 100
```

This is the **average severity** of the findings as a percentage of Critical. Consequences:
- Zero findings gives 0.
- All Critical findings give 100, whether there is one or ten.
- One Medium finding gives 30. Adding a second Medium keeps it at 30.
- Adding a weak finding to a strong one **lowers** the score (Critical + Medium = 65, below Critical alone = 100).

The score therefore measures how severe the typical finding is, not how much total evidence there is.

### Overall risk level (`get_overall_risk_level`)
The **maximum** severity across findings. Any Critical finding makes the prompt Critical; no findings gives Low. This is independent of the numeric score, so the two can disagree (e.g. Critical + Medium: level Critical, score 65).

### Summary (`_generate_summary`)
A fixed sentence per level that includes the finding count. The Low case says "No significant injection vulnerabilities detected."

### Suggestions (`_get_suggestion`)
A static dictionary mapping each category to a generic remediation sentence, with a default for unknown categories. They are not tailored to the prompt.

### Report (`generate_report`)
Runs detection, score, level and summary, and returns a dict: `prompt`, `findings[]`, `risk_score` (rounded to 2 decimals), `overall_risk_level`, `vulnerability_count`, `summary`.

## 5. Server (`server.py`)

Flask app with CORS for localhost and the Render domain. It serves `index.html` at `/` and keeps one module-level `PromptInjectionDetector`.

### Storage
Results are stored as **JSON files on disk**, not in memory:

```
validation_results/{critical,high,medium,low}/<id>.json
```

- `id` = first 16 hex chars of SHA-256 of the prompt text. The same prompt always gets the same id, so re-submitting it overwrites the file.
- The folder is chosen by `overall_risk_level`. The saved JSON gets `id`, `timestamp` (UTC) and `risk_folder` added.
- On a host with an ephemeral filesystem (like Render's free tier) these files are lost on redeploy or restart.

### Endpoints
| Endpoint | Behavior |
|---|---|
| `POST /validate` (alias `/analyze`) | Body `{"prompt": "..."}`. Rejects missing/empty prompts and prompts over 10,000 chars. Runs `generate_report`, saves it, returns the report plus `id` and `timestamp`. |
| `POST /batch-validate` | Body `{"prompts": [...]}`, max 50. Analyzes and saves each non-empty string; skips anything else silently. |
| `GET /result/<id>` | Searches the four folders for `<id>.json`. `id` is passed through `secure_filename`. |
| `GET /results` | Reads every file and returns a summary (`id`, `timestamp`, `risk_score`, `vulnerability_count`, `summary`) grouped by risk level. |
| `DELETE /delete/<id>` | Removes the file wherever it is found. |
| `GET /stats` | Reads every file; returns total count, count per level, total vulnerabilities and mean risk score. |
| `GET /health`, `GET /api/info` | Liveness and endpoint listing. |

`/results` and `/stats` re-read every file on each request, so their cost grows linearly with history size.

## 6. End-to-end flow

```
client --POST /validate--> validate_prompt
   -> check: non-empty, <= 10,000 chars
   -> detector.generate_report(prompt)
        -> pass 1: 9 regexes (first match per category)
        -> pass 2: keyword scan (\bword\b)
        -> dedup
        -> score (mean severity), level (max severity), summary, suggestions
   -> save_analysis: write JSON to validation_results/<level>/<sha256[:16]>.json
   -> return report + id + timestamp
```

## 7. Known limitations (what `PLAN.md` addresses)

- **False positives from context-free keywords.** "run", "show" and "output" flag benign prompts, and "run" alone is Critical, so the overall level is Critical. Related: the pattern `role_override` uses a bare alternation (`forget|pretend|imagine|assume|...`), so any occurrence of "assume" or "imagine" matches, and only the last alternative binds the `roleplay...` tail.
- **Patterns lack word boundaries.** Case-insensitive `DAN` matches inside ordinary words (e.g. "abundance", "Dan"), and `unrestricted` or `unicode` match anywhere.
- **No evasion handling.** No Unicode normalization, homoglyph, leetspeak or zero-width handling. `encoding_bypass` matches the words "base64"/"decode" but never decodes anything.
- **English only; single-prompt only.** No indirect injection, multi-turn context or multilingual coverage.
- **Score semantics.** The score is an average, so more evidence can lower it and the score can disagree with the overall level (section 4).
- **Dedup quirks.** The severity comparison is on strings, and the keyword "already found" check compares against whole matched phrases, which rarely equal a single keyword.
- **Unvalidated weights and patterns.** No benchmark against labeled data; precision and recall are unknown.
- **Storage.** Flat files, ephemeral on some hosts, with full-scan reads for listing and stats.
- **Operational basics missing.** No auth, rate limiting or CI. `CORS(supports_credentials=True)` is set with a fixed origin list.
- **Dead files.** `prompts/`, `input/` and `config/settings.json` are not used.
