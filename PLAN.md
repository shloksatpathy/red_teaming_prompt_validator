# Plan

## 1. Detection quality (highest value)
- [x] Fix keyword false positives: "run", "show", "output" flag benign prompts, and "run" alone scores Critical.
  - [x] Require keywords to appear in an injection context (e.g. "ignore" near "instructions"), or use keyword hits only to boost pattern matches.
- [x] Fix regex problems:
  - [x] `role_override` is a bare alternation (`forget|pretend|imagine|assume|...`), so any occurrence triggers it and `roleplay.*(ignore|...)` binds only to the last alternative; group it properly and require injection context.
  - [x] Add word boundaries: case-insensitive `DAN` matches inside "abundance" and "Dan"; `unrestricted` and `unicode` also match anywhere.
- [x] Fix risk score semantics: it is the mean severity, so adding a weak finding lowers it (Critical + Medium = 65, Critical alone = 100) and it can disagree with the overall level (the max severity). Make it monotonic in evidence (e.g. max severity plus a capped bonus per extra finding) and keep it consistent with the level.
- [x] Fix dedup bugs: severity is compared as strings (`"medium" > "high"`), and the keyword "already found" check compares against whole matched phrases, so it rarely matches. Compare by enum order.
- [x] Catch evasion: normalize text before scanning.
  - [x] Unicode homoglyphs and zero-width characters.
  - [x] Leetspeak and spaced-out letters.
  - [x] Decode base64/rot13 payloads and rescan (`encoding_bypass` currently only matches the words).
- [x] Cover more attack types: indirect injection, multi-turn attacks, non-English prompts.
- [ ] Optional LLM-as-judge second pass for ambiguous scores.
- [x] Benchmark against a public injection dataset (e.g. deepset prompt-injections); report precision/recall and tune risk-score weights. Result: precision 1.00, recall 0.33 (`python3 benchmark/run.py`). Recall is bounded by rule coverage (many dataset injections are plain task hijacks with no trigger phrase), not by the score weights, so the weights were left as is.

## 2. Red-teaming features
- [x] Attack-variant generator that mutates a prompt.
- [ ] Test harness that sends variants to a target LLM and records whether the injection succeeded.
- [ ] "Harden my prompt" suggestions beyond the generic recommendations.

## 3. Backend
- [ ] Persistence: check how results are stored; move to SQLite if in-memory.
- [ ] Rate limiting, API key, input size limits, run under gunicorn.
- [ ] CSV/JSON export of history; OpenAPI spec.

## 4. Frontend
- [ ] Highlight matched text inside the prompt.
- [ ] Trend charts from `/stats`.
- [ ] File upload for batch analysis.

## 5. Engineering hygiene
- [ ] Run `test_detector.py` in CI (GitHub Actions); add tests for `server.py`.
- [ ] Remove leftovers from the old project: `prompts/`, empty `input/`, `config/settings.json`.
- [ ] Move detection patterns into an editable data file.
- [ ] Package the detector as a pip library and CLI; add a pre-commit/CI check for prompt files.

## Suggested order
1. Keyword false-positive fix
2. Benchmark
3. Text normalization
