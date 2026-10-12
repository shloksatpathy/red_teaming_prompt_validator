# Plan

## 1. Detection quality (highest value)
- Fix keyword false positives: "run", "show", "output" flag benign prompts, and "run" alone scores Critical.
  - Require keywords to appear in an injection context (e.g. "ignore" near "instructions"), or use keyword hits only to boost pattern matches.
- Catch evasion: normalize text before scanning.
  - Unicode homoglyphs and zero-width characters.
  - Leetspeak and spaced-out letters.
  - Decode base64/rot13 payloads and rescan (`encoding_bypass` currently only matches the words).
- Cover more attack types: indirect injection, multi-turn attacks, non-English prompts.
- Optional LLM-as-judge second pass for ambiguous scores.
- Benchmark against a public injection dataset (e.g. deepset prompt-injections); report precision/recall and tune risk-score weights.

## 2. Red-teaming features
- Attack-variant generator that mutates a prompt.
- Test harness that sends variants to a target LLM and records whether the injection succeeded.
- "Harden my prompt" suggestions beyond the generic recommendations.

## 3. Backend
- Persistence: check how results are stored; move to SQLite if in-memory.
- Rate limiting, API key, input size limits, run under gunicorn.
- CSV/JSON export of history; OpenAPI spec.

## 4. Frontend
- Highlight matched text inside the prompt.
- Trend charts from `/stats`.
- File upload for batch analysis.

## 5. Engineering hygiene
- Run `test_detector.py` in CI (GitHub Actions); add tests for `server.py`.
- Remove leftovers from the old project: `prompts/`, empty `input/`, `config/settings.json`.
- Move detection patterns into an editable data file.
- Package the detector as a pip library and CLI; add a pre-commit/CI check for prompt files.

## Suggested order
1. Keyword false-positive fix
2. Benchmark
3. Text normalization
