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
- [x] Test harness that sends variants to a target LLM and records whether the injection succeeded. (`harness.py` takes any `target(system_prompt, user_message) -> str` callable; no real model adapter is wired in because no API key is available here.)
- [x] "Harden my prompt" suggestions beyond the generic recommendations.

## 3. Backend
- [x] Persistence: check how results are stored; move to SQLite if in-memory. (Checked: results are JSON files in `validation_results/`, not in memory, so no move. They are still lost on Render's ephemeral disk.)
- [x] Rate limiting, API key, input size limits, run under gunicorn. (Per-IP rate limit per worker, optional `API_KEY` env var checked via `X-API-Key`, 1 MB body cap, per-prompt cap in batch; gunicorn was already the Render start command. Also fixed: `static_folder='.'` exposed `server.py` and `.env` over HTTP.)
- [x] CSV/JSON export of history; OpenAPI spec. (`GET /export?format=csv|json`, `GET /openapi.json`)

## 4. Frontend
- [x] Highlight matched text inside the prompt.
- [x] Trend charts from `/stats`. (Risk-score line chart on the Statistics tab, built from `/results` because `/stats` has no time series. Also fixed history badges, which always showed LOW.)
- [x] File upload for batch analysis. (.txt one prompt per line, or .json array)

## 5. Engineering hygiene
- [x] Run tests in CI (GitHub Actions, `.github/workflows/ci.yml`); add tests for `server.py` (`test_server.py`).
- [x] Remove leftovers from the old project: `prompts/`, empty `input/`, `config/settings.json` (also `submissions.html`, which called the removed `/list` endpoint).
- [x] Move detection patterns into an editable data file. (`patterns.json`: regexes, keywords, levels and suggestions)
- [x] Package the detector as a pip library and CLI; add a pre-commit/CI check for prompt files. (`pyproject.toml`, `prompt-validator` command, `.pre-commit-hooks.yaml`; no prompt files remain in this repo, so there is no CI scan step)

## 6. Testing with open-source Hugging Face models
Two questions: (a) which attacks actually break real open models, and does `harden_prompt` reduce that? (b) how does the rule-based detector compare to, and combine with, open injection classifiers?

### 6a. Open models as harness targets
- [x] Add an optional `hf` extra to `pyproject.toml` (`transformers`, `torch`, `accelerate`). Keep it out of `requirements.txt` so the Render deploy and CI stay light.
- [x] `prompt_validator/hf_target.py`: `make_target(model_id) -> target(system_prompt, user_message) -> str`, built on `transformers.pipeline("text-generation")` with chat messages. Use greedy decoding (`do_sample=False`, `max_new_tokens=128`) so runs can be repeated. Only models whose chat template has a system role are supported (no Gemma yet).
- [x] `benchmark/attacks.json`: 12 attacks, each with a canary (`8841-2290` to output, or the secret `ZEBRA-9182` in the system prompt to leak). Cover instruction override, system-prompt leak, role-play/DAN, delimiter/fake-system, and indirect injection (the attack is inside a "document" the user asks to summarise).
- [x] `benchmark/redteam.py --model <id>`: for each attack variant, call the target with (1) a plain system prompt and (2) `harden_prompt(plain)["hardened_prompt"]`. Print the attack success rate per variant for each prompt, and write the raw replies to `benchmark/results/<model>.json` (gitignored).
- [x] Join with the detector: for every variant that succeeded, record whether `PromptInjectionDetector` flagged it. Successful attacks it missed are the most useful input for new `patterns.json` rules.
- [ ] Models (small enough for CPU or a free Colab T4 first): `Qwen/Qwen2.5-0.5B-Instruct`, `Qwen/Qwen2.5-1.5B-Instruct`, `HuggingFaceTB/SmolLM2-1.7B-Instruct`, `microsoft/Phi-3.5-mini-instruct`; then 7B-class (`mistralai/Mistral-7B-Instruct-v0.3`, `meta-llama/Llama-3.1-8B-Instruct` (gated)) on a GPU.
- [ ] Record results per model in `benchmark/RESULTS.md` (Qwen2.5-0.5B and 1.5B done).

### 6b. Open injection classifiers as a baseline / second pass
- [ ] `benchmark/run.py --classifier <id>`: score `deepset_prompt_injections.csv` with a `text-classification` pipeline and print precision/recall/F1 next to the rule-based numbers (currently P 1.00 / R 0.33).
- [ ] Candidates: `protectai/deberta-v3-base-prompt-injection-v2`, `meta-llama/Llama-Prompt-Guard-2-86M` (gated). Note: deepset is the training data for some of these, so also score the variants from `generate_variants` and the attacks in `benchmark/attacks.json` to get a fair comparison.
- [ ] Try the union (rules OR classifier). If it clearly raises recall without hurting precision, wire it in as the optional second pass from section 1 (enabled with `--classifier` on the CLI; off by default, so the core package keeps no ML dependency).

### Notes
- Gated models need `huggingface-cli login` and accepting the licence on the model page.
- Heavy runs stay out of CI; `test_detector.py` keeps using the fake target. A unit test for `hf_target` can use a tiny model (`sshleifer/tiny-gpt2`) only if it is fast enough.
- Order: 6b classifier benchmark (cheapest, no generation) → 6a with Qwen 0.5B end to end → add more models.

## Suggested order
1. Keyword false-positive fix
2. Benchmark
3. Text normalization

### 6c. Follow-ups from the Qwen runs (`benchmark/RESULTS.md`)
- [x] Find why hardening backfires: not the missing `<user_input>` tags; per-guard ablation blames `instruction_priority` and `role_lock`.
- [x] Reword both guards without attacker vocabulary. `role_lock` is fixed; `instruction_priority` still raises leaks.
- [ ] Decide whether to drop or redesign `instruction_priority`, and recheck on a 3B+ model before changing `harden.py` further.
- [ ] Catch spaced-out variants: the normalizer joins all letters, so word-boundary rules (`\s+`) cannot match.
