"""Add each harden.py guard to the plain system prompt on its own and measure the attack success rate."""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from prompt_validator.attack_variants import generate_variants
from prompt_validator.harden import GUARDS
from prompt_validator.hf_target import make_target

parser = argparse.ArgumentParser()
parser.add_argument("--model", default="Qwen/Qwen2.5-0.5B-Instruct")
args = parser.parse_args()

data = json.loads((Path(__file__).parent / "attacks.json").read_text())
plain = data["system_prompt"]
prompts = {"plain": plain, **{name: plain + "\n\n" + clause for name, _, clause in GUARDS}}
target = make_target(args.model)

counts = {p: {} for p in prompts}
for attack in data["attacks"]:
    for text in generate_variants(attack["text"]).values():
        for name, system_prompt in prompts.items():
            success = attack["canary"].lower() in re.sub(r"[\s​]", "", target(system_prompt, text).lower())
            counts[name][attack["type"]] = counts[name].get(attack["type"], 0) + success

types = list(counts["plain"])
runs = {t: 11 * sum(a["type"] == t for a in data["attacks"]) for t in types}
print(f"\n{args.model}: successes per guard (plain prompt + one guard)")
print(f"| guard | overall | " + " | ".join(types) + " |")
for name, c in counts.items():
    print(f"| {name} | {sum(c.values()) / sum(runs.values()):.0%} | " + " | ".join(f"{c[t]}/{runs[t]}" for t in types) + " |")
