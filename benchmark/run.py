import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from prompt_validator.prompt_injection_detector import PromptInjectionDetector

detector = PromptInjectionDetector()

with open(Path(__file__).parent / "deepset_prompt_injections.csv", newline="") as f:
    rows = [(r["text"], int(r["label"])) for r in csv.DictReader(f)]

scores = [(detector.generate_report(text)["risk_score"], label) for text, label in rows]

print(f"{len(rows)} prompts, {sum(l for _, l in scores)} injections")
print("threshold  precision  recall  f1")
for threshold in [10, 30, 55, 80]:
    tp = sum(1 for s, l in scores if s >= threshold and l)
    fp = sum(1 for s, l in scores if s >= threshold and not l)
    fn = sum(1 for s, l in scores if s < threshold and l)
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
    print(f"{threshold:>9}  {precision:>9.2f}  {recall:>6.2f}  {f1:.2f}")
