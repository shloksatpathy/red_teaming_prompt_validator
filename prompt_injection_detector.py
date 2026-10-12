import base64
import codecs
import json
import re
import unicodedata
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum


PATTERNS_FILE = Path(__file__).parent / "patterns.json"
ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"))
HOMOGLYPHS = str.maketrans("аеорсхіѕԁοναιр", "aeopcxisdovaip")
LEET = str.maketrans("013457@$", "oieastas")
SPACED_LETTERS = re.compile(r"\b(?:\w[ .\-_]){3,}\w\b")
BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class VulnerabilityFinding:
    category: str
    description: str
    pattern_matched: str
    risk_level: RiskLevel
    suggestion: str


class PromptInjectionDetector:
    def __init__(self, patterns_file: Path = PATTERNS_FILE):
        with open(patterns_file, encoding="utf-8") as f:
            rules = json.load(f)
        self.patterns = {
            category: (re.compile(rule["regex"]), RiskLevel(rule["level"]))
            for category, rule in rules["patterns"].items()
        }
        self.keywords = {
            category: (rule["words"], RiskLevel(rule["level"]))
            for category, rule in rules["keywords"].items()
        }
        self.suggestions = {
            category: rule["suggestion"]
            for section in ("patterns", "keywords")
            for category, rule in rules[section].items()
        }

    def _variants(self, prompt: str) -> List[str]:
        normalized = unicodedata.normalize("NFKC", prompt).translate(ZERO_WIDTH).translate(HOMOGLYPHS)
        normalized = SPACED_LETTERS.sub(lambda m: re.sub(r"[ .\-_]", "", m.group(0)), normalized)
        variants = [prompt, normalized, normalized.translate(LEET)]

        for token in BASE64_TOKEN.findall(normalized):
            try:
                variants.append(base64.b64decode(token + "=" * (-len(token) % 4), validate=True).decode("utf-8"))
            except ValueError:
                pass
        if "rot13" in normalized.lower():
            variants.append(codecs.decode(normalized, "rot13"))
        return [v for i, v in enumerate(variants) if v not in variants[:i]]

    def detect_vulnerabilities(self, prompt: str) -> List[VulnerabilityFinding]:
        findings = []
        seen = set()
        for text in self._variants(prompt):
            for finding in self._scan(text):
                key = (finding.category, finding.pattern_matched.lower())
                if key not in seen:
                    seen.add(key)
                    findings.append(finding)
        return findings

    def _scan(self, prompt: str) -> List[VulnerabilityFinding]:
        findings = []

        # Check pattern-based vulnerabilities
        for category, (pattern, risk_level) in self.patterns.items():
            match = pattern.search(prompt)
            if match:
                findings.append(
                    VulnerabilityFinding(
                        category=category,
                        description=f"Detected {category.replace('_', ' ')} pattern",
                        pattern_matched=match.group(0),
                        risk_level=risk_level,
                        suggestion=self._get_suggestion(category),
                    )
                )

        # Check keyword-based vulnerabilities
        for category, (keywords, risk_level) in self.keywords.items():
            for keyword in keywords:
                if re.search(rf"\b{re.escape(keyword)}\b", prompt, re.IGNORECASE):
                    if not any(keyword.lower() in f.pattern_matched.lower() for f in findings):
                        findings.append(
                            VulnerabilityFinding(
                                category=category,
                                description=f"Detected '{keyword}' keyword commonly used in prompt injections",
                                pattern_matched=keyword,
                                risk_level=risk_level,
                                suggestion=self._get_suggestion(category),
                            )
                        )

        return findings

    def _get_suggestion(self, category: str) -> str:
        return self.suggestions[category]

    def calculate_risk_score(self, findings: List[VulnerabilityFinding]) -> float:
        if not findings:
            return 0.0

        # Base from the worst finding; each extra finding adds 3, capped at 20.
        # Ranges (LOW 10-30, MEDIUM 30-50, HIGH 55-75, CRITICAL 80-100) match the overall level.
        base = {
            RiskLevel.LOW: 10,
            RiskLevel.MEDIUM: 30,
            RiskLevel.HIGH: 55,
            RiskLevel.CRITICAL: 80,
        }
        worst = max(base[f.risk_level] for f in findings)
        return float(worst + min(3 * (len(findings) - 1), 20))

    def get_overall_risk_level(self, findings: List[VulnerabilityFinding]) -> RiskLevel:
        if not findings:
            return RiskLevel.LOW

        risk_levels = [f.risk_level for f in findings]
        if RiskLevel.CRITICAL in risk_levels:
            return RiskLevel.CRITICAL
        elif RiskLevel.HIGH in risk_levels:
            return RiskLevel.HIGH
        elif RiskLevel.MEDIUM in risk_levels:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def generate_report(self, prompt: str) -> Dict:
        findings = self.detect_vulnerabilities(prompt)
        risk_score = self.calculate_risk_score(findings)
        overall_risk = self.get_overall_risk_level(findings)

        return {
            "prompt": prompt,
            "findings": [
                {
                    "category": f.category,
                    "description": f.description,
                    "pattern_matched": f.pattern_matched,
                    "risk_level": f.risk_level.value,
                    "suggestion": f.suggestion,
                }
                for f in findings
            ],
            "risk_score": round(risk_score, 2),
            "overall_risk_level": overall_risk.value,
            "vulnerability_count": len(findings),
            "summary": self._generate_summary(findings, overall_risk),
        }

    def _generate_summary(self, findings: List[VulnerabilityFinding], risk_level: RiskLevel) -> str:
        if risk_level == RiskLevel.CRITICAL:
            return f"CRITICAL: Found {len(findings)} vulnerabilities. This prompt is highly susceptible to injection attacks."
        elif risk_level == RiskLevel.HIGH:
            return f"HIGH: Found {len(findings)} vulnerabilities. Implement security measures immediately."
        elif risk_level == RiskLevel.MEDIUM:
            return f"MEDIUM: Found {len(findings)} vulnerabilities. Review and harden the prompt."
        else:
            return "LOW: No significant injection vulnerabilities detected. Keep best practices in mind."
