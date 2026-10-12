import base64
import codecs
import re
import unicodedata
from typing import Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum


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
    def __init__(self):
        self.patterns = self._initialize_patterns()
        self.keywords = self._initialize_keywords()

    def _initialize_patterns(self) -> Dict[str, Tuple[re.Pattern, RiskLevel]]:
        return {
            "instruction_override": (
                re.compile(
                    r"\b(ignore|override|bypass|disregard)\s+(?:all\s+)?(previous|prior|earlier)?.*?(instructions?|rules?|guidelines?|constraints?|prompts?)",
                    re.IGNORECASE,
                ),
                RiskLevel.CRITICAL,
            ),
            "role_override": (
                re.compile(
                    r"\b(?:forget|pretend|imagine|assume|act as if)\b.{0,40}\b(?:you|your|you're|ai|assistant|model)\b|\broleplay\b.*?\b(?:ignore|forget|bypass)\b",
                    re.IGNORECASE,
                ),
                RiskLevel.HIGH,
            ),
            "context_injection": (
                re.compile(
                    r"(?:from now on|henceforth|starting now).*?(?:ignore|forget|act as)",
                    re.IGNORECASE,
                ),
                RiskLevel.HIGH,
            ),
            "delimiter_manipulation": (
                re.compile(
                    r"(?:---+|===+|###|<<<|>>>|\$\$\$).*?(?:ignore|override|end)",
                    re.IGNORECASE,
                ),
                RiskLevel.MEDIUM,
            ),
            "prompt_leaking": (
                re.compile(
                    r"(?:reveal|show|print|display|output).*?(?:system prompt|original prompt|instructions|rules)",
                    re.IGNORECASE,
                ),
                RiskLevel.HIGH,
            ),
            "jailbreak_attempt": (
                re.compile(
                    r"(?-i:\bDAN\b)|\b(?:do anything now|unrestricted|no safety)\b|\bdisable\b.*?\bfilter",
                    re.IGNORECASE,
                ),
                RiskLevel.CRITICAL,
            ),
            "nested_injection": (
                re.compile(
                    r"(?:\[|\{).*?(?:ignore|override|execute).*?(?:\]|\})", re.IGNORECASE
                ),
                RiskLevel.MEDIUM,
            ),
            "meta_prompt_exposure": (
                re.compile(
                    r"(?:what|who).*?(?:were|are|was|is).*?(?:told|instructed|programmed|designed)",
                    re.IGNORECASE,
                ),
                RiskLevel.MEDIUM,
            ),
            "encoding_bypass": (
                re.compile(
                    r"\b(?:base64|rot13|unicode|encoded|escaped)\b.*?\bdecode\b|\bdecode\b.*?\b(?:base64|rot13|unicode)\b",
                    re.IGNORECASE,
                ),
                RiskLevel.HIGH,
            ),
        }

    def _initialize_keywords(self) -> Dict[str, Tuple[List[str], RiskLevel]]:
        # Ambiguous single words are LOW review hints; only specific terms keep a high severity.
        return {
            "instruction_keywords": (
                ["ignore", "bypass", "override", "disregard", "forget"],
                RiskLevel.LOW,
            ),
            "system_keywords": (
                [
                    "system prompt",
                    "original prompt",
                    "initial instructions",
                    "true instructions",
                    "real purpose",
                ],
                RiskLevel.HIGH,
            ),
            "dangerous_commands": (
                ["execute", "eval", "sys.exit", "os.system", "subprocess"],
                RiskLevel.CRITICAL,
            ),
            "extraction_keywords": (
                ["reveal", "dump", "leak"],
                RiskLevel.LOW,
            ),
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
        suggestions = {
            "instruction_override": "Implement prompt guards that prevent users from overriding system instructions. Use clear separators between system and user prompts.",
            "role_override": "Avoid allowing users to change the assistant's role dynamically. Lock the role definition at the system prompt level.",
            "context_injection": "Use strict parsing for time-based or context-based instructions. Validate and sanitize all user input before including in prompts.",
            "delimiter_manipulation": "Use consistent, machine-readable delimiters that cannot be easily exploited. Escape user input that contains delimiters.",
            "prompt_leaking": "Never reveal the system prompt to users. Use input validation to block queries asking for system information.",
            "jailbreak_attempt": "Implement safety guidelines in the system prompt. Use content moderation to detect and block jailbreak attempts.",
            "nested_injection": "Parse and validate all nested structures. Remove or escape special characters in user input.",
            "meta_prompt_exposure": "Avoid questions about the AI's design or instructions. Use response filtering to block meta-questions.",
            "encoding_bypass": "Implement checks for encoded payloads. Decode and analyze any suspicious encoded content in user input.",
            "instruction_keywords": "Avoid using common override keywords in system prompts. Use content filtering on user inputs.",
            "system_keywords": "Add explicit safeguards that prevent disclosure of system prompts or instructions.",
            "dangerous_commands": "Never allow direct execution of code or system commands. Use sandboxed environments with strict permissions.",
            "extraction_keywords": "Implement filters to block extraction attempts. Use response validation to ensure sensitive information isn't leaked.",
        }
        return suggestions.get(category, "Review the system prompt design and implement additional input validation.")

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
