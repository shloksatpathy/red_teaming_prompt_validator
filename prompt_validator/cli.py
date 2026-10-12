import argparse
import sys

from .prompt_injection_detector import PromptInjectionDetector, RiskLevel

LEVELS = [level.value for level in RiskLevel]


def main():
    parser = argparse.ArgumentParser(prog="prompt-validator", description="Scan prompt files for injection vulnerabilities.")
    parser.add_argument("files", nargs="+", help="prompt files to scan, or - for stdin")
    parser.add_argument("--fail-on", choices=LEVELS, default="high", help="exit 1 if any file reaches this level (default: high)")
    args = parser.parse_args()

    detector = PromptInjectionDetector()
    failed = False
    for path in args.files:
        text = sys.stdin.read() if path == "-" else open(path, encoding="utf-8").read()
        report = detector.generate_report(text)
        print(f"{path}: {report['overall_risk_level'].upper()} (score {report['risk_score']}, {report['vulnerability_count']} findings)")
        for finding in report["findings"]:
            print(f"  [{finding['risk_level']}] {finding['category']}: {finding['pattern_matched']!r}")
        if LEVELS.index(report["overall_risk_level"]) >= LEVELS.index(args.fail_on):
            failed = True

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
