"""Command-line entry point for the undercover DLP scanner (Phase 1)."""

from __future__ import annotations

import argparse
import json
import sys

from undercover.dlp.scanner import DLPScanner, ScanResult


def _read_input(path: str | None) -> str:
    if path is None or path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _print_human(result: ScanResult, source_label: str) -> None:
    if not result.has_findings:
        print(f"No sensitive data found in {source_label}.")
    else:
        print(f"Found {len(result.findings)} potential issue(s) in {source_label}:\n")
        for finding in result.findings:
            print(
                f"  [{finding.source:5s}] {finding.label:30s} "
                f"{finding.redacted():20s} "
                f"(offset {finding.start}-{finding.end}, "
                f"confidence {finding.confidence:.2f})"
            )
    if result.ner_skip_reason:
        print(f"\nNote: NER scan skipped -- {result.ner_skip_reason}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="undercover",
        description="Scan text or email content for sensitive data (PII, "
        "credentials, secrets).",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="File to scan. Omit or pass '-' to read from stdin.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output findings as JSON instead of human-readable text.",
    )
    parser.add_argument(
        "--no-ner",
        action="store_true",
        help="Skip the spaCy NER pass and only run regex-based detectors.",
    )
    parser.add_argument(
        "--fail-on-find",
        action="store_true",
        help="Exit with status code 1 if any findings are detected "
        "(useful in CI/pre-commit hooks).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    text = _read_input(args.path)
    scanner = DLPScanner(use_ner=not args.no_ner)
    result = scanner.scan(text)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        source_label = args.path if args.path and args.path != "-" else "<stdin>"
        _print_human(result, source_label)

    if args.fail_on_find and result.has_findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
