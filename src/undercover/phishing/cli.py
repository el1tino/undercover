"""Command-line entry point for phishing analysis (Phase 2): `undercover-phish`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from undercover.api.client import DEFAULT_API_URL, ApiClient, ApiClientError
from undercover.phishing.detector import PhishingDetector
from undercover.phishing.email_message import EmailMessage


def _read_input(path: str | None) -> str:
    if path is None or path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _print_human(result, source_label: str) -> None:
    print(f"Verdict for {source_label}: {result.verdict.upper()}")
    print(f"  combined score: {result.combined_score:.2f}")
    print(f"  rule score:     {result.rule_score:.2f}")
    if result.ml_score is not None:
        print(f"  ML score:       {result.ml_score:.2f}")
    elif result.ml_skip_reason:
        print(f"  ML score:       skipped -- {result.ml_skip_reason}")

    if result.rule_hits:
        print("\n  Rule hits:")
        for hit in result.rule_hits:
            print(f"    - [{hit.name}] {hit.description} (weight {hit.weight:.2f})")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="undercover-phish",
        description="Analyze an email for phishing indicators (rule-based "
        "heuristics + an optional ML classifier).",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Raw email file (.eml, or headers+body text) to analyze. "
        "Omit or pass '-' to read from stdin.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the result as JSON instead of human-readable text.",
    )
    parser.add_argument(
        "--no-ml",
        action="store_true",
        help="Skip the ML classifier and only run rule-based checks.",
    )
    parser.add_argument(
        "--model",
        type=Path,
        default=None,
        help="Path to a pre-trained model (from undercover-phish-train). "
        "If omitted, a model is trained in-memory on the bundled demo dataset.",
    )
    parser.add_argument(
        "--fail-on-detect",
        action="store_true",
        help="Exit with status code 1 if the verdict is not 'clean' "
        "(useful in CI/pre-commit hooks).",
    )
    parser.add_argument(
        "--submit",
        action="store_true",
        help="Submit the result to the undercover API (Phase 3) in addition "
        "to printing it.",
    )
    parser.add_argument(
        "--api-url",
        default=os.environ.get("UNDERCOVER_API_URL", DEFAULT_API_URL),
        help="Base URL of the undercover API (default: %(default)s, or "
        "$UNDERCOVER_API_URL).",
    )
    return parser


def _submit(api_url: str, source_label: str, result) -> None:
    client = ApiClient(base_url=api_url)
    try:
        response = client.submit_phishing_analysis(source_label, result)
        print(
            f"Submitted to API: phishing analysis id={response.get('id')}",
            file=sys.stderr,
        )
    except ApiClientError as exc:
        print(f"Warning: could not submit to API -- {exc}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    source_label = args.path if args.path and args.path != "-" else "<stdin>"
    raw = _read_input(args.path)
    msg = EmailMessage.from_raw(raw)
    detector = PhishingDetector(use_ml=not args.no_ml, model_path=args.model)
    result = detector.analyze(msg)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_human(result, source_label)

    if args.submit:
        _submit(args.api_url, source_label, result)

    if args.fail_on_detect and result.verdict != "clean":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
