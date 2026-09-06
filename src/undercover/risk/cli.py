"""CLI that ties Phases 1-4 together into one risk assessment: `undercover-risk`.

Runs the DLP scanner, the phishing detector, and header analysis on a
single email, optionally checks whether the sender is currently
flagged anomalous (Phase 4, via the API), and fuses everything into
one RiskAssessment -- printed, exported as JSON/CEF, and optionally
submitted to the API for storage.
"""

from __future__ import annotations

import argparse
import os
import sys

from undercover.api.client import DEFAULT_API_URL, ApiClient, ApiClientError
from undercover.attachments.results import AttachmentVerdict
from undercover.attachments.scanner import AttachmentScanner
from undercover.dlp.scanner import DLPScanner
from undercover.phishing.detector import PhishingDetector
from undercover.phishing.email_message import EmailMessage
from undercover.risk.export import to_cef, to_json
from undercover.risk.headers import HeaderAuthReport, analyze_headers
from undercover.risk.scoring import RiskAssessment, assess_risk

_LEVEL_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _read_input(path: str | None) -> str:
    if path is None or path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _check_sender_anomaly(
    api_url: str, sender_email: str | None
) -> tuple[bool | None, str | None]:
    """Returns (is_anomalous, skip_reason) -- exactly one is None."""
    if not sender_email:
        return None, "no sender email parsed from this message"

    client = ApiClient(base_url=api_url)
    try:
        report = client.get_sender_anomalies()
    except ApiClientError as exc:
        return None, str(exc)

    if report.get("skip_reason"):
        return None, report["skip_reason"]

    row = next(
        (r for r in report.get("results", []) if r["sender_email"] == sender_email),
        None,
    )
    if row is None:
        return None, "sender has no prior submissions on record"
    return row["is_anomaly"], None


def _print_human(
    assessment: RiskAssessment,
    header_report: HeaderAuthReport,
    source_label: str,
    anomaly_skip_reason: str | None,
    attachment_verdicts: list[AttachmentVerdict] | None,
) -> None:
    print(f"Risk assessment for {source_label}")
    print(f"  risk level: {assessment.risk_level.upper()}")
    print(f"  risk score: {assessment.risk_score:.2f}")

    if assessment.factors:
        print("\n  Factors:")
        for f in assessment.factors:
            print(
                f"    - [{f.name}] {f.detail} "
                f"(weight {f.weight:.2f}, value {f.value:.2f})"
            )
    else:
        print("\n  No signals were available to assess.")

    if anomaly_skip_reason:
        print(f"\n  Sender anomaly check: skipped -- {anomaly_skip_reason}")

    print("\n  Header authentication:")
    if not header_report.authentication_results_present:
        print("    no Authentication-Results header found")
    else:
        for label, result in (
            ("SPF", header_report.spf),
            ("DKIM", header_report.dkim),
            ("DMARC", header_report.dmarc),
        ):
            print(f"    {label}: {result.result if result else 'not reported'}")

    if attachment_verdicts:
        print("\n  Attachments:")
        for verdict in attachment_verdicts:
            status = (
                "MALICIOUS" if verdict.malicious else "clean" if verdict.checked else "unchecked"
            )
            print(f"    - {verdict.attachment.filename}: {status}")
            for lookup in verdict.lookups:
                if lookup.attempted:
                    print(f"        [{lookup.source}] {lookup.detail}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="undercover-risk",
        description="Run DLP, phishing, and header analysis on an email and "
        "produce one unified risk assessment.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Raw email file (.eml) to assess. Omit or pass '-' to read from stdin.",
    )
    parser.add_argument(
        "--format",
        choices=["human", "json", "cef"],
        default="human",
        help="Output format (default: %(default)s).",
    )
    parser.add_argument(
        "--no-ner", action="store_true", help="Skip spaCy NER in the DLP pass."
    )
    parser.add_argument(
        "--no-ml", action="store_true", help="Skip the ML classifier in the phishing pass."
    )
    parser.add_argument(
        "--no-anomaly-check",
        action="store_true",
        help="Don't check the API for whether this sender is currently "
        "flagged anomalous (Phase 4).",
    )
    parser.add_argument(
        "--api-url",
        default=os.environ.get("UNDERCOVER_API_URL", DEFAULT_API_URL),
        help="Base URL of the undercover API (default: %(default)s, or "
        "$UNDERCOVER_API_URL).",
    )
    parser.add_argument(
        "--submit",
        action="store_true",
        help="Submit the risk assessment to the API in addition to printing it.",
    )
    parser.add_argument(
        "--fail-on-risk",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Exit with status code 1 if the risk level is at or above this "
        "threshold (useful in CI/pre-commit hooks).",
    )
    parser.add_argument(
        "--check-attachments",
        action="store_true",
        help="Check any attachments' hashes against VirusTotal and "
        "MalwareBazaar. Opt-in: this makes real network requests and needs "
        "VT_API_KEY / MALWAREBAZAAR_API_KEY to actually check anything.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    source_label = args.path if args.path and args.path != "-" else "<stdin>"
    raw = _read_input(args.path)

    msg = EmailMessage.from_raw(raw)
    sender_email = msg.sender_email or None

    dlp_result = DLPScanner(use_ner=not args.no_ner).scan(msg.body)
    phishing_result = PhishingDetector(use_ml=not args.no_ml).analyze(msg)
    header_report = analyze_headers(raw)

    sender_is_anomalous = None
    anomaly_skip_reason = None
    if args.no_anomaly_check:
        anomaly_skip_reason = "disabled via --no-anomaly-check"
    else:
        sender_is_anomalous, anomaly_skip_reason = _check_sender_anomaly(
            args.api_url, sender_email
        )

    attachment_verdicts: list[AttachmentVerdict] | None = None
    if args.check_attachments:
        attachment_verdicts = AttachmentScanner().scan(msg.attachments)

    assessment = assess_risk(
        dlp_result=dlp_result,
        phishing_result=phishing_result,
        header_report=header_report,
        sender_is_anomalous=sender_is_anomalous,
        attachment_verdicts=attachment_verdicts,
    )

    if args.format == "json":
        print(to_json(assessment, source_label, sender_email))
    elif args.format == "cef":
        print(to_cef(assessment, source_label, sender_email))
    else:
        _print_human(
            assessment, header_report, source_label, anomaly_skip_reason, attachment_verdicts
        )

    if args.submit:
        client = ApiClient(base_url=args.api_url)
        try:
            response = client.submit_risk_assessment(
                source_label, assessment, sender_email=sender_email
            )
            print(
                f"Submitted to API: risk assessment id={response.get('id')}",
                file=sys.stderr,
            )
        except ApiClientError as exc:
            print(f"Warning: could not submit to API -- {exc}", file=sys.stderr)

    if args.fail_on_risk is not None:
        if _LEVEL_ORDER[assessment.risk_level] >= _LEVEL_ORDER[args.fail_on_risk]:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
