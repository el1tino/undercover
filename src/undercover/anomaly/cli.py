"""CLI to fetch and print Phase 4's sender anomaly report: `undercover-anomaly`.

Unlike the Phase 1/2 CLIs, this doesn't scan anything locally -- the
anomaly report only makes sense over the history the API (Phase 3) has
already accumulated across many submitted phishing analyses, so this
is a thin client over GET /anomaly/senders.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from undercover.api.client import DEFAULT_API_URL, ApiClient, ApiClientError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="undercover-anomaly",
        description="Fetch per-sender anomaly scores computed over submitted "
        "phishing analyses (Phase 4).",
    )
    parser.add_argument(
        "--api-url",
        default=os.environ.get("UNDERCOVER_API_URL", DEFAULT_API_URL),
        help="Base URL of the undercover API (default: %(default)s, or "
        "$UNDERCOVER_API_URL).",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.2,
        help="Expected fraction of anomalous senders, passed to "
        "IsolationForest (default: %(default)s).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the report as JSON instead of a table.",
    )
    return parser


def _print_human(report: dict) -> None:
    if report.get("skip_reason"):
        print(f"Anomaly detection skipped: {report['skip_reason']}")
        return

    results = report.get("results", [])
    if not results:
        print("No senders flagged as anomalous.")
        return

    header = (
        f"{'sender':35s} {'anomaly':8s} {'score':7s} {'msgs':5s} "
        f"{'avg':6s} {'max':6s} {'phishing%':10s}"
    )
    print(header)
    print("-" * len(header))
    for row in results:
        flag = "YES" if row["is_anomaly"] else "no"
        print(
            f"{row['sender_email']:35s} {flag:8s} {row['anomaly_score']:<7.3f} "
            f"{row['message_count']:<5d} {row['avg_combined_score']:<6.2f} "
            f"{row['max_combined_score']:<6.2f} "
            f"{row['phishing_ratio'] * 100:<10.0f}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    client = ApiClient(base_url=args.api_url)
    try:
        report = client.get_sender_anomalies(contamination=args.contamination)
    except ApiClientError as exc:
        print(f"Error: could not reach the API -- {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_human(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
