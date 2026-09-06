"""CLI to train and persist the phishing classifier: `undercover-phish-train`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from undercover.phishing.classifier import (
    DEFAULT_DATASET_PATH,
    is_available,
    load_error,
    save_model,
    train,
)

DEFAULT_MODEL_PATH = Path("models/phishing_classifier.joblib")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="undercover-phish-train",
        description="Train the phishing classifier on a labeled CSV dataset "
        "and save it to disk.",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET_PATH,
        help=f"Path to a text,label CSV (default: bundled demo dataset at "
        f"{DEFAULT_DATASET_PATH}).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_MODEL_PATH,
        help=f"Where to save the trained model (default: {DEFAULT_MODEL_PATH}).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not is_available():
        print(f"Cannot train: {load_error()}", file=sys.stderr)
        return 1

    pipeline = train(args.dataset)
    save_model(pipeline, args.out)
    print(f"Trained on {args.dataset} and saved model to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
