"""CLI to run the API server: `undercover-api`."""

from __future__ import annotations

import argparse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="undercover-api",
        description="Run the undercover API server (FastAPI + SQLite). "
        "Interactive docs are served at /docs once running.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--reload", action="store_true", help="Auto-reload on code changes (dev only)."
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    import uvicorn

    args = build_parser().parse_args(argv)
    uvicorn.run(
        "undercover.api.server:app", host=args.host, port=args.port, reload=args.reload
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
