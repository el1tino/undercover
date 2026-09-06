"""Shared httpx availability check for the alert channels -- both need
exactly the same optional dependency, so this is factored out once
within the package rather than duplicated per-channel."""

from __future__ import annotations

from typing import Optional

_load_error: Optional[str] = None
_import_checked = False


def is_available() -> bool:
    return _check_import() is None


def load_error() -> Optional[str]:
    return _check_import()


def _check_import() -> Optional[str]:
    global _load_error, _import_checked
    if _import_checked:
        return _load_error
    _import_checked = True
    try:
        import httpx  # noqa: F401
    except ImportError:
        _load_error = (
            "httpx is not installed. Install it with "
            "`pip install undercover[alerting]`."
        )
    return _load_error
