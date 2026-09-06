"""HTTP client the CLIs use to submit results to the API (Phase 3).

httpx is the only dependency (part of the `api` extra:
`pip install undercover[api]`). This degrades gracefully like
undercover.dlp.ner and undercover.phishing.classifier do for their
optional dependencies -- a missing httpx (or an unreachable API)
raises ApiClientError, which callers are expected to catch and warn
about rather than letting crash a scan that already succeeded locally.
"""

from __future__ import annotations

from typing import Any, Optional

DEFAULT_API_URL = "http://127.0.0.1:8000"

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
            "httpx is not installed. Install it with `pip install undercover[api]`."
        )
    return _load_error


class ApiClientError(RuntimeError):
    """Raised when submitting to the API fails: httpx missing, the API is
    unreachable, or it returned an error status."""


class ApiClient:
    def __init__(self, base_url: str = DEFAULT_API_URL, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def submit_dlp_scan(self, source: str, result) -> dict:
        """Submit a undercover.dlp.scanner.ScanResult. Returns the created record."""
        return self._post("/dlp/scans", {"source": source, **result.to_dict()})

    def submit_phishing_analysis(
        self, source: str, result, sender_email: Optional[str] = None
    ) -> dict:
        """Submit a undercover.phishing.detector.PhishingResult. Returns the
        created record. sender_email is stored separately from the detection
        result itself so Phase 4's per-sender anomaly detection has a join key."""
        payload = {"source": source, "sender_email": sender_email, **result.to_dict()}
        return self._post("/phishing/analyses", payload)

    def get_sender_anomalies(self, contamination: float = 0.2) -> dict:
        """Fetch Phase 4's per-sender anomaly report."""
        return self._get("/anomaly/senders", params={"contamination": contamination})

    def _post(self, path: str, payload: dict) -> dict:
        if not is_available():
            raise ApiClientError(load_error())

        import httpx

        url = f"{self.base_url}{path}"
        try:
            response = httpx.post(url, json=payload, timeout=self.timeout)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ApiClientError(f"Failed to reach {url}: {exc}") from exc
        return response.json()

    def _get(self, path: str, params: Optional[dict[str, Any]] = None) -> dict:
        if not is_available():
            raise ApiClientError(load_error())

        import httpx

        url = f"{self.base_url}{path}"
        try:
            response = httpx.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ApiClientError(f"Failed to reach {url}: {exc}") from exc
        return response.json()
