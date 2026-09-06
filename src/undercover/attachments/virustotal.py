"""VirusTotal file-hash lookup (public API v3).

This only ever looks up a hash the caller already computed locally
(`GET /files/{sha256}`) -- it never uploads the file itself, so no
attachment content leaves the machine, only its SHA-256.

Requires a VirusTotal API key (https://www.virustotal.com/gui/my-apikey),
passed explicitly or via the VT_API_KEY environment variable. httpx is
optional (the `attachments` extra: `pip install undercover[attachments]`)
and this degrades gracefully -- like every other optional dependency in
the project -- rather than raising when it, or an API key, is missing.
"""

from __future__ import annotations

import os
from typing import Optional

from undercover.attachments._httpx_support import is_available, load_error
from undercover.attachments.results import HashLookupResult

API_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalClient:
    def __init__(self, api_key: Optional[str] = None, timeout: float = 10.0):
        self.api_key = api_key or os.environ.get("VT_API_KEY")
        self.timeout = timeout

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def lookup_hash(self, sha256: str) -> HashLookupResult:
        if not is_available():
            return HashLookupResult(
                source="virustotal", attempted=False, found=False, malicious=False,
                detail=load_error(),
            )
        if not self.is_configured():
            return HashLookupResult(
                source="virustotal", attempted=False, found=False, malicious=False,
                detail="VirusTotal API key not configured (set VT_API_KEY).",
            )

        import httpx

        url = f"{API_BASE}/files/{sha256}"
        try:
            response = httpx.get(
                url, headers={"x-apikey": self.api_key}, timeout=self.timeout
            )
        except httpx.HTTPError as exc:
            return HashLookupResult(
                source="virustotal", attempted=True, found=False, malicious=False,
                detail=f"VirusTotal request failed: {exc}",
            )

        if response.status_code == 404:
            return HashLookupResult(
                source="virustotal", attempted=True, found=False, malicious=False,
                detail="hash not found in VirusTotal",
            )
        if response.status_code != 200:
            return HashLookupResult(
                source="virustotal", attempted=True, found=False, malicious=False,
                detail=f"VirusTotal returned HTTP {response.status_code}",
            )

        attributes = response.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        detail = (
            f"{malicious_count}/{total} engines flagged this file as malicious"
            if total
            else "found in VirusTotal but no analysis stats available"
        )
        return HashLookupResult(
            source="virustotal",
            attempted=True,
            found=True,
            malicious=malicious_count > 0,
            detail=detail,
            malicious_engines=malicious_count,
            total_engines=total,
        )
