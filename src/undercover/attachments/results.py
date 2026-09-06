"""Shared result types for attachment threat-intel lookups."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from undercover.phishing.email_message import Attachment


@dataclass(frozen=True)
class HashLookupResult:
    """The outcome of asking one threat-intel source about one file hash."""

    source: str  # "virustotal" | "malwarebazaar"
    attempted: bool  # True if a request was actually sent (vs. skipped: no key/dependency)
    found: bool  # True if the source had a record for this hash
    malicious: bool
    detail: str
    malicious_engines: Optional[int] = None
    total_engines: Optional[int] = None


@dataclass(frozen=True)
class AttachmentVerdict:
    """The combined verdict for one attachment across all configured sources."""

    attachment: Attachment
    checked: bool  # True if at least one source was actually queried
    malicious: bool
    lookups: list[HashLookupResult]
