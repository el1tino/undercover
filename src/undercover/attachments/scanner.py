"""Combines VirusTotal and MalwareBazaar hash lookups into one verdict
per attachment, and summarizes a batch of verdicts for risk scoring."""

from __future__ import annotations

from typing import Optional

from undercover.attachments.malwarebazaar import MalwareBazaarClient
from undercover.attachments.results import AttachmentVerdict
from undercover.attachments.virustotal import VirusTotalClient
from undercover.phishing.email_message import Attachment


class AttachmentScanner:
    """Checks each attachment's hash against every configured source."""

    def __init__(
        self, vt_api_key: Optional[str] = None, mb_api_key: Optional[str] = None
    ):
        self.vt_client = VirusTotalClient(api_key=vt_api_key)
        self.mb_client = MalwareBazaarClient(api_key=mb_api_key)

    def scan(self, attachments: list[Attachment]) -> list[AttachmentVerdict]:
        return [self._scan_one(attachment) for attachment in attachments]

    def _scan_one(self, attachment: Attachment) -> AttachmentVerdict:
        lookups = [
            self.vt_client.lookup_hash(attachment.sha256),
            self.mb_client.lookup_hash(attachment.sha256),
        ]
        return AttachmentVerdict(
            attachment=attachment,
            checked=any(lookup.attempted for lookup in lookups),
            malicious=any(lookup.malicious for lookup in lookups),
            lookups=lookups,
        )


def summarize_attachment_risk(verdicts: list[AttachmentVerdict]) -> tuple[float, str]:
    """A 0-1 risk value plus a human-readable reason, for
    undercover.risk.scoring to fold into the unified risk score."""
    if not verdicts:
        return 0.0, "no attachments"

    checked = [v for v in verdicts if v.checked]
    if not checked:
        return 0.0, (
            f"{len(verdicts)} attachment(s) present but could not be checked "
            "(no threat-intel API keys configured)"
        )

    malicious = [v for v in checked if v.malicious]
    if malicious:
        names = ", ".join(v.attachment.filename for v in malicious)
        return 1.0, f"malicious attachment(s) detected: {names}"

    return 0.0, f"{len(checked)} attachment(s) checked, none flagged as malicious"
