"""Attachment scanning against VirusTotal and MalwareBazaar.

Computes each email attachment's SHA-256 locally (see
undercover.phishing.email_message.Attachment) and checks that hash --
never the file content itself -- against VirusTotal
(undercover.attachments.virustotal) and MalwareBazaar
(undercover.attachments.malwarebazaar). AttachmentScanner combines both
into one verdict per attachment, folded into undercover-risk's unified
score as an opt-in signal (--check-attachments, since it makes real
network calls and needs API keys). See
docs/attachment-scanning.md and docs/roadmap.md.
"""

from undercover.attachments.results import AttachmentVerdict, HashLookupResult
from undercover.attachments.scanner import AttachmentScanner, summarize_attachment_risk

__all__ = [
    "AttachmentVerdict",
    "HashLookupResult",
    "AttachmentScanner",
    "summarize_attachment_risk",
]
