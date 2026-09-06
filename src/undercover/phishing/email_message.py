"""A minimal, parsed representation of an email used by the phishing checks."""

from __future__ import annotations

import email
import email.policy
import email.utils
import hashlib
import html as html_module
import re
from dataclasses import dataclass, field


def _strip_html(markup: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", markup)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = html_module.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


_LINK_RE = re.compile(r"https?://[^\s\"'<>]+")
_ANCHOR_RE = re.compile(
    r"(?is)<a\b[^>]*\bhref\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>"
)


@dataclass(frozen=True)
class Attachment:
    """A file attached to an email, reduced to what threat-intel lookups need."""

    filename: str
    content_type: str
    sha256: str
    size_bytes: int


@dataclass
class EmailMessage:
    """A parsed email, reduced to the fields the phishing rules need."""

    sender_display_name: str
    sender_email: str
    reply_to_email: str | None
    subject: str
    body: str
    body_html: str | None = None
    links: list[str] = field(default_factory=list)
    anchors: list[tuple[str, str]] = field(default_factory=list)  # (visible_text, href)
    attachments: list[Attachment] = field(default_factory=list)

    @classmethod
    def from_raw(cls, raw: str) -> "EmailMessage":
        """Parse a raw RFC 5322 message (headers + body, MIME or plain)."""
        msg = email.message_from_string(raw, policy=email.policy.default)

        display_name, sender_email = email.utils.parseaddr(msg.get("From", ""))

        reply_to_header = msg.get("Reply-To")
        reply_to_email = (
            email.utils.parseaddr(reply_to_header)[1] if reply_to_header else None
        )

        subject = str(msg.get("Subject", ""))

        plain_part = msg.get_body(preferencelist=("plain",))
        html_part = msg.get_body(preferencelist=("html",))

        body_html = html_part.get_content() if html_part is not None else None
        if plain_part is not None:
            body = plain_part.get_content()
        elif body_html is not None:
            body = _strip_html(body_html)
        else:
            body = ""

        links = sorted(set(_LINK_RE.findall(body)))
        anchors: list[tuple[str, str]] = []
        if body_html:
            links = sorted(set(links) | set(_LINK_RE.findall(body_html)))
            for href, visible in _ANCHOR_RE.findall(body_html):
                anchors.append((_strip_html(visible), href.strip()))

        attachments: list[Attachment] = []
        for part in msg.iter_attachments():
            try:
                payload = part.get_content()
            except (KeyError, LookupError):
                continue
            payload_bytes = (
                payload.encode("utf-8", errors="replace")
                if isinstance(payload, str)
                else payload
            )
            attachments.append(
                Attachment(
                    filename=part.get_filename() or "unnamed",
                    content_type=part.get_content_type(),
                    sha256=hashlib.sha256(payload_bytes).hexdigest(),
                    size_bytes=len(payload_bytes),
                )
            )

        return cls(
            sender_display_name=display_name,
            sender_email=sender_email,
            reply_to_email=reply_to_email or None,
            subject=subject,
            body=body,
            body_html=body_html,
            links=links,
            anchors=anchors,
            attachments=attachments,
        )

    @property
    def full_text(self) -> str:
        """Subject + body, the input the ML classifier trains/predicts on."""
        return f"{self.subject}\n{self.body}"
