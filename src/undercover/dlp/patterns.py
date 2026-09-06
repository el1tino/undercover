"""Regex-based detectors for structured PII and credential-shaped secrets.

Each entry in ``PATTERNS`` is a :class:`PatternRule` pairing a compiled
regex with an optional validator used to reject matches that merely look
right (e.g. digit strings that fail the Luhn checksum).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional


def luhn_checksum(digits: str) -> bool:
    """Return True if ``digits`` (a string of digits) passes the Luhn check."""
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _validate_credit_card(match: re.Match) -> bool:
    digits = re.sub(r"[ -]", "", match.group(0))
    return 13 <= len(digits) <= 19 and luhn_checksum(digits)


def _validate_ssn(match: re.Match) -> bool:
    area, group, serial = match.group(1), match.group(2), match.group(3)
    if area in ("000", "666") or area.startswith("9"):
        return False
    if group == "00" or serial == "0000":
        return False
    return True


def _validate_ip(match: re.Match) -> bool:
    return all(0 <= int(octet) <= 255 for octet in match.groups())


@dataclass(frozen=True)
class PatternRule:
    name: str
    label: str
    regex: "re.Pattern[str]"
    validator: Optional[Callable[[re.Match], bool]] = None
    confidence: float = 0.9


PATTERNS: list[PatternRule] = [
    PatternRule(
        name="ssn",
        label="US Social Security Number",
        regex=re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b"),
        validator=_validate_ssn,
        confidence=0.85,
    ),
    PatternRule(
        name="credit_card",
        label="Credit Card Number",
        regex=re.compile(r"\b(?:\d[ -]?){13,19}\b"),
        validator=_validate_credit_card,
        confidence=0.95,
    ),
    PatternRule(
        name="email",
        label="Email Address",
        regex=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        confidence=0.6,
    ),
    PatternRule(
        name="phone_number",
        label="Phone Number",
        regex=re.compile(
            r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"
        ),
        confidence=0.55,
    ),
    PatternRule(
        name="ipv4",
        label="IPv4 Address",
        regex=re.compile(
            r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b"
        ),
        validator=_validate_ip,
        confidence=0.4,
    ),
    PatternRule(
        name="aws_access_key",
        label="AWS Access Key ID",
        regex=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        confidence=0.97,
    ),
    PatternRule(
        name="aws_secret_key",
        label="AWS Secret Access Key",
        regex=re.compile(
            r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"
        ),
        confidence=0.3,
    ),
    PatternRule(
        name="github_token",
        label="GitHub Access Token",
        regex=re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        confidence=0.97,
    ),
    PatternRule(
        name="slack_token",
        label="Slack Token",
        regex=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        confidence=0.97,
    ),
    PatternRule(
        name="generic_api_key",
        label="Generic API Key / Secret Assignment",
        regex=re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd)"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-/+]{8,})['\"]?"
        ),
        confidence=0.5,
    ),
    PatternRule(
        name="private_key_block",
        label="Private Key Block",
        regex=re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        ),
        confidence=0.99,
    ),
    PatternRule(
        name="jwt",
        label="JSON Web Token",
        regex=re.compile(
            r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
        confidence=0.85,
    ),
]
