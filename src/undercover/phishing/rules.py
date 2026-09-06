"""Rule-based phishing heuristics: links, urgency language, spoofing, mismatches.

Each rule takes an :class:`~undercover.phishing.email_message.EmailMessage`
and returns zero or more :class:`RuleHit` objects. ``RuleEngine.evaluate``
runs every rule and sums the hit weights into a 0-1 score -- this is the
signal Phase 5 will eventually blend with the ML score, anomaly score,
and header-auth results into a single risk number.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from undercover.mitre import AttackTechnique, techniques_for_rule_hit
from undercover.phishing.email_message import EmailMessage

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

URGENCY_PHRASES = [
    "act now",
    "act immediately",
    "urgent action required",
    "verify your account",
    "your account will be closed",
    "your account has been suspended",
    "confirm your identity",
    "confirm your password",
    "unusual activity",
    "click here immediately",
    "limited time",
    "you must respond",
    "failure to respond",
    "final notice",
    "avoid suspension",
    "immediate attention",
]

GENERIC_GREETINGS = [
    "dear customer",
    "dear valued customer",
    "dear user",
    "dear account holder",
    "dear sir/madam",
]

SUSPICIOUS_TLDS = {
    "zip", "xyz", "top", "click", "support", "gq", "tk", "country", "kim", "work",
    "loan", "men", "date", "review",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "goo.gl", "rb.gy",
}

# Brand -> the legitimate root domains it sends mail from. Not exhaustive --
# a demonstration list for the spoofed-display-name and anchor-mismatch checks.
BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com"},
    "microsoft": {"microsoft.com", "office.com", "live.com", "outlook.com"},
    "apple": {"apple.com", "icloud.com"},
    "netflix": {"netflix.com"},
    "google": {"google.com", "gmail.com"},
    "bank of america": {"bankofamerica.com"},
    "wells fargo": {"wellsfargo.com"},
    "irs": {"irs.gov"},
    "chase": {"chase.com"},
    "linkedin": {"linkedin.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
}


@dataclass(frozen=True)
class RuleHit:
    name: str
    description: str
    weight: float

    @property
    def mitre_techniques(self) -> list[AttackTechnique]:
        """MITRE ATT&CK techniques this hit maps to, if any -- see
        undercover.mitre for the mapping and why some rules are untagged."""
        return techniques_for_rule_hit(self.name)


@dataclass(frozen=True)
class RuleEvaluation:
    hits: list[RuleHit]
    score: float


def _domain_of_email(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


def _domain_of_url(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"//{url}")
    return (parsed.hostname or "").lower()


def _matches_brand_domain(domain: str, allowed: set[str]) -> bool:
    return any(domain == d or domain.endswith(f".{d}") for d in allowed)


def check_urgency_language(msg: EmailMessage) -> list[RuleHit]:
    text = f"{msg.subject}\n{msg.body}".lower()
    hits = []
    for phrase in URGENCY_PHRASES:
        if phrase in text:
            hits.append(
                RuleHit(
                    name="urgency_language",
                    description=f"Urgency phrase found: '{phrase}'",
                    weight=0.15,
                )
            )
    return hits


def check_generic_greeting(msg: EmailMessage) -> list[RuleHit]:
    body_lower = msg.body.lower()
    for phrase in GENERIC_GREETINGS:
        if phrase in body_lower:
            return [
                RuleHit(
                    name="generic_greeting",
                    description=f"Generic greeting found: '{phrase}'",
                    weight=0.1,
                )
            ]
    return []


def check_suspicious_links(msg: EmailMessage) -> list[RuleHit]:
    hits = []
    seen_domains: set[str] = set()
    for link in msg.links:
        domain = _domain_of_url(link)
        if not domain or domain in seen_domains:
            continue
        seen_domains.add(domain)

        if _IPV4_RE.match(domain):
            hits.append(
                RuleHit(
                    name="link_ip_host",
                    description=f"Link points directly to an IP address: {domain}",
                    weight=0.3,
                )
            )
        if domain in URL_SHORTENERS:
            hits.append(
                RuleHit(
                    name="link_shortener",
                    description=f"Link uses a URL shortener: {domain}",
                    weight=0.15,
                )
            )
        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        if tld in SUSPICIOUS_TLDS:
            hits.append(
                RuleHit(
                    name="link_suspicious_tld",
                    description=f"Link uses a high-abuse TLD: .{tld}",
                    weight=0.2,
                )
            )

    for visible_text, href in msg.anchors:
        href_domain = _domain_of_url(href)
        visible_domain = _domain_of_url(visible_text)
        if visible_domain and href_domain and visible_domain != href_domain:
            hits.append(
                RuleHit(
                    name="link_anchor_mismatch",
                    description=(
                        f"Link text shows '{visible_domain}' but points to "
                        f"'{href_domain}'"
                    ),
                    weight=0.35,
                )
            )
    return hits


def check_spoofed_display_name(msg: EmailMessage) -> list[RuleHit]:
    display_name = msg.sender_display_name.lower()
    sender_domain = _domain_of_email(msg.sender_email)
    hits = []
    for brand, allowed_domains in BRAND_DOMAINS.items():
        if brand in display_name and not _matches_brand_domain(
            sender_domain, allowed_domains
        ):
            hits.append(
                RuleHit(
                    name="spoofed_display_name",
                    description=(
                        f"Display name references '{brand}' but sender domain "
                        f"'{sender_domain or '(none)'}' does not belong to it"
                    ),
                    weight=0.4,
                )
            )
    return hits


def check_sender_reply_to_mismatch(msg: EmailMessage) -> list[RuleHit]:
    if not msg.reply_to_email:
        return []
    sender_domain = _domain_of_email(msg.sender_email)
    reply_to_domain = _domain_of_email(msg.reply_to_email)
    if sender_domain and reply_to_domain and sender_domain != reply_to_domain:
        return [
            RuleHit(
                name="reply_to_mismatch",
                description=(
                    f"From domain '{sender_domain}' differs from Reply-To "
                    f"domain '{reply_to_domain}'"
                ),
                weight=0.25,
            )
        ]
    return []


RULES = [
    check_urgency_language,
    check_generic_greeting,
    check_suspicious_links,
    check_spoofed_display_name,
    check_sender_reply_to_mismatch,
]


class RuleEngine:
    """Runs every registered rule against a message and aggregates hits."""

    def evaluate(self, msg: EmailMessage) -> RuleEvaluation:
        hits: list[RuleHit] = []
        for rule in RULES:
            hits.extend(rule(msg))
        score = min(1.0, sum(hit.weight for hit in hits))
        return RuleEvaluation(hits=hits, score=score)
