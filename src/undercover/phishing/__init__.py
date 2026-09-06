"""Phishing detection (Phase 2).

Combines a rule-based pass (suspicious links, urgency language, spoofed
display names, mismatched sender domains) with an optional scikit-learn
classifier trained on a labeled phishing/ham dataset. See
docs/phase2-phishing-detection.md for design details and
docs/roadmap.md for the full plan.
"""

from undercover.phishing.detector import PhishingDetector, PhishingResult
from undercover.phishing.email_message import EmailMessage
from undercover.phishing.rules import RuleEngine, RuleHit

__all__ = [
    "PhishingDetector",
    "PhishingResult",
    "EmailMessage",
    "RuleEngine",
    "RuleHit",
]
