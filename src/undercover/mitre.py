"""Maps this project's phishing detections to MITRE ATT&CK (Enterprise) techniques.

Only undercover.phishing.rules.RuleHit gets tagged. DLP findings
(Phase 1) describe data present in a message, not an attacker's
technique, so there's no honest ATT&CK mapping for them -- tagging
"contains a credit card number" with an adversary technique would be
manufacturing a connection that isn't there. Anomaly and header-auth
signals are similarly left untagged here: they're aggregate/contextual
signals, not a single discrete behavior with one clear technique.

References: https://attack.mitre.org/techniques/enterprise/
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AttackTechnique:
    id: str
    name: str
    url: str


TECHNIQUES: dict[str, AttackTechnique] = {
    "T1566": AttackTechnique(
        "T1566", "Phishing", "https://attack.mitre.org/techniques/T1566/"
    ),
    "T1566.002": AttackTechnique(
        "T1566.002",
        "Phishing: Spearphishing Link",
        "https://attack.mitre.org/techniques/T1566/002/",
    ),
    "T1656": AttackTechnique(
        "T1656", "Impersonation", "https://attack.mitre.org/techniques/T1656/"
    ),
}

# undercover.phishing.rules.RuleHit.name -> technique IDs. A rule with no
# entry (or an empty list) is deliberately untagged -- see module docstring
# and docs/mitre-attack-tagging.md for the reasoning behind each mapping.
RULE_HIT_TECHNIQUES: dict[str, list[str]] = {
    "urgency_language": ["T1566"],
    "link_ip_host": ["T1566.002"],
    "link_shortener": ["T1566.002"],
    "link_suspicious_tld": ["T1566.002"],
    "link_anchor_mismatch": ["T1566.002"],
    "spoofed_display_name": ["T1656"],
    "reply_to_mismatch": ["T1656"],
    "generic_greeting": [],  # too weak a signal on its own to tag confidently
}


def techniques_for_rule_hit(rule_name: str) -> list[AttackTechnique]:
    return [TECHNIQUES[tid] for tid in RULE_HIT_TECHNIQUES.get(rule_name, [])]
