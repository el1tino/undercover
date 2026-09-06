"""Risk scoring, header analysis, and SIEM export (Phase 5).

Ties the earlier phases together: undercover.risk.headers parses
SPF/DKIM/DMARC results from a message's Authentication-Results header,
undercover.risk.scoring fuses that with DLP findings, the phishing
verdict, and sender-anomaly status into one RiskAssessment, and
undercover.risk.export renders it as CEF or JSON for a SIEM. Exposed
via the `undercover-risk` CLI and the API's /risk/assessments routes.
See docs/phase5-risk-scoring.md and docs/roadmap.md.
"""

from undercover.risk.headers import AuthResult, HeaderAuthReport, analyze_headers
from undercover.risk.scoring import RiskAssessment, RiskFactor, assess_risk

__all__ = [
    "AuthResult",
    "HeaderAuthReport",
    "analyze_headers",
    "RiskAssessment",
    "RiskFactor",
    "assess_risk",
]
