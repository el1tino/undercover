"""Unified risk scoring: fuses whichever signals are available for a
message into one risk score and level.

Every input is optional. A message might only have gone through the
DLP scanner, or only the phishing detector, or all five -- the score
is a weighted average over whatever evidence is actually present,
rather than assuming every signal ran. This mirrors the graceful
degradation used throughout the project for *dependencies*
(undercover.dlp.ner, undercover.phishing.classifier,
undercover.anomaly.detector), just applied to *signals* instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from undercover.attachments.scanner import summarize_attachment_risk
from undercover.risk.headers import HeaderAuthReport

if TYPE_CHECKING:
    from undercover.attachments.results import AttachmentVerdict
    from undercover.dlp.scanner import ScanResult
    from undercover.phishing.detector import PhishingResult

# Relative weights when every signal is present. RiskAssessment normalizes
# by the weight of signals actually supplied, so a message missing a signal
# isn't penalized for it -- see the module docstring.
PHISHING_WEIGHT = 0.40
DLP_WEIGHT = 0.20
HEADER_WEIGHT = 0.15
ANOMALY_WEIGHT = 0.10
ATTACHMENT_WEIGHT = 0.15

CRITICAL_THRESHOLD = 0.8
HIGH_THRESHOLD = 0.6
MEDIUM_THRESHOLD = 0.3


@dataclass(frozen=True)
class RiskFactor:
    name: str
    weight: float
    value: float  # 0-1 contribution from this signal
    detail: str


@dataclass
class RiskAssessment:
    risk_score: float
    risk_level: str  # "low" | "medium" | "high" | "critical"
    factors: list[RiskFactor] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "risk_score": round(self.risk_score, 4),
            "risk_level": self.risk_level,
            "factors": [
                {
                    "name": f.name,
                    "weight": f.weight,
                    "value": round(f.value, 4),
                    "detail": f.detail,
                }
                for f in self.factors
            ],
        }


def _risk_level_for(score: float) -> str:
    if score >= CRITICAL_THRESHOLD:
        return "critical"
    if score >= HIGH_THRESHOLD:
        return "high"
    if score >= MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def _dlp_contribution(dlp_result: "ScanResult") -> tuple[float, str]:
    """Noisy-OR over finding confidences: probability at least one finding
    is real, treating each as an independent (imperfect) piece of evidence."""
    if not dlp_result.findings:
        return 0.0, "no sensitive-data findings"
    complement = 1.0
    for finding in dlp_result.findings:
        complement *= 1.0 - finding.confidence
    value = 1.0 - complement
    return value, f"{len(dlp_result.findings)} sensitive-data finding(s)"


def assess_risk(
    dlp_result: Optional["ScanResult"] = None,
    phishing_result: Optional["PhishingResult"] = None,
    header_report: Optional[HeaderAuthReport] = None,
    sender_is_anomalous: Optional[bool] = None,
    attachment_verdicts: Optional[list["AttachmentVerdict"]] = None,
) -> RiskAssessment:
    factors: list[RiskFactor] = []

    if phishing_result is not None:
        factors.append(
            RiskFactor(
                name="phishing",
                weight=PHISHING_WEIGHT,
                value=phishing_result.combined_score,
                detail=f"phishing verdict: {phishing_result.verdict}",
            )
        )

    if dlp_result is not None:
        value, detail = _dlp_contribution(dlp_result)
        factors.append(RiskFactor(name="dlp", weight=DLP_WEIGHT, value=value, detail=detail))

    if header_report is not None:
        value, detail = header_report.risk_contribution()
        factors.append(
            RiskFactor(name="header_auth", weight=HEADER_WEIGHT, value=value, detail=detail)
        )

    if sender_is_anomalous is not None:
        factors.append(
            RiskFactor(
                name="sender_anomaly",
                weight=ANOMALY_WEIGHT,
                value=1.0 if sender_is_anomalous else 0.0,
                detail=(
                    "sender flagged as anomalous"
                    if sender_is_anomalous
                    else "sender not flagged as anomalous"
                ),
            )
        )

    if attachment_verdicts is not None:
        value, detail = summarize_attachment_risk(attachment_verdicts)
        factors.append(
            RiskFactor(
                name="attachments", weight=ATTACHMENT_WEIGHT, value=value, detail=detail
            )
        )

    if not factors:
        return RiskAssessment(risk_score=0.0, risk_level="low", factors=[])

    total_weight = sum(f.weight for f in factors)
    risk_score = sum(f.weight * f.value for f in factors) / total_weight
    return RiskAssessment(
        risk_score=risk_score, risk_level=_risk_level_for(risk_score), factors=factors
    )
