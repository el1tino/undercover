"""The Alert data shape and how one is built from a risk assessment."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol, Sequence


class _FactorLike(Protocol):
    value: float
    detail: str


class _AssessmentLike(Protocol):
    """Structural type for whatever `build_alert` is handed -- both
    undercover.risk.scoring.RiskAssessment (dataclass) and
    undercover.api.schemas.RiskAssessmentCreate (Pydantic model, used
    when the API route builds an alert straight from a submission)
    satisfy this without either needing to import the other."""

    risk_level: str
    risk_score: float
    factors: Sequence[_FactorLike]


@dataclass(frozen=True)
class Alert:
    title: str
    message: str
    risk_level: str
    risk_score: float
    source: str
    sender_email: Optional[str] = None


def build_alert(
    assessment: _AssessmentLike, source: str, sender_email: Optional[str] = None
) -> Alert:
    """Summarize a risk assessment's top contributing factors into an Alert."""
    top_factors = sorted(assessment.factors, key=lambda f: f.value, reverse=True)[:3]
    message = "; ".join(f.detail for f in top_factors) or "no contributing factors"
    return Alert(
        title=f"{assessment.risk_level.upper()} risk email detected",
        message=message,
        risk_level=assessment.risk_level,
        risk_score=assessment.risk_score,
        source=source,
        sender_email=sender_email,
    )
