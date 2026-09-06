"""Shared logic for persisting a phishing analysis and its audit entry.

Used by both POST /phishing/analyses (the client already computed the
result) and POST /report/email (the server computes it from raw email
text). Both inputs are duck-typed against the Protocols below, the
same approach undercover.api.risk_persistence uses for risk
assessments -- this module needs to know nothing about where the
result came from.
"""

from __future__ import annotations

import logging
from typing import Optional, Protocol, Sequence

from fastapi import Request
from sqlalchemy.orm import Session

from undercover.api import models
from undercover.api.audit import record_audit_event

logger = logging.getLogger(__name__)


class RuleHitLike(Protocol):
    name: str
    description: str
    weight: float


class PhishingResultLike(Protocol):
    """Structural type satisfied by both
    undercover.phishing.detector.PhishingResult (dataclass) and
    undercover.api.schemas.PhishingAnalysisCreate (Pydantic model)."""

    verdict: str
    combined_score: float
    rule_score: float
    ml_score: Optional[float]
    ml_skip_reason: Optional[str]
    rule_hits: Sequence[RuleHitLike]


def persist_phishing_analysis(
    db: Session,
    request: Request,
    result: PhishingResultLike,
    source: str,
    sender_email: Optional[str],
    audit_action: str = "phishing_analysis.created",
) -> models.PhishingAnalysis:
    analysis = models.PhishingAnalysis(
        source=source,
        sender_email=sender_email,
        verdict=result.verdict,
        combined_score=result.combined_score,
        rule_score=result.rule_score,
        ml_score=result.ml_score,
        ml_skip_reason=result.ml_skip_reason,
    )
    analysis.rule_hits = [
        models.PhishingRuleHit(name=h.name, description=h.description, weight=h.weight)
        for h in result.rule_hits
    ]
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    try:
        record_audit_event(
            db,
            action=audit_action,
            resource_type="phishing_analysis",
            resource_id=analysis.id,
            source_ip=request.client.host if request.client else None,
            detail=f"source={source!r}, verdict={analysis.verdict!r}",
        )
    except Exception:
        logger.exception("Audit logging failed for phishing analysis id=%s", analysis.id)

    return analysis
