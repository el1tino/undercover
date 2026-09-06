"""Shared logic for persisting a risk assessment and firing its side
effects (alerting, audit logging).

Used by both POST /risk/assessments (the client already computed the
assessment) and POST /report/email (the server computes it from raw
email text). Both inputs are duck-typed against
undercover.alerting.AssessmentLike, so this module needs to know
nothing about where the assessment came from.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import Request
from sqlalchemy.orm import Session

from undercover.alerting import AlertManager, AssessmentLike, build_alert
from undercover.api import models
from undercover.api.audit import record_audit_event

logger = logging.getLogger(__name__)


def persist_risk_assessment(
    db: Session,
    request: Request,
    assessment_data: AssessmentLike,
    source: str,
    sender_email: Optional[str],
    audit_action: str = "risk_assessment.created",
) -> models.RiskAssessment:
    assessment = models.RiskAssessment(
        source=source,
        sender_email=sender_email,
        risk_score=assessment_data.risk_score,
        risk_level=assessment_data.risk_level,
    )
    assessment.factors = [
        models.RiskFactor(name=f.name, weight=f.weight, value=f.value, detail=f.detail)
        for f in assessment_data.factors
    ]
    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    # A broken alert channel or a broken audit write must never take down
    # the submission itself -- the assessment is already committed by
    # this point. See docs/alerting.md and docs/audit-logging.md.
    try:
        alert = build_alert(assessment_data, source=source, sender_email=sender_email)
        AlertManager().maybe_alert(alert)
    except Exception:
        logger.exception("Alerting failed for risk assessment id=%s", assessment.id)

    try:
        record_audit_event(
            db,
            action=audit_action,
            resource_type="risk_assessment",
            resource_id=assessment.id,
            source_ip=request.client.host if request.client else None,
            detail=f"source={source!r}, risk_level={assessment.risk_level!r}",
        )
    except Exception:
        logger.exception("Audit logging failed for risk assessment id=%s", assessment.id)

    return assessment
