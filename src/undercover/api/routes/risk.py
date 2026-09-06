"""Endpoints for submitting and querying unified risk assessments (Phase 5)."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from undercover.alerting import AlertManager, build_alert
from undercover.api import models, schemas
from undercover.api.audit import record_audit_event
from undercover.api.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/risk", tags=["risk"])


@router.post("/assessments", response_model=schemas.RiskAssessmentOut, status_code=201)
def create_assessment(
    payload: schemas.RiskAssessmentCreate, request: Request, db: Session = Depends(get_db)
) -> models.RiskAssessment:
    assessment = models.RiskAssessment(
        source=payload.source,
        sender_email=payload.sender_email,
        risk_score=payload.risk_score,
        risk_level=payload.risk_level,
    )
    assessment.factors = [
        models.RiskFactor(**factor.model_dump()) for factor in payload.factors
    ]
    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    # Centralized alerting: fires regardless of which client submitted this
    # (CLI, a future dashboard, anything else hitting the API), unlike
    # undercover-risk's own --alert-threshold which only covers its own run.
    # A broken alert channel must never take down the submission itself --
    # the assessment is already committed by this point.
    try:
        alert = build_alert(
            payload, source=payload.source, sender_email=payload.sender_email
        )
        AlertManager().maybe_alert(alert)
    except Exception:
        logger.exception("Alerting failed for risk assessment id=%s", assessment.id)

    try:
        record_audit_event(
            db,
            action="risk_assessment.created",
            resource_type="risk_assessment",
            resource_id=assessment.id,
            source_ip=request.client.host if request.client else None,
            detail=f"source={assessment.source!r}, risk_level={assessment.risk_level!r}",
        )
    except Exception:
        logger.exception("Audit logging failed for risk assessment id=%s", assessment.id)

    return assessment


@router.get("/assessments", response_model=list[schemas.RiskAssessmentSummary])
def list_assessments(
    limit: int = 50, offset: int = 0, db: Session = Depends(get_db)
) -> list[models.RiskAssessment]:
    return (
        db.query(models.RiskAssessment)
        .order_by(models.RiskAssessment.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/assessments/{assessment_id}", response_model=schemas.RiskAssessmentOut)
def get_assessment(
    assessment_id: int, db: Session = Depends(get_db)
) -> models.RiskAssessment:
    assessment = db.get(models.RiskAssessment, assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment
