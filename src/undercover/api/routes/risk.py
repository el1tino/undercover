"""Endpoints for submitting, querying, and triaging unified risk assessments."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from undercover.api import models, schemas
from undercover.api.audit import record_audit_event
from undercover.api.database import get_db
from undercover.api.risk_persistence import persist_risk_assessment

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/risk", tags=["risk"])


@router.post("/assessments", response_model=schemas.RiskAssessmentOut, status_code=201)
def create_assessment(
    payload: schemas.RiskAssessmentCreate, request: Request, db: Session = Depends(get_db)
) -> models.RiskAssessment:
    return persist_risk_assessment(
        db, request, payload, source=payload.source, sender_email=payload.sender_email
    )


@router.get("/assessments", response_model=list[schemas.RiskAssessmentSummary])
def list_assessments(
    limit: int = 50,
    offset: int = 0,
    status: schemas.CaseStatus | None = None,
    risk_level: str | None = None,
    db: Session = Depends(get_db),
) -> list[models.RiskAssessment]:
    query = db.query(models.RiskAssessment)
    if status is not None:
        query = query.filter(models.RiskAssessment.status == status)
    if risk_level is not None:
        query = query.filter(models.RiskAssessment.risk_level == risk_level)
    return (
        query.order_by(models.RiskAssessment.created_at.desc())
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


@router.patch("/assessments/{assessment_id}/status", response_model=schemas.RiskAssessmentOut)
def update_assessment_status(
    assessment_id: int,
    payload: schemas.RiskAssessmentStatusUpdate,
    request: Request,
    db: Session = Depends(get_db),
) -> models.RiskAssessment:
    assessment = db.get(models.RiskAssessment, assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")

    previous_status = assessment.status
    assessment.status = payload.status
    db.commit()
    db.refresh(assessment)

    try:
        record_audit_event(
            db,
            action="risk_assessment.status_changed",
            resource_type="risk_assessment",
            resource_id=assessment.id,
            source_ip=request.client.host if request.client else None,
            detail=f"status: {previous_status!r} -> {payload.status!r}",
        )
    except Exception:
        logger.exception(
            "Audit logging failed for status change on risk assessment id=%s",
            assessment.id,
        )

    return assessment
