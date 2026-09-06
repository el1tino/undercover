"""Endpoints for submitting and querying unified risk assessments (Phase 5)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from undercover.api import models, schemas
from undercover.api.database import get_db

router = APIRouter(prefix="/risk", tags=["risk"])


@router.post("/assessments", response_model=schemas.RiskAssessmentOut, status_code=201)
def create_assessment(
    payload: schemas.RiskAssessmentCreate, db: Session = Depends(get_db)
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
