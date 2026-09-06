"""Endpoints for submitting and querying phishing analysis results."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from undercover.api import models, schemas
from undercover.api.database import get_db

router = APIRouter(prefix="/phishing", tags=["phishing"])


@router.post("/analyses", response_model=schemas.PhishingAnalysisOut, status_code=201)
def create_analysis(
    payload: schemas.PhishingAnalysisCreate, db: Session = Depends(get_db)
) -> models.PhishingAnalysis:
    analysis = models.PhishingAnalysis(
        source=payload.source,
        sender_email=payload.sender_email,
        verdict=payload.verdict,
        combined_score=payload.combined_score,
        rule_score=payload.rule_score,
        ml_score=payload.ml_score,
        ml_skip_reason=payload.ml_skip_reason,
    )
    analysis.rule_hits = [
        models.PhishingRuleHit(**hit.model_dump()) for hit in payload.rule_hits
    ]
    db.add(analysis)
    db.commit()
    db.refresh(analysis)
    return analysis


@router.get("/analyses", response_model=list[schemas.PhishingAnalysisSummary])
def list_analyses(
    limit: int = 50, offset: int = 0, db: Session = Depends(get_db)
) -> list[models.PhishingAnalysis]:
    return (
        db.query(models.PhishingAnalysis)
        .order_by(models.PhishingAnalysis.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/analyses/{analysis_id}", response_model=schemas.PhishingAnalysisOut)
def get_analysis(
    analysis_id: int, db: Session = Depends(get_db)
) -> models.PhishingAnalysis:
    analysis = db.get(models.PhishingAnalysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis
