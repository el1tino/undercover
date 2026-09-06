"""Endpoint for Phase 4's per-sender anomaly report.

Unlike the /dlp and /phishing routes, this doesn't accept submissions --
it's computed on demand from the phishing analyses Phase 3 has already
stored, which is why it depends on Phase 3 existing first (see
docs/architecture.md).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from undercover.anomaly.detector import AnomalyDetector
from undercover.anomaly.features import extract_sender_features
from undercover.api import models, schemas
from undercover.api.database import get_db

router = APIRouter(prefix="/anomaly", tags=["anomaly"])


@router.get("/senders", response_model=schemas.AnomalyReportOut)
def get_sender_anomalies(
    contamination: float = 0.2, db: Session = Depends(get_db)
) -> schemas.AnomalyReportOut:
    rows = (
        db.query(models.PhishingAnalysis)
        .filter(models.PhishingAnalysis.sender_email.isnot(None))
        .all()
    )
    records = [
        {
            "sender_email": row.sender_email,
            "verdict": row.verdict,
            "combined_score": row.combined_score,
            "created_at": row.created_at,
        }
        for row in rows
    ]
    features = extract_sender_features(records)
    report = AnomalyDetector(contamination=contamination).detect(features)

    return schemas.AnomalyReportOut(
        skip_reason=report.skip_reason,
        results=[
            schemas.AnomalySenderResult(
                sender_email=result.sender_email,
                is_anomaly=result.is_anomaly,
                anomaly_score=round(result.anomaly_score, 4),
                message_count=result.features.message_count,
                avg_combined_score=round(result.features.avg_combined_score, 4),
                max_combined_score=round(result.features.max_combined_score, 4),
                phishing_ratio=round(result.features.phishing_ratio, 4),
                suspicious_ratio=round(result.features.suspicious_ratio, 4),
                send_hour_stddev=round(result.features.send_hour_stddev, 4),
            )
            for result in report.results
        ],
    )
