"""POST /report/email: run the full local analysis pipeline server-side.

This is what makes the browser extension (and any other HTTP client --
a future web app, a Slack bot) able to get an undercover-risk-equivalent
verdict without the CLI or Python installed locally. It's the same
DLPScanner + PhishingDetector + header analysis + sender-anomaly logic
`undercover-risk` runs, just invoked from the server on a raw email
string instead of from a local process reading a file.

Persists both a PhishingAnalysis and a RiskAssessment (the same two
resources `undercover-phish --submit` and `undercover-risk --submit`
would create separately) so a reported email also becomes part of the
sender history Phase 4's anomaly detection and the dashboard's
technique-frequency table draw on -- a report shouldn't be a dead end
that never feeds back into the rest of the system.

The sender-anomaly check queries the database directly (via
undercover.anomaly) rather than calling GET /anomaly/senders over
HTTP, since this route already has a session open on the very database
that endpoint would query -- an HTTP round-trip to itself would be
pointless.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from undercover.anomaly.detector import AnomalyDetector
from undercover.anomaly.features import extract_sender_features
from undercover.api import models, schemas
from undercover.api.database import get_db
from undercover.api.phishing_persistence import persist_phishing_analysis
from undercover.api.risk_persistence import persist_risk_assessment
from undercover.dlp.scanner import DLPScanner
from undercover.phishing.detector import PhishingDetector
from undercover.phishing.email_message import EmailMessage
from undercover.risk.headers import analyze_headers
from undercover.risk.scoring import assess_risk

router = APIRouter(prefix="/report", tags=["report"])


def _sender_is_anomalous(db: Session, sender_email: str | None) -> bool | None:
    if not sender_email:
        return None
    rows = (
        db.query(models.PhishingAnalysis)
        .filter(models.PhishingAnalysis.sender_email.isnot(None))
        .all()
    )
    records = [
        {
            "sender_email": r.sender_email,
            "verdict": r.verdict,
            "combined_score": r.combined_score,
            "created_at": r.created_at,
        }
        for r in rows
    ]
    features = extract_sender_features(records)
    report = AnomalyDetector().detect(features)
    row = next((f for f in report.results if f.sender_email == sender_email), None)
    return row.is_anomaly if row else None


@router.post("/email", response_model=schemas.EmailReportResponse, status_code=201)
def report_email(
    payload: schemas.EmailReportRequest, request: Request, db: Session = Depends(get_db)
) -> schemas.EmailReportResponse:
    msg = EmailMessage.from_raw(payload.raw_email)
    sender_email = msg.sender_email or None

    dlp_result = DLPScanner(use_ner=payload.use_ner).scan(msg.body)
    phishing_result = PhishingDetector(use_ml=payload.use_ml).analyze(msg)
    header_report = analyze_headers(payload.raw_email)

    # Check anomaly status *before* persisting this submission's own
    # phishing analysis, so a first-time malicious sender isn't compared
    # against a history that already includes this very message.
    sender_is_anomalous = (
        _sender_is_anomalous(db, sender_email) if payload.check_anomaly else None
    )

    assessment_data = assess_risk(
        dlp_result=dlp_result,
        phishing_result=phishing_result,
        header_report=header_report,
        sender_is_anomalous=sender_is_anomalous,
    )

    analysis = persist_phishing_analysis(
        db,
        request,
        phishing_result,
        source=payload.source,
        sender_email=sender_email,
        audit_action="phishing_analysis.created_via_report",
    )
    assessment = persist_risk_assessment(
        db,
        request,
        assessment_data,
        source=payload.source,
        sender_email=sender_email,
        audit_action="risk_assessment.created_via_report",
    )

    base = schemas.RiskAssessmentOut.model_validate(assessment)
    rule_hits = [schemas.PhishingRuleHitOut.model_validate(hit) for hit in analysis.rule_hits]
    return schemas.EmailReportResponse(
        **base.model_dump(), phishing_analysis_id=analysis.id, rule_hits=rule_hits
    )
