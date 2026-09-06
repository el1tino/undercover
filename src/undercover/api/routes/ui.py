"""Server-rendered HTML views: a case (triage) list/detail and a trend
dashboard.

A "case" here is just a RiskAssessment viewed for triage -- see
docs/case-management-and-dashboard.md for why there's no separate
Case table. These are plain server-rendered pages (Jinja2, no
external CDN, no client-side JS) so status changes work as ordinary
HTML forms.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session

from undercover.anomaly.detector import AnomalyDetector
from undercover.anomaly.features import extract_sender_features
from undercover.api import models, schemas
from undercover.api.audit import record_audit_event
from undercover.api.database import get_db
from undercover.mitre import techniques_for_rule_hit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui", tags=["ui"])

templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("/cases", response_class=HTMLResponse)
def cases_list(
    request: Request,
    status: schemas.CaseStatus | None = None,
    risk_level: str | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(models.RiskAssessment)
    if status is not None:
        query = query.filter(models.RiskAssessment.status == status)
    if risk_level is not None:
        query = query.filter(models.RiskAssessment.risk_level == risk_level)
    cases = query.order_by(models.RiskAssessment.created_at.desc()).limit(100).all()

    return templates.TemplateResponse(
        request,
        "cases_list.html",
        {
            "active": "cases",
            "cases": cases,
            "statuses": schemas.CASE_STATUSES,
            "risk_levels": schemas.RISK_LEVELS,
            "status_filter": status,
            "level_filter": risk_level,
        },
    )


@router.get("/cases/{case_id}", response_class=HTMLResponse)
def case_detail(case_id: int, request: Request, db: Session = Depends(get_db)):
    case = db.get(models.RiskAssessment, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")

    return templates.TemplateResponse(
        request,
        "case_detail.html",
        {"active": "cases", "case": case, "statuses": schemas.CASE_STATUSES},
    )


@router.post("/cases/{case_id}/status")
def update_case_status_form(
    case_id: int,
    request: Request,
    status: str = Form(...),
    db: Session = Depends(get_db),
):
    case = db.get(models.RiskAssessment, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    if status not in schemas.CASE_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status: {status!r}")

    previous_status = case.status
    case.status = status
    db.commit()

    try:
        record_audit_event(
            db,
            action="risk_assessment.status_changed",
            resource_type="risk_assessment",
            resource_id=case.id,
            source_ip=request.client.host if request.client else None,
            detail=f"status: {previous_status!r} -> {status!r} (via UI)",
        )
    except Exception:
        logger.exception(
            "Audit logging failed for status change on risk assessment id=%s", case.id
        )

    return RedirectResponse(url=f"/ui/cases/{case_id}", status_code=303)


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    total_dlp_scans = db.query(models.DlpScan).count()
    total_phishing = db.query(models.PhishingAnalysis).count()
    total_risk_assessments = db.query(models.RiskAssessment).count()

    verdict_counts = dict(
        db.query(models.PhishingAnalysis.verdict, func.count())
        .group_by(models.PhishingAnalysis.verdict)
        .all()
    )
    risk_level_counts = dict(
        db.query(models.RiskAssessment.risk_level, func.count())
        .group_by(models.RiskAssessment.risk_level)
        .all()
    )
    status_counts = dict(
        db.query(models.RiskAssessment.status, func.count())
        .group_by(models.RiskAssessment.status)
        .all()
    )

    rule_hit_counts = (
        db.query(models.PhishingRuleHit.name, func.count())
        .group_by(models.PhishingRuleHit.name)
        .all()
    )
    technique_counts: dict[str, dict] = {}
    for name, count in rule_hit_counts:
        for technique in techniques_for_rule_hit(name):
            entry = technique_counts.setdefault(
                technique.id, {"name": technique.name, "url": technique.url, "count": 0}
            )
            entry["count"] += count
    top_techniques = sorted(
        technique_counts.items(), key=lambda item: item[1]["count"], reverse=True
    )

    sender_rows = (
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
        for r in sender_rows
    ]
    anomaly_report = AnomalyDetector().detect(extract_sender_features(records))
    top_anomalous_senders = [r for r in anomaly_report.results if r.is_anomaly][:5]

    recent_cases = (
        db.query(models.RiskAssessment)
        .order_by(models.RiskAssessment.created_at.desc())
        .limit(10)
        .all()
    )

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "active": "dashboard",
            "total_dlp_scans": total_dlp_scans,
            "total_phishing": total_phishing,
            "total_risk_assessments": total_risk_assessments,
            "verdict_counts": verdict_counts,
            "risk_level_counts": risk_level_counts,
            "risk_levels": schemas.RISK_LEVELS,
            "status_counts": status_counts,
            "statuses": schemas.CASE_STATUSES,
            "top_techniques": top_techniques,
            "top_anomalous_senders": top_anomalous_senders,
            "anomaly_skip_reason": anomaly_report.skip_reason,
            "recent_cases": recent_cases,
        },
    )
