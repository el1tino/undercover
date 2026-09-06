"""Endpoints for submitting and querying DLP scan results."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from undercover.api import models, schemas
from undercover.api.database import get_db

router = APIRouter(prefix="/dlp", tags=["dlp"])


@router.post("/scans", response_model=schemas.DlpScanOut, status_code=201)
def create_scan(
    payload: schemas.DlpScanCreate, db: Session = Depends(get_db)
) -> models.DlpScan:
    scan = models.DlpScan(
        source=payload.source,
        ner_ran=payload.ner_ran,
        ner_skip_reason=payload.ner_skip_reason,
    )
    scan.findings = [
        models.DlpFinding(**finding.model_dump()) for finding in payload.findings
    ]
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@router.get("/scans", response_model=list[schemas.DlpScanSummary])
def list_scans(
    limit: int = 50, offset: int = 0, db: Session = Depends(get_db)
) -> list[models.DlpScan]:
    return (
        db.query(models.DlpScan)
        .order_by(models.DlpScan.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/scans/{scan_id}", response_model=schemas.DlpScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)) -> models.DlpScan:
    scan = db.get(models.DlpScan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
