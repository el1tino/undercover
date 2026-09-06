"""Read-only view of the audit log.

Entries are written by the other routes (dlp, phishing, risk) as a
side effect of each submission -- there's no POST here, since nothing
should be able to submit an audit entry directly.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from undercover.api import models, schemas
from undercover.api.database import get_db

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/log", response_model=list[schemas.AuditLogEntryOut])
def list_audit_log(
    limit: int = 50,
    offset: int = 0,
    action: str | None = None,
    resource_type: str | None = None,
    db: Session = Depends(get_db),
) -> list[models.AuditLogEntry]:
    query = db.query(models.AuditLogEntry)
    if action is not None:
        query = query.filter(models.AuditLogEntry.action == action)
    if resource_type is not None:
        query = query.filter(models.AuditLogEntry.resource_type == resource_type)
    return (
        query.order_by(models.AuditLogEntry.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
