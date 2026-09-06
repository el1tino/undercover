"""Append-only audit log of mutating API actions.

There's no authentication in this API (see
docs/phase3-api-and-database.md's Known Limitations), so this can't
record *who* did something in any meaningful identity sense -- only
*what* happened, *when*, and from *which* source IP. That's still
useful for after-the-fact investigation (a burst of submissions from
one IP, exactly when a given resource was created) even without a
login system, and it's the honest scope for what this API can audit
today.

Callers are expected to wrap calls to record_audit_event in their own
try/except (see undercover.api.routes.dlp/phishing/risk) -- a failure
here must never break the request that triggered it, the same
principle already applied to alerting.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from undercover.api import models


def record_audit_event(
    db: Session,
    action: str,
    resource_type: str,
    resource_id: Optional[int] = None,
    source_ip: Optional[str] = None,
    detail: Optional[str] = None,
) -> models.AuditLogEntry:
    entry = models.AuditLogEntry(
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        source_ip=source_ip,
        detail=detail,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
