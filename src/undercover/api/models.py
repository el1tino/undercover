"""SQLAlchemy ORM models for stored DLP scans, phishing analyses, and
unified risk assessments.

These mirror the DLP `Finding`/`ScanResult`, phishing `PhishingResult`,
and risk `RiskAssessment`/`RiskFactor` shapes from Phases 1-2 and 5
(see undercover.dlp.scanner, undercover.phishing.detector, and
undercover.risk.scoring) but persisted rather than printed.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from undercover.api.database import Base
from undercover.mitre import techniques_for_rule_hit


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class DlpScan(Base):
    __tablename__ = "dlp_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(500))
    ner_ran: Mapped[bool] = mapped_column(default=False)
    ner_skip_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )

    findings: Mapped[list["DlpFinding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )

    @property
    def finding_count(self) -> int:
        return len(self.findings)


class DlpFinding(Base):
    __tablename__ = "dlp_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("dlp_scans.id"))
    type: Mapped[str] = mapped_column(String(100))
    label: Mapped[str] = mapped_column(String(200))
    value: Mapped[str] = mapped_column(String(500))  # already redacted by the client
    start: Mapped[int] = mapped_column(Integer)
    end: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(20))  # "regex" | "ner"
    confidence: Mapped[float] = mapped_column(Float)

    scan: Mapped["DlpScan"] = relationship(back_populates="findings")


class PhishingAnalysis(Base):
    __tablename__ = "phishing_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(500))
    sender_email: Mapped[str | None] = mapped_column(
        String(320), nullable=True, index=True
    )
    verdict: Mapped[str] = mapped_column(String(20))
    combined_score: Mapped[float] = mapped_column(Float)
    rule_score: Mapped[float] = mapped_column(Float)
    ml_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    ml_skip_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )

    rule_hits: Mapped[list["PhishingRuleHit"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )

    @property
    def rule_hit_count(self) -> int:
        return len(self.rule_hits)


class PhishingRuleHit(Base):
    __tablename__ = "phishing_rule_hits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("phishing_analyses.id"))
    name: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(Text)
    weight: Mapped[float] = mapped_column(Float)

    analysis: Mapped["PhishingAnalysis"] = relationship(back_populates="rule_hits")

    @property
    def mitre_techniques(self) -> list[dict]:
        """Derived from `name` at read time -- deterministic, so there's
        nothing to store (see undercover.mitre)."""
        return [
            {"id": t.id, "name": t.name, "url": t.url}
            for t in techniques_for_rule_hit(self.name)
        ]


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(500))
    sender_email: Mapped[str | None] = mapped_column(
        String(320), nullable=True, index=True
    )
    risk_score: Mapped[float] = mapped_column(Float)
    risk_level: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )

    factors: Mapped[list["RiskFactor"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )


class RiskFactor(Base):
    __tablename__ = "risk_factors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("risk_assessments.id"))
    name: Mapped[str] = mapped_column(String(50))
    weight: Mapped[float] = mapped_column(Float)
    value: Mapped[float] = mapped_column(Float)
    detail: Mapped[str] = mapped_column(Text)

    assessment: Mapped["RiskAssessment"] = relationship(back_populates="factors")


class AuditLogEntry(Base):
    """An append-only record of a mutating API action.

    There's no authentication in this API, so this can't record *who*
    did something in any identity sense -- only *what* happened,
    *when*, and from *which* source IP. See undercover.api.audit.
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    action: Mapped[str] = mapped_column(String(50))
    resource_type: Mapped[str] = mapped_column(String(50))
    resource_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
