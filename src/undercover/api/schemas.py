"""Pydantic request/response schemas for the API.

These deliberately match the `.to_dict()` shapes already produced by
`undercover.dlp.scanner.ScanResult` and `undercover.phishing.detector.PhishingResult`,
so the CLI client can submit `{"source": ..., **result.to_dict()}` directly.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# A RiskAssessment doubles as this project's "case" for triage purposes --
# see docs/case-management-and-dashboard.md for why no separate Case table.
CASE_STATUSES: tuple[str, ...] = ("open", "investigating", "resolved", "false_positive")
CaseStatus = Literal["open", "investigating", "resolved", "false_positive"]
RISK_LEVELS: tuple[str, ...] = ("low", "medium", "high", "critical")


class DlpFindingIn(BaseModel):
    type: str
    label: str
    value: str
    start: int
    end: int
    source: str
    confidence: float


class DlpFindingOut(DlpFindingIn):
    model_config = ConfigDict(from_attributes=True)

    id: int


class DlpScanCreate(BaseModel):
    source: str = Field(..., max_length=500)
    findings: list[DlpFindingIn] = Field(default_factory=list)
    ner_ran: bool = False
    ner_skip_reason: str | None = None


class DlpScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source: str
    ner_ran: bool
    ner_skip_reason: str | None
    created_at: datetime
    findings: list[DlpFindingOut] = Field(default_factory=list)


class DlpScanSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source: str
    created_at: datetime
    finding_count: int


class PhishingRuleHitIn(BaseModel):
    name: str
    description: str
    weight: float


class AttackTechniqueOut(BaseModel):
    id: str
    name: str
    url: str


class PhishingRuleHitOut(PhishingRuleHitIn):
    model_config = ConfigDict(from_attributes=True)

    id: int
    mitre_techniques: list[AttackTechniqueOut] = Field(default_factory=list)


class PhishingAnalysisCreate(BaseModel):
    source: str = Field(..., max_length=500)
    sender_email: str | None = Field(default=None, max_length=320)
    verdict: str
    combined_score: float
    rule_score: float
    ml_score: float | None = None
    ml_skip_reason: str | None = None
    rule_hits: list[PhishingRuleHitIn] = Field(default_factory=list)


class PhishingAnalysisOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source: str
    sender_email: str | None
    verdict: str
    combined_score: float
    rule_score: float
    ml_score: float | None
    ml_skip_reason: str | None
    created_at: datetime
    rule_hits: list[PhishingRuleHitOut] = Field(default_factory=list)


class PhishingAnalysisSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source: str
    sender_email: str | None
    verdict: str
    combined_score: float
    created_at: datetime


class AnomalySenderResult(BaseModel):
    sender_email: str
    is_anomaly: bool
    anomaly_score: float
    message_count: int
    avg_combined_score: float
    max_combined_score: float
    phishing_ratio: float
    suspicious_ratio: float
    send_hour_stddev: float


class AnomalyReportOut(BaseModel):
    results: list[AnomalySenderResult] = Field(default_factory=list)
    skip_reason: str | None = None


class RiskFactorIn(BaseModel):
    name: str
    weight: float
    value: float
    detail: str


class RiskFactorOut(RiskFactorIn):
    model_config = ConfigDict(from_attributes=True)

    id: int


class RiskAssessmentCreate(BaseModel):
    source: str = Field(..., max_length=500)
    sender_email: str | None = Field(default=None, max_length=320)
    risk_score: float
    risk_level: str
    factors: list[RiskFactorIn] = Field(default_factory=list)


class RiskAssessmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source: str
    sender_email: str | None
    risk_score: float
    risk_level: str
    status: CaseStatus
    created_at: datetime
    factors: list[RiskFactorOut] = Field(default_factory=list)


class RiskAssessmentSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source: str
    sender_email: str | None
    risk_score: float
    risk_level: str
    status: CaseStatus
    created_at: datetime


class RiskAssessmentStatusUpdate(BaseModel):
    status: CaseStatus


class AuditLogEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    action: str
    resource_type: str
    resource_id: int | None
    source_ip: str | None
    detail: str | None


class EmailReportRequest(BaseModel):
    source: str = Field(..., max_length=500)
    raw_email: str
    use_ner: bool = False
    use_ml: bool = True
    check_anomaly: bool = True


class EmailReportResponse(RiskAssessmentOut):
    """POST /report/email persists both a PhishingAnalysis and a
    RiskAssessment (see undercover.api.routes.report) -- this returns the
    RiskAssessment's fields plus a pointer to the phishing analysis and
    its rule hits, so a caller (e.g. the browser extension) can show why
    the email was flagged without a second request."""

    phishing_analysis_id: int
    rule_hits: list[PhishingRuleHitOut] = Field(default_factory=list)
