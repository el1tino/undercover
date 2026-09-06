"""Pydantic request/response schemas for the API.

These deliberately match the `.to_dict()` shapes already produced by
`undercover.dlp.scanner.ScanResult` and `undercover.phishing.detector.PhishingResult`,
so the CLI client can submit `{"source": ..., **result.to_dict()}` directly.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


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


class PhishingRuleHitOut(PhishingRuleHitIn):
    model_config = ConfigDict(from_attributes=True)

    id: int


class PhishingAnalysisCreate(BaseModel):
    source: str = Field(..., max_length=500)
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
    verdict: str
    combined_score: float
    created_at: datetime
