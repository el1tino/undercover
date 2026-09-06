"""SIEM-friendly export of a RiskAssessment: JSON and CEF (Common Event Format).

CEF is the format most SIEMs (ArcSight, Splunk, QRadar, etc.) ingest
out of the box: `CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension`.
See https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf
for the full spec; this implements the header fields plus a practical
subset of extension keys rather than the entire dictionary.
"""

from __future__ import annotations

import json

from undercover.risk.scoring import RiskAssessment

CEF_VENDOR = "undercover"
CEF_PRODUCT = "SecurityScanner"
CEF_VERSION = "0.1.0"
CEF_SIGNATURE_ID = "risk-assessment"
CEF_NAME = "Email risk assessment"


def _cef_escape_header(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _cef_escape_extension(value: str) -> str:
    return value.replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ")


def to_json(assessment: RiskAssessment, source: str, sender_email: str | None = None) -> str:
    payload = {"source": source, "sender_email": sender_email, **assessment.to_dict()}
    return json.dumps(payload, indent=2)


def to_cef(assessment: RiskAssessment, source: str, sender_email: str | None = None) -> str:
    severity = max(0, min(10, round(assessment.risk_score * 10)))
    factor_summary = "; ".join(f.detail for f in assessment.factors)

    extensions = {
        "fname": source,
        "suser": sender_email or "unknown",
        "cs1Label": "RiskLevel",
        "cs1": assessment.risk_level,
        "cn1Label": "FactorCount",
        "cn1": str(len(assessment.factors)),
        "msg": factor_summary or "no signals available",
    }
    extension_str = " ".join(
        f"{key}={_cef_escape_extension(str(value))}" for key, value in extensions.items()
    )

    header_fields = [
        "CEF:0",
        _cef_escape_header(CEF_VENDOR),
        _cef_escape_header(CEF_PRODUCT),
        _cef_escape_header(CEF_VERSION),
        _cef_escape_header(CEF_SIGNATURE_ID),
        _cef_escape_header(CEF_NAME),
        str(severity),
    ]
    return "|".join(header_fields) + "|" + extension_str
