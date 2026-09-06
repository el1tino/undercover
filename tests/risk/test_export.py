"""Unit tests for undercover.risk.export (JSON and CEF rendering)."""

import json

from undercover.risk.export import to_cef, to_json
from undercover.risk.scoring import RiskAssessment, RiskFactor


def make_assessment() -> RiskAssessment:
    return RiskAssessment(
        risk_score=0.87,
        risk_level="critical",
        factors=[
            RiskFactor(name="phishing", weight=0.45, value=1.0, detail="phishing verdict: phishing"),
            RiskFactor(name="header_auth", weight=0.20, value=1.0, detail="DMARC authentication failed"),
        ],
    )


class TestToJson:
    def test_produces_valid_json_with_expected_fields(self):
        raw = to_json(make_assessment(), "phishing.eml", "attacker@evil.example")
        payload = json.loads(raw)
        assert payload["source"] == "phishing.eml"
        assert payload["sender_email"] == "attacker@evil.example"
        assert payload["risk_level"] == "critical"
        assert len(payload["factors"]) == 2

    def test_sender_email_optional(self):
        raw = to_json(make_assessment(), "phishing.eml")
        payload = json.loads(raw)
        assert payload["sender_email"] is None


class TestToCef:
    def test_starts_with_cef_header(self):
        cef = to_cef(make_assessment(), "phishing.eml", "attacker@evil.example")
        assert cef.startswith("CEF:0|undercover|SecurityScanner|")

    def test_severity_reflects_risk_score(self):
        cef = to_cef(make_assessment(), "phishing.eml")
        # risk_score 0.87 -> severity round(8.7) == 9
        fields = cef.split("|")
        assert fields[6] == "9"

    def test_extension_contains_risk_level_and_sender(self):
        cef = to_cef(make_assessment(), "phishing.eml", "attacker@evil.example")
        assert "cs1Label=RiskLevel" in cef
        assert "cs1=critical" in cef
        assert "suser=attacker@evil.example" in cef

    def test_unknown_sender_when_none(self):
        cef = to_cef(make_assessment(), "phishing.eml", None)
        assert "suser=unknown" in cef

    def test_escapes_equals_in_extension_values(self):
        # Per the CEF spec, extension values are space-delimited key=value
        # pairs, so only "=" and "\" need escaping there -- "|" is only
        # special in the pipe-delimited header fields (vendor/product/...).
        assessment = RiskAssessment(
            risk_score=0.5,
            risk_level="medium",
            factors=[RiskFactor(name="x", weight=0.5, value=0.5, detail="a=b|c")],
        )
        cef = to_cef(assessment, "source with = sign.eml")
        assert "a\\=b|c" in cef
        assert "source with \\= sign.eml" in cef

    def test_escapes_pipe_in_header_fields(self):
        # Header fields (before the final "|" that starts the extension)
        # must escape "|" since that's their delimiter.
        cef = to_cef(make_assessment(), "irrelevant.eml")
        header_part = cef.split("|", 7)[:7]
        assert all("|" not in field for field in header_part[1:])

    def test_zero_score_has_zero_severity(self):
        assessment = RiskAssessment(risk_score=0.0, risk_level="low", factors=[])
        cef = to_cef(assessment, "clean.eml")
        fields = cef.split("|")
        assert fields[6] == "0"
