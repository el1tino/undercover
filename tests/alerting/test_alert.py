"""Unit tests for undercover.alerting.alert.build_alert."""

from dataclasses import dataclass

from undercover.alerting.alert import build_alert


@dataclass(frozen=True)
class FakeFactor:
    value: float
    detail: str


@dataclass(frozen=True)
class FakeAssessment:
    risk_level: str
    risk_score: float
    factors: list


def test_title_reflects_risk_level():
    assessment = FakeAssessment(risk_level="critical", risk_score=0.9, factors=[])
    alert = build_alert(assessment, "phishing.eml")
    assert "CRITICAL" in alert.title


def test_message_uses_top_three_factors_by_value():
    factors = [
        FakeFactor(value=0.9, detail="phishing verdict: phishing"),
        FakeFactor(value=0.1, detail="no sensitive-data findings"),
        FakeFactor(value=1.0, detail="DMARC authentication failed"),
        FakeFactor(value=0.5, detail="sender flagged as anomalous"),
    ]
    assessment = FakeAssessment(risk_level="critical", risk_score=0.85, factors=factors)
    alert = build_alert(assessment, "phishing.eml")
    assert "DMARC authentication failed" in alert.message
    assert "phishing verdict: phishing" in alert.message
    assert "sender flagged as anomalous" in alert.message
    assert "no sensitive-data findings" not in alert.message


def test_no_factors_has_placeholder_message():
    assessment = FakeAssessment(risk_level="low", risk_score=0.0, factors=[])
    alert = build_alert(assessment, "clean.eml")
    assert alert.message == "no contributing factors"


def test_carries_source_and_sender():
    assessment = FakeAssessment(risk_level="high", risk_score=0.7, factors=[])
    alert = build_alert(assessment, "phishing.eml", sender_email="attacker@evil.example")
    assert alert.source == "phishing.eml"
    assert alert.sender_email == "attacker@evil.example"


def test_sender_email_defaults_to_none():
    assessment = FakeAssessment(risk_level="high", risk_score=0.7, factors=[])
    alert = build_alert(assessment, "phishing.eml")
    assert alert.sender_email is None
