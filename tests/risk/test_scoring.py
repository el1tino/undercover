"""Unit tests for undercover.risk.scoring.assess_risk."""

from undercover.dlp.scanner import Finding, ScanResult
from undercover.phishing.detector import PhishingResult
from undercover.risk.headers import HeaderAuthReport
from undercover.risk.scoring import HEADER_WEIGHT, PHISHING_WEIGHT, assess_risk


def make_dlp_result(*confidences: float) -> ScanResult:
    findings = [
        Finding(
            type="email",
            label="Email",
            value="x",
            start=0,
            end=1,
            source="regex",
            confidence=c,
        )
        for c in confidences
    ]
    return ScanResult(findings=findings, ner_ran=False, ner_skip_reason=None)


def make_phishing_result(combined_score: float, verdict: str = "phishing") -> PhishingResult:
    return PhishingResult(
        rule_hits=[],
        rule_score=combined_score,
        ml_score=None,
        ml_skip_reason=None,
        combined_score=combined_score,
        verdict=verdict,
    )


def make_malicious_attachment_verdict():
    from undercover.attachments.results import AttachmentVerdict
    from undercover.phishing.email_message import Attachment

    return AttachmentVerdict(
        attachment=Attachment(
            filename="invoice.exe",
            content_type="application/octet-stream",
            sha256="a" * 64,
            size_bytes=1024,
        ),
        checked=True,
        malicious=True,
        lookups=[],
    )


def make_header_report(all_pass: bool = True) -> HeaderAuthReport:
    from undercover.risk.headers import AuthResult

    result = "pass" if all_pass else "fail"
    return HeaderAuthReport(
        authentication_results_present=True,
        spf=AuthResult("spf", result),
        dkim=AuthResult("dkim", result),
        dmarc=AuthResult("dmarc", result),
    )


class TestNoSignals:
    def test_no_signals_is_zero_and_low(self):
        assessment = assess_risk()
        assert assessment.risk_score == 0.0
        assert assessment.risk_level == "low"
        assert assessment.factors == []


class TestSingleSignal:
    def test_phishing_only(self):
        assessment = assess_risk(phishing_result=make_phishing_result(0.9))
        assert len(assessment.factors) == 1
        assert assessment.factors[0].name == "phishing"
        # only one signal present -> risk_score equals that signal's value
        assert assessment.risk_score == 0.9
        assert assessment.risk_level == "critical"

    def test_dlp_only_no_findings(self):
        assessment = assess_risk(dlp_result=make_dlp_result())
        assert assessment.risk_score == 0.0

    def test_dlp_only_with_findings(self):
        assessment = assess_risk(dlp_result=make_dlp_result(0.9))
        assert assessment.risk_score == 0.9

    def test_header_only_all_pass(self):
        assessment = assess_risk(header_report=make_header_report(all_pass=True))
        assert assessment.risk_score == 0.0

    def test_header_only_all_fail(self):
        assessment = assess_risk(header_report=make_header_report(all_pass=False))
        assert assessment.risk_score == 1.0
        assert assessment.risk_level == "critical"

    def test_anomaly_only_flagged(self):
        assessment = assess_risk(sender_is_anomalous=True)
        assert assessment.risk_score == 1.0

    def test_anomaly_only_not_flagged(self):
        assessment = assess_risk(sender_is_anomalous=False)
        assert assessment.risk_score == 0.0

    def test_attachments_only_malicious(self):
        assessment = assess_risk(attachment_verdicts=[make_malicious_attachment_verdict()])
        assert assessment.risk_score == 1.0
        assert assessment.factors[0].name == "attachments"

    def test_attachments_only_none_present(self):
        assessment = assess_risk(attachment_verdicts=[])
        assert assessment.risk_score == 0.0
        assert "no attachments" in assessment.factors[0].detail


class TestMultipleSignals:
    def test_missing_signals_dont_drag_score_down(self):
        # Only phishing present, maxed out -> should score as high as if it
        # were the only signal, not diluted by "missing" weight.
        only_phishing = assess_risk(phishing_result=make_phishing_result(1.0))
        all_signals_all_bad = assess_risk(
            phishing_result=make_phishing_result(1.0),
            dlp_result=make_dlp_result(1.0),
            header_report=make_header_report(all_pass=False),
            sender_is_anomalous=True,
            attachment_verdicts=[make_malicious_attachment_verdict()],
        )
        assert only_phishing.risk_score == 1.0
        assert all_signals_all_bad.risk_score == 1.0

    def test_mixed_signals_produce_weighted_average(self):
        assessment = assess_risk(
            phishing_result=make_phishing_result(1.0),
            header_report=make_header_report(all_pass=True),
        )
        # weighted average of phishing=1.0 and header=0.0
        expected = (PHISHING_WEIGHT * 1.0 + HEADER_WEIGHT * 0.0) / (
            PHISHING_WEIGHT + HEADER_WEIGHT
        )
        assert abs(assessment.risk_score - expected) < 1e-9

    def test_factor_count_matches_signals_supplied(self):
        assessment = assess_risk(
            phishing_result=make_phishing_result(0.5),
            dlp_result=make_dlp_result(0.5),
        )
        assert len(assessment.factors) == 2
        names = {f.name for f in assessment.factors}
        assert names == {"phishing", "dlp"}


class TestRiskLevelThresholds:
    def test_low(self):
        assert assess_risk(phishing_result=make_phishing_result(0.1)).risk_level == "low"

    def test_medium(self):
        assert assess_risk(phishing_result=make_phishing_result(0.4)).risk_level == "medium"

    def test_high(self):
        assert assess_risk(phishing_result=make_phishing_result(0.65)).risk_level == "high"

    def test_critical(self):
        assert assess_risk(phishing_result=make_phishing_result(0.9)).risk_level == "critical"


class TestToDict:
    def test_shape(self):
        assessment = assess_risk(phishing_result=make_phishing_result(0.5))
        d = assessment.to_dict()
        assert set(d.keys()) == {"risk_score", "risk_level", "factors"}
        assert d["factors"][0]["name"] == "phishing"
