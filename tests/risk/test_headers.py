"""Unit tests for undercover.risk.headers."""

from email.message import EmailMessage as StdlibEmailMessage

from undercover.risk.headers import analyze_headers, parse_authentication_results


def _raw(auth_results: str | None = None, dkim_signature: bool = False) -> str:
    msg = StdlibEmailMessage()
    msg["From"] = "sender@example.com"
    msg["Subject"] = "Hello"
    if auth_results is not None:
        msg["Authentication-Results"] = auth_results
    if dkim_signature:
        msg["DKIM-Signature"] = "v=1; a=rsa-sha256; d=example.com; s=selector; b=abc123"
    msg.set_content("Body text.")
    return msg.as_string()


class TestParseAuthenticationResults:
    def test_parses_all_three_mechanisms(self):
        header = (
            "mx.example.com; spf=pass smtp.mailfrom=x@y.com; "
            "dkim=pass header.d=y.com; dmarc=pass header.from=y.com"
        )
        results = parse_authentication_results(header)
        by_mechanism = {r.mechanism: r.result for r in results}
        assert by_mechanism == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}

    def test_parses_mixed_results(self):
        header = "mx.example.com; spf=fail smtp.mailfrom=x@y.com; dkim=none"
        results = parse_authentication_results(header)
        by_mechanism = {r.mechanism: r.result for r in results}
        assert by_mechanism == {"spf": "fail", "dkim": "none"}

    def test_empty_header_returns_no_results(self):
        assert parse_authentication_results("mx.example.com; none") == []


class TestAnalyzeHeaders:
    def test_no_auth_results_header(self):
        report = analyze_headers(_raw())
        assert report.authentication_results_present is False
        assert report.spf is None
        score, detail = report.risk_contribution()
        assert score == 0.3
        assert "no Authentication-Results" in detail

    def test_all_pass(self):
        raw = _raw("mx.example.com; spf=pass; dkim=pass; dmarc=pass")
        report = analyze_headers(raw)
        assert report.authentication_results_present is True
        assert report.spf.result == "pass"
        assert report.dkim.result == "pass"
        assert report.dmarc.result == "pass"
        score, detail = report.risk_contribution()
        assert score == 0.0

    def test_dmarc_fail_is_highest_risk(self):
        raw = _raw("mx.example.com; spf=pass; dkim=pass; dmarc=fail")
        report = analyze_headers(raw)
        score, detail = report.risk_contribution()
        assert score == 1.0
        assert "DMARC" in detail

    def test_spf_fail(self):
        raw = _raw("mx.example.com; spf=fail; dkim=pass; dmarc=pass")
        report = analyze_headers(raw)
        score, _ = report.risk_contribution()
        assert score == 0.7

    def test_inconclusive_results(self):
        raw = _raw("mx.example.com; spf=softfail; dkim=neutral")
        report = analyze_headers(raw)
        score, _ = report.risk_contribution()
        assert score == 0.4

    def test_detects_dkim_signature_presence(self):
        report = analyze_headers(_raw(dkim_signature=True))
        assert report.has_dkim_signature is True

    def test_no_dkim_signature(self):
        report = analyze_headers(_raw())
        assert report.has_dkim_signature is False

    def test_uses_first_of_multiple_authentication_results_headers(self):
        msg = StdlibEmailMessage()
        msg["From"] = "sender@example.com"
        msg["Subject"] = "Hello"
        msg["Authentication-Results"] = "mx1.example.com; spf=pass; dkim=pass; dmarc=pass"
        msg["Authentication-Results"] = "mx2.example.com; spf=fail; dkim=fail; dmarc=fail"
        msg.set_content("Body.")
        raw = msg.as_string()

        report = analyze_headers(raw)
        assert len(report.raw_authentication_results) == 2
        # The first header in the raw message (added by the most recent hop)
        # wins -- here that's the mx1 (all-pass) one.
        assert report.spf.result == "pass"
