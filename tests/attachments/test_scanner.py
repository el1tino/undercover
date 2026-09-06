"""Unit tests for undercover.attachments.scanner (combining sources,
summarizing a batch for risk scoring). These use hand-built
HashLookupResult/AttachmentVerdict objects rather than real clients, so
they run regardless of whether httpx is installed."""

from undercover.attachments.results import AttachmentVerdict, HashLookupResult
from undercover.attachments.scanner import AttachmentScanner, summarize_attachment_risk
from undercover.phishing.email_message import Attachment


def make_attachment(filename="invoice.exe", sha256="a" * 64) -> Attachment:
    return Attachment(
        filename=filename, content_type="application/octet-stream", sha256=sha256,
        size_bytes=1024,
    )


def make_verdict(filename, checked, malicious, lookups=None) -> AttachmentVerdict:
    return AttachmentVerdict(
        attachment=make_attachment(filename=filename),
        checked=checked,
        malicious=malicious,
        lookups=lookups or [],
    )


class TestAttachmentScannerCombination:
    def test_malicious_if_either_source_flags_it(self, monkeypatch):
        scanner = AttachmentScanner(vt_api_key="k1", mb_api_key="k2")
        monkeypatch.setattr(
            scanner.vt_client,
            "lookup_hash",
            lambda h: HashLookupResult("virustotal", True, True, False, "clean per VT"),
        )
        monkeypatch.setattr(
            scanner.mb_client,
            "lookup_hash",
            lambda h: HashLookupResult("malwarebazaar", True, True, True, "known malware"),
        )
        verdicts = scanner.scan([make_attachment()])
        assert verdicts[0].malicious is True
        assert verdicts[0].checked is True

    def test_not_checked_when_neither_source_attempted(self, monkeypatch):
        scanner = AttachmentScanner()  # no keys configured
        verdicts = scanner.scan([make_attachment()])
        assert verdicts[0].checked is False
        assert verdicts[0].malicious is False

    def test_checked_but_clean_when_both_sources_say_clean(self, monkeypatch):
        scanner = AttachmentScanner(vt_api_key="k1")
        monkeypatch.setattr(
            scanner.vt_client,
            "lookup_hash",
            lambda h: HashLookupResult("virustotal", True, True, False, "clean per VT"),
        )
        verdicts = scanner.scan([make_attachment()])
        assert verdicts[0].checked is True
        assert verdicts[0].malicious is False

    def test_scans_multiple_attachments_independently(self, monkeypatch):
        scanner = AttachmentScanner(vt_api_key="k1")

        def fake_lookup(sha256):
            malicious = sha256 == "bad" * 21 + "b"
            return HashLookupResult("virustotal", True, True, malicious, "x")

        monkeypatch.setattr(scanner.vt_client, "lookup_hash", fake_lookup)
        attachments = [
            make_attachment(filename="clean.txt", sha256="good" * 16),
            make_attachment(filename="evil.exe", sha256="bad" * 21 + "b"),
        ]
        verdicts = scanner.scan(attachments)
        by_name = {v.attachment.filename: v for v in verdicts}
        assert by_name["clean.txt"].malicious is False
        assert by_name["evil.exe"].malicious is True


class TestSummarizeAttachmentRisk:
    def test_no_attachments(self):
        value, detail = summarize_attachment_risk([])
        assert value == 0.0
        assert "no attachments" in detail

    def test_none_could_be_checked(self):
        verdicts = [make_verdict("a.exe", checked=False, malicious=False)]
        value, detail = summarize_attachment_risk(verdicts)
        assert value == 0.0
        assert "could not be checked" in detail

    def test_checked_and_clean(self):
        verdicts = [
            make_verdict("a.exe", checked=True, malicious=False),
            make_verdict("b.pdf", checked=True, malicious=False),
        ]
        value, detail = summarize_attachment_risk(verdicts)
        assert value == 0.0
        assert "none flagged" in detail

    def test_one_malicious_attachment_maxes_risk(self):
        verdicts = [
            make_verdict("a.exe", checked=True, malicious=True),
            make_verdict("b.pdf", checked=True, malicious=False),
        ]
        value, detail = summarize_attachment_risk(verdicts)
        assert value == 1.0
        assert "a.exe" in detail
        assert "b.pdf" not in detail

    def test_mixed_checked_and_unchecked_with_malicious_present(self):
        verdicts = [
            make_verdict("a.exe", checked=True, malicious=True),
            make_verdict("b.pdf", checked=False, malicious=False),
        ]
        value, _ = summarize_attachment_risk(verdicts)
        assert value == 1.0
