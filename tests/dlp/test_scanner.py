"""Unit tests for the DLPScanner orchestration and Finding/ScanResult behavior."""

from undercover.dlp.scanner import DLPScanner, Finding


class TestFindingRedaction:
    def test_redacts_all_but_last_four_chars(self):
        finding = Finding(
            type="credit_card",
            label="Credit Card Number",
            value="4111111111111111",
            start=0,
            end=17,
            source="regex",
            confidence=0.95,
        )
        redacted = finding.redacted()
        assert redacted.endswith("1111")
        assert redacted == "*" * 12 + "1111"

    def test_short_values_fully_masked(self):
        finding = Finding(
            type="phone_number",
            label="Phone",
            value="123",
            start=0,
            end=3,
            source="regex",
            confidence=0.5,
        )
        assert finding.redacted() == "***"

    def test_to_dict_never_leaks_raw_value(self):
        finding = Finding(
            type="ssn",
            label="SSN",
            value="523-45-6789",
            start=0,
            end=11,
            source="regex",
            confidence=0.85,
        )
        d = finding.to_dict()
        assert "523-45-6789" not in d["value"]
        assert d["value"].endswith("6789")


class TestDLPScannerOrchestration:
    def test_scan_without_ner_does_not_attempt_ner(self):
        scanner = DLPScanner(use_ner=False)
        result = scanner.scan("Nothing sensitive here.")
        assert result.ner_ran is False
        assert result.ner_skip_reason is None

    def test_scan_with_ner_requested_but_unavailable_reports_reason(self):
        # In the test environment spaCy/the model are not installed, so
        # requesting NER should degrade gracefully with a reason rather
        # than raising.
        scanner = DLPScanner(use_ner=True)
        result = scanner.scan("Contact Jane Doe in New York.")
        assert result.ner_ran is False
        assert result.ner_skip_reason is not None

    def test_findings_are_sorted_by_start_offset(self):
        scanner = DLPScanner(use_ner=False)
        text = "Email jane@example.com then call 415-555-0132."
        result = scanner.scan(text)
        starts = [f.start for f in result.findings]
        assert starts == sorted(starts)

    def test_by_type_groups_findings(self):
        scanner = DLPScanner(use_ner=False)
        text = "jane@example.com and john@example.com"
        result = scanner.scan(text)
        grouped = result.by_type()
        assert "email" in grouped
        assert len(grouped["email"]) == 2

    def test_has_findings_false_on_clean_text(self):
        scanner = DLPScanner(use_ner=False)
        result = scanner.scan("A perfectly ordinary sentence.")
        assert result.has_findings is False

    def test_to_dict_shape(self):
        scanner = DLPScanner(use_ner=False)
        result = scanner.scan("jane@example.com")
        d = result.to_dict()
        assert set(d.keys()) == {"findings", "ner_ran", "ner_skip_reason"}
        assert isinstance(d["findings"], list)
