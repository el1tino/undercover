"""Unit tests for regex pattern detectors and their validators."""

from undercover.dlp.patterns import luhn_checksum
from undercover.dlp.scanner import DLPScanner


def scan_regex_only(text: str):
    return DLPScanner(use_ner=False).scan(text)


class TestLuhnChecksum:
    def test_valid_visa_test_number(self):
        assert luhn_checksum("4111111111111111") is True

    def test_valid_mastercard_test_number(self):
        assert luhn_checksum("5500005555555559") is True

    def test_invalid_number(self):
        assert luhn_checksum("1234567890123456") is False


class TestCreditCardDetection:
    def test_detects_valid_card_number(self):
        result = scan_regex_only("My card is 4111111111111111, don't share it.")
        types = [f.type for f in result.findings]
        assert "credit_card" in types

    def test_ignores_luhn_invalid_digit_run(self):
        result = scan_regex_only("Tracking number: 1234567890123456")
        types = [f.type for f in result.findings]
        assert "credit_card" not in types

    def test_detects_card_with_separators(self):
        result = scan_regex_only("Card: 4111-1111-1111-1111")
        types = [f.type for f in result.findings]
        assert "credit_card" in types


class TestSSNDetection:
    def test_detects_plausible_ssn(self):
        result = scan_regex_only("SSN: 523-45-6789")
        types = [f.type for f in result.findings]
        assert "ssn" in types

    def test_rejects_invalid_area_number(self):
        result = scan_regex_only("Not an SSN: 000-45-6789")
        types = [f.type for f in result.findings]
        assert "ssn" not in types

    def test_rejects_zero_group_or_serial(self):
        result = scan_regex_only("Fake: 523-00-6789 and 523-45-0000")
        types = [f.type for f in result.findings]
        assert "ssn" not in types


class TestSecretDetection:
    def test_detects_aws_access_key(self):
        result = scan_regex_only("key=AKIAABCDEFGHIJKLMNOP")
        types = [f.type for f in result.findings]
        assert "aws_access_key" in types

    def test_detects_github_token(self):
        result = scan_regex_only(
            "token: ghp_" + "a" * 36
        )
        types = [f.type for f in result.findings]
        assert "github_token" in types

    def test_detects_slack_token(self):
        result = scan_regex_only("xoxb-1234567890-abcdefghijklmnop")
        types = [f.type for f in result.findings]
        assert "slack_token" in types

    def test_detects_private_key_block(self):
        result = scan_regex_only("-----BEGIN RSA PRIVATE KEY-----\nMIIB...")
        types = [f.type for f in result.findings]
        assert "private_key_block" in types

    def test_detects_jwt(self):
        fake_jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        result = scan_regex_only(f"Authorization: Bearer {fake_jwt}")
        types = [f.type for f in result.findings]
        assert "jwt" in types

    def test_detects_generic_password_assignment(self):
        result = scan_regex_only('password: "SuperSecret123!"')
        types = [f.type for f in result.findings]
        assert "generic_api_key" in types


class TestEmailAndPhoneDetection:
    def test_detects_email_address(self):
        result = scan_regex_only("Contact me at jane.doe@example.com please.")
        types = [f.type for f in result.findings]
        assert "email" in types

    def test_detects_phone_number(self):
        result = scan_regex_only("Call me at 415-555-0132.")
        types = [f.type for f in result.findings]
        assert "phone_number" in types


class TestNoFalsePositivesOnCleanText:
    def test_clean_text_has_no_findings(self):
        result = scan_regex_only(
            "The quarterly report is due Friday. Please review the "
            "attached slides before our sync."
        )
        assert result.findings == []
