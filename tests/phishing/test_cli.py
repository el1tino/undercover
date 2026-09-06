"""Unit tests for the undercover-phish CLI entry point."""

import io
import json

from undercover.phishing.cli import main

RAW_CLEAN_EMAIL = (
    "From: Jane Doe <jane@example.com>\n"
    "Subject: Meeting notes\n"
    "\n"
    "Here are the notes from our meeting today.\n"
)

RAW_PHISHING_EMAIL = (
    "From: PayPal Support <support@paypal-security.net>\n"
    "Subject: Verify your account immediately\n"
    "\n"
    "Dear valued customer, we detected unusual activity. Act now or your "
    "account will be closed. Visit http://192.168.1.5/login now.\n"
)


def test_clean_email_exits_zero(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(RAW_CLEAN_EMAIL))
    exit_code = main(["--no-ml"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "CLEAN" in captured.out


def test_phishing_email_with_fail_on_detect_exits_one(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(RAW_PHISHING_EMAIL))
    exit_code = main(["--no-ml", "--fail-on-detect"])
    assert exit_code == 1


def test_json_output_is_valid_json(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(RAW_PHISHING_EMAIL))
    main(["--no-ml", "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["verdict"] in {"clean", "suspicious", "phishing"}
    assert "rule_hits" in payload


def test_scans_a_file(tmp_path, capsys):
    sample = tmp_path / "sample.eml"
    sample.write_text(RAW_PHISHING_EMAIL)
    exit_code = main(["--no-ml", str(sample)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Verdict for" in captured.out


def test_submit_to_unreachable_api_warns_but_does_not_crash(tmp_path, capsys):
    sample = tmp_path / "sample.eml"
    sample.write_text(RAW_CLEAN_EMAIL)
    exit_code = main(
        ["--no-ml", "--submit", "--api-url", "http://127.0.0.1:59999", str(sample)]
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Warning: could not submit to API" in captured.err
